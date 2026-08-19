/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Command httpsig-resolver serves HTTP message signature keys to kube-apiserver from
// a YAML file.
//
// It implements k8s.io/externalhttpsig: kube-apiserver asks it which key verifies
// signatures bearing a key ID and whose identity that is, and asks it to record the
// nonce each accepted signature carries. kube-apiserver does all of the cryptography;
// this process holds key material and nonce state and never sees a request.
//
// It exists to make the API's shape concrete and to give the demo something to point
// at. It is not a key management system. Two things in particular are wrong for
// anything real, and both are wrong in the direction of being obvious rather than
// subtle:
//
// Key material sits in a file on disk, in plaintext, next to the identity it
// authenticates. That is the same objection this whole API exists to answer, moved
// one process over. What moving it buys even here is real, though: the file is not
// kube-apiserver's configuration, so it is not on every control plane node, editing
// it takes effect without restarting anything, and the blast radius of reading it is
// one process rather than the API server.
//
// Nonce state is in memory in one process. That is correct for one resolver and wrong
// the moment there are two: two resolvers behind one socket path would each accept a
// replay the other had already seen. A real deployment needs shared storage with an
// atomic compare-and-set, which is exactly what this RPC's contract requires and this
// implementation satisfies only by being alone.
//
// Usage:
//
//	httpsig-resolver --keys keys.yaml --listen /var/run/httpsig/resolver.sock
//
// The socket path may begin with @ for a Linux abstract socket. Point kube-apiserver
// at it with an httpSignature entry whose endpoint is unix:///<path>, with three
// slashes, including for the abstract form.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"

	externalhttpsig "k8s.io/externalhttpsig/apis/v1alpha1"
	"k8s.io/klog/v2"
)

func main() {
	klog.InitFlags(nil)
	var (
		keysPath   = flag.String("keys", "", "Path to the YAML key file. Required.")
		listen     = flag.String("listen", "", "Unix socket path to serve on, or @name for a Linux abstract socket. Required.")
		maxNonces  = flag.Int("max-nonces", 65536, "Maximum unexpired nonce records to hold. A full store rejects rather than evicting, because evicting a record permits the replay it was preventing.")
		socketMode = flag.String("socket-mode", "0600", "Octal permissions for the socket. Access to the socket is the whole trust boundary, so this is a security setting. Widen it only to reach kube-apiserver running as another user, and prefer a shared group (0660) over anything world-accessible.")
	)
	flag.Parse()

	if err := run(*keysPath, *listen, *maxNonces, *socketMode); err != nil {
		klog.ErrorS(err, "httpsig-resolver")
		os.Exit(1)
	}
}

func run(keysPath, listen string, maxNonces int, socketMode string) error {
	if keysPath == "" {
		return fmt.Errorf("--keys is required")
	}
	if listen == "" {
		return fmt.Errorf("--listen is required")
	}
	if maxNonces <= 0 {
		return fmt.Errorf("--max-nonces must be positive: a store that holds no nonces detects no replay")
	}
	mode, err := parseSocketMode(socketMode)
	if err != nil {
		return err
	}

	// Loaded before listening, so a malformed key file is an exit code and a message
	// rather than a resolver that answers not-found for everything.
	r, err := newResolver(keysPath, maxNonces)
	if err != nil {
		return fmt.Errorf("loading %s: %w", keysPath, err)
	}

	listener, err := listenOn(listen, mode)
	if err != nil {
		return err
	}

	server := grpc.NewServer()
	externalhttpsig.RegisterExternalHTTPSignatureServiceServer(server, r)

	// The socket carries key material and relayed session tokens in the clear, and
	// nothing authenticates the peer. Its permissions are the whole trust boundary,
	// so the effective mode is stated in the log where an operator will see it, read
	// back from the filesystem rather than echoed from the flag.
	klog.InfoS("Serving", "socket", listen, "keys", keysPath, "permissions", effectiveMode(listen))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-stop
		klog.InfoS("Shutting down", "signal", sig.String(), "noncesHeld", r.nonces.size())
		// Graceful, so a lookup already in flight completes. An abrupt stop would
		// surface at the API server as a failed authentication for a request that was
		// about to succeed.
		server.GracefulStop()
	}()

	return server.Serve(listener)
}

// parseSocketMode reads the octal permissions for the socket.
func parseSocketMode(text string) (os.FileMode, error) {
	value, err := strconv.ParseUint(text, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("--socket-mode %q is not octal permissions such as 0600: %w", text, err)
	}
	mode := os.FileMode(value)
	if mode&^os.ModePerm != 0 {
		return 0, fmt.Errorf("--socket-mode %q sets bits outside the permission bits", text)
	}
	if mode&0002 != 0 {
		// Refused rather than warned about. On Linux, connecting to a unix socket
		// requires write permission, so world-writable means any local process can
		// vend an identity to this cluster. There is no deployment where that is the
		// intent, and a warning in a log is not a control.
		return 0, fmt.Errorf("--socket-mode %q is world-writable, which lets any local process vend an identity to this cluster; use 0600, or 0660 with a group shared with kube-apiserver", text)
	}
	return mode, nil
}

// listenOn opens the socket, clearing a stale one left by a previous run.
//
// A resolver that wedges on restart because its own socket file survived is a defect
// dressed as an operational step, so the file is removed when nothing is listening on
// it. It is not removed when something is: a second copy of this process should fail
// rather than take the first one's traffic, because two of them would each accept
// replays the other had recorded.
//
// The mode is applied twice on purpose. net.Listen creates the socket with
// 0777 & ^umask, so without the umask below the permissions of the trust boundary
// would be whatever the invoking shell happened to be set to. The umask closes the
// window between bind and chmod; the chmod makes the final mode exact rather than
// merely no wider than asked for.
func listenOn(path string, mode os.FileMode) (net.Listener, error) {
	abstract := strings.HasPrefix(path, "@")
	if !abstract {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return nil, fmt.Errorf("creating the socket directory: %w", err)
		}
		if _, err := os.Stat(path); err == nil {
			conn, dialErr := net.DialTimeout("unix", path, time.Second)
			if dialErr == nil {
				_ = conn.Close()
				return nil, fmt.Errorf("%s already has a resolver listening on it; stop it before starting another, because two resolvers do not share nonce state and each would accept replays the other recorded", path)
			}
			klog.InfoS("Removing a stale socket left by a previous run", "socket", path)
			if err := os.Remove(path); err != nil {
				return nil, fmt.Errorf("removing the stale socket %s: %w", path, err)
			}
		}
	}

	if abstract {
		// An abstract socket has no filesystem entry, so it has no permissions to set.
		// Nothing here can bound it; the network namespace is the only boundary, and
		// the startup log says so.
		return net.Listen("unix", path)
	}

	previous := syscall.Umask(int(os.ModePerm & ^mode))
	listener, err := net.Listen("unix", path)
	syscall.Umask(previous)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("setting the socket permissions on %s: %w", path, err)
	}
	return listener, nil
}

// effectiveMode reports the socket's permissions as the filesystem has them, for the
// startup log. Read back rather than echoed from the flag, so the log says what is
// true rather than what was asked for.
//
// An abstract socket has no permissions at all and says so, because that is the case
// where the answer is surprising.
func effectiveMode(path string) string {
	if strings.HasPrefix(path, "@") {
		return "none (abstract socket, bounded only by the network namespace)"
	}
	info, err := os.Stat(path)
	if err != nil {
		return "unknown"
	}
	return info.Mode().Perm().String()
}
