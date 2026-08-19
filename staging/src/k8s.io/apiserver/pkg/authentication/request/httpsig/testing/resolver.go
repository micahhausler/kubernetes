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

// Package testing runs an HTTP signature key resolver in process, on a real
// socket, for tests and for the end to end demo.
//
// It is a real gRPC server over a real Unix socket rather than a bufconn or a
// direct call, because the parts most likely to be wrong are the ones a direct
// call skips: endpoint parsing, the dialer, status code mapping, and the
// distinction between a resolver that says not-found and one that is not there.
package testing

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	externalhttpsig "k8s.io/externalhttpsig/apis/v1alpha1"
)

// Resolver is a configurable in-process resolver.
//
// Every field is guarded by its mutex and may be changed while the server runs,
// so a test can revoke a key, break the resolver, or change its metadata between
// requests without restarting anything.
type Resolver struct {
	externalhttpsig.UnimplementedExternalHTTPSignatureServiceServer

	server   *grpc.Server
	listener net.Listener
	endpoint string
	stopOnce sync.Once

	mu sync.Mutex

	// keys are the answers to give, by key ID. A key ID that is absent is answered
	// NOT_FOUND.
	keys map[string]*externalhttpsig.ResolveKeyResponse

	// metadata is the answer to Metadata.
	metadata *externalhttpsig.MetadataResponse

	// metadataErr, resolveErr, and nonceErr make the corresponding call fail, for
	// testing a resolver that is reachable but broken. A resolver that is not
	// there at all is tested by stopping the server instead.
	metadataErr error
	resolveErr  error
	nonceErr    error

	// nonces is the nonce store, keyed by key ID and nonce. Recording is done under
	// the same mutex as the check, which is the atomicity the protocol requires.
	nonces map[string]map[string]time.Time

	// Call counts, for asserting that a lookup was cached or that a rejected
	// signature never reached the nonce store.
	ResolveCalls  int
	NonceCalls    int
	MetadataCalls int

	// LastResolve is the most recent ResolveKey request, for asserting what was
	// relayed.
	LastResolve *externalhttpsig.ResolveKeyRequest

	// LastNonce is the most recent ConsumeNonce request, for asserting the expiry
	// the resolver is asked to honor.
	LastNonce *externalhttpsig.ConsumeNonceRequest
}

// New starts a resolver on socketPath and stops it when the test ends.
//
// socketPath may be a filesystem path or, on Linux, an abstract socket name
// beginning with "@". Both are rendered as unix:///<path>, with three slashes,
// because the endpoint parser reads the abstract form out of the URL path and
// unix://@name would parse @name as a host.
func New(t interface {
	Fatalf(string, ...any)
	Cleanup(func())
}, socketPath string) *Resolver {
	r := &Resolver{
		endpoint: "unix:///" + strings.TrimPrefix(socketPath, "/"),
		keys:     map[string]*externalhttpsig.ResolveKeyResponse{},
		nonces:   map[string]map[string]time.Time{},
		metadata: &externalhttpsig.MetadataResponse{},
		server:   grpc.NewServer(),
	}
	externalhttpsig.RegisterExternalHTTPSignatureServiceServer(r.server, r)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listening on %s: %v", socketPath, err)
	}
	r.listener = listener
	// The server is captured rather than read from r inside the goroutine, because
	// Stop may run first.
	server := r.server
	go func() {
		// Serve returns when the server is stopped, which the cleanup below does.
		_ = server.Serve(listener)
	}()
	t.Cleanup(r.Stop)
	return r
}

// Endpoint is the value to put in an authenticator's endpoint field.
func (r *Resolver) Endpoint() string { return r.endpoint }

// Stop shuts the resolver down. Calling it more than once is safe, which is what
// lets a test stop the resolver mid-test to simulate one that is not there and
// still have cleanup run.
func (r *Resolver) Stop() {
	r.stopOnce.Do(r.server.Stop)
}

// SetKey makes keyID resolve to resp. A key ID with no entry answers NOT_FOUND.
func (r *Resolver) SetKey(keyID string, resp *externalhttpsig.ResolveKeyResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[keyID] = resp
}

// DeleteKey revokes a key, so it answers NOT_FOUND from now on.
func (r *Resolver) DeleteKey(keyID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.keys, keyID)
}

// SetMetadata sets the Metadata answer.
func (r *Resolver) SetMetadata(resp *externalhttpsig.MetadataResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.metadata = resp
}

// SetErrors makes the corresponding calls fail. A nil argument leaves that call
// working.
func (r *Resolver) SetErrors(metadata, resolve, nonce error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.metadataErr, r.resolveErr, r.nonceErr = metadata, resolve, nonce
}

// Counts returns the call counts.
func (r *Resolver) Counts() (resolve, nonce, metadata int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ResolveCalls, r.NonceCalls, r.MetadataCalls
}

// LastRequests returns the most recent ResolveKey and ConsumeNonce requests.
func (r *Resolver) LastRequests() (*externalhttpsig.ResolveKeyRequest, *externalhttpsig.ConsumeNonceRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.LastResolve, r.LastNonce
}

func (r *Resolver) Metadata(_ context.Context, _ *externalhttpsig.MetadataRequest) (*externalhttpsig.MetadataResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.MetadataCalls++
	if r.metadataErr != nil {
		return nil, r.metadataErr
	}
	return r.metadata, nil
}

func (r *Resolver) ResolveKey(_ context.Context, req *externalhttpsig.ResolveKeyRequest) (*externalhttpsig.ResolveKeyResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ResolveCalls++
	r.LastResolve = req
	if r.resolveErr != nil {
		return nil, r.resolveErr
	}
	// The whole key ID first, then the segment before its first slash. A derived
	// key's key ID carries its claimed scope after the name, and decomposing that
	// is the resolver's job because the resolver is the party that holds the
	// ladder. kube-apiserver hands the key ID over whole and does not parse it.
	resp, ok := r.keys[req.GetKeyId()]
	if !ok {
		name, _, found := strings.Cut(req.GetKeyId(), "/")
		if found {
			resp, ok = r.keys[name]
		}
	}
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no key with keyID %q", req.GetKeyId())
	}
	return resp, nil
}

func (r *Resolver) ConsumeNonce(_ context.Context, req *externalhttpsig.ConsumeNonceRequest) (*externalhttpsig.ConsumeNonceResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.NonceCalls++
	r.LastNonce = req
	if r.nonceErr != nil {
		return nil, r.nonceErr
	}

	perKey := r.nonces[req.GetKeyId()]
	if perKey == nil {
		perKey = map[string]time.Time{}
		r.nonces[req.GetKeyId()] = perKey
	}
	if _, seen := perKey[req.GetNonce()]; seen {
		return &externalhttpsig.ConsumeNonceResponse{
			Accepted: false,
			Reason:   fmt.Sprintf("nonce %q has already been used for keyID %q", req.GetNonce(), req.GetKeyId()),
		}, nil
	}
	perKey[req.GetNonce()] = req.GetExpiresAt().AsTime()
	return &externalhttpsig.ConsumeNonceResponse{Accepted: true}, nil
}
