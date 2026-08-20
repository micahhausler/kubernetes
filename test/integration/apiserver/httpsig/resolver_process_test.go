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

package httpsig

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/micahhausler/httpsig/keyscope"
	authenticationv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	transporthttpsig "k8s.io/client-go/transport/httpsig"
)

// The tests in this file drive the httpsig-resolver command as a separate process,
// rather than the in-process resolver the rest of the package uses.
//
// They exist because everything else in this repository tests a resolver that shares
// the API server's address space, and that is not the shape anything ships in. What a
// separate process adds: the key file is parsed by the code that will parse it, the
// PEM the demo writes has to survive conversion to the DER the wire takes, the socket
// is created by one process and dialed by another, and a resolver that dies is a
// resolver that actually died. None of that is exercised by a fake.

// buildResolver compiles the resolver command once per test binary run.
func buildResolver(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "httpsig-resolver")
	// The package path is relative to this file, which sits under test/integration.
	cmd := exec.Command("go", "build", "-o", binary, "k8s.io/kubernetes/httpsig/e2e/cmd/httpsig-resolver")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building httpsig-resolver: %v\n%s", err, out)
	}
	return binary
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// test/integration/apiserver/httpsig -> repository root.
	for i := 0; i < 4; i++ {
		dir = filepath.Dir(dir)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatalf("could not find the repository root from the test's working directory: %v", err)
	}
	return dir
}

// startResolverProcess writes a key file, starts the resolver on a socket, waits for
// the socket to appear, and returns the endpoint plus the key file's path so a test
// can rewrite it.
func startResolverProcess(t *testing.T, binary, keysYAML string) (endpoint, keysPath string) {
	t.Helper()
	dir := t.TempDir()
	keysPath = filepath.Join(dir, "keys.yaml")
	if err := os.WriteFile(keysPath, []byte(keysYAML), 0600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "resolver.sock")

	cmd := exec.Command(binary, "--keys", keysPath, "--listen", socket, "-v", "4")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the resolver: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// Waited for rather than slept past, and the wait is on the socket existing
	// because that is what the API server needs. Its own dial budget would cover a
	// slower start, but a test that raced would fail as an unhelpful timeout.
	if err := wait.PollUntilContextTimeout(context.Background(), 50*time.Millisecond, 30*time.Second, true,
		func(context.Context) (bool, error) {
			_, err := os.Stat(socket)
			return err == nil, nil
		}); err != nil {
		t.Fatalf("the resolver never created its socket at %s: %v", socket, err)
	}
	return "unix://" + socket, keysPath
}

// TestResolverProcessAuthenticates is the existence proof for the command: a real API
// server, a real socket, a real signature, and a key file a person could have written.
func TestResolverProcessAuthenticates(t *testing.T) {
	binary := buildResolver(t)
	keyFile, publicKeyDER := keyPair(t, "alice", "ed25519")

	// The key file states the public key as PEM, which is what openssl and the demo
	// tool produce. The resolver converts it to the DER the protocol takes, and this
	// is the only test where that conversion runs in the process that will do it.
	endpoint, _ := startResolverProcess(t, binary, fmt.Sprintf(`keys:
  ed25519:
    %s:
      publicKey: |
%s
      user:
        username: %s
        uid: uid-alice
        groups: [%s]
        extra:
          demo: [resolver-process]
      cacheTTL: 5m
`, aliceKeyID, indentPEM(publicKeyDER, "        "), aliceUser, signerGrp))

	server, _ := startServer(t, fmt.Sprintf(`apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: resolver
    resolver:
      endpoint: %s
`, endpoint))
	grantPodReader(t, server)

	clientConfig := signingClientConfig(t, server, aliceUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion: "client.authentication.k8s.io/v1alpha1",
		Algorithm:  "ed25519",
		KeyID:      aliceKeyID,
		KeyFile:    keyFile,
	})
	client := kubernetes.NewForConfigOrDie(clientConfig)
	ctx := context.Background()

	review := selfReview(t, client)
	if got := review.Status.UserInfo.Username; got != aliceUser {
		t.Errorf("username: got %q, want %q", got, aliceUser)
	}
	if got := review.Status.UserInfo.UID; got != "uid-alice" {
		t.Errorf("uid: got %q, want %q", got, "uid-alice")
	}
	if got := review.Status.UserInfo.Groups; !containsString(got, signerGrp) {
		t.Errorf("groups: got %v, want to contain %q", got, signerGrp)
	}
	// Extra survives the round trip through the proto's map-of-repeated shape.
	if got := review.Status.UserInfo.Extra["demo"]; len(got) != 1 || got[0] != "resolver-process" {
		t.Errorf("extra: got %v, want [resolver-process]", got)
	}

	if _, err := client.CoreV1().Pods("default").List(ctx, metav1.ListOptions{}); err != nil {
		t.Errorf("listing pods: %v", err)
	}

	// A replay, refused by the resolver process's nonce store rather than by anything
	// in the API server.
	if err := assertReplayRejected(t, clientConfig); err != nil {
		t.Error(err)
	}
}

// TestResolverProcessRevokesOnFileEdit is the revocation story, end to end: removing a
// key from the file stops it authenticating, and the delay is the cache duration the
// file itself set.
func TestResolverProcessRevokesOnFileEdit(t *testing.T) {
	binary := buildResolver(t)
	keyFile, publicKeyDER := keyPair(t, "alice", "ed25519")

	// A one-second cache, so the revocation window is short enough to watch and long
	// enough to prove caching happened at all.
	endpoint, keysPath := startResolverProcess(t, binary, fmt.Sprintf(`keys:
  ed25519:
    %s:
      publicKey: |
%s
      user: {username: %s, groups: [%s]}
      cacheTTL: 1s
`, aliceKeyID, indentPEM(publicKeyDER, "        "), aliceUser, signerGrp))

	server, _ := startServer(t, fmt.Sprintf(`apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: resolver
    resolver:
      endpoint: %s
`, endpoint))

	clientConfig := signingClientConfig(t, server, aliceUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion: "client.authentication.k8s.io/v1alpha1",
		Algorithm:  "ed25519",
		KeyID:      aliceKeyID,
		KeyFile:    keyFile,
	})
	client := kubernetes.NewForConfigOrDie(clientConfig)
	ctx := context.Background()
	selfReview(t, client)

	// The key leaves the file. Nothing is restarted and nothing is signaled.
	if err := os.WriteFile(keysPath, []byte(fmt.Sprintf(`keys:
  ed25519:
    someone-else:
      publicKey: |
%s
      user: {username: someone-else}
      cacheTTL: 1s
`, indentPEM(publicKeyDER, "        "))), 0600); err != nil {
		t.Fatal(err)
	}

	// Bounded well above the one-second cache, because what is being asserted is that
	// revocation happens at all, not how fast.
	if err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 30*time.Second, true,
		func(ctx context.Context) (bool, error) {
			_, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
			return apierrors.IsUnauthorized(err), nil
		}); err != nil {
		t.Fatalf("a key removed from the resolver's file never stopped authenticating: %v", err)
	}
}

// TestResolverProcessDeathRejects covers fail-closed against a resolver that really
// died, rather than one told to return an error. The key is cached and still valid;
// the nonce cannot be recorded, so the request cannot be shown not to be a replay.
func TestResolverProcessDeathRejects(t *testing.T) {
	binary := buildResolver(t)
	keyFile, publicKeyDER := keyPair(t, "alice", "ed25519")

	dir := t.TempDir()
	keysPath := filepath.Join(dir, "keys.yaml")
	if err := os.WriteFile(keysPath, []byte(fmt.Sprintf(`keys:
  ed25519:
    %s:
      publicKey: |
%s
      user: {username: %s, groups: [%s]}
      cacheTTL: 30m
`, aliceKeyID, indentPEM(publicKeyDER, "        "), aliceUser, signerGrp)), 0600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "resolver.sock")
	cmd := exec.Command(binary, "--keys", keysPath, "--listen", socket)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			_ = cmd.Process.Kill()
		}
		_, _ = cmd.Process.Wait()
	})
	if err := wait.PollUntilContextTimeout(context.Background(), 50*time.Millisecond, 30*time.Second, true,
		func(context.Context) (bool, error) { _, err := os.Stat(socket); return err == nil, nil }); err != nil {
		t.Fatalf("the resolver never created its socket: %v", err)
	}

	server, _ := startServer(t, fmt.Sprintf(`apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: resolver
    resolver:
      endpoint: unix://%s
`, socket))

	clientConfig := signingClientConfig(t, server, aliceUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion: "client.authentication.k8s.io/v1alpha1",
		Algorithm:  "ed25519",
		KeyID:      aliceKeyID,
		KeyFile:    keyFile,
	})
	client := kubernetes.NewForConfigOrDie(clientConfig)
	selfReview(t, client)

	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	killed = true
	_, _ = cmd.Process.Wait()

	_, err := client.AuthenticationV1().SelfSubjectReviews().Create(
		context.Background(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err == nil {
		t.Fatal("a request was accepted after the resolver died, so its nonce was never recorded")
	}
	if !apierrors.IsUnauthorized(err) {
		t.Errorf("want 401 Unauthorized, got %v", err)
	}
}

// TestResolverProcessVendsARung covers the derivation path through the real binary: the
// file holds a rung, the resolver states the ladder in Metadata, and the API server
// folds the remaining steps per request.
func TestResolverProcessVendsARung(t *testing.T) {
	binary := buildResolver(t)

	ladderYAML := `keyDerivation:
  kind: hmac-ladder
  hash: sha-256
  secretPrefix: DEMO1
  steps:
  - {name: date, date: YYYYMMDD}
  - {name: cluster, scope: true}
  - {name: terminator, literal: demo1_request}
`
	clientLadder := &clientcmdapi.HTTPSignatureKeyDerivation{
		Kind: "hmac-ladder", Hash: "sha-256", SecretPrefix: "DEMO1",
		Steps: []clientcmdapi.HTTPSignatureKeyDerivationStep{
			{Name: "date", Date: "YYYYMMDD"},
			{Name: "cluster", Scope: true},
			{Name: "terminator", Literal: "demo1_request"},
		},
	}
	ladder, digest, err := transporthttpsig.DerivationFrom(clientLadder)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("client ladder digest: %s (the resolver logs its own; they have to match)", digest)

	// The broker's half, folded down to the cluster step for both parties.
	root, err := keyscope.New(ladder, keyscope.Stage{Name: bobKeyID, Scope: map[string]string{"cluster": "cluster-a"}}, []byte("a-root-secret-only-the-broker-holds"))
	if err != nil {
		t.Fatal(err)
	}
	rung, stage, err := root.Derive("cluster", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	endpoint, _ := startResolverProcess(t, binary, fmt.Sprintf(ladderYAML+`keys:
  hmac-sha256:
    %s:
      secretBase64: %s
      stage:
        from: %s
        scope: {date: '%s', cluster: '%s'}
      user: {username: %s, groups: [%s]}
      cacheTTL: 5m
`, bobKeyID, base64.StdEncoding.EncodeToString(rung), stage.From,
		stage.Scope["date"], stage.Scope["cluster"], bobUser, signerGrp))

	server, _ := startServer(t, fmt.Sprintf(`apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: resolver
    resolver:
      endpoint: %s
`, endpoint))

	stageJSON := fmt.Sprintf(`{"from":%q,"scope":{"date":%q,"cluster":%q}}`, stage.From, stage.Scope["date"], stage.Scope["cluster"])
	credFile := writeTempFile(t, "credential.yaml", fmt.Sprintf(
		`{"apiVersion":%q,"kind":%q,"keyID":%q,"secretBase64":%q,"stage":%s}`,
		transporthttpsig.SigningCredentialAPIVersion, transporthttpsig.SigningCredentialKind,
		bobKeyID, base64.StdEncoding.EncodeToString(rung), stageJSON))

	clientConfig := signingClientConfig(t, server, bobUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion:     "client.authentication.k8s.io/v1alpha1",
		Algorithm:      "hmac-sha256",
		CredentialFile: credFile,
		KeyDerivation:  clientLadder,
	})
	review := selfReview(t, kubernetes.NewForConfigOrDie(clientConfig))
	if got := review.Status.UserInfo.Username; got != bobUser {
		t.Errorf("username: got %q, want %q", got, bobUser)
	}
}

// TestResolverProcessRefusesASystemIdentity covers the rule at the file rather than at
// the trust boundary: the resolver will not start with a key claiming a name Kubernetes
// issues, so the mistake is an exit code with a message instead of a 401 whose reason
// is in a server log.
func TestResolverProcessRefusesASystemIdentity(t *testing.T) {
	binary := buildResolver(t)
	dir := t.TempDir()
	keysPath := filepath.Join(dir, "keys.yaml")
	if err := os.WriteFile(keysPath, []byte(`keys:
  hmac-sha256:
    k:
      secret: a
      user: {username: 'system:masters-user'}
`), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(binary, "--keys", keysPath, "--listen", filepath.Join(dir, "r.sock")).CombinedOutput()
	if err == nil {
		t.Fatal("the resolver started with a key claiming a system: identity")
	}
	if !strings.Contains(string(out), "reserved for identities Kubernetes issues") {
		t.Errorf("the failure should name the rule, got:\n%s", out)
	}
}

// indentPEM renders a PKIX DER public key as a PEM block indented for a YAML block
// scalar, which is how a person writes one into a key file.
func indentPEM(der []byte, pad string) string {
	text := pemPublicKey(der)
	return pad + strings.ReplaceAll(strings.TrimRight(text, "\n"), "\n", "\n"+pad)
}
