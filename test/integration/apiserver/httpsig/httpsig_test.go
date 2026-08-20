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

// Package httpsig holds integration tests for authenticating requests by HTTP
// message signature (RFC 9421).
//
// These tests exercise the whole path that unit tests on either side cannot: a
// client-go client configured from a kubeconfig, signing over a real connection,
// against a kube-apiserver that resolves keys from a resolver on a socket. The
// floor components include the authority and the path, so a real connection is the
// only way to know the two sides agree on what those are, and a real resolver on a
// real socket is the only way to know the endpoint, the dialer, and the not-found
// status all line up.
package httpsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/micahhausler/httpsig/keyscope"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	nettesting "k8s.io/apimachinery/pkg/util/net/testing"
	"k8s.io/apimachinery/pkg/util/wait"
	resolvertesting "k8s.io/apiserver/pkg/authentication/request/httpsig/testing"
	clientfeatures "k8s.io/client-go/features"
	clientfeaturestesting "k8s.io/client-go/features/testing"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	transporthttpsig "k8s.io/client-go/transport/httpsig"
	externalhttpsig "k8s.io/externalhttpsig/apis/v1alpha1"
	kubeapiserverapptesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/test/integration/framework"
)

const (
	aliceKeyID = "alice-key"
	aliceUser  = "alice"
	bobKeyID   = "AKIABOBEXAMPLE"
	bobUser    = "bob"
	signerGrp  = "httpsig-signers"
)

func TestMain(m *testing.M) {
	framework.EtcdMain(m.Run)
}

// keyPair writes a private key to disk and returns its path and the public key in
// the PKIX DER encoding a resolver answers with.
func keyPair(t *testing.T, name string, algorithm string) (keyFile string, publicKeyDER []byte) {
	t.Helper()
	var priv, pub any
	switch algorithm {
	case "ed25519":
		p, s, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		priv, pub = s, p
	case "ecdsa-p256-sha256":
		s, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		priv, pub = s, &s.PublicKey
	default:
		t.Fatalf("keyPair does not handle %s", algorithm)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyFile = filepath.Join(t.TempDir(), name+".pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600); err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return keyFile, pubDER
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// indent pushes a PEM document to the depth a block scalar needs inside the
// authentication config. Authenticators are list items at indent 2, so their
// fields sit at indent 4 and block scalar content has to be deeper than that.
func indent(s string) string {
	const pad = "        "
	return pad + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n"+pad)
}

// newResolver starts a resolver on a socket unique to this test.
func newResolver(t *testing.T, name string) *resolvertesting.Resolver {
	t.Helper()
	socket := nettesting.MakeSocketNameForTest(t, fmt.Sprintf("httpsig-int-%s-%d.sock", name, time.Now().UnixNano()))
	return resolvertesting.New(t, socket)
}

// authConfigFor renders an authentication configuration whose httpSignature
// section points at the given resolvers, in order.
func authConfigFor(resolvers ...*resolvertesting.Resolver) string {
	var b strings.Builder
	b.WriteString("apiVersion: apiserver.config.k8s.io/v1alpha1\nkind: AuthenticationConfiguration\nhttpSignature:\n  authenticators:\n")
	for i, r := range resolvers {
		fmt.Fprintf(&b, "  - name: resolver-%d\n    resolver:\n      endpoint: %s\n", i, r.Endpoint())
	}
	return b.String()
}

// asymmetricAnswer is the response a resolver gives for a public key.
func asymmetricAnswer(algorithm string, publicKeyDER []byte, username string, groups ...string) *externalhttpsig.ResolveKeyResponse {
	return &externalhttpsig.ResolveKeyResponse{
		Algorithm:       algorithm,
		Material:        &externalhttpsig.ResolveKeyResponse_PublicKey{PublicKey: publicKeyDER},
		User:            &externalhttpsig.UserInfo{Username: username, Groups: groups},
		CacheTtlSeconds: 300,
	}
}

// secretAnswer is the response a resolver gives for a shared secret.
func secretAnswer(secret string, username string, groups ...string) *externalhttpsig.ResolveKeyResponse {
	return &externalhttpsig.ResolveKeyResponse{
		Algorithm:       "hmac-sha256",
		Material:        &externalhttpsig.ResolveKeyResponse_Secret{Secret: []byte(secret)},
		User:            &externalhttpsig.UserInfo{Username: username, Groups: groups},
		CacheTtlSeconds: 300,
	}
}

// signingClientConfig derives a rest.Config that signs, from the server's own
// config. It goes through kubeconfig rather than setting rest.Config directly, so
// the test covers the kubeconfig field, its validation, and its translation.
func signingClientConfig(t *testing.T, server kubeapiserverapptesting.TestServer, user string, sig *clientcmdapi.HTTPSignatureConfig, exec ...*clientcmdapi.ExecConfig) *rest.Config {
	t.Helper()
	config := clientcmdapi.NewConfig()
	config.Clusters["test"] = &clientcmdapi.Cluster{
		Server:                   server.ClientConfig.Host,
		CertificateAuthorityData: server.ClientConfig.CAData,
		// The test server presents its loopback certificate, whose name does not
		// match the address, so the client's expected name has to be carried too.
		TLSServerName: server.ClientConfig.ServerName,
	}
	authInfo := &clientcmdapi.AuthInfo{HTTPSignature: sig}
	if len(exec) > 0 {
		// httpSignature says what the signature looks like; exec is where the
		// credential comes from. They are peers rather than alternatives.
		authInfo.Exec = exec[0]
	}
	config.AuthInfos[user] = authInfo
	config.Contexts["test"] = &clientcmdapi.Context{Cluster: "test", AuthInfo: user}
	config.CurrentContext = "test"

	restConfig, err := clientcmd.NewDefaultClientConfig(*config, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatalf("building a client config that signs: %v", err)
	}
	return restConfig
}

// startServer brings up a kube-apiserver whose authentication configuration holds
// the given httpSignature section. The path is returned so a test can rewrite it
// and exercise reload.
func startServer(t *testing.T, authConfig string, extraFlags ...string) (kubeapiserverapptesting.TestServer, string) {
	t.Helper()
	configPath := writeTempFile(t, "authn.yaml", authConfig)
	flags := []string{
		"--authorization-mode=RBAC",
		"--feature-gates=HTTPSignatureAuthentication=true",
		fmt.Sprintf("--authentication-config=%s", configPath),
	}
	flags = append(flags, extraFlags...)
	server, err := kubeapiserverapptesting.StartTestServer(
		t,
		kubeapiserverapptesting.NewDefaultTestServerOptions(),
		flags,
		framework.SharedEtcd(),
	)
	if err != nil {
		t.Fatalf("starting kube-apiserver: %v", err)
	}
	t.Cleanup(server.TearDownFn)
	return server, configPath
}

// grantPodReader gives the signing group permission to read pods, so a signed
// request can be observed doing something and not merely authenticating.
func grantPodReader(t *testing.T, server kubeapiserverapptesting.TestServer) {
	t.Helper()
	admin := kubernetes.NewForConfigOrDie(server.ClientConfig)
	ctx := context.Background()
	if _, err := admin.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "httpsig-pod-reader"},
		Rules: []rbacv1.PolicyRule{{
			Verbs:     []string{"get", "list", "create"},
			APIGroups: []string{""},
			Resources: []string{"pods", "configmaps"},
		}},
	}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	if _, err := admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "httpsig-pod-reader"},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: signerGrp}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "httpsig-pod-reader"},
	}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
}

func selfReview(t *testing.T, client kubernetes.Interface) *authenticationv1.SelfSubjectReview {
	t.Helper()
	review, err := client.AuthenticationV1().SelfSubjectReviews().Create(
		context.Background(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("a signed request was not authenticated: %v", err)
	}
	return review
}

// TestSignedRequestAuthenticates is the end-to-end claim: a kubeconfig with an
// httpSignature stanza produces a client whose requests the API server accepts, and
// the identity it reports is the one the resolver vended.
func TestSignedRequestAuthenticates(t *testing.T) {
	keyFile, publicKeyDER := keyPair(t, "alice", "ed25519")
	r := newResolver(t, "alice")
	r.SetKey(aliceKeyID, asymmetricAnswer("ed25519", publicKeyDER, aliceUser, signerGrp))

	server, _ := startServer(t, authConfigFor(r))
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
	if got := review.Status.UserInfo.Groups; !containsString(got, signerGrp) {
		t.Errorf("groups: got %v, want to contain %q", got, signerGrp)
	}

	if _, err := client.CoreV1().Pods("default").List(ctx, metav1.ListOptions{}); err != nil {
		t.Errorf("listing pods with a signed request: %v", err)
	}
	// A write exercises the body digest over a real connection.
	if _, err := client.CoreV1().ConfigMaps("default").Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "signed-write"},
		Data:       map[string]string{"signed": "yes"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating a config map with a signed request: %v", err)
	}

	// One resolver call for many requests: the key is cached for the duration the
	// resolver stated.
	if calls, _, _ := r.Counts(); calls != 1 {
		t.Errorf("ResolveKey calls for four requests: got %d, want 1", calls)
	}
	// A nonce call per request, because a nonce is per request by definition.
	if _, nonceCalls, _ := r.Counts(); nonceCalls < 3 {
		t.Errorf("ConsumeNonce calls: got %d, want one per authenticated request", nonceCalls)
	}
}

// TestUnknownKeyIsRejected covers both ways a key can fail to resolve to something
// that verifies: a key ID the resolver does not serve, and one it serves with
// different material than the client signed with.
func TestUnknownKeyIsRejected(t *testing.T) {
	_, publicKeyDER := keyPair(t, "alice", "ed25519")
	// The client signs with a second key that the resolver never vends.
	otherKeyFile, _ := keyPair(t, "attacker", "ed25519")

	r := newResolver(t, "unknown")
	r.SetKey(aliceKeyID, asymmetricAnswer("ed25519", publicKeyDER, aliceUser, signerGrp))
	server, _ := startServer(t, authConfigFor(r))

	for _, tc := range []struct {
		name  string
		keyID string
	}{
		{name: "unknown keyID", keyID: "no-such-key"},
		{name: "known keyID, wrong key", keyID: aliceKeyID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientConfig := signingClientConfig(t, server, "attacker", &clientcmdapi.HTTPSignatureConfig{
				APIVersion: "client.authentication.k8s.io/v1alpha1",
				Algorithm:  "ed25519",
				KeyID:      tc.keyID,
				KeyFile:    otherKeyFile,
			})
			client := kubernetes.NewForConfigOrDie(clientConfig)
			_, err := client.AuthenticationV1().SelfSubjectReviews().Create(context.Background(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
			if err == nil {
				t.Fatal("a signature the server cannot verify was accepted")
			}
			if !apierrors.IsUnauthorized(err) {
				t.Errorf("want 401 Unauthorized, got %v", err)
			}
		})
	}
}

// TestReplayedRequestIsRejected replays a captured request over the wire. This is
// the property the whole design is for, and moving nonce records to the resolver is
// what makes it hold across more than one API server, which this asserts for one.
func TestReplayedRequestIsRejected(t *testing.T) {
	keyFile, publicKeyDER := keyPair(t, "alice", "ecdsa-p256-sha256")
	r := newResolver(t, "replay")
	r.SetKey(aliceKeyID, asymmetricAnswer("ecdsa-p256-sha256", publicKeyDER, aliceUser, signerGrp))
	server, _ := startServer(t, authConfigFor(r))
	grantPodReader(t, server)

	clientConfig := signingClientConfig(t, server, aliceUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion: "client.authentication.k8s.io/v1alpha1",
		Algorithm:  "ecdsa-p256-sha256",
		KeyID:      aliceKeyID,
		KeyFile:    keyFile,
	})
	if err := assertReplayRejected(t, clientConfig); err != nil {
		t.Error(err)
	}
}

// assertReplayRejected sends one signed request, captures the bytes that went out, and
// sends them again through a transport that does not sign.
//
// Capturing rather than re-signing is the whole point: a re-signed request would carry
// a fresh nonce and prove nothing. This is the same bytes, signature included, which is
// the only thing that tests the nonce record.
func assertReplayRejected(t *testing.T, clientConfig *rest.Config) error {
	t.Helper()
	var captured *http.Request
	capturing := *clientConfig
	capturing.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			captured = req.Clone(req.Context())
			return rt.RoundTrip(req)
		})
	})
	client, err := kubernetes.NewForConfig(&capturing)
	if err != nil {
		return err
	}
	if _, err := client.AuthenticationV1().SelfSubjectReviews().Create(
		context.Background(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("the first request should be authenticated: %w", err)
	}
	if captured == nil {
		return fmt.Errorf("no request was captured")
	}

	plain := rest.CopyConfig(clientConfig)
	plain.HTTPSignature = nil
	transport, err := rest.TransportFor(plain)
	if err != nil {
		return err
	}
	captured.Body = http.NoBody
	resp, err := transport.RoundTrip(captured)
	if err != nil {
		return fmt.Errorf("replaying the captured request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		return fmt.Errorf("replaying a captured request: got %d, want 401; the resolver had already recorded its nonce", resp.StatusCode)
	}
	return nil
}

// pemPublicKey renders a PKIX DER public key as PEM, the form a person writes into a
// resolver key file.
func pemPublicKey(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestResolverRoutingByKeyIDPrefix covers a deployment with two identity systems:
// each resolver is asked only about the key IDs its prefixes admit, so the other is
// never called, and the identity each vends is the one that arrives.
func TestResolverRoutingByKeyIDPrefix(t *testing.T) {
	aliceKeyFile, alicePub := keyPair(t, "alice", "ed25519")
	bobKeyFile, bobPub := keyPair(t, "bob", "ed25519")

	aliceResolver := newResolver(t, "alice-only")
	aliceResolver.SetKey(aliceKeyID, asymmetricAnswer("ed25519", alicePub, aliceUser, signerGrp))
	bobResolver := newResolver(t, "bob-only")
	bobResolver.SetKey(bobKeyID, asymmetricAnswer("ed25519", bobPub, bobUser, signerGrp))

	authConfig := fmt.Sprintf(`apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: alice-resolver
    resolver:
      endpoint: %s
      keyIDPrefixes: [%s]
  - name: bob-resolver
    resolver:
      endpoint: %s
      keyIDPrefixes: [%s]
`, aliceResolver.Endpoint(), aliceKeyID, bobResolver.Endpoint(), bobKeyID)

	server, _ := startServer(t, authConfig)

	for _, tc := range []struct {
		name     string
		keyID    string
		keyFile  string
		wantUser string
		asked    *resolvertesting.Resolver
		notAsked *resolvertesting.Resolver
	}{
		{name: "alice", keyID: aliceKeyID, keyFile: aliceKeyFile, wantUser: aliceUser, asked: aliceResolver, notAsked: bobResolver},
		{name: "bob", keyID: bobKeyID, keyFile: bobKeyFile, wantUser: bobUser, asked: bobResolver, notAsked: aliceResolver},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, _, _ := tc.notAsked.Counts()
			clientConfig := signingClientConfig(t, server, tc.wantUser, &clientcmdapi.HTTPSignatureConfig{
				APIVersion: "client.authentication.k8s.io/v1alpha1",
				Algorithm:  "ed25519",
				KeyID:      tc.keyID,
				KeyFile:    tc.keyFile,
			})
			review := selfReview(t, kubernetes.NewForConfigOrDie(clientConfig))
			if got := review.Status.UserInfo.Username; got != tc.wantUser {
				t.Errorf("username: got %q, want %q", got, tc.wantUser)
			}
			if after, _, _ := tc.notAsked.Counts(); after != before {
				t.Errorf("a resolver whose prefixes exclude this keyID was asked (%d calls became %d)", before, after)
			}
		})
	}
}

// TestRelayedSessionTokenHeader covers the deployment where the identity is not in
// the key ID: the client covers a session token header, kube-apiserver relays its
// value to the resolver, and the resolver decides who the request is from.
//
// The value is a secret and never appears in the kubeconfig. It reaches the
// resolver over the socket and nothing else about the request goes with it.
func TestRelayedSessionTokenHeader(t *testing.T) {
	secret := "an-hmac-secret-that-would-be-derived"
	r := newResolver(t, "relay")
	server, _ := startServer(t, fmt.Sprintf(`apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: session-resolver
    resolver:
      endpoint: %s
      relayedHeaders: [X-Session-Token]
`, r.Endpoint()))
	grantPodReader(t, server)

	// A resolver that vends an identity chosen by the relayed token rather than by
	// the key ID. The key ID names the key; the token names the session.
	r.SetKey(bobKeyID, secretAnswer(secret, bobUser, signerGrp))

	// The credential document is what a helper wrapping a cloud provider SDK writes
	// and rewrites on rotation. Nothing rotating sits in the kubeconfig.
	credFile := writeTempFile(t, "credential.yaml", fmt.Sprintf(
		`{"apiVersion":%q,"kind":%q,"keyID":%q,"secret":%q,"signedHeaders":{"X-Session-Token":"a-session-token-value"}}`,
		transporthttpsig.SigningCredentialAPIVersion, transporthttpsig.SigningCredentialKind, bobKeyID, secret))

	clientConfig := signingClientConfig(t, server, bobUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion:     "client.authentication.k8s.io/v1alpha1",
		Algorithm:      "hmac-sha256",
		CredentialFile: credFile,
		SignedHeaders:  []clientcmdapi.HTTPSignatureHeader{{Name: "X-Session-Token"}},
	})
	review := selfReview(t, kubernetes.NewForConfigOrDie(clientConfig))
	if got := review.Status.UserInfo.Username; got != bobUser {
		t.Errorf("username: got %q, want %q", got, bobUser)
	}

	resolve, _ := r.LastRequests()
	if resolve == nil {
		t.Fatal("the resolver was never asked")
	}
	if got := resolve.GetRelayedHeaders()["x-session-token"]; got != "a-session-token-value" {
		t.Errorf("relayed session token: got %q, want %q", got, "a-session-token-value")
	}
	if len(resolve.GetRelayedHeaders()) != 1 {
		t.Errorf("only the configured header should be relayed, got %v", resolve.GetRelayedHeaders())
	}
}

// TestSignedImpersonation checks impersonation still works, and that the
// impersonation headers travel inside the signature rather than beside it.
func TestSignedImpersonation(t *testing.T) {
	keyFile, publicKeyDER := keyPair(t, "alice", "ed25519")
	r := newResolver(t, "impersonate")
	r.SetKey(aliceKeyID, asymmetricAnswer("ed25519", publicKeyDER, aliceUser, signerGrp))
	server, _ := startServer(t, authConfigFor(r))
	grantPodReader(t, server)

	admin := kubernetes.NewForConfigOrDie(server.ClientConfig)
	if _, err := admin.RbacV1().ClusterRoles().Create(context.Background(), &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "httpsig-impersonator"},
		Rules: []rbacv1.PolicyRule{{
			Verbs:     []string{"impersonate"},
			APIGroups: []string{""},
			Resources: []string{"users"},
		}},
	}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	if _, err := admin.RbacV1().ClusterRoleBindings().Create(context.Background(), &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "httpsig-impersonator"},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: aliceUser}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "httpsig-impersonator"},
	}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}

	clientConfig := signingClientConfig(t, server, aliceUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion: "client.authentication.k8s.io/v1alpha1",
		Algorithm:  "ed25519",
		KeyID:      aliceKeyID,
		KeyFile:    keyFile,
	})
	clientConfig.Impersonate = rest.ImpersonationConfig{UserName: "someone-else"}
	review := selfReview(t, kubernetes.NewForConfigOrDie(clientConfig))
	if got := review.Status.UserInfo.Username; got != "someone-else" {
		t.Errorf("impersonated username: got %q, want %q", got, "someone-else")
	}
}

// TestInjectedImpersonationIsRejected is the coverage rule against addition: a
// signature cannot stop a header being appended, so presence is checked against the
// covered set.
func TestInjectedImpersonationIsRejected(t *testing.T) {
	keyFile, publicKeyDER := keyPair(t, "alice", "ed25519")
	r := newResolver(t, "injected")
	r.SetKey(aliceKeyID, asymmetricAnswer("ed25519", publicKeyDER, aliceUser, signerGrp))
	server, _ := startServer(t, authConfigFor(r))
	grantPodReader(t, server)

	clientConfig := signingClientConfig(t, server, aliceUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion: "client.authentication.k8s.io/v1alpha1",
		Algorithm:  "ed25519",
		KeyID:      aliceKeyID,
		KeyFile:    keyFile,
	})
	// A wrapper installed outside the signer, which is where a proxy sits: the
	// request is already signed when this runs.
	injecting := *clientConfig
	injecting.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			req.Header.Set("Impersonate-User", "system:masters-wannabe")
			return rt.RoundTrip(req)
		})
	})
	client, err := kubernetes.NewForConfig(&injecting)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{})
	if err == nil {
		t.Fatal("a request with an impersonation header added after signing was accepted")
	}
	if !apierrors.IsUnauthorized(err) {
		t.Errorf("want 401 Unauthorized, got %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// TestDerivedHMACWithBrokeredRung covers key derivation end to end, with the ladder
// now coming from the resolver rather than from the server's configuration file.
//
// The broker holding the root secret hands the client a rung scoped to today and one
// cluster, and hands the resolver a rung too. The resolver states the ladder in its
// metadata, and kube-apiserver folds the remaining steps per request from the created
// timestamp and claimed scope each signature carries. Nothing rotating or secret sits
// in the kubeconfig, and neither the client nor the API server ever sees the root.
func TestDerivedHMACWithBrokeredRung(t *testing.T) {
	// One statement of the ladder, converted for each party that states it. Both
	// sides deriving from one source is the property under test: they have to agree,
	// and a test that wrote the ladder twice could not tell agreement from luck.
	protoLadder := &externalhttpsig.KeyDerivation{
		Kind:         "hmac-ladder",
		Hash:         "sha-256",
		SecretPrefix: "K8S1",
		Steps: []*externalhttpsig.KeyDerivationStep{
			{Name: "date", Date: "YYYYMMDD"},
			{Name: "cluster", Scope: true},
			{Name: "terminator", Literal: "k8s1_request"},
		},
	}
	clientLadder := &clientcmdapi.HTTPSignatureKeyDerivation{
		Kind:         protoLadder.GetKind(),
		Hash:         protoLadder.GetHash(),
		SecretPrefix: protoLadder.GetSecretPrefix(),
	}
	for _, step := range protoLadder.GetSteps() {
		clientLadder.Steps = append(clientLadder.Steps, clientcmdapi.HTTPSignatureKeyDerivationStep{
			Name: step.GetName(), Literal: step.GetLiteral(), Scope: step.GetScope(), Date: step.GetDate(),
		})
	}

	ladder, ladderDigest, err := transporthttpsig.DerivationFrom(clientLadder)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ladder digest: %s", ladderDigest)

	// The broker's half: fold the ladder down to the cluster step and hand the rung
	// out, using the hand-off operation against the same ladder every other party
	// derives through.
	rootSecret := "a-root-secret-held-only-by-the-broker"
	now := time.Now()
	brokerFor := func(cluster string) ([]byte, keyscope.Stage) {
		root, err := keyscope.New(ladder, keyscope.Stage{
			Name:  bobKeyID,
			Scope: map[string]string{"cluster": cluster},
		}, []byte(rootSecret))
		if err != nil {
			t.Fatal(err)
		}
		material, stage, err := root.Derive("cluster", now)
		if err != nil {
			t.Fatal(err)
		}
		return material, stage
	}

	serverRung, serverStage := brokerFor("cluster-a")
	r := newResolver(t, "derived")
	r.SetMetadata(&externalhttpsig.MetadataResponse{KeyDerivation: protoLadder})
	r.SetKey(bobKeyID, &externalhttpsig.ResolveKeyResponse{
		Algorithm: "hmac-sha256",
		Material: &externalhttpsig.ResolveKeyResponse_DerivedKey{
			DerivedKey: &externalhttpsig.DerivedKey{
				Key:   serverRung,
				From:  serverStage.From,
				Scope: serverStage.Scope,
			},
		},
		User:            &externalhttpsig.UserInfo{Username: bobUser, Groups: []string{signerGrp}},
		CacheTtlSeconds: 300,
	})

	server, _ := startServer(t, authConfigFor(r))
	grantPodReader(t, server)

	credentialFor := func(name string, material []byte, stage keyscope.Stage) string {
		stageJSON, err := json.Marshal(&transporthttpsig.Stage{From: stage.From, Scope: stage.Scope})
		if err != nil {
			t.Fatal(err)
		}
		return writeTempFile(t, name, fmt.Sprintf(
			`{"apiVersion":%q,"kind":%q,"keyID":%q,"secretBase64":%q,"stage":%s}`,
			transporthttpsig.SigningCredentialAPIVersion, transporthttpsig.SigningCredentialKind,
			bobKeyID, base64.StdEncoding.EncodeToString(material), stageJSON))
	}

	clientRung, clientStage := brokerFor("cluster-a")
	clientConfig := signingClientConfig(t, server, bobUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion:     "client.authentication.k8s.io/v1alpha1",
		Algorithm:      "hmac-sha256",
		CredentialFile: credentialFor("credential.yaml", clientRung, clientStage),
		KeyDerivation:  clientLadder,
	})
	client := kubernetes.NewForConfigOrDie(clientConfig)

	review := selfReview(t, client)
	if got := review.Status.UserInfo.Username; got != bobUser {
		t.Errorf("username: got %q, want %q", got, bobUser)
	}

	// A write exercises derivation together with the body digest.
	if _, err := client.CoreV1().ConfigMaps("default").Create(context.Background(), &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "derived-write"},
		Data:       map[string]string{"signed": "with a derived key"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating a config map with a rung-signed request: %v", err)
	}

	// The domain separation half: the same broker's rung for a different cluster must
	// not authenticate here, even though every party derives from the same root.
	otherRung, otherStage := brokerFor("cluster-b")
	otherConfig := signingClientConfig(t, server, bobUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion:     "client.authentication.k8s.io/v1alpha1",
		Algorithm:      "hmac-sha256",
		CredentialFile: credentialFor("other-credential.yaml", otherRung, otherStage),
		KeyDerivation:  clientLadder,
	})
	_, err = kubernetes.NewForConfigOrDie(otherConfig).AuthenticationV1().SelfSubjectReviews().Create(
		context.Background(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err == nil {
		t.Fatal("a rung scoped to another cluster authenticated against this one")
	}
	if !apierrors.IsUnauthorized(err) {
		t.Errorf("want 401 Unauthorized, got %v", err)
	}
}

// TestResolverUnavailableRejects covers fail-closed at the level where it matters. A
// resolver that is not there cannot vend a key and cannot record a nonce, so requests
// bearing its keys are refused rather than admitted.
//
// It also covers the other half: a key already cached keeps working, because a brief
// resolver outage should not log out a client whose key is still valid.
func TestResolverUnavailableRejects(t *testing.T) {
	keyFile, publicKeyDER := keyPair(t, "alice", "ed25519")
	r := newResolver(t, "outage")
	r.SetKey(aliceKeyID, asymmetricAnswer("ed25519", publicKeyDER, aliceUser, signerGrp))
	server, _ := startServer(t, authConfigFor(r))

	clientConfig := signingClientConfig(t, server, aliceUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion: "client.authentication.k8s.io/v1alpha1",
		Algorithm:  "ed25519",
		KeyID:      aliceKeyID,
		KeyFile:    keyFile,
	})
	client := kubernetes.NewForConfigOrDie(clientConfig)
	selfReview(t, client)

	// The resolver goes away. The key is cached, but the nonce cannot be recorded,
	// so a request cannot be shown not to be a replay and is refused.
	r.Stop()
	_, err := client.AuthenticationV1().SelfSubjectReviews().Create(
		context.Background(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err == nil {
		t.Fatal("a request whose nonce could not be recorded was accepted")
	}
	if !apierrors.IsUnauthorized(err) {
		t.Errorf("want 401 Unauthorized, got %v", err)
	}
}

// TestConfigReloadAddsResolver covers the reload path: a resolver added by editing
// the authentication configuration file takes effect without restarting.
//
// This is the case a static key list could never serve, and it is why the signature
// authenticator is in the chain even when no resolver is configured: an authenticator
// absent from the chain cannot be swapped into it.
func TestConfigReloadAddsResolver(t *testing.T) {
	keyFile, publicKeyDER := keyPair(t, "alice", "ed25519")
	added := newResolver(t, "added")
	added.SetKey(aliceKeyID, asymmetricAnswer("ed25519", publicKeyDER, aliceUser, signerGrp))

	// Start with no resolvers at all.
	server, configPath := startServer(t, `apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
jwt: []
`)

	clientConfig := signingClientConfig(t, server, aliceUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion: "client.authentication.k8s.io/v1alpha1",
		Algorithm:  "ed25519",
		KeyID:      aliceKeyID,
		KeyFile:    keyFile,
	})
	client := kubernetes.NewForConfigOrDie(clientConfig)
	ctx := context.Background()

	if _, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{}); err == nil {
		t.Fatal("a signed request was accepted before any resolver was configured")
	}

	// Rewritten by rename, which is how a ConfigMap update arrives.
	updated := authConfigFor(added)
	staged := configPath + ".new"
	if err := os.WriteFile(staged, []byte(updated), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staged, configPath); err != nil {
		t.Fatal(err)
	}

	// The watcher polls at a one-minute interval as a backstop, and fires on the
	// filesystem event well before that. Reload also health-gates the new generation
	// before swapping it in, so this waits rather than asserting immediately.
	if err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 3*time.Minute, true, func(ctx context.Context) (bool, error) {
		_, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
		return err == nil, nil
	}); err != nil {
		t.Fatalf("a resolver added to the configuration file never took effect: %v", err)
	}
}

// TestExecPluginSignsRequests covers the delivery mode the design leads with: a
// credential plugin, named where every other credential plugin is named, that
// returns signing key material instead of a token.
//
// Two things are asserted that no unit test can. The plugin really is told what the
// signature has to satisfy, through the same environment variable every exec plugin
// reads. And the credential is cached for its stated lifetime, because a plugin
// invoked per request is the failure this mode exists to avoid.
func TestExecPluginSignsRequests(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientfeatures.ClientsAllowHTTPSignature, true)

	secret := "a-secret-only-the-plugin-and-the-resolver-know"
	r := newResolver(t, "exec")
	r.SetKey(bobKeyID, secretAnswer(secret, bobUser, signerGrp))

	// The plugin records what it was told and how often it ran, then answers with key
	// material rather than a token.
	runLog := filepath.Join(t.TempDir(), "runs")
	specLog := filepath.Join(t.TempDir(), "spec")
	script := writeTempFile(t, "signing-plugin.sh", fmt.Sprintf(`#!/bin/sh
echo run >> %q
printf '%%s' "$KUBERNETES_EXEC_INFO" > %q
cat <<JSON
{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential",
 "status":{
   "expirationTimestamp":"%s",
   "httpSignature":{
     "keyID":%q,
     "secret":%q,
     "signedHeaders":{"X-Session-Token":"minted-by-the-plugin"}
   }}}
JSON
`, runLog, specLog, time.Now().Add(time.Hour).UTC().Format(time.RFC3339), bobKeyID, secret))
	if err := os.Chmod(script, 0700); err != nil {
		t.Fatal(err)
	}

	server, _ := startServer(t, fmt.Sprintf(`apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: session-resolver
    resolver:
      endpoint: %s
      relayedHeaders: [X-Session-Token]
`, r.Endpoint()))
	grantPodReader(t, server)

	clientConfig := signingClientConfig(t, server, bobUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion:    "client.authentication.k8s.io/v1alpha1",
		Algorithm:     "hmac-sha256",
		SignedHeaders: []clientcmdapi.HTTPSignatureHeader{{Name: "X-Session-Token"}},
	}, &clientcmdapi.ExecConfig{
		Command:         script,
		APIVersion:      "client.authentication.k8s.io/v1",
		InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
	})
	client := kubernetes.NewForConfigOrDie(clientConfig)
	ctx := context.Background()

	review := selfReview(t, client)
	if got := review.Status.UserInfo.Username; got != bobUser {
		t.Errorf("username: got %q, want %q", got, bobUser)
	}
	// Several more requests, including a write with a body.
	if _, err := client.CoreV1().Pods("default").List(ctx, metav1.ListOptions{}); err != nil {
		t.Errorf("listing pods: %v", err)
	}
	if _, err := client.CoreV1().ConfigMaps("default").Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "exec-signed-write"},
		Data:       map[string]string{"signed": "with material from an exec plugin"},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating a config map: %v", err)
	}

	// The plugin's session token reached the resolver, which is the whole point of
	// relaying it: the plugin mints it and nothing in the kubeconfig knows it.
	resolve, _ := r.LastRequests()
	if got := resolve.GetRelayedHeaders()["x-session-token"]; got != "minted-by-the-plugin" {
		t.Errorf("relayed token: got %q, want %q", got, "minted-by-the-plugin")
	}

	// What the plugin was told. Without the header name it would have to guess, and a
	// credential missing a value for a covered header is refused before a request is
	// sent.
	spec, err := os.ReadFile(specLog)
	if err != nil {
		t.Fatal(err)
	}
	var received struct {
		Spec struct {
			HTTPSignature *struct {
				Algorithm     string `json:"algorithm"`
				SignedHeaders []struct {
					Name string `json:"name"`
				} `json:"signedHeaders"`
			} `json:"httpSignature"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(spec, &received); err != nil {
		t.Fatalf("the plugin was passed something that is not an ExecCredential: %v", err)
	}
	if received.Spec.HTTPSignature == nil {
		t.Fatal("the plugin was not told what signature to produce material for")
	}
	if got := received.Spec.HTTPSignature.Algorithm; got != "hmac-sha256" {
		t.Errorf("algorithm passed to the plugin: got %q, want hmac-sha256", got)
	}
	if len(received.Spec.HTTPSignature.SignedHeaders) != 1 ||
		received.Spec.HTTPSignature.SignedHeaders[0].Name != "X-Session-Token" {
		t.Errorf("covered headers passed to the plugin: %+v", received.Spec.HTTPSignature.SignedHeaders)
	}

	// The credential is good for an hour, so the plugin ran once for the whole
	// sequence.
	data, err := os.ReadFile(runLog)
	if err != nil {
		t.Fatal(err)
	}
	if runs := strings.Count(string(data), "run"); runs != 1 {
		t.Errorf("the plugin ran %d times for four requests, want 1", runs)
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// TestNonceHandlingIgnoreAcceptsReplay is the configured escape hatch, over the wire.
//
// It asserts an uncomfortable thing on purpose. With nonceHandling: Ignore a captured
// request really is accepted again, which is what "replay protection off" means, and a
// test that only checked the resolver was not called would not have shown it.
func TestNonceHandlingIgnoreAcceptsReplay(t *testing.T) {
	keyFile, publicKeyDER := keyPair(t, "alice", "ed25519")
	r := newResolver(t, "ignore-nonces")
	r.SetKey(aliceKeyID, asymmetricAnswer("ed25519", publicKeyDER, aliceUser, signerGrp))
	// The resolver would refuse a replay if it were asked. It is not asked.
	r.SetErrors(nil, nil, nil)

	// v1 rather than v1alpha1, deliberately. This is the version an operator writes,
	// the conversion to the internal type is generated, and a field declared in one
	// version and missing from another would show up nowhere else. Decoding is strict,
	// so a field the server does not know is a hard error rather than a silent default.
	server, _ := startServer(t, fmt.Sprintf(`apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: resolver
    resolver:
      endpoint: %s
      nonceHandling: Ignore
`, r.Endpoint()))
	grantPodReader(t, server)

	clientConfig := signingClientConfig(t, server, aliceUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion: "client.authentication.k8s.io/v1alpha1",
		Algorithm:  "ed25519",
		KeyID:      aliceKeyID,
		KeyFile:    keyFile,
	})

	// Capture a signed request, then send the same bytes twice.
	var captured *http.Request
	capturing := *clientConfig
	capturing.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			captured = req.Clone(req.Context())
			return rt.RoundTrip(req)
		})
	})
	client, err := kubernetes.NewForConfig(&capturing)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{}); err != nil {
		t.Fatalf("the first request should be authenticated: %v", err)
	}

	plain := rest.CopyConfig(clientConfig)
	plain.HTTPSignature = nil
	transport, err := rest.TransportFor(plain)
	if err != nil {
		t.Fatal(err)
	}
	captured.Body = http.NoBody
	resp, err := transport.RoundTrip(captured)
	if err != nil {
		t.Fatalf("replaying the captured request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Error("the replay was rejected, so nonceHandling: Ignore did not take effect")
	}

	// The resolver was never asked about a nonce. That is the difference between this
	// and a resolver that always answers yes: no round trip, and the configuration
	// says what is happening.
	if _, nonceCalls, _ := r.Counts(); nonceCalls != 0 {
		t.Errorf("ConsumeNonce was called %d times; with Ignore the call is skipped entirely", nonceCalls)
	}
}

// TestNonceHandlingIsValidatedAcrossVersions asserts the field is declared in every
// served version and spelled the same way in each.
//
// Decoding is strict, so a version missing the field rejects a configuration that uses
// it, and a version that misspells it rejects one that does not. Either is a failure an
// operator meets as a server that will not start, which is the right failure but a poor
// place to discover a typo in a generated conversion.
func TestNonceHandlingIsValidatedAcrossVersions(t *testing.T) {
	for _, version := range []string{"v1", "v1beta1", "v1alpha1"} {
		t.Run(version, func(t *testing.T) {
			keyFile, publicKeyDER := keyPair(t, "alice", "ed25519")
			r := newResolver(t, "versions-"+version)
			r.SetKey(aliceKeyID, asymmetricAnswer("ed25519", publicKeyDER, aliceUser, signerGrp))

			server, _ := startServer(t, fmt.Sprintf(`apiVersion: apiserver.config.k8s.io/%s
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: resolver
    resolver:
      endpoint: %s
      nonceHandling: Consume
`, version, r.Endpoint()))

			clientConfig := signingClientConfig(t, server, aliceUser, &clientcmdapi.HTTPSignatureConfig{
				APIVersion: "client.authentication.k8s.io/v1alpha1",
				Algorithm:  "ed25519",
				KeyID:      aliceKeyID,
				KeyFile:    keyFile,
			})
			selfReview(t, kubernetes.NewForConfigOrDie(clientConfig))
			// Consume was asked for, so the resolver is asked.
			if _, nonceCalls, _ := r.Counts(); nonceCalls != 1 {
				t.Errorf("ConsumeNonce calls: got %d, want 1", nonceCalls)
			}
		})
	}
}

// issueCertificate mints a certificate authority and one leaf it signed, writing
// the leaf's certificate and key to disk. The authority's PEM is what the server's
// configuration holds.
func issueCertificate(t *testing.T, commonName string, organizations []string, uris []string) (caPEM, certFile, keyFile, bundleFile string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "httpsig-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parsedURIs := make([]*url.URL, 0, len(uris))
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		parsedURIs = append(parsedURIs, u)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName, Organization: organizations},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(12 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		URIs:         parsedURIs,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, leafKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}

	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER})

	dir := t.TempDir()
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	// Key block first, then the chain, which is what a pod certificate projected
	// volume writes.
	bundleFile = filepath.Join(dir, "bundle.pem")
	for path, content := range map[string][]byte{
		certFile:   leafCertPEM,
		keyFile:    leafKeyPEM,
		bundleFile: append(append([]byte{}, leafKeyPEM...), leafCertPEM...),
	} {
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return caPEM, certFile, keyFile, bundleFile
}

// certificateAuthConfig is the server configuration used by the certificate tests:
// one authenticator holding a trust anchor bundle and nothing per client.
func certificateAuthConfig(t *testing.T, caPEM string, extra string) string {
	t.Helper()
	return fmt.Sprintf(`
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: workload-certificates
    x509:
      certificateAuthority: |
%s
      claimMappings:
        username:
          expression: '"cert:" + cert.subject.commonName'
        groups:
          expression: cert.subject.organization
        uid:
          expression: cert.sha256Thumbprint
        extra:
        - key: example.org/workload-id
          valueExpression: cert.uriSANs
%s`, indent(caPEM), extra)
}

// TestCertificateSignedRequestAuthenticates is the end-to-end claim for the
// certificate flow: a kubeconfig naming a certificate and key produces a client
// the API server accepts, with an identity derived from the certificate. The server
// holds a trust anchor bundle and nothing about this client.
func TestCertificateSignedRequestAuthenticates(t *testing.T) {
	caPEM, certFile, keyFile, _ := issueCertificate(t, "builder", []string{signerGrp}, []string{"spiffe://cluster.local/ns/default/sa/builder"})
	server, _ := startServer(t, certificateAuthConfig(t, caPEM, ""))
	grantPodReader(t, server)

	clientConfig := signingClientConfig(t, server, "builder", &clientcmdapi.HTTPSignatureConfig{
		APIVersion: "client.authentication.k8s.io/v1alpha1",
		// No algorithm and no keyID: the certificate determines both.
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	client := kubernetes.NewForConfigOrDie(clientConfig)
	ctx := context.Background()

	review, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("a request signed with a certificate was not authenticated: %v", err)
	}
	if got, want := review.Status.UserInfo.Username, "cert:builder"; got != want {
		t.Errorf("username = %q, want %q", got, want)
	}
	if got := review.Status.UserInfo.Groups; !containsString(got, signerGrp) {
		t.Errorf("groups = %v, want to contain %q", got, signerGrp)
	}
	if got := review.Status.UserInfo.Extra["example.org/workload-id"]; len(got) != 1 || got[0] != "spiffe://cluster.local/ns/default/sa/builder" {
		t.Errorf("workload-id extra = %v, want the URI SAN", got)
	}

	// Authorized by a group the certificate carried, so the identity is doing
	// something and not merely being reported.
	if _, err := client.CoreV1().Pods("default").List(ctx, metav1.ListOptions{}); err != nil {
		t.Errorf("listing pods as the mapped identity: %v", err)
	}
	// A write, so the body digest is covered over the wire and not only in a unit
	// test.
	if _, err := client.CoreV1().ConfigMaps("default").Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "signed-by-certificate"},
		Data:       map[string]string{"signed": "true"},
	}, metav1.CreateOptions{}); err != nil {
		t.Errorf("creating a configmap with a signed body: %v", err)
	}
}

// TestCertificateBundleAuthenticates covers the one-file form, which is the form a
// pod gets and the one that cannot be read mid-rotation.
func TestCertificateBundleAuthenticates(t *testing.T) {
	caPEM, _, _, bundleFile := issueCertificate(t, "pod", []string{signerGrp}, nil)
	server, _ := startServer(t, certificateAuthConfig(t, caPEM, ""))
	grantPodReader(t, server)

	clientConfig := signingClientConfig(t, server, "pod", &clientcmdapi.HTTPSignatureConfig{
		APIVersion:           "client.authentication.k8s.io/v1alpha1",
		CredentialBundleFile: bundleFile,
	})
	client := kubernetes.NewForConfigOrDie(clientConfig)

	review, err := client.AuthenticationV1().SelfSubjectReviews().Create(context.Background(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("a request signed from a credential bundle was not authenticated: %v", err)
	}
	if got, want := review.Status.UserInfo.Username, "cert:pod"; got != want {
		t.Errorf("username = %q, want %q", got, want)
	}
}

// TestCertificateFromAnotherAuthorityIsRejected is the trust boundary over the
// wire. Holding the key of a well-formed certificate proves possession and nothing
// else, so a certificate from an authority the server does not hold gets a 401.
func TestCertificateFromAnotherAuthorityIsRejected(t *testing.T) {
	configuredCA, _, _, _ := issueCertificate(t, "unused", nil, nil)
	_, otherCert, otherKey, _ := issueCertificate(t, "builder", []string{signerGrp}, nil)

	server, _ := startServer(t, certificateAuthConfig(t, configuredCA, ""))
	grantPodReader(t, server)

	clientConfig := signingClientConfig(t, server, "builder", &clientcmdapi.HTTPSignatureConfig{
		APIVersion: "client.authentication.k8s.io/v1alpha1",
		CertFile:   otherCert,
		KeyFile:    otherKey,
	})
	client := kubernetes.NewForConfigOrDie(clientConfig)

	_, err := client.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{})
	if err == nil {
		t.Fatal("a certificate from an unconfigured authority was accepted")
	}
	if !apierrors.IsUnauthorized(err) {
		t.Errorf("want 401 Unauthorized, got %v", err)
	}
}

// TestCertificateRulesRejectOverTheWire checks that the rules and the mappings are
// the cluster's say over what a certificate may claim, and that refusing produces a
// 401 rather than an identity.
func TestCertificateRulesRejectOverTheWire(t *testing.T) {
	caPEM, certFile, keyFile, _ := issueCertificate(t, "builder", []string{"wrong-org"}, nil)
	server, _ := startServer(t, certificateAuthConfig(t, caPEM, `
      certificateValidationRules:
      - expression: cert.subject.organization.exists(o, o == "`+signerGrp+`")
        message: certificate must be issued to the signers organization
`))
	grantPodReader(t, server)

	clientConfig := signingClientConfig(t, server, "builder", &clientcmdapi.HTTPSignatureConfig{
		APIVersion: "client.authentication.k8s.io/v1alpha1",
		CertFile:   certFile,
		KeyFile:    keyFile,
	})
	client := kubernetes.NewForConfigOrDie(clientConfig)

	_, err := client.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{})
	if err == nil {
		t.Fatal("a certificate a validation rule rejects was accepted")
	}
	if !apierrors.IsUnauthorized(err) {
		t.Errorf("want 401 Unauthorized, got %v", err)
	}
}

// TestCertificateSubstitutionIsRejected replays a captured request with a different
// certificate from the same authority. The keyid names the certificate's digest and
// is covered by the signature, so this is refused by the binding rather than by the
// trust anchors.
func TestCertificateSubstitutionIsRejected(t *testing.T) {
	caPEM, certFile, keyFile, _ := issueCertificate(t, "builder", []string{signerGrp}, nil)
	server, _ := startServer(t, certificateAuthConfig(t, caPEM, ""))
	grantPodReader(t, server)

	clientConfig := signingClientConfig(t, server, "builder", &clientcmdapi.HTTPSignatureConfig{
		APIVersion: "client.authentication.k8s.io/v1alpha1",
		CertFile:   certFile,
		KeyFile:    keyFile,
	})

	// Capture a signed request, then send it again with someone else's certificate
	// in the header. The signature and its keyid are untouched.
	var captured *http.Request
	capturing := rest.CopyConfig(clientConfig)
	capturing.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			captured = req.Clone(req.Context())
			return rt.RoundTrip(req)
		})
	})
	client := kubernetes.NewForConfigOrDie(capturing)
	if _, err := client.CoreV1().Pods("default").List(context.Background(), metav1.ListOptions{}); err != nil {
		t.Fatalf("the original request should authenticate: %v", err)
	}
	if captured == nil {
		t.Fatal("no request was captured")
	}

	// A different leaf from the same authority, which would chain fine.
	_, _, _, otherBundle := issueCertificate(t, "someone-else", []string{signerGrp}, nil)
	otherPEM, err := os.ReadFile(otherBundle)
	if err != nil {
		t.Fatal(err)
	}
	otherDER := firstCertificateDER(t, otherPEM)
	captured.Header.Set(transporthttpsig.CertificateHeader, transporthttpsig.CertificateHeaderValue(otherDER))

	base, err := rest.TransportFor(rest.AnonymousClientConfig(clientConfig))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := base.RoundTrip(captured.Clone(context.Background()))
	if err != nil {
		t.Fatalf("sending the altered request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a request whose certificate was swapped got %d, want 401", resp.StatusCode)
	}
}

// TestCertificateAndEndpointCoexistOverTheWire is the deployment shape the
// authenticator list exists for: a resolver serving ordinary keyids alongside a
// certificate authority, over the wire, with a real API server deciding which one
// answers each request.
//
// The resolver is listed first and states no prefixes, so it is asked about every
// keyid it is allowed to be. The certificate request still reaches the certificate
// authenticator, because the certificate keyid form is reserved from resolvers.
func TestCertificateAndEndpointCoexistOverTheWire(t *testing.T) {
	keyFile, publicKeyDER := keyPair(t, "alice", "ed25519")
	caPEM, certFile, certKeyFile, _ := issueCertificate(t, "builder", []string{signerGrp}, nil)

	r := newResolver(t, "coexist")
	r.SetKey(aliceKeyID, asymmetricAnswer("ed25519", publicKeyDER, aliceUser, signerGrp))

	server, _ := startServer(t, fmt.Sprintf(`
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: resolver
    resolver:
      endpoint: %s
  - name: workload-certificates
    x509:
      certificateAuthority: |
%s
      claimMappings:
        username:
          expression: '"cert:" + cert.subject.commonName'
        groups:
          expression: cert.subject.organization
`, r.Endpoint(), indent(caPEM)))
	grantPodReader(t, server)

	for _, tc := range []struct {
		name string
		sig  *clientcmdapi.HTTPSignatureConfig
		want string
	}{{
		name: "resolved key",
		sig: &clientcmdapi.HTTPSignatureConfig{
			APIVersion: "client.authentication.k8s.io/v1alpha1",
			Algorithm:  "ed25519",
			KeyID:      aliceKeyID,
			KeyFile:    keyFile,
		},
		want: aliceUser,
	}, {
		name: "certificate",
		sig: &clientcmdapi.HTTPSignatureConfig{
			APIVersion: "client.authentication.k8s.io/v1alpha1",
			CertFile:   certFile,
			KeyFile:    certKeyFile,
		},
		want: "cert:builder",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			client := kubernetes.NewForConfigOrDie(signingClientConfig(t, server, tc.want, tc.sig))
			review := selfReview(t, client)
			if got := review.Status.UserInfo.Username; got != tc.want {
				t.Errorf("username = %q, want %q", got, tc.want)
			}
		})
	}
}

// firstCertificateDER returns the DER of the first certificate in a PEM document.
func firstCertificateDER(t *testing.T, data []byte) []byte {
	t.Helper()
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			t.Fatal("no CERTIFICATE block found")
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes
		}
	}
}
