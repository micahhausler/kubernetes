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
// against a kube-apiserver that verifies with its configured keys. The floor
// components include the authority and the path, so a real connection is the
// only way to know the two sides agree on what those are.
package httpsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
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
	clientfeatures "k8s.io/client-go/features"
	clientfeaturestesting "k8s.io/client-go/features/testing"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	transporthttpsig "k8s.io/client-go/transport/httpsig"
	kubeapiserverapptesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/test/integration/framework"
	"sigs.k8s.io/yaml"
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

// keyPair writes a private key to disk and returns its path and public key PEM.
func keyPair(t *testing.T, name string, algorithm string) (keyFile string, publicKeyPEM string) {
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
	return keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// indent puts a PEM block into a YAML block scalar. The keys are list items at
// indent 2, so their fields sit at indent 4 and block scalar content has to be
// deeper than that.
func indent(s string) string {
	const pad = "      "
	return pad + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n"+pad)
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
// the given httpSignature section.
func startServer(t *testing.T, authConfig string, extraFlags ...string) kubeapiserverapptesting.TestServer {
	t.Helper()
	flags := []string{
		"--authorization-mode=RBAC",
		"--feature-gates=HTTPSignatureAuthentication=true",
		fmt.Sprintf("--authentication-config=%s", writeTempFile(t, "authn.yaml", authConfig)),
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
	return server
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

// TestSignedRequestAuthenticates is the end-to-end claim: a kubeconfig with an
// httpSignature stanza produces a client whose requests the API server accepts,
// and the identity it reports is the one the key is configured for.
func TestSignedRequestAuthenticates(t *testing.T) {
	keyFile, publicKey := keyPair(t, "alice", "ed25519")
	server := startServer(t, fmt.Sprintf(`
apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
httpSignature:
  keys:
  - keyID: %s
    algorithm: ed25519
    publicKey: |
%s
    user:
      username: %s
      uid: alice-uid
      groups: [%s]
`, aliceKeyID, indent(publicKey), aliceUser, signerGrp))
	grantPodReader(t, server)

	clientConfig := signingClientConfig(t, server, aliceUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion: "client.authentication.k8s.io/v1alpha1",
		Algorithm:  "ed25519",
		KeyID:      aliceKeyID,
		KeyFile:    keyFile,
		TTL:        "30s",
	})
	client := kubernetes.NewForConfigOrDie(clientConfig)
	ctx := context.Background()

	review, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("a signed request was not authenticated: %v", err)
	}
	if got := review.Status.UserInfo.Username; got != aliceUser {
		t.Errorf("username: got %q, want %q", got, aliceUser)
	}
	if got := review.Status.UserInfo.UID; got != "alice-uid" {
		t.Errorf("uid: got %q, want alice-uid", got)
	}
	var hasGroup bool
	for _, g := range review.Status.UserInfo.Groups {
		if g == signerGrp {
			hasGroup = true
		}
	}
	if !hasGroup {
		t.Errorf("groups %v do not include %q", review.Status.UserInfo.Groups, signerGrp)
	}

	// A read, which carries no body.
	if _, err := client.CoreV1().Pods("default").List(ctx, metav1.ListOptions{}); err != nil {
		t.Errorf("listing pods as a signing client: %v", err)
	}

	// A write, which does. This is the path where the digest is computed by the
	// client, covered by the signature, and checked against the body by the
	// server before the handler decodes it.
	created, err := client.CoreV1().ConfigMaps("default").Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "signed-write"},
		Data:       map[string]string{"written": "by a signed request"},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("creating a config map with a signed request body: %v", err)
	}
	if created.Data["written"] != "by a signed request" {
		t.Errorf("the server stored %q, so the body the digest covered is not the body it decoded", created.Data)
	}
}

// TestUnknownKeyIsRejected checks that a well-formed signature from a key the
// server does not know gets 401 rather than anonymous access or a 500.
func TestUnknownKeyIsRejected(t *testing.T) {
	_, publicKey := keyPair(t, "alice", "ed25519")
	// The client signs with a second key that the server never sees.
	otherKeyFile, _ := keyPair(t, "attacker", "ed25519")

	server := startServer(t, fmt.Sprintf(`
apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
httpSignature:
  keys:
  - keyID: %s
    algorithm: ed25519
    publicKey: |
%s
    user:
      username: %s
      groups: [%s]
`, aliceKeyID, indent(publicKey), aliceUser, signerGrp))

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

// The feature gate is deliberately not tested here. A server given an
// httpSignature section with the gate disabled fails to start, which is the
// right behavior and is covered by a unit test in
// k8s.io/apiserver/pkg/apis/apiserver/validation. It cannot be asserted at this
// level: a kube-apiserver that fails to start leaks three workqueue goroutines
// from its partially built server chain, and the integration framework's leak
// detector waits ten minutes for them before reporting. That is a defect in the
// failed-start cleanup path rather than in this feature, so it is recorded in
// httpsig/DECISIONS.md instead of worked around here.

// TestHMACWithSessionTokenHeader covers the AWS shaped deployment: the key
// identifier and the shared secret come from the environment, and a session token
// travels as a signed header rather than sitting in the kubeconfig.
func TestHMACWithSessionTokenHeader(t *testing.T) {
	secret := "an-hmac-secret-that-would-be-derived"
	secretFile := writeTempFile(t, "hmac.secret", secret)

	server := startServer(t, fmt.Sprintf(`
apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
httpSignature:
  keys:
  - keyID: %s
    algorithm: hmac-sha256
    secretFile: %s
    user:
      username: %s
      groups: [%s]
`, bobKeyID, secretFile, bobUser, signerGrp))
	grantPodReader(t, server)

	// The credential document is what a helper wrapping a cloud provider SDK
	// writes and rewrites on rotation. Nothing rotating sits in the kubeconfig.
	credFile := writeTempFile(t, "credential.yaml", fmt.Sprintf(
		`{"apiVersion":%q,"kind":%q,"keyID":%q,"secret":%q,"signedHeaders":{"X-Session-Token":"a-session-token-value"}}`,
		transporthttpsig.SigningCredentialAPIVersion, transporthttpsig.SigningCredentialKind, bobKeyID, secret))

	clientConfig := signingClientConfig(t, server, bobUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion:     "client.authentication.k8s.io/v1alpha1",
		Algorithm:      "hmac-sha256",
		CredentialFile: credFile,
		SignedHeaders:  []clientcmdapi.HTTPSignatureHeader{{Name: "X-Session-Token"}},
	})
	client := kubernetes.NewForConfigOrDie(clientConfig)

	review, err := client.AuthenticationV1().SelfSubjectReviews().Create(context.Background(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("an hmac signed request was not authenticated: %v", err)
	}
	if got := review.Status.UserInfo.Username; got != bobUser {
		t.Errorf("username: got %q, want %q", got, bobUser)
	}
}

// TestSignedImpersonation checks impersonation still works, and that the
// impersonation headers travel inside the signature rather than beside it.
func TestSignedImpersonation(t *testing.T) {
	keyFile, publicKey := keyPair(t, "alice", "ed25519")
	server := startServer(t, fmt.Sprintf(`
apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
httpSignature:
  keys:
  - keyID: %s
    algorithm: ed25519
    publicKey: |
%s
    user:
      username: %s
      groups: [%s]
`, aliceKeyID, indent(publicKey), aliceUser, signerGrp))

	admin := kubernetes.NewForConfigOrDie(server.ClientConfig)
	ctx := context.Background()
	if _, err := admin.RbacV1().ClusterRoles().Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "httpsig-impersonator"},
		Rules: []rbacv1.PolicyRule{{
			Verbs:     []string{"impersonate"},
			APIGroups: []string{""},
			Resources: []string{"users"},
		}},
	}, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		t.Fatal(err)
	}
	if _, err := admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "httpsig-impersonator"},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.GroupKind, Name: signerGrp}},
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
	clientConfig.Impersonate = rest.ImpersonationConfig{UserName: "carol"}
	client := kubernetes.NewForConfigOrDie(clientConfig)

	review, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("a signed impersonating request was rejected: %v", err)
	}
	if got := review.Status.UserInfo.Username; got != "carol" {
		t.Errorf("impersonated username: got %q, want carol", got)
	}
}

// TestInjectedImpersonationIsRejected is the attack the covered header rule
// exists for, observed at the API server. The signature is alice's own and
// verifies. A party on the path adds an impersonation header she never signed.
func TestInjectedImpersonationIsRejected(t *testing.T) {
	keyFile, publicKey := keyPair(t, "alice", "ed25519")
	server := startServer(t, fmt.Sprintf(`
apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
httpSignature:
  keys:
  - keyID: %s
    algorithm: ed25519
    publicKey: |
%s
    user:
      username: %s
      groups: [%s]
`, aliceKeyID, indent(publicKey), aliceUser, signerGrp))
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

// TestDerivedHMACWithBrokeredRung covers the key derivation deployment end to
// end: a broker holding the root secret hands the client a rung scoped to
// today and one cluster; the server holds the root and re-derives from the
// created timestamp and claimed scope each signature carries. Nothing rotating
// or secret sits in the kubeconfig, and the client never sees the root.
func TestDerivedHMACWithBrokeredRung(t *testing.T) {
	// One statement of the ladder, from which the server's configuration is
	// rendered. Both sides deriving from one source is the property under test:
	// they have to agree, and a test that wrote the ladder twice could not tell
	// agreement from luck.
	apiLadder := &clientcmdapi.HTTPSignatureKeyDerivation{
		Kind:         "hmac-ladder",
		Hash:         "sha-256",
		SecretPrefix: "K8S1",
		Steps: []clientcmdapi.HTTPSignatureKeyDerivationStep{
			{Name: "date", Date: "YYYYMMDD"},
			{Name: "cluster", Scope: true},
			{Name: "terminator", Literal: "k8s1_request"},
		},
	}
	rootSecret := "a-root-secret-held-by-the-broker-and-the-server"
	rootFile := writeTempFile(t, "root.secret", rootSecret)

	// The broker's half: fold the ladder down to the cluster step and hand the
	// rung out, using the hand-off operation against the same ladder every other
	// party derives through.
	ladder, ladderDigest, err := transporthttpsig.DerivationFrom(apiLadder)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("ladder digest: %s", ladderDigest)
	now := time.Now()
	brokerFor := func(cluster string) ([]byte, *transporthttpsig.Stage) {
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
		return material, &transporthttpsig.Stage{From: stage.From, Scope: stage.Scope}
	}

	server := startServer(t, fmt.Sprintf(`
apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
httpSignature:
  # The ladder describes the deployment, so it is stated once rather than on
  # every key. Each key says where its own material sits, in its stage.
  keyDerivation:
%s
  keys:
  - keyID: %s
    algorithm: hmac-sha256
    secretFile: %s
    stage:
      scope: {cluster: cluster-a}
    user:
      username: %s
      groups: [%s]
`, indentYAML(t, apiLadder, "    "), bobKeyID, rootFile, bobUser, signerGrp))
	grantPodReader(t, server)

	credentialFor := func(name string, material []byte, stage *transporthttpsig.Stage) string {
		stageJSON, err := json.Marshal(stage)
		if err != nil {
			t.Fatal(err)
		}
		return writeTempFile(t, name, fmt.Sprintf(
			`{"apiVersion":%q,"kind":%q,"keyID":%q,"secretBase64":%q,"stage":%s}`,
			transporthttpsig.SigningCredentialAPIVersion, transporthttpsig.SigningCredentialKind,
			bobKeyID, base64.StdEncoding.EncodeToString(material), stageJSON))
	}

	rung, rungStage := brokerFor("cluster-a")
	clientConfig := signingClientConfig(t, server, bobUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion:     "client.authentication.k8s.io/v1alpha1",
		Algorithm:      "hmac-sha256",
		CredentialFile: credentialFor("credential.yaml", rung, rungStage),
		KeyDerivation:  apiLadder,
	})
	client := kubernetes.NewForConfigOrDie(clientConfig)

	review, err := client.AuthenticationV1().SelfSubjectReviews().Create(context.Background(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("a rung-signed request was not authenticated: %v", err)
	}
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

	// The domain separation half: the same broker's rung for a different
	// cluster must not authenticate here, even though every party derives from
	// the same root.
	otherRung, otherStage := brokerFor("cluster-b")
	otherConfig := signingClientConfig(t, server, bobUser, &clientcmdapi.HTTPSignatureConfig{
		APIVersion:     "client.authentication.k8s.io/v1alpha1",
		Algorithm:      "hmac-sha256",
		CredentialFile: credentialFor("other-credential.yaml", otherRung, otherStage),
		KeyDerivation:  apiLadder,
	})
	otherClient := kubernetes.NewForConfigOrDie(otherConfig)
	_, err = otherClient.AuthenticationV1().SelfSubjectReviews().Create(context.Background(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err == nil {
		t.Fatal("a rung scoped to another cluster authenticated against this one")
	}
	if !apierrors.IsUnauthorized(err) {
		t.Errorf("want 401 Unauthorized, got %v", err)
	}
}

// TestExecCredentialEndToEnd covers the delivery mode D3 leads with, against a
// real API server: a command produces the credential, so nothing rotating and
// nothing secret appears in the kubeconfig, and a long-lived client refreshes by
// running the command again rather than by restarting.
//
// The command is a shell script written by the test. A real one would wrap a
// credential broker or a provider SDK.
// TestExecPluginSignsRequests covers the delivery mode the design leads with: a
// credential plugin, named where every other credential plugin is named, that
// returns signing key material instead of a token.
//
// Two things are asserted that no unit test can. The plugin really is told what
// the signature has to satisfy, through the same environment variable every exec
// plugin reads. And the credential is cached for its stated lifetime, because a
// plugin invoked per request is the failure this mode exists to avoid.
func TestExecPluginSignsRequests(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientfeatures.ClientsAllowHTTPSignature, true)

	secret := "a-secret-only-the-plugin-and-the-server-know"
	secretFile := writeTempFile(t, "hmac.secret", secret)

	// The plugin records what it was told and how often it ran, then answers with
	// key material rather than a token.
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

	server := startServer(t, fmt.Sprintf(`
apiVersion: apiserver.config.k8s.io/v1alpha1
kind: AuthenticationConfiguration
httpSignature:
  keys:
  - keyID: %s
    algorithm: hmac-sha256
    secretFile: %s
    user:
      username: %s
      groups: [%s]
`, bobKeyID, secretFile, bobUser, signerGrp))
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

	review, err := client.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("a request signed with material from an exec plugin was not authenticated: %v", err)
	}
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

	// What the plugin was told. Without the header name it would have to guess,
	// and a credential missing a value for a covered header is refused before a
	// request is sent.
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

// indentYAML renders a value as YAML indented for embedding in a larger
// document, so a configuration file and the client can be built from one
// statement of the same thing.
func indentYAML(t *testing.T, v any, indent string) string {
	t.Helper()
	data, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	for i, line := range lines {
		lines[i] = indent + line
	}
	return strings.Join(lines, "\n")
}
