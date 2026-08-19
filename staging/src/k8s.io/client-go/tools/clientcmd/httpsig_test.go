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

package clientcmd

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	transporthttpsig "k8s.io/client-go/transport/httpsig"
)

// httpSignatureKubeconfigTemplate is written as a user would write it. The tests
// exist because the serialized field names are the contract with users: a rename
// or a case change in the v1 types silently produces a config that parses to
// nothing. %s is the private key path.
const httpSignatureKubeconfigTemplate = `
apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster:
    server: https://api.example.com
contexts:
- name: prod
  context:
    cluster: prod
    user: alice
current-context: prod
users:
- name: alice
  user:
    httpSignature:
      apiVersion: client.authentication.k8s.io/v1alpha1
      algorithm: ed25519
      credentialFile: %s
      ttl: 30s
      signedHeaders:
      - name: X-Session-Token
`

// httpSignatureKubeconfig writes a credential file and returns a kubeconfig
// naming it. The file has to exist because validation opens it, the same way it
// opens a client certificate.
func httpSignatureKubeconfig(t *testing.T) (string, []byte) {
	t.Helper()
	credFile := filepath.Join(t.TempDir(), "credential.yaml")
	if err := os.WriteFile(credFile, []byte("contents are parsed by the signer, not by clientcmd"), 0600); err != nil {
		t.Fatal(err)
	}
	return credFile, []byte(fmt.Sprintf(httpSignatureKubeconfigTemplate, credFile))
}

func TestLoadHTTPSignatureKubeconfig(t *testing.T) {
	credFile, kubeconfig := httpSignatureKubeconfig(t)
	config, err := Load(kubeconfig)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	sig := config.AuthInfos["alice"].HTTPSignature
	if sig == nil {
		t.Fatal("httpSignature did not deserialize; check the json tags on the v1 AuthInfo field")
	}
	if sig.APIVersion != "client.authentication.k8s.io/v1alpha1" {
		t.Errorf("apiVersion: got %q", sig.APIVersion)
	}
	if sig.Algorithm != "ed25519" {
		t.Errorf("algorithm: got %q", sig.Algorithm)
	}
	if sig.CredentialFile != credFile {
		t.Errorf("credentialFile: got %q", sig.CredentialFile)
	}
	if sig.TTL != "30s" {
		t.Errorf("ttl: got %q", sig.TTL)
	}
	if len(sig.SignedHeaders) != 1 {
		t.Fatalf("signedHeaders: got %d entries, want 1", len(sig.SignedHeaders))
	}
	if got := sig.SignedHeaders[0]; got.Name != "X-Session-Token" {
		t.Errorf("signedHeaders[0]: got %+v", got)
	}
}

// TestHTTPSignatureRoundTripsThroughYAML checks the stanza survives being written
// back out. kubectl config commands rewrite the whole file, so a field that
// serializes under a different name than it parses would be dropped on the next
// write.
func TestHTTPSignatureRoundTripsThroughYAML(t *testing.T) {
	_, kubeconfig := httpSignatureKubeconfig(t)
	config, err := Load(kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Write(*config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "httpSignature:") {
		t.Fatalf("serialized kubeconfig has no httpSignature stanza:\n%s", out)
	}
	reloaded, err := Load(out)
	if err != nil {
		t.Fatal(err)
	}
	before := config.AuthInfos["alice"].HTTPSignature
	after := reloaded.AuthInfos["alice"].HTTPSignature
	if after == nil {
		t.Fatalf("httpSignature lost on rewrite:\n%s", out)
	}
	if !reflect.DeepEqual(before, after) {
		t.Errorf("httpSignature changed on rewrite: before %+v, after %+v", before, after)
	}
}

func TestHTTPSignatureToRestConfig(t *testing.T) {
	credFile, kubeconfig := httpSignatureKubeconfig(t)
	config, err := Load(kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	restConfig, err := NewDefaultClientConfig(*config, &ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatalf("ClientConfig: %v", err)
	}
	if restConfig.HTTPSignature == nil {
		t.Fatal("rest.Config.HTTPSignature is unset, so requests would go unsigned")
	}
	want := transporthttpsig.Config{
		Algorithm:      "ed25519",
		CredentialFile: credFile,
		TTL:            30 * time.Second,
		SignedHeaders:  []transporthttpsig.Header{{Name: "X-Session-Token"}},
	}
	got := *restConfig.HTTPSignature
	if got.Algorithm != want.Algorithm || got.CredentialFile != want.CredentialFile || got.TTL != want.TTL {
		t.Errorf("translated config: got %+v, want %+v", got, want)
	}
	if len(got.SignedHeaders) != 1 || got.SignedHeaders[0] != want.SignedHeaders[0] {
		t.Errorf("translated signed headers: got %+v, want %+v", got.SignedHeaders, want.SignedHeaders)
	}
	// A signing config alone identifies the user, so client-go must not fall
	// back to prompting for a username and password.
	if restConfig.Username != "" || restConfig.Password != "" {
		t.Error("client-go treated a signing config as insufficient identification")
	}
}

func TestHTTPSignatureRejectsUnknownAPIVersion(t *testing.T) {
	_, kubeconfig := httpSignatureKubeconfig(t)
	bad := strings.Replace(string(kubeconfig),
		"apiVersion: client.authentication.k8s.io/v1alpha1",
		"apiVersion: client.authentication.k8s.io/v99", 1)
	config, err := Load([]byte(bad))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDefaultClientConfig(*config, &ConfigOverrides{}).ClientConfig(); err == nil {
		t.Fatal("want an error for an unknown httpSignature apiVersion")
	}
}

func TestValidateHTTPSignature(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(keyFile, []byte("not really a key"), 0600); err != nil {
		t.Fatal(err)
	}
	valid := func() *clientcmdapi.HTTPSignatureConfig {
		return &clientcmdapi.HTTPSignatureConfig{
			APIVersion: "client.authentication.k8s.io/v1alpha1",
			Algorithm:  "ed25519",
			KeyID:      "alice-key",
			KeyFile:    keyFile,
		}
	}
	credFile := filepath.Join(t.TempDir(), "credential.yaml")
	if err := os.WriteFile(credFile, []byte("read by the signer"), 0600); err != nil {
		t.Fatal(err)
	}
	// Validation checks that these are readable and leaves their contents to the
	// signer, so they hold nothing meaningful.
	certFile := filepath.Join(t.TempDir(), "tls.crt")
	if err := os.WriteFile(certFile, []byte("parsed by the signer"), 0600); err != nil {
		t.Fatal(err)
	}
	bundleFile := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(bundleFile, []byte("parsed by the signer"), 0600); err != nil {
		t.Fatal(err)
	}
	// asCertificate rewrites a stanza into the certificate form, which states
	// neither an algorithm nor a key identifier because the certificate determines
	// both.
	asCertificate := func(a *clientcmdapi.AuthInfo) {
		a.HTTPSignature.Algorithm = ""
		a.HTTPSignature.KeyID = ""
		a.HTTPSignature.CertFile = certFile
	}

	for _, tc := range []struct {
		name     string
		authInfo func(*clientcmdapi.AuthInfo)
		want     string
	}{{
		name:     "valid",
		authInfo: func(*clientcmdapi.AuthInfo) {},
	}, {
		name:     "with a bearer token",
		authInfo: func(a *clientcmdapi.AuthInfo) { a.Token = "abc" },
		want:     "only one is allowed",
	}, {
		name:     "with basic auth",
		authInfo: func(a *clientcmdapi.AuthInfo) { a.Username = "alice"; a.Password = "s3cr3t" },
		want:     "only one is allowed",
	}, {
		// An exec plugin is a credential source rather than a competing
		// credential, so this is two sources rather than a forbidden
		// combination. The valid form, exec with no key file, is below.
		name: "with an exec plugin alongside a key file",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.Exec = testExec()
		},
		want: "exactly one credential source must be specified",
	}, {
		name: "with an auth provider",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.AuthProvider = &clientcmdapi.AuthProviderConfig{Name: "oidc"}
		},
		want: "authProvider cannot be provided in combination with httpSignature",
	}, {
		name:     "no apiVersion",
		authInfo: func(a *clientcmdapi.AuthInfo) { a.HTTPSignature.APIVersion = "" },
		want:     "apiVersion must be specified",
	}, {
		name:     "no algorithm",
		authInfo: func(a *clientcmdapi.AuthInfo) { a.HTTPSignature.Algorithm = "" },
		want:     "algorithm must be specified",
	}, {
		name:     "key file with no key identifier",
		authInfo: func(a *clientcmdapi.AuthInfo) { a.HTTPSignature.KeyID = "" },
		want:     "keyID must be specified alongside keyFile",
	}, {
		name: "both key sources",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.CredentialFile = credFile
		},
		want: "exactly one credential source must be specified",
	}, {
		name: "no key source",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.KeyFile = ""
			a.HTTPSignature.KeyID = ""
		},
		want: "exactly one credential source must be specified",
	}, {
		name: "credential file with a key identifier",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.KeyFile = ""
			a.HTTPSignature.CredentialFile = credFile
		},
		want: "keyID must not be specified alongside credentialFile",
	}, {
		name: "signed headers without a credential file",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.SignedHeaders = []clientcmdapi.HTTPSignatureHeader{{Name: "X-Session-Token"}}
		},
		want: "signedHeaders requires credentialFile or exec",
	}, {
		name:     "unreadable key file",
		authInfo: func(a *clientcmdapi.AuthInfo) { a.HTTPSignature.KeyFile = "/nonexistent/key.pem" },
		want:     "unable to read httpSignature keyFile",
	}, {
		name: "unreadable credential file",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.KeyFile = ""
			a.HTTPSignature.KeyID = ""
			a.HTTPSignature.CredentialFile = "/nonexistent/credential.yaml"
		},
		want: "unable to read httpSignature credentialFile",
	}, {
		name:     "malformed ttl",
		authInfo: func(a *clientcmdapi.AuthInfo) { a.HTTPSignature.TTL = "half an hour" },
		want:     "invalid httpSignature ttl",
	}, {
		name:     "negative ttl",
		authInfo: func(a *clientcmdapi.AuthInfo) { a.HTTPSignature.TTL = "-30s" },
		want:     "must be positive",
	}, {
		// A derived signing key comes from the credential's secret, so a
		// derivation with no credential has nothing to derive from.
		name: "derivation without a credential",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.KeyDerivation = testLadder()
		},
		want: "keyDerivation requires credentialFile or exec",
	}, {
		// The ladder is validated where it is stated, so a deployment learns its
		// ladder is wrong from its kubeconfig rather than from a 401.
		name: "invalid derivation",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.KeyFile = ""
			a.HTTPSignature.KeyID = ""
			a.HTTPSignature.CredentialFile = credFile
			ladder := testLadder()
			ladder.Steps[0].Date = "20060102"
			a.HTTPSignature.KeyDerivation = ladder
		},
		want: "keyDerivation is invalid",
	}, {
		name: "derivation with a credential file",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.KeyFile = ""
			a.HTTPSignature.KeyID = ""
			a.HTTPSignature.CredentialFile = credFile
			a.HTTPSignature.KeyDerivation = testLadder()
		},
	}, {
		// An exec plugin is a credential source like the others, so httpSignature
		// alongside exec is a valid configuration rather than a conflict.
		name: "exec as the credential source",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.KeyFile = ""
			a.HTTPSignature.KeyID = ""
			a.Exec = testExec()
		},
	}, {
		name: "exec with a key identifier",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.KeyFile = ""
			a.Exec = testExec()
		},
		want: "keyID must not be specified alongside exec",
	}, {
		name: "exec and credential file together",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.KeyFile = ""
			a.HTTPSignature.KeyID = ""
			a.HTTPSignature.CredentialFile = credFile
			a.Exec = testExec()
		},
		want: "exactly one credential source must be specified",
	}, {
		name:     "certificate and key",
		authInfo: asCertificate,
	}, {
		name: "credential bundle",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.Algorithm = ""
			a.HTTPSignature.KeyID = ""
			a.HTTPSignature.KeyFile = ""
			a.HTTPSignature.CredentialBundleFile = bundleFile
		},
	}, {
		// The certificate's key type determines the algorithm on both sides, so a
		// stated one is a second copy of a value with one correct answer.
		name: "certificate with an algorithm",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			asCertificate(a)
			a.HTTPSignature.Algorithm = "ecdsa-p256-sha256"
		},
		want: "algorithm must not be specified",
	}, {
		name: "certificate with a key identifier",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			asCertificate(a)
			a.HTTPSignature.KeyID = "alice-key"
		},
		want: "keyID must not be specified",
	}, {
		name: "certificate with no key",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			asCertificate(a)
			a.HTTPSignature.KeyFile = ""
		},
		want: "keyFile must be specified alongside certFile",
	}, {
		name: "certificate and bundle together",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			asCertificate(a)
			a.HTTPSignature.CredentialBundleFile = bundleFile
		},
		want: "certFile and credentialBundleFile are alternatives",
	}, {
		name: "bundle with a key file",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.Algorithm = ""
			a.HTTPSignature.KeyID = ""
			a.HTTPSignature.CredentialBundleFile = bundleFile
		},
		want: "keyFile must not be specified alongside credentialBundleFile",
	}, {
		name: "certificate and credential file together",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			asCertificate(a)
			a.HTTPSignature.CredentialFile = credFile
		},
		want: "the certificate is the credential",
	}, {
		name: "unreadable certificate",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			asCertificate(a)
			a.HTTPSignature.CertFile = "/nonexistent/tls.crt"
		},
		want: "unable to read httpSignature certFile",
	}, {
		// A client certificate and a signature are both credentials the server can
		// authenticate, and the server's chain reaches its mTLS authenticator
		// first, so the signature would never be consulted.
		name: "client certificate alongside a signature",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.ClientCertificate = certFile
			a.ClientKey = keyFile
		},
		want: "client-cert cannot be provided in combination with httpSignature",
	}, {
		name: "signed headers with a certificate",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			asCertificate(a)
			a.HTTPSignature.SignedHeaders = []clientcmdapi.HTTPSignatureHeader{{Name: "X-Session-Token"}}
		},
		want: "signedHeaders requires credentialFile or exec",
	}, {
		name: "derivation with exec",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.KeyFile = ""
			a.HTTPSignature.KeyID = ""
			a.Exec = testExec()
			a.HTTPSignature.KeyDerivation = testLadder()
		},
	}, {
		name: "signed headers with exec",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.KeyFile = ""
			a.HTTPSignature.KeyID = ""
			a.Exec = testExec()
			a.HTTPSignature.SignedHeaders = []clientcmdapi.HTTPSignatureHeader{{Name: "X-Session-Token"}}
		},
	}, {
		name: "reserved signed header",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.KeyFile = ""
			a.HTTPSignature.KeyID = ""
			a.HTTPSignature.CredentialFile = credFile
			a.HTTPSignature.SignedHeaders = []clientcmdapi.HTTPSignatureHeader{{Name: "Authorization"}}
		},
		want: "is reserved",
	}, {
		name: "impersonation header by another name",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.KeyFile = ""
			a.HTTPSignature.KeyID = ""
			a.HTTPSignature.CredentialFile = credFile
			a.HTTPSignature.SignedHeaders = []clientcmdapi.HTTPSignatureHeader{{Name: "impersonate-extra-scopes"}}
		},
		want: "is reserved",
	}, {
		name: "duplicate signed header",
		authInfo: func(a *clientcmdapi.AuthInfo) {
			a.HTTPSignature.KeyFile = ""
			a.HTTPSignature.KeyID = ""
			a.HTTPSignature.CredentialFile = credFile
			a.HTTPSignature.SignedHeaders = []clientcmdapi.HTTPSignatureHeader{
				{Name: "X-Token"},
				{Name: "x-token"},
			}
		},
		want: "specified more than once",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			authInfo := clientcmdapi.AuthInfo{HTTPSignature: valid()}
			tc.authInfo(&authInfo)
			errs := validateAuthInfo("alice", authInfo)
			if tc.want == "" {
				if len(errs) != 0 {
					t.Fatalf("want no errors, got %v", errs)
				}
				return
			}
			for _, err := range errs {
				if strings.Contains(err.Error(), tc.want) {
					return
				}
			}
			t.Errorf("want an error mentioning %q, got %v", tc.want, errs)
		})
	}
}

// testLadder is a neutral derivation ladder. Step names are arbitrary labels, so
// these are the deployment dimensions an example should have rather than any
// provider's.
func testLadder() *clientcmdapi.HTTPSignatureKeyDerivation {
	return &clientcmdapi.HTTPSignatureKeyDerivation{
		Kind:         "hmac-ladder",
		Hash:         "sha-256",
		SecretPrefix: "EXAMPLE1",
		Steps: []clientcmdapi.HTTPSignatureKeyDerivationStep{
			{Name: "day", Date: "YYYYMMDD"},
			{Name: "cell", Scope: true},
			{Name: "purpose", Scope: true},
			{Name: "terminator", Literal: "example1_request"},
		},
	}
}

// testExec is a minimal exec stanza, valid enough that any error a case reports
// comes from the httpSignature rules under test rather than from exec's own.
func testExec() *clientcmdapi.ExecConfig {
	return &clientcmdapi.ExecConfig{
		Command:         "credential-helper",
		APIVersion:      "client.authentication.k8s.io/v1",
		InteractiveMode: clientcmdapi.NeverExecInteractiveMode,
	}
}
