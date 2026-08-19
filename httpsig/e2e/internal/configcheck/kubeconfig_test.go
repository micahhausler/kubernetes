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

package configcheck

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	transporthttpsig "k8s.io/client-go/transport/httpsig"
)

// TestGeneratedKubeconfigIsAccepted loads the kubeconfig write-kubeconfig.sh wrote
// and validates every context, then builds the client configuration each one
// produces.
//
// A released kubectl would accept this file however wrong it is, because kubeconfig
// parsing drops fields it does not recognize: an httpSignature block with a typo
// becomes a user with no credential, and the request goes out unauthenticated. So
// the check has to be strict validation rather than "kubectl parsed it".
//
// Building the client configuration is the second half, and it is where the signing
// transport reads the key material. That turns a missing or malformed certificate
// into an error naming the file, rather than a 401 from the server.
func TestGeneratedKubeconfigIsAccepted(t *testing.T) {
	path := os.Getenv("HTTPSIG_KUBECONFIG")
	if path == "" {
		t.Skip("HTTPSIG_KUBECONFIG is unset; write-kubeconfig.sh sets it")
	}
	config, err := clientcmd.LoadFromFile(path)
	if err != nil {
		t.Fatalf("loading %s: %v", path, err)
	}
	if err := clientcmd.Validate(*config); err != nil {
		t.Fatalf("the generated kubeconfig is invalid: %v", err)
	}

	// Every context, because a demo with a context nobody builds is a context that
	// works until someone selects it.
	if len(config.Contexts) == 0 {
		t.Fatal("the generated kubeconfig has no contexts")
	}
	for name := range config.Contexts {
		t.Run(name, func(t *testing.T) {
			overrides := &clientcmd.ConfigOverrides{CurrentContext: name}
			rest, err := clientcmd.NewNonInteractiveClientConfig(*config, name, overrides, nil).ClientConfig()
			if err != nil {
				t.Fatalf("building a client for context %q: %v", name, err)
			}
			if rest.HTTPSignature == nil {
				t.Fatalf("context %q produced a client that does not sign; a kubeconfig field that was dropped "+
					"rather than rejected would send unauthenticated requests instead", name)
			}
			// The certificate forms must not put their material into the TLS
			// configuration as well, which would authenticate the connection and
			// leave the signature unconsulted.
			sig := rest.HTTPSignature
			if sig.CertFile != "" || sig.CredentialBundleFile != "" {
				if rest.TLSClientConfig.CertFile != "" || len(rest.TLSClientConfig.CertData) > 0 {
					t.Errorf("context %q sends its signing certificate as a client certificate as well", name)
				}
				if sig.Algorithm != "" {
					t.Errorf("context %q states algorithm %q alongside a certificate, which determines it", name, sig.Algorithm)
				}
			}
		})
	}
}

// TestLeafThumbprintMatchesOpenSSL checks that the digest test.sh computes with
// openssl is the digest the server reports as the identity's UID.
//
// test.sh asserts the two agree, and on its own that assertion could be wrong in the
// same direction as itself: it compares an openssl pipeline against a mapping that
// reads cert.sha256Thumbprint, and nothing in the shell knows what the server means
// by that. This states the correspondence once, in the language that defines it.
func TestLeafThumbprintMatchesOpenSSL(t *testing.T) {
	leaf := os.Getenv("HTTPSIG_LEAF")
	want := os.Getenv("HTTPSIG_OPENSSL_THUMBPRINT")
	if leaf == "" || want == "" {
		t.Skip("HTTPSIG_LEAF and HTTPSIG_OPENSSL_THUMBPRINT are unset; gen-fixtures.sh sets them")
	}
	data, err := os.ReadFile(leaf)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s holds no PEM block", leaf)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimPrefix(transporthttpsig.CertificateKeyID(cert.Raw), transporthttpsig.CertificateKeyIDPrefix)
	if got != want {
		t.Errorf("the server reports the certificate digest as %q; openssl in test.sh computes %q", got, want)
	}
}
