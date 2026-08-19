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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig/keyscope"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// testLeaf is a self-signed certificate and its key in PEM. Self-signed is enough
// here: this file tests what the client does with a certificate, and whether the
// certificate is trusted is the verifier's question.
type testLeaf struct {
	cert    *x509.Certificate
	certPEM []byte
	keyPEM  []byte
}

func newTestLeaf(t *testing.T, notAfter time.Time) *testLeaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "builder"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &testLeaf{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestCertificateCredentialDerivesKeyIDAndAlgorithm covers what the client takes
// from the certificate rather than from configuration. Each of these is a value
// with one correct answer, which is why none of them is configurable.
func TestCertificateCredentialDerivesKeyIDAndAlgorithm(t *testing.T) {
	leaf := newTestLeaf(t, time.Time{})
	cred, err := certificateCredential("test", leaf.certPEM, leaf.keyPEM)
	if err != nil {
		t.Fatalf("building credential: %v", err)
	}

	if want := CertificateKeyID(leaf.cert.Raw); cred.KeyID != want {
		t.Errorf("keyID = %q, want %q", cred.KeyID, want)
	}
	if !strings.HasPrefix(cred.KeyID, CertificateKeyIDPrefix) {
		t.Errorf("keyID %q does not carry the prefix that tells a verifier this is a certificate signature", cred.KeyID)
	}
	if got, want := cred.Signer.Algorithm(), httpsig.ECDSAP256SHA256; got != want {
		t.Errorf("algorithm = %s, want %s derived from the P-256 key", got, want)
	}
	// The certificate's own expiry becomes the credential's, so the client fails
	// closed rather than signing with an expired certificate.
	if !cred.NotAfter.Equal(leaf.cert.NotAfter) {
		t.Errorf("notAfter = %s, want the leaf's %s", cred.NotAfter, leaf.cert.NotAfter)
	}
	if string(cred.Certificate) != string(leaf.cert.Raw) {
		t.Error("the credential does not carry the leaf's DER, so the verifier would have nothing to validate")
	}
}

// TestCertificateCredentialRefusesAMismatchedPair is the two-file rotation case.
// Reading a certificate and a key that were written separately can catch them
// between the two writes, and signing with the pair would produce a signature the
// server rejects with nothing in the error to say why.
func TestCertificateCredentialRefusesAMismatchedPair(t *testing.T) {
	one := newTestLeaf(t, time.Time{})
	two := newTestLeaf(t, time.Time{})

	_, err := certificateCredential("/etc/certs", one.certPEM, two.keyPEM)
	if err == nil {
		t.Fatal("a certificate and a key from different pairs were accepted")
	}
	if !strings.Contains(err.Error(), "mid-rotation") {
		t.Errorf("the error should name the rotation case, which is what this usually is, got %v", err)
	}
	if !strings.Contains(err.Error(), "/etc/certs") {
		t.Errorf("the error should name where the material came from, got %v", err)
	}
}

// TestCertificateCredentialRefusesAnExpiredCertificate checks the fail-closed
// behavior: an expired certificate is refused here rather than signed with and
// rejected by the server.
func TestCertificateCredentialRefusesAnExpiredCertificate(t *testing.T) {
	leaf := newTestLeaf(t, time.Now().Add(-time.Minute))
	dir := t.TempDir()
	source := &certificateFileSource{
		certWatcher: &fileWatcher{path: writeFile(t, dir, "tls.crt", leaf.certPEM)},
		keyWatcher:  &fileWatcher{path: writeFile(t, dir, "tls.key", leaf.keyPEM)},
	}
	if _, err := source.Credential(time.Now()); err == nil {
		t.Fatal("an expired certificate was accepted for signing")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Errorf("want an expiry error, got %v", err)
	}
}

// TestCertificateFileSourceRereadsOnRotation checks that a long-running client
// picks up a rotated certificate without a restart, which is the whole reason the
// source is asked on every request.
func TestCertificateFileSourceRereadsOnRotation(t *testing.T) {
	dir := t.TempDir()
	first := newTestLeaf(t, time.Time{})
	certPath := writeFile(t, dir, "tls.crt", first.certPEM)
	keyPath := writeFile(t, dir, "tls.key", first.keyPEM)

	source := &certificateFileSource{
		certWatcher: &fileWatcher{path: certPath},
		keyWatcher:  &fileWatcher{path: keyPath},
	}
	before, err := source.Credential(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if want := CertificateKeyID(first.cert.Raw); before.KeyID != want {
		t.Fatalf("keyID = %q, want %q", before.KeyID, want)
	}

	// Rewrite both halves, as a rotation does. The modification time has to move
	// for the watcher to notice, and a test can outrun the filesystem's timestamp
	// resolution.
	second := newTestLeaf(t, time.Time{})
	if err := os.WriteFile(certPath, second.certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, second.keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Second)
	for _, p := range []string{certPath, keyPath} {
		if err := os.Chtimes(p, future, future); err != nil {
			t.Fatal(err)
		}
	}

	after, err := source.Credential(time.Now())
	if err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	if want := CertificateKeyID(second.cert.Raw); after.KeyID != want {
		t.Errorf("keyID after rotation = %q, want %q; the rotated certificate was not picked up", after.KeyID, want)
	}
}

// TestCredentialBundleSigns covers the one-file form. It exists because two files
// can be read between the two writes of a rotation and one cannot, so this asserts
// the shape rather than just that it parses: key block first, chain after.
func TestCredentialBundleSigns(t *testing.T) {
	leaf := newTestLeaf(t, time.Time{})
	dir := t.TempDir()
	bundle := append(append([]byte{}, leaf.keyPEM...), leaf.certPEM...)
	source := &certificateFileSource{certWatcher: &fileWatcher{path: writeFile(t, dir, "bundle.pem", bundle)}}

	cred, err := source.Credential(time.Now())
	if err != nil {
		t.Fatalf("reading a credential bundle: %v", err)
	}
	if want := CertificateKeyID(leaf.cert.Raw); cred.KeyID != want {
		t.Errorf("keyID = %q, want %q", cred.KeyID, want)
	}

	// A bundle carrying the chain after the leaf still resolves to the leaf, which
	// is what "leaf first" buys.
	issuer := newTestLeaf(t, time.Time{})
	withChain := append(append(append([]byte{}, leaf.keyPEM...), leaf.certPEM...), issuer.certPEM...)
	source = &certificateFileSource{certWatcher: &fileWatcher{path: writeFile(t, dir, "chain.pem", withChain)}}
	cred, err = source.Credential(time.Now())
	if err != nil {
		t.Fatalf("reading a bundle with a chain: %v", err)
	}
	if want := CertificateKeyID(leaf.cert.Raw); cred.KeyID != want {
		t.Errorf("keyID = %q, want the leaf's %q; a bundle's first certificate is the leaf", cred.KeyID, want)
	}
}

// TestRoundTripperSendsTheCertificate checks the header the round tripper sets and
// that the signature covers it. Coverage is not the binding mechanism, the keyid
// is, but a client that failed to cover it would produce signatures this project's
// own verifier refuses.
func TestRoundTripperSendsTheCertificate(t *testing.T) {
	leaf := newTestLeaf(t, time.Time{})
	dir := t.TempDir()
	c := &capture{}
	rt, err := NewRoundTripper(Config{
		CertFile: writeFile(t, dir, "tls.crt", leaf.certPEM),
		KeyFile:  writeFile(t, dir, "tls.key", leaf.keyPEM),
	}, c)
	if err != nil {
		t.Fatalf("building round tripper: %v", err)
	}
	req, err := http.NewRequest("GET", "https://example.com/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("signing: %v", err)
	}

	value := c.req.Header.Get(CertificateHeader)
	if value == "" {
		t.Fatalf("the round tripper did not set %s", CertificateHeader)
	}
	der, err := ParseCertificateHeader([]string{value})
	if err != nil {
		t.Fatalf("the header this client wrote does not parse: %v", err)
	}
	if string(der) != string(leaf.cert.Raw) {
		t.Error("the header does not carry the leaf's DER")
	}
	if input := c.req.Header.Get("Signature-Input"); !strings.Contains(input, `"signature-certificate"`) {
		t.Errorf("the signature does not cover the certificate header: %s", input)
	}
	// The keyid names the certificate, which is what binds the two.
	if input := c.req.Header.Get("Signature-Input"); !strings.Contains(input, CertificateKeyID(leaf.cert.Raw)) {
		t.Errorf("the signature's keyid does not name the certificate: %s", input)
	}
}

// TestCertificateConfigErrors covers the configurations refused when the client is
// built. Each is a value that would be a second copy of something the certificate
// already determines.
func TestCertificateConfigErrors(t *testing.T) {
	leaf := newTestLeaf(t, time.Time{})
	dir := t.TempDir()
	certFile := writeFile(t, dir, "tls.crt", leaf.certPEM)
	keyFile := writeFile(t, dir, "tls.key", leaf.keyPEM)
	bundle := writeFile(t, dir, "bundle.pem", append(append([]byte{}, leaf.keyPEM...), leaf.certPEM...))

	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{{
		name: "algorithm stated alongside a certificate",
		cfg:  Config{CertFile: certFile, KeyFile: keyFile, Algorithm: "ecdsa-p256-sha256"},
		want: "algorithm must not be set with certFile or credentialBundleFile",
	}, {
		name: "keyID stated alongside a certificate",
		cfg:  Config{CertFile: certFile, KeyFile: keyFile, KeyID: "mine"},
		want: "keyID must not be set",
	}, {
		name: "certificate with no key",
		cfg:  Config{CertFile: certFile},
		want: "keyFile is required with certFile",
	}, {
		name: "signed headers with a certificate",
		cfg:  Config{CredentialBundleFile: bundle, SignedHeaders: []Header{{Name: "X-Session"}}},
		want: "signedHeaders requires credentialFile",
	}, {
		name: "derivation with a certificate",
		cfg: Config{CredentialBundleFile: bundle, KeyDerivation: &keyscope.Derivation{
			Kind:  "hmac-ladder",
			Steps: []keyscope.Step{{Name: "purpose", Literal: "signing"}},
		}},
		want: "a certificate carries its own key",
	}, {
		name: "a bundle and a certificate file",
		cfg:  Config{CredentialBundleFile: bundle, CertFile: certFile, KeyFile: keyFile},
		want: "exactly one of credential",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewRoundTripper(tc.cfg, nil); err == nil {
				t.Fatalf("want an error mentioning %q, got none", tc.want)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v does not mention %q", err, tc.want)
			}
		})
	}
}

// TestNewCertificateCredentialTakesTheEarlierExpiry covers the exec plugin's case,
// where two expiries with different meanings arrive: the certificate says when
// signing must stop, and the plugin's status says when to ask again.
func TestNewCertificateCredentialTakesTheEarlierExpiry(t *testing.T) {
	leaf := newTestLeaf(t, time.Now().Add(time.Hour))

	// The plugin's expiry is sooner, so it binds: continuing to sign past it would
	// be signing with material the plugin has declared stale.
	sooner := metav1.NewTime(time.Now().Add(time.Minute))
	bound, err := NewCertificateCredential("exec plugin", leaf.certPEM, leaf.keyPEM, &sooner)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := bound.At(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !cred.NotAfter.Equal(sooner.Time) {
		t.Errorf("notAfter = %s, want the plugin's earlier %s", cred.NotAfter, sooner.Time)
	}

	// The certificate's expiry is sooner, so it binds: the plugin cannot extend a
	// certificate's life by saying so.
	later := metav1.NewTime(time.Now().Add(24 * time.Hour))
	bound, err = NewCertificateCredential("exec plugin", leaf.certPEM, leaf.keyPEM, &later)
	if err != nil {
		t.Fatal(err)
	}
	cred, err = bound.At(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !cred.NotAfter.Equal(leaf.cert.NotAfter) {
		t.Errorf("notAfter = %s, want the certificate's earlier %s", cred.NotAfter, leaf.cert.NotAfter)
	}
}

// TestCertificateIsRedacted checks that a credential carrying a certificate still
// prints safely. The certificate is not secret, but the key it pairs with is, and
// the Signer field holds it behind an interface.
func TestCertificateIsRedacted(t *testing.T) {
	leaf := newTestLeaf(t, time.Time{})
	cred, err := certificateCredential("test", leaf.certPEM, leaf.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, printed := range []string{cred.String(), cred.GoString()} {
		if strings.Contains(printed, "PRIVATE KEY") {
			t.Errorf("a printed credential leaked key material: %s", printed)
		}
		// The key ID survives, so the output is still worth logging.
		if !strings.Contains(printed, cred.KeyID) {
			t.Errorf("a printed credential does not name its key ID: %s", printed)
		}
	}
}
