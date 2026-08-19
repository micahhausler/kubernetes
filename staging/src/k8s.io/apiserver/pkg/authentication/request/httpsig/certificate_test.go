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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
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

	"github.com/micahhausler/httpsig"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/user"
	transporthttpsig "k8s.io/client-go/transport/httpsig"
	"k8s.io/component-base/metrics/legacyregistry"
)

// The tests here exercise the certificate flow end to end: a real client
// transport signs a real request with a real keypair, and the verifier is handed
// the request in the shape a server receives it. Nothing constructs a signature by
// hand, because a hand-built signature is a test of the test.

// authority is a certificate authority for tests, able to issue leaves.
type authority struct {
	cert *x509.Certificate
	key  crypto.Signer
	pem  string
}

func newAuthority(t *testing.T, commonName string, lifetime time.Duration) *authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating authority key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(lifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("creating authority certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing authority certificate: %v", err)
	}
	return &authority{
		cert: cert,
		key:  key,
		pem:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
}

// leaf is an issued certificate and its private key, in the PEM forms a client
// reads from disk.
type leaf struct {
	cert    *x509.Certificate
	certPEM []byte
	keyPEM  []byte
}

type leafOptions struct {
	commonName   string
	organization []string
	uris         []string
	dnsNames     []string
	notAfter     time.Time
	extKeyUsage  []x509.ExtKeyUsage
	// key overrides the generated key, for testing an unsupported key type.
	key crypto.Signer
	// publicKey embeds a public key with no matching private half, for testing
	// what a verifier accepts from a certificate rather than what can sign.
	// CreateCertificate does not need the private half of the subject's key.
	publicKey crypto.PublicKey
	// keyUsage overrides the default digitalSignature. A negative value omits the
	// extension, which is a distinct case from setting it to nothing.
	keyUsage x509.KeyUsage
	isCA     bool
}

func (a *authority) issue(t *testing.T, opts leafOptions) *leaf {
	t.Helper()
	key := opts.key
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generating leaf key: %v", err)
		}
	}
	notAfter := opts.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}
	uris := make([]*url.URL, 0, len(opts.uris))
	for _, raw := range opts.uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parsing URI SAN %q: %v", raw, err)
		}
		uris = append(uris, u)
	}
	keyUsage := x509.KeyUsageDigitalSignature
	switch {
	case opts.keyUsage < 0:
		keyUsage = 0
	case opts.keyUsage != 0:
		keyUsage = opts.keyUsage
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   opts.commonName,
			Organization: opts.organization,
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           opts.extKeyUsage,
		URIs:                  uris,
		DNSNames:              opts.dnsNames,
		IsCA:                  opts.isCA,
		BasicConstraintsValid: opts.isCA,
	}
	subjectPublicKey := crypto.PublicKey(key.Public())
	if opts.publicKey != nil {
		subjectPublicKey = opts.publicKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, subjectPublicKey, a.key)
	if err != nil {
		t.Fatalf("issuing leaf: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing leaf: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling leaf key: %v", err)
	}
	return &leaf{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

// files writes the certificate and key to disk and returns their paths.
func (l *leaf) files(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, l.certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, l.keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// bundle writes one credential bundle, key block first then the chain, which is
// what a pod certificate projected volume produces.
func (l *leaf) bundle(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.pem")
	if err := os.WriteFile(path, append(append([]byte{}, l.keyPEM...), l.certPEM...), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// stubSignature builds a parsed signature carrying a chosen keyid, for the paths
// that reject a request before any signature math happens. Going through
// ParseSignatures rather than fabricating a Signature keeps the library's own
// parsing in the loop.
type stubSignature struct {
	keyID string
}

func (s *stubSignature) parse(t *testing.T, req *http.Request) *httpsig.Signature {
	t.Helper()
	req.Header.Set("Signature-Input", `sig1=("@method");keyid="`+s.keyID+`";created=1;nonce="n";alg="ed25519"`)
	req.Header.Set("Signature", `sig1=:AAAA:`)
	sigs, err := httpsig.ParseSignatures(req, nil)
	if err != nil {
		t.Fatalf("parsing the stub signature: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("got %d signatures, want 1", len(sigs))
	}
	return sigs[0]
}

// certAuthenticator builds a verifier with one certificate authenticator.
func certAuthenticator(t *testing.T, a *authority, mutate func(*apiserver.HTTPSignatureAuthenticator)) *Authenticator {
	t.Helper()
	c := apiserver.HTTPSignatureAuthenticator{
		Name: "certs",
		X509: &apiserver.HTTPSignatureX509{CertificateAuthority: a.pem},
		ClaimMappings: &apiserver.HTTPSignatureClaimMappings{
			Username: apiserver.HTTPSignatureClaimExpression{Expression: `cert.subject.commonName`},
		},
	}
	if mutate != nil {
		mutate(&c)
	}
	auth, err := New(&apiserver.HTTPSignatureConfig{
		Authenticators: []apiserver.HTTPSignatureAuthenticator{c},
	}, nil)
	if err != nil {
		t.Fatalf("building authenticator: %v", err)
	}
	return auth
}

// certSigner returns a transport signing with a certificate from two files.
func certSigner(t *testing.T, l *leaf) (http.RoundTripper, *capture) {
	t.Helper()
	certFile, keyFile := l.files(t)
	c := &capture{}
	rt, err := transporthttpsig.NewRoundTripper(transporthttpsig.Config{
		CertFile: certFile,
		KeyFile:  keyFile,
	}, c)
	if err != nil {
		t.Fatalf("building signing transport: %v", err)
	}
	return rt, c
}

func certRequest(t *testing.T, rt http.RoundTripper, c *capture) *http.Request {
	t.Helper()
	return signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
}

// TestCertificateAuthenticatesSignedRequest is the whole flow: a client signs with
// a certificate it holds, and the server maps that certificate to an identity
// without holding anything about the client.
func TestCertificateAuthenticatesSignedRequest(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	l := ca.issue(t, leafOptions{
		commonName:   "builder",
		organization: []string{"platform"},
		uris:         []string{"spiffe://cluster.local/ns/default/sa/builder"},
	})
	auth := certAuthenticator(t, ca, func(c *apiserver.HTTPSignatureAuthenticator) {
		c.ClaimMappings.Username = apiserver.HTTPSignatureClaimExpression{Expression: `"cert:" + cert.subject.commonName`}
		c.ClaimMappings.Groups = apiserver.HTTPSignatureClaimExpression{Expression: `cert.subject.organization`}
		c.ClaimMappings.UID = apiserver.HTTPSignatureClaimExpression{Expression: `cert.sha256Thumbprint`}
		c.ClaimMappings.Extra = []apiserver.ExtraMapping{{
			Key:             "example.org/spiffe-id",
			ValueExpression: `cert.uriSANs`,
		}}
	})

	rt, c := certSigner(t, l)
	req := certRequest(t, rt, c)

	resp, ok, err := auth.AuthenticateRequest(req)
	if err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	if !ok {
		t.Fatal("a request signed with a certificate from the configured authority was not authenticated")
	}
	if got, want := resp.User.GetName(), "cert:builder"; got != want {
		t.Errorf("username = %q, want %q", got, want)
	}
	if got := resp.User.GetGroups(); len(got) != 1 || got[0] != "platform" {
		t.Errorf("groups = %v, want [platform]", got)
	}
	// The UID is the certificate's digest, which is the same value the keyid
	// carries. If these disagree, the two sides are hashing different bytes.
	wantUID := strings.TrimPrefix(transporthttpsig.CertificateKeyID(l.cert.Raw), transporthttpsig.CertificateKeyIDPrefix)
	if got := resp.User.GetUID(); got != wantUID {
		t.Errorf("uid = %q, want the leaf digest %q", got, wantUID)
	}
	if got := resp.User.GetExtra()["example.org/spiffe-id"]; len(got) != 1 || got[0] != "spiffe://cluster.local/ns/default/sa/builder" {
		t.Errorf("extra spiffe-id = %v", got)
	}
}

// TestCertificateHeaderIsCoveredAndCleared checks the two things the header itself
// has to satisfy: the signature covers it, and it does not survive into the
// handler chain as something that could be mistaken for a credential.
func TestCertificateHeaderIsCoveredAndCleared(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	l := ca.issue(t, leafOptions{commonName: "builder"})
	auth := certAuthenticator(t, ca, nil)
	rt, c := certSigner(t, l)
	req := certRequest(t, rt, c)

	if got := req.Header.Get(transporthttpsig.CertificateHeader); got == "" {
		t.Fatalf("the client did not send the %s header", transporthttpsig.CertificateHeader)
	}
	// Covered, because it is a protected header and the client covers those when
	// present. The verifier separately refuses a protected header it does not
	// cover, so this is the client half of that agreement.
	input := req.Header.Get("Signature-Input")
	if !strings.Contains(input, `"signature-certificate"`) {
		t.Errorf("the signature does not cover the certificate header: %s", input)
	}

	if _, ok, err := auth.AuthenticateRequest(req); !ok || err != nil {
		t.Fatalf("authenticating: ok=%v err=%v", ok, err)
	}
	for _, name := range []string{"Signature", "Signature-Input", transporthttpsig.CertificateHeader} {
		if got := req.Header.Get(name); got != "" {
			t.Errorf("%s survived authentication as %q; it should be cleared so nothing downstream reads it as a credential", name, got)
		}
	}
}

// TestCertificateKeyIDBindsTheCertificate is the binding argument as a test. The
// keyid names the certificate's digest and the verifier recomputes it, so swapping
// the certificate for another one issued by the same authority is refused by name
// rather than surfacing as a signature mismatch.
func TestCertificateKeyIDBindsTheCertificate(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	mine := ca.issue(t, leafOptions{commonName: "builder"})
	theirs := ca.issue(t, leafOptions{commonName: "someone-else"})
	auth := certAuthenticator(t, ca, nil)

	rt, c := certSigner(t, mine)
	req := certRequest(t, rt, c)
	// Substitute a certificate the same authority issued, leaving the signature
	// and its keyid alone.
	req.Header.Set(transporthttpsig.CertificateHeader, transporthttpsig.CertificateHeaderValue(theirs.cert.Raw))

	_, ok, err := auth.AuthenticateRequest(req)
	if ok {
		t.Fatal("a request whose certificate was swapped for another was authenticated")
	}
	if err == nil || !strings.Contains(err.Error(), "names a different certificate") {
		t.Errorf("want an error naming the certificate mismatch, got %v", err)
	}
}

// TestCertificateRequiresOneHeader covers the two degenerate header shapes. Two
// asserted certificates is a question about which the request meant, and every
// answer to it is a guess.
func TestCertificateRequiresOneHeader(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	l := ca.issue(t, leafOptions{commonName: "builder"})
	auth := certAuthenticator(t, ca, nil)

	for _, tc := range []struct {
		name   string
		values []string
		want   string
	}{{
		name:   "no header",
		values: nil,
		want:   "carries no Signature-Certificate header",
	}, {
		name:   "two headers",
		values: []string{transporthttpsig.CertificateHeaderValue(l.cert.Raw), transporthttpsig.CertificateHeaderValue(l.cert.Raw)},
		want:   "exactly one certificate may be asserted",
	}, {
		name:   "not a byte sequence",
		values: []string{"not-a-byte-sequence"},
		want:   "is not a byte sequence",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			rt, c := certSigner(t, l)
			req := certRequest(t, rt, c)
			req.Header.Del(transporthttpsig.CertificateHeader)
			for _, v := range tc.values {
				req.Header.Add(transporthttpsig.CertificateHeader, v)
			}
			_, ok, err := auth.AuthenticateRequest(req)
			if ok {
				t.Fatal("the request was authenticated")
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want an error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

// TestCertificateRequiresTrustAnchor is the trust boundary: holding the key of a
// well-formed certificate proves possession and nothing else.
func TestCertificateRequiresTrustAnchor(t *testing.T) {
	configured := newAuthority(t, "configured-ca", time.Hour)
	other := newAuthority(t, "other-ca", time.Hour)
	l := other.issue(t, leafOptions{commonName: "builder"})
	auth := certAuthenticator(t, configured, nil)

	rt, c := certSigner(t, l)
	req := certRequest(t, rt, c)

	_, ok, err := auth.AuthenticateRequest(req)
	if ok {
		t.Fatal("a certificate from an unconfigured authority was accepted")
	}
	if err == nil || !strings.Contains(err.Error(), "does not chain to this authenticator's trust anchors") {
		t.Errorf("want a chain error, got %v", err)
	}
	// The error names the certificate so an operator can find it, and does not
	// echo its bytes.
	if err != nil && !strings.Contains(err.Error(), "builder") {
		t.Errorf("the error should name the certificate's subject, got %v", err)
	}
}

// TestCertificateIntermediatesComeFromConfiguration checks that a caller cannot
// extend the chain with certificates of their own choosing by sending them.
func TestCertificateIntermediatesComeFromConfiguration(t *testing.T) {
	configured := newAuthority(t, "configured-ca", time.Hour)
	other := newAuthority(t, "other-ca", time.Hour)
	l := other.issue(t, leafOptions{commonName: "builder"})
	auth := certAuthenticator(t, configured, nil)

	rt, c := certSigner(t, l)
	req := certRequest(t, rt, c)
	// Append the issuing authority to the header. Only the leaf is read, so this
	// changes the digest and is refused before the chain is even considered.
	req.Header.Set(transporthttpsig.CertificateHeader,
		transporthttpsig.CertificateHeaderValue(append(append([]byte{}, l.cert.Raw...), other.cert.Raw...)))

	if _, ok, _ := auth.AuthenticateRequest(req); ok {
		t.Fatal("a caller supplied their own issuer in the header and was authenticated")
	}
}

// TestCertificateValidationRules checks that rules run and that they run before
// the mappings, so a mapping never reads a certificate no rule has vetted.
func TestCertificateValidationRules(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	l := ca.issue(t, leafOptions{commonName: "builder", organization: []string{"platform"}})

	for _, tc := range []struct {
		name   string
		mutate func(*apiserver.HTTPSignatureAuthenticator)
		want   string
	}{{
		name: "rule passes",
		mutate: func(c *apiserver.HTTPSignatureAuthenticator) {
			c.CertificateValidationRules = []apiserver.CertificateValidationRule{{
				Expression: `cert.subject.organization.exists(o, o == "platform")`,
			}}
		},
	}, {
		name: "rule fails with its message",
		mutate: func(c *apiserver.HTTPSignatureAuthenticator) {
			c.CertificateValidationRules = []apiserver.CertificateValidationRule{{
				Expression: `cert.subject.organization.exists(o, o == "other")`,
				Message:    "certificate must be issued to the other organization",
			}}
		},
		want: "certificate must be issued to the other organization",
	}, {
		// A rule bounding the certificate's lifetime, which is the reason the
		// validity bounds are exposed as timestamps rather than as a dedicated
		// maximum lifetime field.
		name: "lifetime rule fails",
		mutate: func(c *apiserver.HTTPSignatureAuthenticator) {
			c.CertificateValidationRules = []apiserver.CertificateValidationRule{{
				Expression: `cert.notAfter - cert.notBefore <= duration("1m")`,
				Message:    "certificate lifetime must not exceed one minute",
			}}
		},
		want: "certificate lifetime must not exceed one minute",
	}, {
		// The rules run first, so a mapping that would fail on this certificate is
		// never reached. If the order were reversed the error would name the
		// mapping instead.
		name: "rules run before mappings",
		mutate: func(c *apiserver.HTTPSignatureAuthenticator) {
			c.CertificateValidationRules = []apiserver.CertificateValidationRule{{
				Expression: `cert.dnsSANs.size() > 0`,
				Message:    "certificate must carry a DNS name",
			}}
			c.ClaimMappings.Username = apiserver.HTTPSignatureClaimExpression{Expression: `cert.dnsSANs[0]`}
		},
		want: "certificate must carry a DNS name",
	}, {
		name: "user rule rejects the mapped identity",
		mutate: func(c *apiserver.HTTPSignatureAuthenticator) {
			c.ClaimMappings.Username = apiserver.HTTPSignatureClaimExpression{Expression: `"system:" + cert.subject.commonName`}
			c.UserValidationRules = []apiserver.UserValidationRule{{
				Expression: `!user.username.startsWith("system:")`,
				Message:    "username must not use the system: prefix",
			}}
		},
		want: "username must not use the system: prefix",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			auth := certAuthenticator(t, ca, tc.mutate)
			rt, c := certSigner(t, l)
			req := certRequest(t, rt, c)

			_, ok, err := auth.AuthenticateRequest(req)
			if tc.want == "" {
				if !ok || err != nil {
					t.Fatalf("want authentication, got ok=%v err=%v", ok, err)
				}
				return
			}
			if ok {
				t.Fatal("the request was authenticated")
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want an error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

// TestCertificateMappingMustProduceAUsername covers the mapping failures that are
// not expressible as CEL compile errors.
func TestCertificateMappingMustProduceAUsername(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	l := ca.issue(t, leafOptions{commonName: ""})
	auth := certAuthenticator(t, ca, nil)
	rt, c := certSigner(t, l)
	req := certRequest(t, rt, c)

	_, ok, err := auth.AuthenticateRequest(req)
	if ok {
		t.Fatal("a certificate mapping to an empty username was accepted")
	}
	if err == nil || !strings.Contains(err.Error(), "empty user name") {
		t.Errorf("want an empty username error, got %v", err)
	}
}

// TestCertificateValidationIsCached checks that a second request skips the chain
// build and the expressions, and that the cache is keyed on the certificate rather
// than on anything a client claims.
func TestCertificateValidationIsCached(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	l := ca.issue(t, leafOptions{commonName: "builder"})
	auth := certAuthenticator(t, ca, nil)
	r := auth.resolvers[0].(*certificateResolver)

	rt, c := certSigner(t, l)
	for i := 0; i < 3; i++ {
		req := certRequest(t, rt, c)
		if _, ok, err := auth.AuthenticateRequest(req); !ok || err != nil {
			t.Fatalf("request %d: ok=%v err=%v", i, ok, err)
		}
	}
	if got := len(r.cache.Keys()); got != 1 {
		t.Errorf("cache holds %d entries after three requests with one certificate, want 1", got)
	}
	// Keyed on the certificate the server digested, which is the keyid form.
	if _, ok := r.cache.Get(transporthttpsig.CertificateKeyID(l.cert.Raw)); !ok {
		t.Error("the cache is not keyed on the certificate's digest")
	}
}

// TestCertificateFailuresAreNotCached is the bound on the cache: entries are
// created only on success, so occupying one requires a certificate the configured
// authority actually issued. A negative cache would be keyed on bytes any caller
// can choose.
func TestCertificateFailuresAreNotCached(t *testing.T) {
	configured := newAuthority(t, "configured-ca", time.Hour)
	other := newAuthority(t, "other-ca", time.Hour)
	auth := certAuthenticator(t, configured, nil)
	r := auth.resolvers[0].(*certificateResolver)

	for i := 0; i < 5; i++ {
		l := other.issue(t, leafOptions{commonName: fmt.Sprintf("attacker-%d", i)})
		rt, c := certSigner(t, l)
		req := certRequest(t, rt, c)
		if _, ok, _ := auth.AuthenticateRequest(req); ok {
			t.Fatalf("request %d from an unconfigured authority was authenticated", i)
		}
	}
	if got := len(r.cache.Keys()); got != 0 {
		t.Errorf("cache holds %d entries after five rejected certificates, want 0: "+
			"a cache a rejected caller can fill is a way to evict entries that were earned", got)
	}
}

// TestCertificateCacheTTLIsClampedByTheChain is the bound that keeps the cache
// from outliving the thing that vouched for it. Without the chain clamp, a TTL
// longer than a trust anchor's remaining life would keep admitting requests past
// the anchor's expiry, which is the one case where the cache would grant something
// the uncached path refuses.
func TestCertificateCacheTTLIsClampedByTheChain(t *testing.T) {
	// The authority outlives the configured TTL by less than the TTL, so the
	// anchor is the binding constraint.
	ca := newAuthority(t, "short-lived-ca", 2*time.Minute)
	l := ca.issue(t, leafOptions{commonName: "builder", notAfter: time.Now().Add(24 * time.Hour)})
	auth := certAuthenticator(t, ca, func(c *apiserver.HTTPSignatureAuthenticator) {
		c.X509.CertificateCache = &apiserver.HTTPSignatureCertificateCache{
			TTL: &metav1.Duration{Duration: time.Hour},
		}
	})
	r := auth.resolvers[0].(*certificateResolver)

	chains, err := l.cert.Verify(x509.VerifyOptions{
		Roots:     r.roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		t.Fatalf("verifying the leaf: %v", err)
	}
	ttl := r.entryTTL(l.cert, chains)
	if ttl > 2*time.Minute {
		t.Errorf("entry TTL is %s, but the trust anchor expires in about 2m; the configured hour must be clamped to it", ttl)
	}
	if ttl <= 0 {
		t.Errorf("entry TTL is %s, want a positive duration", ttl)
	}

	// And the leaf clamps it too, when the leaf is the shorter of the two.
	shortLeaf := ca.issue(t, leafOptions{commonName: "builder", notAfter: time.Now().Add(30 * time.Second)})
	chains, err = shortLeaf.cert.Verify(x509.VerifyOptions{
		Roots:     r.roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		t.Fatalf("verifying the short leaf: %v", err)
	}
	if ttl := r.entryTTL(shortLeaf.cert, chains); ttl > 30*time.Second {
		t.Errorf("entry TTL is %s, but the leaf expires in about 30s", ttl)
	}
}

// TestCertificateBundleSigns covers the one-file form, which is what a pod
// certificate projected volume writes and the form that cannot be read
// mid-rotation.
func TestCertificateBundleSigns(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	l := ca.issue(t, leafOptions{commonName: "pod"})
	auth := certAuthenticator(t, ca, nil)

	c := &capture{}
	rt, err := transporthttpsig.NewRoundTripper(transporthttpsig.Config{
		CredentialBundleFile: l.bundle(t),
	}, c)
	if err != nil {
		t.Fatalf("building signing transport from a bundle: %v", err)
	}
	req := certRequest(t, rt, c)

	resp, ok, err := auth.AuthenticateRequest(req)
	if err != nil || !ok {
		t.Fatalf("authenticating a bundle-signed request: ok=%v err=%v", ok, err)
	}
	if got := resp.User.GetName(); got != "pod" {
		t.Errorf("username = %q, want %q", got, "pod")
	}
}

// TestCertificateAlgorithmsPerKeyType checks that each supported key type signs
// and verifies. The algorithm is a fixed function of the key type on both sides,
// so this is where the two agree or do not.
func TestCertificateAlgorithmsPerKeyType(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	for _, tc := range []struct {
		name string
		key  func(*testing.T) crypto.Signer
	}{{
		name: "ed25519",
		key: func(t *testing.T) crypto.Signer {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return key
		},
	}, {
		name: "ecdsa p256",
		key: func(t *testing.T) crypto.Signer {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return key
		},
	}, {
		name: "ecdsa p384",
		key: func(t *testing.T) crypto.Signer {
			key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return key
		},
	}, {
		name: "rsa",
		key: func(t *testing.T) crypto.Signer {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			return key
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			l := ca.issue(t, leafOptions{commonName: "builder", key: tc.key(t)})
			auth := certAuthenticator(t, ca, nil)
			rt, c := certSigner(t, l)
			req := certRequest(t, rt, c)
			if _, ok, err := auth.AuthenticateRequest(req); !ok || err != nil {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
		})
	}
}

// TestCertificateKeyIDPrefixIsReservedForCertificates checks that a configured key
// cannot be named so that a certificate signature would select it, which would
// make identity depend on the order the two authenticators appear in.
func TestCertificateKeyIDPrefixIsReservedForCertificates(t *testing.T) {
	_, err := New(&apiserver.HTTPSignatureConfig{
		Authenticators: []apiserver.HTTPSignatureAuthenticator{{
			Name: "keys",
			Keys: []apiserver.HTTPSignatureKey{{
				KeyID:     transporthttpsig.CertificateKeyIDPrefix + "deadbeef",
				Algorithm: "ed25519",
				PublicKey: "unused",
				User:      apiserver.HTTPSignatureUser{Username: "alice"},
			}},
		}},
	}, nil)
	if err == nil {
		t.Fatal("a configured key claiming the certificate keyid form was accepted")
	}
	if !strings.Contains(err.Error(), "reserved for signatures whose key is asserted by a certificate") {
		t.Errorf("want an error naming the reservation, got %v", err)
	}
}

// TestCertificateAndKeysCoexist checks that both kinds of authenticator can be
// configured at once and that a signature reaches the right one, decided by its
// keyid rather than by which happens to be listed first.
func TestCertificateAndKeysCoexist(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	l := ca.issue(t, leafOptions{commonName: "builder"})

	keyRT, keyCapture, keyConfig := signerFor(t)
	config := &apiserver.HTTPSignatureConfig{
		Authenticators: []apiserver.HTTPSignatureAuthenticator{
			keyConfig.Authenticators[0],
			{
				Name: "certs",
				X509: &apiserver.HTTPSignatureX509{CertificateAuthority: ca.pem},
				ClaimMappings: &apiserver.HTTPSignatureClaimMappings{
					Username: apiserver.HTTPSignatureClaimExpression{Expression: `cert.subject.commonName`},
				},
			},
		},
	}
	auth, err := New(config, nil)
	if err != nil {
		t.Fatalf("building authenticator: %v", err)
	}

	certRT, certCapture := certSigner(t, l)
	for _, tc := range []struct {
		name string
		req  *http.Request
		want string
	}{
		{"configured key", certRequest(t, keyRT, keyCapture), testUser},
		{"certificate", certRequest(t, certRT, certCapture), "builder"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, ok, err := auth.AuthenticateRequest(tc.req)
			if !ok || err != nil {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
			if got := resp.User.GetName(); got != tc.want {
				t.Errorf("username = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCertificateAuthenticatorConfigErrors covers the configurations refused at
// construction, which is where a mistake should surface rather than on a request.
func TestCertificateAuthenticatorConfigErrors(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	base := func() apiserver.HTTPSignatureAuthenticator {
		return apiserver.HTTPSignatureAuthenticator{
			Name: "certs",
			X509: &apiserver.HTTPSignatureX509{CertificateAuthority: ca.pem},
			ClaimMappings: &apiserver.HTTPSignatureClaimMappings{
				Username: apiserver.HTTPSignatureClaimExpression{Expression: `cert.subject.commonName`},
			},
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*apiserver.HTTPSignatureAuthenticator)
		want   string
	}{{
		name:   "no claim mappings",
		mutate: func(c *apiserver.HTTPSignatureAuthenticator) { c.ClaimMappings = nil },
		want:   "claimMappings is required",
	}, {
		name: "both keys and x509",
		mutate: func(c *apiserver.HTTPSignatureAuthenticator) {
			c.Keys = []apiserver.HTTPSignatureKey{{KeyID: "k", Algorithm: "ed25519"}}
		},
		want: "keys and x509 are alternatives",
	}, {
		name: "derivation ladder",
		mutate: func(c *apiserver.HTTPSignatureAuthenticator) {
			c.KeyDerivation = &apiserver.HTTPSignatureKeyDerivation{Kind: "hmac-ladder"}
		},
		want: "a certificate carries its own key",
	}, {
		name:   "unparseable trust anchors",
		mutate: func(c *apiserver.HTTPSignatureAuthenticator) { c.X509.CertificateAuthority = "not a certificate" },
		want:   "certificateAuthority",
	}, {
		name: "expression that does not compile",
		mutate: func(c *apiserver.HTTPSignatureAuthenticator) {
			c.ClaimMappings.Username = apiserver.HTTPSignatureClaimExpression{Expression: `cert.noSuchField`}
		},
		want: "claimMappings.username.expression",
	}, {
		name: "certificate rule that is not a boolean",
		mutate: func(c *apiserver.HTTPSignatureAuthenticator) {
			c.CertificateValidationRules = []apiserver.CertificateValidationRule{{Expression: `cert.subject.commonName`}}
		},
		want: "certificateValidationRules[0].expression",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(&c)
			_, err := New(&apiserver.HTTPSignatureConfig{
				Authenticators: []apiserver.HTTPSignatureAuthenticator{c},
			}, nil)
			if err == nil {
				t.Fatalf("want an error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v does not mention %q", err, tc.want)
			}
		})
	}
}

// TestCertificateFailedAttemptsAreNotCountedWhenAnotherSucceeds is about the
// metric being readable. A signature is offered to every authenticator whose keyid
// form it matches, so with two certificate authorities configured a client's
// certificate chains to one and fails against the other. Counting that failure
// would make a correct configuration report a rejection on every single request.
func TestCertificateFailedAttemptsAreNotCountedWhenAnotherSucceeds(t *testing.T) {
	first := newAuthority(t, "first-ca", time.Hour)
	second := newAuthority(t, "second-ca", time.Hour)
	// Issued by the second authority, so the first authenticator is tried and
	// fails before the second one succeeds.
	l := second.issue(t, leafOptions{commonName: "builder"})

	mapping := func(ca *authority, name string) apiserver.HTTPSignatureAuthenticator {
		return apiserver.HTTPSignatureAuthenticator{
			Name: name,
			X509: &apiserver.HTTPSignatureX509{CertificateAuthority: ca.pem},
			ClaimMappings: &apiserver.HTTPSignatureClaimMappings{
				Username: apiserver.HTTPSignatureClaimExpression{Expression: `cert.subject.commonName`},
			},
		}
	}
	auth, err := New(&apiserver.HTTPSignatureConfig{
		Authenticators: []apiserver.HTTPSignatureAuthenticator{
			mapping(first, "first"),
			mapping(second, "second"),
		},
	}, nil)
	if err != nil {
		t.Fatalf("building authenticator: %v", err)
	}

	before := outcomeCounts(t)
	rt, c := certSigner(t, l)
	req := certRequest(t, rt, c)
	resp, ok, err := auth.AuthenticateRequest(req)
	if !ok || err != nil {
		t.Fatalf("a certificate from the second authority should authenticate: ok=%v err=%v", ok, err)
	}
	if got := resp.User.GetName(); got != "builder" {
		t.Errorf("username = %q, want %q", got, "builder")
	}
	after := outcomeCounts(t)

	if got := after["second/"+outcomeAuthenticated] - before["second/"+outcomeAuthenticated]; got != 1 {
		t.Errorf("authenticated count for the second authenticator rose by %d, want 1", got)
	}
	// The first authenticator was tried and could not validate the certificate.
	// That is the configuration working, so nothing about it is counted.
	for _, outcome := range []string{outcomeRejectedIdentity, outcomeUnresolved, outcomeBadSignature} {
		if got := after["first/"+outcome] - before["first/"+outcome]; got != 0 {
			t.Errorf("the first authenticator counted %d %s for a request another authenticator authenticated; "+
				"a correct two-authority configuration would report a rejection on every request", got, outcome)
		}
	}
}

// TestCertificateFailedAttemptsAreCountedWhenNothingSucceeds is the other half:
// when the request really is refused, the attempts are what says why, so they are
// recorded.
func TestCertificateFailedAttemptsAreCountedWhenNothingSucceeds(t *testing.T) {
	configured := newAuthority(t, "configured-ca", time.Hour)
	other := newAuthority(t, "other-ca", time.Hour)
	l := other.issue(t, leafOptions{commonName: "builder"})
	auth := certAuthenticator(t, configured, func(c *apiserver.HTTPSignatureAuthenticator) {
		c.Name = "only"
	})

	before := outcomeCounts(t)
	rt, c := certSigner(t, l)
	if _, ok, _ := auth.AuthenticateRequest(certRequest(t, rt, c)); ok {
		t.Fatal("a certificate from an unconfigured authority was authenticated")
	}
	after := outcomeCounts(t)

	if got := after["only/"+outcomeRejectedIdentity] - before["only/"+outcomeRejectedIdentity]; got != 1 {
		t.Errorf("rejected_identity rose by %d, want 1: a refused request is what the counter is for", got)
	}
}

// outcomeCounts reads the outcome counter, keyed "authenticator/outcome". Reading
// the registry rather than a test double is what makes this a test of the metric
// that ships.
func outcomeCounts(t *testing.T) map[string]int {
	t.Helper()
	registerMetrics()
	metrics, err := legacyregistry.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering metrics: %v", err)
	}
	counts := map[string]int{}
	for _, family := range metrics {
		if family.GetName() != "apiserver_httpsig_signature_outcomes_total" {
			continue
		}
		for _, m := range family.GetMetric() {
			var name, outcome string
			for _, label := range m.GetLabel() {
				switch label.GetName() {
				case "authenticator":
					name = label.GetValue()
				case "outcome":
					outcome = label.GetValue()
				}
			}
			counts[name+"/"+outcome] = int(m.GetCounter().GetValue())
		}
	}
	return counts
}

// TestCertificateBoundsVerificationCost is the bound on what an unauthenticated
// caller can make the verifier spend.
//
// The key comes from a certificate the verifier has not yet decided to trust, so
// one verification costs whatever the presented key costs. Neither Go's
// certificate parser nor its RSA package bounds a modulus from above, and
// ParseCertificate does not check the certificate's own signature, so a fabricated
// oversized modulus needs no matching private key to construct. Measured on the
// code before the bound existed: a 65536-bit modulus fits in an 8.4 kB certificate
// and cost about 158 ms of CPU per request.
func TestCertificateBoundsVerificationCost(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	auth := certAuthenticator(t, ca, nil)
	r := auth.resolvers[0].(*certificateResolver)

	// A modulus no one generated: an odd integer of the requested width, which the
	// parser accepts and which crypto/rsa will happily exponentiate against.
	fabricate := func(bits int) *rsa.PublicKey {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
		if err != nil {
			t.Fatal(err)
		}
		n.SetBit(n, bits-1, 1)
		n.SetBit(n, 0, 1)
		return &rsa.PublicKey{N: n, E: 65537}
	}

	for _, tc := range []struct {
		name string
		pub  *rsa.PublicKey
		want string
	}{
		{"accepted 2048", fabricate(2048), ""},
		{"accepted 4096", fabricate(4096), ""},
		{"oversized 8192", fabricate(8192), "outside the accepted 2048 to 4096 bits"},
		{"oversized 65536", fabricate(65536), "outside the accepted 2048 to 4096 bits"},
		{"undersized 1024", fabricate(1024), "outside the accepted 2048 to 4096 bits"},
		{"even exponent", &rsa.PublicKey{N: fabricate(2048).N, E: 4}, "public exponent"},
		{"huge exponent", &rsa.PublicKey{N: fabricate(2048).N, E: 1 << 30}, "public exponent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := transporthttpsig.CertificateAlgorithm(tc.pub)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("want acceptance, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want an error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v does not mention %q", err, tc.want)
			}
		})
	}

	// And the gate is reached before a verifier is built, on the request path. The
	// certificate is signed by the configured authority, so nothing but the size
	// can be what refuses it.
	oversized := ca.issue(t, leafOptions{commonName: "oversized", publicKey: fabricate(65536)})
	req, err := http.NewRequest("GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(transporthttpsig.CertificateHeader, transporthttpsig.CertificateHeaderValue(oversized.cert.Raw))
	sig := &stubSignature{keyID: transporthttpsig.CertificateKeyID(oversized.cert.Raw)}
	if _, err := r.resolve(req, sig.parse(t, req)); err == nil {
		t.Error("an oversized key was resolved to a verifier; the cost bound has to be checked before the verifier exists")
	} else if !strings.Contains(err.Error(), "outside the accepted") {
		t.Errorf("want a size error, got %v", err)
	}
}

// TestCertificateCacheHitStillVerifies is the bypass a plausible optimization
// would introduce. The cache holds a verification key and a mapped identity, never
// the conclusion that the caller holds the key. If a hit short-circuited signature
// verification, anyone who had merely observed a certificate would authenticate as
// its subject, which an intermediary, a log, or a packet capture all supply.
func TestCertificateCacheHitStillVerifies(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	l := ca.issue(t, leafOptions{commonName: "builder"})
	auth := certAuthenticator(t, ca, nil)
	r := auth.resolvers[0].(*certificateResolver)

	// Populate the cache with a legitimate request.
	rt, c := certSigner(t, l)
	if _, ok, err := auth.AuthenticateRequest(certRequest(t, rt, c)); !ok || err != nil {
		t.Fatalf("the first request should authenticate: ok=%v err=%v", ok, err)
	}
	if _, cached := r.cache.Get(transporthttpsig.CertificateKeyID(l.cert.Raw)); !cached {
		t.Fatal("the certificate was not cached, so this test would not be testing the hit path")
	}

	// Now the observer: the same certificate, the same keyid, a signature made
	// with a key they do hold rather than the certificate's.
	impostor := ca.issue(t, leafOptions{commonName: "impostor"})
	impostorRT, impostorCapture := certSigner(t, impostor)
	forged := certRequest(t, impostorRT, impostorCapture)
	// Present the cached certificate and claim its keyid, keeping the signature
	// the impostor's own key produced.
	forged.Header.Set(transporthttpsig.CertificateHeader, transporthttpsig.CertificateHeaderValue(l.cert.Raw))

	_, ok, err := auth.AuthenticateRequest(forged)
	if ok {
		t.Fatal("a cached certificate authenticated a request signed by a different key: " +
			"observing a certificate must not be enough to authenticate as its subject")
	}
	if err == nil {
		t.Fatal("want an error")
	}
}

// TestCertificateMustBeUsableForSigning covers what a certificate's own extensions
// say about whether its key may sign.
func TestCertificateMustBeUsableForSigning(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	auth := certAuthenticator(t, ca, nil)

	for _, tc := range []struct {
		name string
		opts leafOptions
		want string
	}{{
		// The extension is optional, so a certificate without it makes no claim
		// either way and is not refused for that.
		name: "no key usage extension",
		opts: leafOptions{commonName: "builder", keyUsage: -1},
	}, {
		name: "key usage without digitalSignature",
		opts: leafOptions{commonName: "builder", keyUsage: x509.KeyUsageKeyEncipherment},
		want: "does not have the digitalSignature key usage",
	}, {
		// Requires the anchor's private key, so nothing is gained by it, but the
		// chain would build trivially and the anchor's subject would map to a user.
		name: "a certificate authority as the leaf",
		opts: leafOptions{commonName: "builder", isCA: true},
		want: "is a certificate authority, not a leaf",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			l := ca.issue(t, tc.opts)
			rt, c := certSigner(t, l)
			_, ok, err := auth.AuthenticateRequest(certRequest(t, rt, c))
			if tc.want == "" {
				if !ok || err != nil {
					t.Fatalf("want authentication, got ok=%v err=%v", ok, err)
				}
				return
			}
			if ok {
				t.Fatal("the request was authenticated")
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want an error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

// TestCachedIdentityIsNotShared checks that two requests hitting one cache entry do
// not receive the same mutable identity. The authenticated group adder builds a
// fresh user.Info but carries the Extra map over by reference, so a shared cached
// map would be reachable by anything downstream that annotated it, and the failure
// would be one request's attributes appearing on another's identity.
func TestCachedIdentityIsNotShared(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	l := ca.issue(t, leafOptions{commonName: "builder", organization: []string{"platform"}})
	auth := certAuthenticator(t, ca, func(c *apiserver.HTTPSignatureAuthenticator) {
		c.ClaimMappings.Groups = apiserver.HTTPSignatureClaimExpression{Expression: `cert.subject.organization`}
		c.ClaimMappings.Extra = []apiserver.ExtraMapping{{Key: "example.org/id", ValueExpression: `cert.subject.commonName`}}
	})
	rt, c := certSigner(t, l)

	first, ok, err := auth.AuthenticateRequest(certRequest(t, rt, c))
	if !ok || err != nil {
		t.Fatalf("first request: ok=%v err=%v", ok, err)
	}
	// Something downstream annotates the identity it was handed.
	first.User.(*user.DefaultInfo).Groups = append(first.User.GetGroups(), "injected-group")
	first.User.GetExtra()["example.org/id"] = []string{"injected-value"}

	second, ok, err := auth.AuthenticateRequest(certRequest(t, rt, c))
	if !ok || err != nil {
		t.Fatalf("second request: ok=%v err=%v", ok, err)
	}
	for _, group := range second.User.GetGroups() {
		if group == "injected-group" {
			t.Error("a group added to one request's identity appeared on another's")
		}
	}
	if got := second.User.GetExtra()["example.org/id"]; len(got) != 1 || got[0] != "builder" {
		t.Errorf("extra = %v, want [builder]: one request's annotation reached another's identity", got)
	}
}

// TestTooManySignaturesAreRefused bounds work the sender chooses the amount of. A
// request may legitimately carry more than one signature, but each costs a
// signature base and possibly a verification, and the signing library imposes no
// bound of its own.
func TestTooManySignaturesAreRefused(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	l := ca.issue(t, leafOptions{commonName: "builder"})
	auth := certAuthenticator(t, ca, nil)

	rt, c := certSigner(t, l)
	req := certRequest(t, rt, c)
	// Repeat the client's own signature under fresh labels. Each is individually
	// well formed, so the count is the only thing that can refuse the request.
	input := req.Header.Get("Signature-Input")
	signature := req.Header.Get("Signature")
	inputs, signatures := []string{input}, []string{signature}
	for i := 0; i < maxSignatures; i++ {
		label := fmt.Sprintf("extra%d", i)
		inputs = append(inputs, strings.Replace(input, "sig1=", label+"=", 1))
		signatures = append(signatures, strings.Replace(signature, "sig1=", label+"=", 1))
	}
	req.Header.Set("Signature-Input", strings.Join(inputs, ", "))
	req.Header.Set("Signature", strings.Join(signatures, ", "))

	_, ok, err := auth.AuthenticateRequest(req)
	if ok {
		t.Fatal("a request carrying more signatures than the server considers was authenticated")
	}
	if err == nil || !strings.Contains(err.Error(), "more than the") {
		t.Errorf("want an error naming the bound, got %v", err)
	}
}

// TestCertificateCannotMapToReservedIdentity is the escalation path a derivation
// opens. The operator writes a mapping from the certificate's subject; whoever can
// request a certificate then chooses what that subject says. With a general-purpose
// certificate authority in the bundle, a requester putting "system:masters" in
// their organization would receive cluster administrator.
//
// The certificates here are issued by the configured authority and the signatures
// are valid, so nothing but the mapped name can be what refuses them.
func TestCertificateCannotMapToReservedIdentity(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)

	// The mapping an operator would plausibly write: identity from the subject.
	subjectMapping := func(c *apiserver.HTTPSignatureAuthenticator) {
		c.ClaimMappings.Username = apiserver.HTTPSignatureClaimExpression{Expression: `cert.subject.commonName`}
		c.ClaimMappings.Groups = apiserver.HTTPSignatureClaimExpression{Expression: `cert.subject.organization`}
	}

	for _, tc := range []struct {
		name string
		opts leafOptions
		want string
	}{{
		name: "group the framework asserts",
		opts: leafOptions{commonName: "builder", organization: []string{"system:authenticated"}},
		want: "an authenticator may not claim",
	}, {
		name: "unauthenticated group",
		opts: leafOptions{commonName: "builder", organization: []string{"system:unauthenticated"}},
		want: "an authenticator may not claim",
	}, {
		name: "the anonymous username",
		opts: leafOptions{commonName: "system:anonymous"},
		want: "the anonymous authenticator asserts",
	}, {
		// Allowed, and the reason a blanket prefix ban would be wrong: this is the
		// obvious legitimate mapping for a node's certificate.
		name: "a node username",
		opts: leafOptions{commonName: "system:node:worker-1", organization: []string{"system:nodes"}},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			auth := certAuthenticator(t, ca, subjectMapping)
			l := ca.issue(t, tc.opts)
			rt, c := certSigner(t, l)
			_, ok, err := auth.AuthenticateRequest(certRequest(t, rt, c))
			if tc.want == "" {
				if !ok || err != nil {
					t.Fatalf("want authentication, got ok=%v err=%v", ok, err)
				}
				return
			}
			if ok {
				t.Fatalf("a certificate whose subject named %v was authenticated", tc.opts)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want an error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

// TestCertificateReservedNamesByRule is the other half of the mapping question.
// Names such as system:masters are policy rather than incoherence, so they are left
// to userValidationRules, where an operator states them against their own mappings,
// and the canonical example configuration carries the rule.
//
// This matters because a mapping derives from the certificate: with
// groups: cert.subject.organization and a general-purpose authority in the bundle,
// whoever can request a certificate chooses their groups. The rule is what closes
// that, so this asserts the rule closes it.
func TestCertificateReservedNamesByRule(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	withRule := func(c *apiserver.HTTPSignatureAuthenticator) {
		c.ClaimMappings.Username = apiserver.HTTPSignatureClaimExpression{Expression: `cert.subject.commonName`}
		c.ClaimMappings.Groups = apiserver.HTTPSignatureClaimExpression{Expression: `cert.subject.organization`}
		// The rule shipped in the example configuration, verbatim.
		c.UserValidationRules = []apiserver.UserValidationRule{{
			Expression: `!user.username.startsWith("system:") && !user.groups.exists(g, g.startsWith("system:"))`,
			Message:    "this authenticator may not assert an identity under the system: prefix",
		}}
	}
	for _, tc := range []struct {
		name string
		opts leafOptions
		want bool
	}{
		{"an ordinary identity", leafOptions{commonName: "builder", organization: []string{"platform"}}, true},
		{"the group that bypasses authorization", leafOptions{commonName: "builder", organization: []string{"system:masters"}}, false},
		{"a service account username", leafOptions{commonName: "system:serviceaccount:kube-system:default"}, false},
		{"a node username", leafOptions{commonName: "system:node:worker-1"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := certAuthenticator(t, ca, withRule)
			rt, c := certSigner(t, ca.issue(t, tc.opts))
			_, ok, err := auth.AuthenticateRequest(certRequest(t, rt, c))
			if ok != tc.want {
				t.Fatalf("authenticated = %v, want %v (err=%v)", ok, tc.want, err)
			}
			if !tc.want && !strings.Contains(err.Error(), "may not assert an identity under the system: prefix") {
				t.Errorf("want the rule's own message, got %v", err)
			}
		})
	}
}

// TestCertificateKeyIDCommitsToTheLeafBytes states the invariant every accepted
// keyid format has to satisfy, as a property rather than as a comment: the keyid is
// a collision-resistant commitment to the exact bytes presented.
//
// The shape of CertificateKeyID is what protects this. It takes the leaf's DER and
// nothing else, so a format keyed on anything narrower, a subject public key digest
// or a serial number, cannot be added without widening that signature, and widening
// it is the visible tripwire.
func TestCertificateKeyIDCommitsToTheLeafBytes(t *testing.T) {
	ca := newAuthority(t, "test-ca", time.Hour)
	l := ca.issue(t, leafOptions{commonName: "builder", organization: []string{"platform"}})
	base := transporthttpsig.CertificateKeyID(l.cert.Raw)

	// Every byte of the certificate is committed to, not a prefix and not a field.
	for i := range l.cert.Raw {
		altered := make([]byte, len(l.cert.Raw))
		copy(altered, l.cert.Raw)
		altered[i] ^= 0x01
		if got := transporthttpsig.CertificateKeyID(altered); got == base {
			t.Fatalf("flipping a bit in byte %d of the certificate left the keyid unchanged, "+
				"so the keyid does not commit to the whole certificate", i)
		}
	}

	// And the format is exact: fixed width, lowercase hex, one prefix. Two spellings
	// of one certificate would be two identities.
	if want := transporthttpsig.CertificateKeyIDPrefix + strings.Repeat("0", 64); len(base) != len(want) {
		t.Errorf("keyid %q is %d characters, want %d", base, len(base), len(want))
	}
	if base != strings.ToLower(base) {
		t.Errorf("keyid %q is not lowercase, so a certificate would have more than one spelling", base)
	}
}
