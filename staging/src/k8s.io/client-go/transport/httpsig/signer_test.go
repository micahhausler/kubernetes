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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/micahhausler/httpsig"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/ktesting"
)

// capture records the request a round tripper sent.
type capture struct {
	req *http.Request
}

func (c *capture) RoundTrip(req *http.Request) (*http.Response, error) {
	c.req = req
	return &http.Response{StatusCode: 200, Body: http.NoBody, Request: req}, nil
}

// writeCredential writes a signing credential document and returns its path.
func writeCredential(t *testing.T, material Material) string {
	t.Helper()
	cred := SigningCredential{
		APIVersion: SigningCredentialAPIVersion,
		Kind:       SigningCredentialKind,
		Material:   material,
	}
	data, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credential.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// ed25519PEM returns a PEM-encoded ed25519 private key and its public key.
func ed25519PEM(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), pub
}

func writeEd25519Key(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path, pub
}

// signAndCapture signs one request with cfg and returns what went to the wire.
func signAndCapture(t *testing.T, cfg Config, req *http.Request) *http.Request {
	t.Helper()
	c := &capture{}
	rt, err := NewRoundTripper(cfg, c)
	if err != nil {
		t.Fatalf("NewRoundTripper: %v", err)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	return c.req
}

// covered returns the component identifiers the sent request's signature covers.
func covered(t *testing.T, req *http.Request, pub ed25519.PublicKey) []string {
	t.Helper()
	sigs, err := httpsig.ParseSignatures(req, nil)
	if err != nil {
		t.Fatalf("ParseSignatures: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("got %d signatures, want 1", len(sigs))
	}
	verifier, err := httpsig.NewVerifier(httpsig.Ed25519, pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := sigs[0].Verify(verifier, httpsig.Policy{MaxAge: time.Minute}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var names []string
	for _, c := range sigs[0].Components() {
		names = append(names, c.Name)
	}
	return names
}

func TestSignsFloorComponents(t *testing.T) {
	keyFile, pub := writeEd25519Key(t)
	cfg := Config{Algorithm: string(httpsig.Ed25519), KeyID: "k1", KeyFile: keyFile}

	req, err := http.NewRequest("GET", "https://api.example.com/api/v1/pods?watch=true", nil)
	if err != nil {
		t.Fatal(err)
	}
	sent := signAndCapture(t, cfg, req)

	want := []string{"@method", "@authority", "@path", "@query"}
	got := covered(t, sent, pub)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("covered components: got %v, want %v", got, want)
	}
	if sent.Header.Get("Content-Digest") != "" {
		t.Error("a request with no body should carry no Content-Digest")
	}
}

func TestSignsBodyWithContentDigest(t *testing.T) {
	keyFile, pub := writeEd25519Key(t)
	cfg := Config{Algorithm: string(httpsig.Ed25519), KeyID: "k1", KeyFile: keyFile}

	body := `{"kind":"Pod"}`
	req, err := http.NewRequest("POST", "https://api.example.com/api/v1/pods", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	sent := signAndCapture(t, cfg, req)

	digest := sent.Header.Get("Content-Digest")
	if digest == "" {
		t.Fatal("a request with a body should carry a Content-Digest")
	}
	if err := VerifyContentDigest([]string{digest}, []byte(body)); err != nil {
		t.Errorf("digest does not match the body: %v", err)
	}
	got := covered(t, sent, pub)
	want := []string{"@method", "@authority", "@path", "@query", "content-digest", "content-type"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("covered components: got %v, want %v", got, want)
	}

	// The body must survive signing, and be replayable for a retry.
	if sent.GetBody == nil {
		t.Fatal("signed request has no GetBody, so a retry would send an empty body")
	}
	rc, err := sent.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	buf := make([]byte, len(body))
	if _, err := rc.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != body {
		t.Errorf("body after signing: got %q, want %q", buf, body)
	}
}

// TestCoversProtectedHeadersPresent is the client half of the header addition
// defense. The verifier's half is that a protected header present on a request
// must be covered; this checks the client covers the ones it sets.
func TestCoversProtectedHeadersPresent(t *testing.T) {
	keyFile, pub := writeEd25519Key(t)
	cfg := Config{Algorithm: string(httpsig.Ed25519), KeyID: "k1", KeyFile: keyFile}

	req, err := http.NewRequest("GET", "https://api.example.com/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Impersonate-User", "bob")
	req.Header.Add("Impersonate-Group", "dev")
	req.Header.Add("Impersonate-Group", "ops")
	req.Header.Set("Impersonate-Extra-Scopes", "read")
	req.Header.Set("Audit-ID", "audit-1")
	req.Header.Set("User-Agent", "kubectl/v1.99.0")
	req.Header.Set("Accept", "application/json")
	// Not protected, and so not covered.
	req.Header.Set("X-Unrelated", "whatever")

	got := covered(t, signAndCapture(t, cfg, req), pub)
	want := []string{
		"@method", "@authority", "@path", "@query",
		"impersonate-user", "impersonate-group", "audit-id", "accept", "user-agent",
		"impersonate-extra-scopes",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("covered components: got %v, want %v", got, want)
	}
}

func TestSignedHeadersFromCredential(t *testing.T) {
	keyPEM, pub := ed25519PEM(t)
	credFile := writeCredential(t, Material{
		KeyID:         "k1",
		PrivateKey:    keyPEM,
		SignedHeaders: map[string]string{"X-Session-Token": "session-value"},
	})
	cfg := Config{
		Algorithm:      string(httpsig.Ed25519),
		CredentialFile: credFile,
		SignedHeaders:  []Header{{Name: "X-Session-Token"}},
	}

	req, err := http.NewRequest("GET", "https://api.example.com/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	sent := signAndCapture(t, cfg, req)
	if got := sent.Header.Get("X-Session-Token"); got != "session-value" {
		t.Errorf("X-Session-Token: got %q, want %q", got, "session-value")
	}
	got := covered(t, sent, pub)
	if got[len(got)-1] != "x-session-token" {
		t.Errorf("covered components %v do not end with the configured header", got)
	}
}

// TestCredentialFileRotation is the reason the credential is asked for on every
// request. A long-lived client outlives its credentials, so the whole rotating
// triple, key ID, secret, and session token, has to be picked up from the file
// without restarting the process.
//
// Environment variables cannot do this. A process's environment is fixed when it
// starts and nothing outside can change it, so a credential sourced from the
// environment works until it expires and then fails until the process restarts.
// That is why there is no env option here.
func TestCredentialFileRotation(t *testing.T) {
	credFile := writeCredential(t, Material{
		KeyID:         "AKIAFIRST",
		Secret:        "secret-one",
		SignedHeaders: map[string]string{"X-Session-Token": "token-one"},
	})
	cfg := Config{
		Algorithm:      string(httpsig.HMACSHA256),
		CredentialFile: credFile,
		SignedHeaders:  []Header{{Name: "X-Session-Token"}},
	}
	c := &capture{}
	rt, err := NewRoundTripper(cfg, c)
	if err != nil {
		t.Fatal(err)
	}

	send := func() *httpsig.Signature {
		req, err := http.NewRequest("GET", "https://api.example.com/api/v1/pods", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rt.RoundTrip(req); err != nil {
			t.Fatal(err)
		}
		sigs, err := httpsig.ParseSignatures(c.req, nil)
		if err != nil {
			t.Fatal(err)
		}
		return sigs[0]
	}

	if got := send().KeyID(); got != "AKIAFIRST" {
		t.Fatalf("first request keyid: got %q, want AKIAFIRST", got)
	}

	// Rewrite the file the way a credential helper would.
	rotated, err := json.Marshal(SigningCredential{
		APIVersion: SigningCredentialAPIVersion,
		Kind:       SigningCredentialKind,
		Material: Material{
			KeyID:         "AKIASECOND",
			Secret:        "secret-two",
			SignedHeaders: map[string]string{"X-Session-Token": "token-two"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The watcher compares modification time and size, and a same-second rewrite
	// of the same length would be missed, so make the change visible.
	if err := os.WriteFile(credFile, append(rotated, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(credFile, time.Now().Add(time.Second), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	sig := send()
	if got := sig.KeyID(); got != "AKIASECOND" {
		t.Errorf("after rotation keyid: got %q, want AKIASECOND", got)
	}
	if got := c.req.Header.Get("X-Session-Token"); got != "token-two" {
		t.Errorf("after rotation session token: got %q, want token-two", got)
	}
	// Verifying with the new secret is what proves the whole credential was
	// taken from one read rather than mixed across two.
	verifier, err := httpsig.NewVerifier(httpsig.HMACSHA256, []byte("secret-two"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Verify(verifier, httpsig.Policy{MaxAge: time.Minute}); err != nil {
		t.Errorf("signature does not verify with the rotated secret: %v", err)
	}
}

// TestExpiredCredentialFailsClosed checks that an expired credential stops the
// request here rather than producing a rejection at the server.
func TestExpiredCredentialFailsClosed(t *testing.T) {
	past := metav1.NewTime(time.Now().Add(-time.Minute))
	credFile := writeCredential(t, Material{
		KeyID:               "k1",
		Secret:              "secret",
		ExpirationTimestamp: &past,
	})
	c := &capture{}
	_, err := NewRoundTripper(Config{
		Algorithm:      string(httpsig.HMACSHA256),
		CredentialFile: credFile,
	}, c)
	if err == nil {
		t.Fatal("want an error for an expired credential")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error %q does not say the credential expired", err)
	}
	if c.req != nil {
		t.Error("a request was sent with an expired credential")
	}
}

// TestKeyFileRotation covers the simple case: a private key on disk, replaced.
// The key is re-read on change, so a long-lived client survives key rotation.
func TestKeyFileRotation(t *testing.T) {
	keyFile, firstPub := writeEd25519Key(t)
	cfg := Config{Algorithm: string(httpsig.Ed25519), KeyID: "k1", KeyFile: keyFile}
	c := &capture{}
	rt, err := NewRoundTripper(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	send := func() *httpsig.Signature {
		req, err := http.NewRequest("GET", "https://api.example.com/api/v1/pods", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rt.RoundTrip(req); err != nil {
			t.Fatal(err)
		}
		sigs, err := httpsig.ParseSignatures(c.req, nil)
		if err != nil {
			t.Fatal(err)
		}
		return sigs[0]
	}
	firstVerifier, err := httpsig.NewVerifier(httpsig.Ed25519, firstPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := send().Verify(firstVerifier, httpsig.Policy{MaxAge: time.Minute}); err != nil {
		t.Fatalf("first signature does not verify: %v", err)
	}

	secondPEM, secondPub := ed25519PEM(t)
	if err := os.WriteFile(keyFile, []byte(secondPEM), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keyFile, time.Now().Add(time.Second), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	sig := send()
	secondVerifier, err := httpsig.NewVerifier(httpsig.Ed25519, secondPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Verify(secondVerifier, httpsig.Policy{MaxAge: time.Minute}); err != nil {
		t.Errorf("the rotated key was not picked up: %v", err)
	}
	if err := sig.Verify(firstVerifier, httpsig.Policy{MaxAge: time.Minute}); err == nil {
		t.Error("the signature still verifies with the replaced key")
	}
}

func TestSignatureParameters(t *testing.T) {
	keyFile, _ := writeEd25519Key(t)
	cfg := Config{
		Algorithm: string(httpsig.Ed25519),
		KeyID:     "k1",
		KeyFile:   keyFile,
		TTL:       30 * time.Second,
	}
	req, err := http.NewRequest("GET", "https://api.example.com/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	sent := signAndCapture(t, cfg, req)
	sigs, err := httpsig.ParseSignatures(sent, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig := sigs[0]
	if sig.Nonce() == "" {
		t.Error("signature carries no nonce, so signatures over an identical request would be identical")
	}
	if sig.Created().IsZero() {
		t.Error("signature carries no created, so its age cannot be bounded")
	}
	if sig.Expires().IsZero() {
		t.Error("a configured ttl should set expires")
	}
	if got := sig.Expires().Sub(sig.Created()); got != 30*time.Second {
		t.Errorf("expires - created: got %v, want 30s", got)
	}
	if sig.Tag() != Tag {
		t.Errorf("tag: got %q, want %q", sig.Tag(), Tag)
	}
	if sig.Alg() != httpsig.Ed25519 {
		t.Errorf("alg: got %q, want %q", sig.Alg(), httpsig.Ed25519)
	}
}

// TestSignatureFieldsAreLogged checks the diagnostic that exists because the
// debugging round tripper cannot produce it. That round tripper wraps this one
// from the outside and reads the header map of the original request, so the
// signature fields are absent from -v9 output no matter how it is invoked, and
// this line is the only place they appear.
func TestSignatureFieldsAreLogged(t *testing.T) {
	keyFile, _ := writeEd25519Key(t)
	cfg := Config{Algorithm: string(httpsig.Ed25519), KeyID: "k1", KeyFile: keyFile}

	logger := ktesting.NewLogger(t, ktesting.NewConfig(ktesting.Verbosity(7), ktesting.BufferLogs(true)))
	req, err := http.NewRequest("GET", "https://api.example.com/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	sent := signAndCapture(t, cfg, req.WithContext(klog.NewContext(req.Context(), logger)))

	// The structured values are compared rather than the rendered text: a
	// header value contains double quotes, which the renderer escapes, so a
	// substring check against the rendered line fails for a value that is in
	// fact present.
	logged := loggedSignatureFields(t, logger)
	for field, key := range map[string]string{
		"Signature-Input": "signatureInput",
		"Signature":       "signature",
	} {
		want := sent.Header.Get(field)
		if want == "" {
			t.Fatalf("the request carries no %s header", field)
		}
		// The value is required verbatim. A truncated or masked signature
		// cannot be compared against what a verifier reconstructed, which is
		// the only reason to read this line.
		if got := logged[key]; got != want {
			t.Errorf("logged %s: got %q, want %q", key, got, want)
		}
	}
}

// loggedSignatureFields returns the key/value pairs of the signing round
// tripper's log entry, or nil if it logged nothing.
func loggedSignatureFields(t *testing.T, logger logr.Logger) map[string]string {
	t.Helper()
	fields := map[string]string{}
	for _, entry := range logger.GetSink().(ktesting.Underlier).GetBuffer().Data() {
		if !strings.Contains(entry.Message, "HTTP message signature") {
			continue
		}
		kvs := entry.ParameterKVList
		for i := 0; i+1 < len(kvs); i += 2 {
			key, ok := kvs[i].(string)
			if !ok {
				t.Fatalf("log key %v is not a string", kvs[i])
			}
			value, ok := kvs[i+1].(string)
			if !ok {
				t.Fatalf("log value for %q is not a string: %v", key, kvs[i+1])
			}
			fields[key] = value
		}
	}
	return fields
}

// TestSignatureFieldsAreNotLoggedBelowThreshold keeps the diagnostic off the
// default path. Signing happens on every request, and the signature is usable
// against the API server until it ages out.
func TestSignatureFieldsAreNotLoggedBelowThreshold(t *testing.T) {
	keyFile, _ := writeEd25519Key(t)
	cfg := Config{Algorithm: string(httpsig.Ed25519), KeyID: "k1", KeyFile: keyFile}

	logger := ktesting.NewLogger(t, ktesting.NewConfig(ktesting.Verbosity(6), ktesting.BufferLogs(true)))
	req, err := http.NewRequest("GET", "https://api.example.com/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	signAndCapture(t, cfg, req.WithContext(klog.NewContext(req.Context(), logger)))

	if fields := loggedSignatureFields(t, logger); len(fields) != 0 {
		t.Errorf("the signature fields were logged at verbosity 6: %v", fields)
	}
}

// TestNoncesDiffer checks the nonce is per request. A constant one would make
// every signature over the same request identical, which is the property a
// verifier tracking nonces would depend on.
func TestNoncesDiffer(t *testing.T) {
	keyFile, _ := writeEd25519Key(t)
	cfg := Config{Algorithm: string(httpsig.Ed25519), KeyID: "k1", KeyFile: keyFile}
	c := &capture{}
	rt, err := NewRoundTripper(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		req, err := http.NewRequest("GET", "https://api.example.com/api/v1/pods", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rt.RoundTrip(req); err != nil {
			t.Fatal(err)
		}
		sigs, err := httpsig.ParseSignatures(c.req, nil)
		if err != nil {
			t.Fatal(err)
		}
		nonce := sigs[0].Nonce()
		if seen[nonce] {
			t.Fatalf("nonce %q repeated", nonce)
		}
		seen[nonce] = true
	}
}

func TestCallersRequestNotModified(t *testing.T) {
	keyPEM, _ := ed25519PEM(t)
	credFile := writeCredential(t, Material{
		KeyID:         "k1",
		PrivateKey:    keyPEM,
		SignedHeaders: map[string]string{"X-Session-Token": "from the credential"},
	})
	cfg := Config{
		Algorithm:      string(httpsig.Ed25519),
		CredentialFile: credFile,
		SignedHeaders:  []Header{{Name: "X-Session-Token"}},
	}
	req, err := http.NewRequest("GET", "https://api.example.com/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	signAndCapture(t, cfg, req)
	for _, name := range []string{"Signature", "Signature-Input", "X-Session-Token"} {
		if got := req.Header.Get(name); got != "" {
			t.Errorf("caller's request was modified: %s = %q", name, got)
		}
	}
}

func TestConfigErrors(t *testing.T) {
	keyFile, _ := writeEd25519Key(t)
	keyPEM, _ := ed25519PEM(t)
	hmacCred := writeCredential(t, Material{KeyID: "k1", Secret: "secret"})
	asymCred := writeCredential(t, Material{KeyID: "k1", PrivateKey: keyPEM})

	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{{
		name: "no algorithm",
		cfg:  Config{KeyID: "k1", KeyFile: keyFile},
		want: "algorithm is required",
	}, {
		name: "no key source",
		cfg:  Config{Algorithm: string(httpsig.Ed25519), KeyID: "k1"},
		want: "exactly one of credential, keyFile, credentialFile, certFile with keyFile, or credentialBundleFile",
	}, {
		name: "both key sources",
		cfg:  Config{Algorithm: string(httpsig.Ed25519), KeyID: "k1", KeyFile: keyFile, CredentialFile: asymCred},
		want: "exactly one of credential, keyFile, credentialFile, certFile with keyFile, or credentialBundleFile",
	}, {
		name: "hmac with a key file",
		cfg:  Config{Algorithm: string(httpsig.HMACSHA256), KeyID: "k1", KeyFile: keyFile},
		want: "requires credentialFile",
	}, {
		name: "key file without a key ID",
		cfg:  Config{Algorithm: string(httpsig.Ed25519), KeyFile: keyFile},
		want: "keyID is required with keyFile",
	}, {
		name: "credential file with a key ID",
		cfg:  Config{Algorithm: string(httpsig.Ed25519), KeyID: "k1", CredentialFile: asymCred},
		want: "keyID comes from the credential",
	}, {
		name: "signed headers with a key file",
		cfg: Config{Algorithm: string(httpsig.Ed25519), KeyID: "k1", KeyFile: keyFile,
			SignedHeaders: []Header{{Name: "X-Token"}}},
		want: "requires credentialFile",
	}, {
		name: "missing key file",
		cfg:  Config{Algorithm: string(httpsig.Ed25519), KeyID: "k1", KeyFile: filepath.Join(t.TempDir(), "absent")},
		want: "no such file",
	}, {
		name: "missing credential file",
		cfg:  Config{Algorithm: string(httpsig.Ed25519), CredentialFile: filepath.Join(t.TempDir(), "absent")},
		want: "no such file",
	}, {
		name: "unknown algorithm",
		cfg:  Config{Algorithm: "ed448", KeyID: "k1", KeyFile: keyFile},
		want: "ed448",
	}, {
		name: "reserved signed header",
		cfg: Config{Algorithm: string(httpsig.HMACSHA256), CredentialFile: hmacCred,
			SignedHeaders: []Header{{Name: "Impersonate-User"}}},
		want: "is reserved",
	}, {
		name: "duplicate signed header",
		cfg: Config{Algorithm: string(httpsig.HMACSHA256), CredentialFile: hmacCred,
			SignedHeaders: []Header{{Name: "X-Token"}, {Name: "x-token"}}},
		want: "listed more than once",
	}, {
		name: "credential has no value for a declared header",
		cfg: Config{Algorithm: string(httpsig.HMACSHA256), CredentialFile: hmacCred,
			SignedHeaders: []Header{{Name: "X-Session-Token"}}},
		want: "no value for signed header",
	}, {
		name: "hmac credential for an asymmetric algorithm",
		cfg:  Config{Algorithm: string(httpsig.Ed25519), CredentialFile: hmacCred},
		want: "sets no privateKey",
	}, {
		name: "asymmetric credential for hmac",
		cfg:  Config{Algorithm: string(httpsig.HMACSHA256), CredentialFile: asymCred},
		want: "exactly one of secret or secretBase64",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRoundTripper(tc.cfg, &capture{})
			if err == nil {
				t.Fatalf("want an error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestCredentialFileSchemaErrors covers the document itself. The schema is the
// contract with whatever writes it, so a wrong document has to fail loudly
// rather than produce a client that signs with something unintended.
func TestCredentialFileSchemaErrors(t *testing.T) {
	keyPEM, _ := ed25519PEM(t)
	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{{
		name:    "wrong apiVersion",
		content: `{"apiVersion":"httpsig.authentication.k8s.io/v99","kind":"SigningCredential","keyID":"k","privateKey":"x"}`,
		want:    "want \"httpsig.authentication.k8s.io/v1alpha1\"",
	}, {
		name:    "wrong kind",
		content: `{"apiVersion":"httpsig.authentication.k8s.io/v1alpha1","kind":"Secret","keyID":"k","privateKey":"x"}`,
		want:    "has kind",
	}, {
		name:    "no keyID",
		content: `{"apiVersion":"httpsig.authentication.k8s.io/v1alpha1","kind":"SigningCredential","privateKey":"x"}`,
		want:    "sets no keyID",
	}, {
		name:    "unknown field",
		content: `{"apiVersion":"httpsig.authentication.k8s.io/v1alpha1","kind":"SigningCredential","keyID":"k","secrets":"typo"}`,
		want:    "unknown field",
	}, {
		name:    "not a document",
		content: `this is not yaml: [`,
		want:    "parsing credential from",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "credential.yaml")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := NewRoundTripper(Config{
				Algorithm:      string(httpsig.Ed25519),
				CredentialFile: path,
			}, &capture{})
			if err == nil {
				t.Fatalf("want an error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
	_ = keyPEM
}

func TestBodyOverLimitIsNotSent(t *testing.T) {
	keyFile, _ := writeEd25519Key(t)
	cfg := Config{Algorithm: string(httpsig.Ed25519), KeyID: "k1", KeyFile: keyFile, MaxBodyBytes: 8}
	c := &capture{}
	rt, err := NewRoundTripper(cfg, c)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", "https://api.example.com/api/v1/pods", strings.NewReader("more than eight bytes"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = rt.RoundTrip(req)
	if err == nil {
		t.Fatal("want an error for a body over the signing limit")
	}
	if !strings.Contains(err.Error(), "signing limit") {
		t.Errorf("error %q does not say the body exceeded the signing limit", err)
	}
	if c.req != nil {
		t.Error("a request that could not be signed was sent anyway")
	}
}

// TestAgainstServer signs a real request over a loopback connection, so the
// authority and path the verifier reconstructs come from the wire rather than
// from the client's own view of the request.
func TestAgainstServer(t *testing.T) {
	keyFile, pub := writeEd25519Key(t)
	verifier, err := httpsig.NewVerifier(httpsig.Ed25519, pub)
	if err != nil {
		t.Fatal(err)
	}

	var verifyErr error
	var componentCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sigs, err := httpsig.ParseSignatures(r, &httpsig.ParseOptions{Scheme: "http", Authority: r.Host})
		if err != nil {
			verifyErr = err
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		componentCount = len(sigs[0].Components())
		verifyErr = sigs[0].Verify(verifier, httpsig.Policy{
			RequiredComponents: FloorComponents,
			MaxAge:             time.Minute,
		})
		if verifyErr != nil {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	cfg := Config{Algorithm: string(httpsig.Ed25519), KeyID: "k1", KeyFile: keyFile}
	rt, err := NewRoundTripper(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: rt}
	resp, err := client.Get(srv.URL + "/api/v1/pods?limit=5")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if verifyErr != nil {
		t.Fatalf("server rejected the signature: %v", verifyErr)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if componentCount < len(FloorComponents) {
		t.Errorf("covered %d components, want at least the floor's %d", componentCount, len(FloorComponents))
	}
}

// TestInlineCredential covers signing with material the caller holds, which is
// the analogue of setting rest.Config.BearerToken rather than BearerTokenFile.
// A caller that already has a key should not have to write it to disk for this
// package to read back.
func TestInlineCredential(t *testing.T) {
	keyPEM, pub := ed25519PEM(t)
	c := &capture{}
	rt, err := NewRoundTripper(Config{
		Algorithm: string(httpsig.Ed25519),
		Credential: &Material{
			KeyID:      "inline-key",
			PrivateKey: keyPEM,
		},
	}, c)
	if err != nil {
		t.Fatalf("building a client with an inline credential: %v", err)
	}
	req, err := http.NewRequest("GET", "https://example.com/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("signing with an inline credential: %v", err)
	}
	sigs, err := httpsig.ParseSignatures(c.req, nil)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := httpsig.NewVerifier(httpsig.Ed25519, pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := sigs[0].Verify(verifier, httpsig.Policy{MaxAge: time.Minute}); err != nil {
		t.Fatalf("a signature made with an inline credential does not verify: %v", err)
	}
	if got := sigs[0].KeyID(); got != "inline-key" {
		t.Errorf("keyID: got %q, want inline-key", got)
	}

	// The same rules apply as to a credential from a file, because both end at
	// one builder: a shared secret used directly is refused for hmac-sha256.
	if _, err := NewRoundTripper(Config{
		Algorithm:  string(httpsig.HMACSHA256),
		Credential: &Material{KeyID: "k", Secret: "s", PrivateKey: keyPEM},
	}, c); err == nil {
		t.Error("an inline credential setting both a secret and a private key was accepted")
	}

	// An inline credential rotates by nothing, so an expired one is a
	// configuration error rather than a runtime one: it is reported when the
	// client is built, because no later attempt could succeed.
	expired := metav1.NewTime(time.Now().Add(-time.Hour))
	_, err = NewRoundTripper(Config{
		Algorithm: string(httpsig.Ed25519),
		Credential: &Material{
			KeyID:               "inline-key",
			PrivateKey:          keyPEM,
			ExpirationTimestamp: &expired,
		},
	}, c)
	if err == nil {
		t.Error("a client was built around an already expired inline credential")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Errorf("the error does not say the credential expired: %v", err)
	}
}

// TestInlineCredentialIsNotShared covers two ways an inline credential could
// leak: through a copy that shares its maps, and through the printed form.
// rest.CopyConfig hands the result to an independently mutable config, and a
// String method is where secrets end up in logs.
func TestInlineCredentialIsNotShared(t *testing.T) {
	cfg := &Config{
		Algorithm: string(httpsig.HMACSHA256),
		Credential: &Material{
			KeyID:         "k1",
			Secret:        "the-shared-secret",
			SignedHeaders: map[string]string{"X-Session-Token": "session-value"},
			Stage:         &Stage{From: "cell", Scope: map[string]string{"cell": "cell-a"}},
		},
	}
	copied := cfg.DeepCopy()
	copied.Credential.SignedHeaders["X-Session-Token"] = "someone-elses-value"
	copied.Credential.Stage.Scope["cell"] = "cell-b"
	if got := cfg.Credential.SignedHeaders["X-Session-Token"]; got != "session-value" {
		t.Errorf("a copy's edit reached the original's header values: %q", got)
	}
	if got := cfg.Credential.Stage.Scope["cell"]; got != "cell-a" {
		t.Errorf("a copy's edit reached the original's scope: %q", got)
	}

	printed := cfg.String()
	if strings.Contains(printed, "the-shared-secret") || strings.Contains(printed, "session-value") {
		t.Errorf("the printed config discloses credential material: %s", printed)
	}
	if !strings.Contains(printed, "k1") {
		t.Errorf("the printed config does not name the key, which is not secret: %s", printed)
	}
}
