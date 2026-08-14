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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/micahhausler/httpsig"

	"github.com/micahhausler/httpsig/keyscope"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/apis/apiserver"

	transporthttpsig "k8s.io/client-go/transport/httpsig"
)

const (
	testKeyID   = "alice-key"
	testUser    = "alice"
	testGroup   = "signers"
	testAuthort = "api.example.com"
)

// signerFor returns a signing round tripper and the matching server config.
func signerFor(t *testing.T) (http.RoundTripper, *capture, *apiserver.HTTPSignatureAuthenticator) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0600); err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	config := &apiserver.HTTPSignatureAuthenticator{
		Keys: []apiserver.HTTPSignatureKey{{
			KeyID:     testKeyID,
			Algorithm: string(httpsig.Ed25519),
			PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
			User: apiserver.HTTPSignatureUser{
				Username: testUser,
				UID:      "uid-1",
				Groups:   []string{testGroup},
			},
		}},
	}
	c := &capture{}
	rt, err := transporthttpsig.NewRoundTripper(transporthttpsig.Config{
		Algorithm: string(httpsig.Ed25519),
		KeyID:     testKeyID,
		KeyFile:   keyFile,
	}, c)
	if err != nil {
		t.Fatal(err)
	}
	return rt, c, config
}

type capture struct {
	req *http.Request
}

func (c *capture) RoundTrip(req *http.Request) (*http.Response, error) {
	c.req = req
	return &http.Response{StatusCode: 200, Body: http.NoBody, Request: req}, nil
}

// signedRequest produces a request as the client transport would send it, then
// hands it back shaped as the server receives it.
func signedRequest(t *testing.T, rt http.RoundTripper, c *capture, method, target string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("signing: %v", err)
	}
	return asServerRequest(c.req)
}

// asServerRequest reshapes a client request into the form net/http hands a
// server: the authority lives in Host, the URL holds only path and query, and
// there is no scheme. The verifier derives @authority from the URL first and
// falls back to Host, so a test using a client-shaped request would never
// exercise the path a real server takes.
func asServerRequest(req *http.Request) *http.Request {
	req.Host = req.URL.Host
	req.RequestURI = req.URL.RequestURI()
	req.URL.Scheme = ""
	req.URL.Host = ""
	return req
}

func TestAuthenticatesSignedRequest(t *testing.T) {
	rt, c, config := signerFor(t)
	auth, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods?watch=true", nil)

	resp, ok, err := auth.AuthenticateRequest(req)
	if err != nil {
		t.Fatalf("AuthenticateRequest: %v", err)
	}
	if !ok {
		t.Fatal("signed request was not authenticated")
	}
	if got := resp.User.GetName(); got != testUser {
		t.Errorf("username: got %q, want %q", got, testUser)
	}
	if got := resp.User.GetUID(); got != "uid-1" {
		t.Errorf("uid: got %q, want uid-1", got)
	}
	if got := resp.User.GetGroups(); len(got) != 1 || got[0] != testGroup {
		t.Errorf("groups: got %v, want [%s]", got, testGroup)
	}
	// The signature fields are spent. Leaving them for something downstream to
	// read is the mistake the bearer token authenticator avoids by deleting its
	// own header.
	if req.Header.Get("Signature") != "" || req.Header.Get("Signature-Input") != "" {
		t.Error("signature fields were not cleared after authentication")
	}
}

func TestNoOpinionWithoutSignature(t *testing.T) {
	_, _, config := signerFor(t)
	auth, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, ok, err := auth.AuthenticateRequest(req)
	if resp != nil || ok || err != nil {
		t.Errorf("an unsigned request must draw no opinion so the chain continues: got (%v, %v, %v)", resp, ok, err)
	}
}

// TestRejectsSignatureMissingFloorComponents is the first of the two invariants
// this package exists to enforce. An attacker with their own key signs a
// component list of their choosing. The signature is internally valid. It must
// still be rejected, because the covered set is this server's requirement and
// not the signature's claim.
func TestRejectsSignatureMissingFloorComponents(t *testing.T) {
	for _, omit := range []string{"@method", "@authority", "@path", "@query"} {
		t.Run("without "+omit, func(t *testing.T) {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			pubDER, err := x509.MarshalPKIXPublicKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			auth, err := New(&apiserver.HTTPSignatureAuthenticator{
				Keys: []apiserver.HTTPSignatureKey{{
					KeyID:     testKeyID,
					Algorithm: string(httpsig.Ed25519),
					PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
					User:      apiserver.HTTPSignatureUser{Username: testUser},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}

			var components []httpsig.Component
			for _, c := range transporthttpsig.FloorComponents {
				if c.Name == omit {
					continue
				}
				components = append(components, c)
			}
			signer, err := httpsig.NewSigner(httpsig.Ed25519, priv)
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest("GET", "https://"+testAuthort+"/api/v1/pods", nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := httpsig.Sign(req, signer, httpsig.SignOptions{
				Components: components,
				KeyID:      testKeyID,
				Nonce:      "nonce-1",
				Created:    time.Now(),
			}); err != nil {
				t.Fatal(err)
			}

			_, ok, err := auth.AuthenticateRequest(asServerRequest(req))
			if ok {
				t.Fatalf("a signature omitting %s was accepted", omit)
			}
			if err == nil {
				t.Fatalf("a signature omitting %s drew no error", omit)
			}
			// The signature is otherwise valid: made by the configured key, with
			// a nonce and a created. So it has to be rejected for the missing
			// component and not for something incidental, or this test could pass
			// while the floor requirement was gone.
			if !errors.Is(err, httpsig.ErrMissingComponent) {
				t.Errorf("want a missing component error, got %v", err)
			}
			if !strings.Contains(err.Error(), omit) {
				t.Errorf("error %q does not name the missing component %s", err, omit)
			}
		})
	}
}

// TestRejectsInjectedProtectedHeader is the second invariant. The signature is
// the client's own and verifies. An intermediary appended an impersonation
// header the client never signed. Coverage cannot detect an addition, so the
// verifier has to compare what is present against what is covered.
func TestRejectsInjectedProtectedHeader(t *testing.T) {
	for _, name := range []string{
		"Impersonate-User",
		"Impersonate-Group",
		"Impersonate-Uid",
		"Impersonate-Extra-Scopes",
		"Audit-ID",
		"Content-Type",
	} {
		t.Run(name, func(t *testing.T) {
			rt, c, config := signerFor(t)
			auth, err := New(config)
			if err != nil {
				t.Fatal(err)
			}
			req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)

			// The request was signed without this header. Adding it now is what
			// a relaying party on the path can do.
			req.Header.Set(name, "injected")

			_, ok, err := auth.AuthenticateRequest(req)
			if ok {
				t.Fatalf("a request with an injected %s was accepted", name)
			}
			if err == nil || !strings.Contains(err.Error(), "does not cover") {
				t.Fatalf("want an error about uncovered protected headers, got %v", err)
			}
		})
	}
}

// TestAcceptsCoveredProtectedHeader is the counterpart: impersonation set by the
// client and covered by its signature is allowed through. Without this the
// previous test could pass by rejecting impersonation outright.
func TestAcceptsCoveredProtectedHeader(t *testing.T) {
	rt, c, config := signerFor(t)
	auth, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Impersonate-User", "bob")
	req.Header.Set("Audit-ID", "audit-1")
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := auth.AuthenticateRequest(asServerRequest(c.req)); !ok {
		t.Fatalf("a request whose impersonation headers were signed was rejected: %v", err)
	}
}

func TestBodyDigest(t *testing.T) {
	body := `{"kind":"Pod","metadata":{"name":"a"}}`

	t.Run("signed body is accepted and readable downstream", func(t *testing.T) {
		rt, c, config := signerFor(t)
		auth, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		req := signedRequest(t, rt, c, "POST", "https://"+testAuthort+"/api/v1/pods", strings.NewReader(body))
		if _, ok, err := auth.AuthenticateRequest(req); !ok {
			t.Fatalf("a signed request with a body was rejected: %v", err)
		}
		// The verifier reads the body to check the digest. If it does not put it
		// back, every write request breaks in a way no signature test would show.
		got, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != body {
			t.Errorf("body after authentication: got %q, want %q", got, body)
		}
	})

	t.Run("altered body is rejected", func(t *testing.T) {
		rt, c, config := signerFor(t)
		auth, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		req := signedRequest(t, rt, c, "POST", "https://"+testAuthort+"/api/v1/pods", strings.NewReader(body))
		// The Content-Digest header is covered by the signature and cannot be
		// changed. The body it describes can.
		req.Body = io.NopCloser(strings.NewReader(`{"kind":"Pod","metadata":{"name":"evil"}}`))

		if _, ok, err := auth.AuthenticateRequest(req); ok {
			t.Fatal("a request whose body no longer matches its signed digest was accepted")
		} else if err == nil || !strings.Contains(err.Error(), "Content-Digest") {
			t.Fatalf("want a Content-Digest error, got %v", err)
		}
	})

	t.Run("body added to a bodiless signed request is rejected", func(t *testing.T) {
		rt, c, config := signerFor(t)
		auth, err := New(config)
		if err != nil {
			t.Fatal(err)
		}
		req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
		// A GET signed with no body, then given one. Nothing in the signature
		// mentions a digest, so only the "body without a covered digest" rule
		// catches this.
		req.Body = io.NopCloser(strings.NewReader(body))

		if _, ok, err := auth.AuthenticateRequest(req); ok {
			t.Fatal("a body attached to a signed bodiless request was accepted")
		} else if err == nil || !strings.Contains(err.Error(), "not bound to the signature") {
			t.Fatalf("want an error about the body not being bound, got %v", err)
		}
	})
}

func TestReplayIsRejected(t *testing.T) {
	rt, c, config := signerFor(t)
	auth, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	first := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)

	// A captured request, resent byte for byte.
	replay, err := http.NewRequest("GET", "https://"+first.Host+first.RequestURI, nil)
	if err != nil {
		t.Fatal(err)
	}
	replay = asServerRequest(replay)
	for name, values := range first.Header {
		for _, v := range values {
			replay.Header.Add(name, v)
		}
	}

	if _, ok, err := auth.AuthenticateRequest(first); !ok {
		t.Fatalf("first request was rejected: %v", err)
	}
	_, ok, err := auth.AuthenticateRequest(replay)
	if ok {
		t.Fatal("a replayed request was accepted")
	}
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("want a nonce error, got %v", err)
	}
}

// TestNoncesAreTrackedPerKey checks that one client cannot evict another's
// records. A shared cache would let a noisy client make replay possible for
// everyone else.
func TestNoncesAreTrackedPerKey(t *testing.T) {
	pubA, privA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, privB, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemFor := func(pub ed25519.PublicKey) string {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	one := int32(1)
	auth, err := New(&apiserver.HTTPSignatureAuthenticator{
		MaxNoncesPerKey: &one,
		Keys: []apiserver.HTTPSignatureKey{{
			KeyID: "key-a", Algorithm: string(httpsig.Ed25519), PublicKey: pemFor(pubA),
			User: apiserver.HTTPSignatureUser{Username: "alice"},
		}, {
			KeyID: "key-b", Algorithm: string(httpsig.Ed25519), PublicKey: pemFor(pubB),
			User: apiserver.HTTPSignatureUser{Username: "bob"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	sign := func(priv ed25519.PrivateKey, keyID, nonce string) *http.Request {
		signer, err := httpsig.NewSigner(httpsig.Ed25519, priv)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest("GET", "https://"+testAuthort+"/api/v1/pods", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := httpsig.Sign(req, signer, httpsig.SignOptions{
			Components: transporthttpsig.FloorComponents,
			KeyID:      keyID,
			Nonce:      nonce,
			Created:    time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
		return asServerRequest(req)
	}

	// Alice records a nonce. Bob then fills his own single-entry cache several
	// times over, which would evict Alice's record from a shared cache.
	if _, ok, err := auth.AuthenticateRequest(sign(privA, "key-a", "alice-nonce")); !ok {
		t.Fatalf("alice's request was rejected: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, ok, err := auth.AuthenticateRequest(sign(privB, "key-b", "bob-nonce-"+string(rune('a'+i)))); !ok {
			t.Fatalf("bob's request %d was rejected: %v", i, err)
		}
	}
	if _, ok, _ := auth.AuthenticateRequest(sign(privA, "key-a", "alice-nonce")); ok {
		t.Error("alice's nonce was forgotten after another key's traffic, so her request could be replayed")
	}
}

func TestRejectsMissingNonce(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := New(&apiserver.HTTPSignatureAuthenticator{
		Keys: []apiserver.HTTPSignatureKey{{
			KeyID: testKeyID, Algorithm: string(httpsig.Ed25519),
			PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
			User:      apiserver.HTTPSignatureUser{Username: testUser},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := httpsig.NewSigner(httpsig.Ed25519, priv)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := httpsig.Sign(req, signer, httpsig.SignOptions{
		Components: transporthttpsig.FloorComponents,
		KeyID:      testKeyID,
		Created:    time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := auth.AuthenticateRequest(asServerRequest(req)); ok {
		t.Fatal("a signature with no nonce was accepted, so nothing could track its replay")
	} else if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("want a nonce error, got %v", err)
	}
}

func TestRejectsStaleSignature(t *testing.T) {
	rt, c, config := signerFor(t)
	config.MaxAge = &metav1.Duration{Duration: time.Second}
	auth, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	// Rather than sleep, move the created parameter into the past by verifying
	// against a policy whose clock is ahead.
	auth.policy.Now = func() time.Time { return time.Now().Add(time.Hour) }

	_, ok, err := auth.AuthenticateRequest(req)
	if ok {
		t.Fatal("a signature older than maxAge was accepted")
	}
	// The signature is otherwise valid, so age has to be the reason. Without this
	// the test would pass even if maxAge were ignored and something incidental
	// rejected the request.
	if !errors.Is(err, httpsig.ErrExpired) {
		t.Errorf("want an expiry error, got %v", err)
	}
}

func TestRejectsUnknownKeyID(t *testing.T) {
	rt, c, config := signerFor(t)
	config.Keys[0].KeyID = "some-other-key"
	auth, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if _, ok, err := auth.AuthenticateRequest(req); ok {
		t.Fatal("a signature naming an unconfigured key was accepted")
	} else if err == nil || !strings.Contains(err.Error(), "unknown keyID") {
		t.Fatalf("want an unknown keyID error, got %v", err)
	}
}

// TestRejectsWrongKeyForKeyID checks that the keyid is only a selector. It is an
// unverified claim from the wire, so naming a key you do not hold must fail.
func TestRejectsWrongKeyForKeyID(t *testing.T) {
	_, _, config := signerFor(t)
	auth, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	_, attackerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := httpsig.NewSigner(httpsig.Ed25519, attackerKey)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := httpsig.Sign(req, signer, httpsig.SignOptions{
		Components: transporthttpsig.FloorComponents,
		KeyID:      testKeyID,
		Nonce:      "nonce-1",
		Created:    time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	_, ok, err := auth.AuthenticateRequest(asServerRequest(req))
	if ok {
		t.Fatal("a signature made with the wrong key was accepted")
	}
	// This is the test that proves naming someone else's key ID gets you nothing,
	// so the reason has to be the signature check and not bookkeeping.
	if !errors.Is(err, httpsig.ErrSignatureMismatch) {
		t.Errorf("want a signature mismatch, got %v", err)
	}
}

// TestRejectsAlgorithmSubstitution checks that a key configured for one
// algorithm is not usable under another.
func TestRejectsAlgorithmSubstitution(t *testing.T) {
	_, _, config := signerFor(t)
	// The configured key is ed25519. Claim hmac-sha256 with the public key bytes
	// as the shared secret, the classic confusion attack.
	auth, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := httpsig.NewSigner(httpsig.HMACSHA256, []byte(config.Keys[0].PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := httpsig.Sign(req, signer, httpsig.SignOptions{
		Components: transporthttpsig.FloorComponents,
		KeyID:      testKeyID,
		Nonce:      "nonce-1",
		Created:    time.Now(),
		IncludeAlg: true,
	}); err != nil {
		t.Fatal(err)
	}
	_, ok, err := auth.AuthenticateRequest(asServerRequest(req))
	if ok {
		t.Fatal("a signature claiming a different algorithm than the key was accepted")
	}
	// Algorithm confusion is closed by the alg parameter disagreeing with the
	// key, not by the signature bytes happening not to match. Only the specific
	// error distinguishes the two, and only one of them is a real defense.
	if !errors.Is(err, httpsig.ErrAlgorithmMismatch) {
		t.Errorf("want an algorithm mismatch, got %v", err)
	}
}

// TestAuthorityOverride covers the TLS-terminating proxy deployment: the client
// signs the external authority, and the connection this server sees carries a
// different one.
func TestAuthorityOverride(t *testing.T) {
	rt, c, config := signerFor(t)
	config.Authority = testAuthort
	config.Scheme = "https"
	auth, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	// The proxy rewrote Host to the backend's own name.
	req.Host = "10.0.0.7:6443"

	if _, ok, err := auth.AuthenticateRequest(req); !ok {
		t.Fatalf("a signature over the external authority was rejected behind a proxy: %v", err)
	}
}

func TestAuthorityMismatchIsRejected(t *testing.T) {
	rt, c, config := signerFor(t)
	auth, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	// Without an override, a rewritten authority must fail: this is what stops a
	// signature being replayed against a different API server.
	req.Host = "other.example.com"

	_, ok, err := auth.AuthenticateRequest(req)
	if ok {
		t.Fatal("a signature over a different authority was accepted")
	}
	// Covering @authority is what makes a rewritten Host fail, and it fails as a
	// signature mismatch because the base cannot be reconstructed.
	if !errors.Is(err, httpsig.ErrSignatureMismatch) {
		t.Errorf("want a signature mismatch, got %v", err)
	}
}

func TestHMACKeyFromSecretFile(t *testing.T) {
	secret := "correct-horse-battery-staple"
	secretFile := filepath.Join(t.TempDir(), "secret")
	// Written with a trailing newline, which is what an editor leaves behind.
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	auth, err := New(&apiserver.HTTPSignatureAuthenticator{
		Keys: []apiserver.HTTPSignatureKey{{
			KeyID:      "AKIAEXAMPLE",
			Algorithm:  string(httpsig.HMACSHA256),
			SecretFile: secretFile,
			User:       apiserver.HTTPSignatureUser{Username: testUser},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// The client side takes the rotating half of the credential from a file that
	// something else maintains, which is what lets a long-lived client survive
	// credential rotation.
	credFile := filepath.Join(t.TempDir(), "credential.yaml")
	credDoc := fmt.Sprintf(`{"apiVersion":%q,"kind":%q,"keyID":"AKIAEXAMPLE","secret":%q}`,
		transporthttpsig.SigningCredentialAPIVersion, transporthttpsig.SigningCredentialKind, secret)
	if err := os.WriteFile(credFile, []byte(credDoc), 0600); err != nil {
		t.Fatal(err)
	}
	c := &capture{}
	rt, err := transporthttpsig.NewRoundTripper(transporthttpsig.Config{
		Algorithm:      string(httpsig.HMACSHA256),
		CredentialFile: credFile,
	}, c)
	if err != nil {
		t.Fatal(err)
	}
	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)

	resp, ok, err := auth.AuthenticateRequest(req)
	if !ok {
		t.Fatalf("an hmac signed request was rejected: %v", err)
	}
	if resp.User.GetName() != testUser {
		t.Errorf("username: got %q, want %q", resp.User.GetName(), testUser)
	}
}

func TestNewErrors(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	validUser := apiserver.HTTPSignatureUser{Username: testUser}

	for _, tc := range []struct {
		name string
		keys []apiserver.HTTPSignatureKey
		want string
	}{{
		name: "duplicate keyID",
		keys: []apiserver.HTTPSignatureKey{
			{KeyID: "k", Algorithm: string(httpsig.Ed25519), PublicKey: pubPEM, User: validUser},
			{KeyID: "k", Algorithm: string(httpsig.Ed25519), PublicKey: pubPEM, User: validUser},
		},
		want: "duplicate keyID",
	}, {
		name: "asymmetric algorithm with a secret file",
		keys: []apiserver.HTTPSignatureKey{{KeyID: "k", Algorithm: string(httpsig.Ed25519), SecretFile: "/dev/null", User: validUser}},
		want: "uses a public key, not secretFile",
	}, {
		name: "hmac with a public key",
		keys: []apiserver.HTTPSignatureKey{{KeyID: "k", Algorithm: string(httpsig.HMACSHA256), PublicKey: pubPEM, User: validUser}},
		want: "uses a shared secret, not publicKey",
	}, {
		name: "unreadable secret file",
		keys: []apiserver.HTTPSignatureKey{{KeyID: "k", Algorithm: string(httpsig.HMACSHA256), SecretFile: "/nonexistent/secret", User: validUser}},
		want: "reading secretFile",
	}, {
		name: "malformed public key",
		keys: []apiserver.HTTPSignatureKey{{KeyID: "k", Algorithm: string(httpsig.Ed25519), PublicKey: "not pem", User: validUser}},
		want: "no PEM block",
	}, {
		name: "unknown algorithm",
		keys: []apiserver.HTTPSignatureKey{{KeyID: "k", Algorithm: "ed448", PublicKey: pubPEM, User: validUser}},
		want: "ed448",
	}, {
		name: "no algorithm",
		keys: []apiserver.HTTPSignatureKey{{KeyID: "k", PublicKey: pubPEM, User: validUser}},
		want: "algorithm is required",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(&apiserver.HTTPSignatureAuthenticator{Keys: tc.keys})
			if err == nil {
				t.Fatalf("want an error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// ladderDoc scopes a key by day, cell, and purpose. The step names are this
// test's own choice: nothing in the implementation treats any name, prefix, or
// literal as special. The published SigV4 vector, which uses this same
// mechanism with different names, is verified in
// k8s.io/client-go/transport/httpsig.
// testLadder is the ladder these tests derive through, stated as the server
// states it. Step names are arbitrary labels, so these are neutral deployment
// dimensions rather than any provider's.
func testLadder() *apiserver.HTTPSignatureKeyDerivation {
	return &apiserver.HTTPSignatureKeyDerivation{
		Kind:         "hmac-ladder",
		Hash:         "sha-256",
		SecretPrefix: "K8SDEMO1",
		Steps: []apiserver.HTTPSignatureKeyDerivationStep{
			{Name: "day", Date: "YYYYMMDD"},
			{Name: "cell", Scope: true},
			{Name: "purpose", Scope: true},
			{Name: "terminator", Literal: "k8sdemo1_request"},
		},
	}
}

// clientLadder is the same ladder as a client states it. The two API groups
// declare their own types, and the digests agreeing is what says they mean the
// same thing.
func clientLadder(t *testing.T, ladder *apiserver.HTTPSignatureKeyDerivation) *keyscope.Derivation {
	t.Helper()
	converted, _, err := transporthttpsig.DerivationFrom(ladder)
	if err != nil {
		t.Fatal(err)
	}
	return &converted
}

// deriveRung is the broker's half: fold the ladder down to the service step
// and hand the rung out, using the library's own hand-off operation.
func deriveRung(t *testing.T, secret string, at time.Time) ([]byte, *transporthttpsig.Stage) {
	t.Helper()
	root, err := keyscope.New(*clientLadder(t, testLadder()), keyscope.Stage{
		Name:  testKeyID,
		Scope: map[string]string{"cell": "cell-a", "purpose": "apiserver"},
	}, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	material, stage, err := root.Derive("purpose", at)
	if err != nil {
		t.Fatal(err)
	}
	return material, &transporthttpsig.Stage{From: stage.From, Scope: stage.Scope}
}

// derivedClient builds a signing round tripper whose credential is either the
// root secret or a rung, per stage.
func derivedClient(t *testing.T, ladder *apiserver.HTTPSignatureKeyDerivation, cred transporthttpsig.Material) (http.RoundTripper, *capture) {
	t.Helper()
	data, err := json.Marshal(transporthttpsig.SigningCredential{
		APIVersion: transporthttpsig.SigningCredentialAPIVersion,
		Kind:       transporthttpsig.SigningCredentialKind,
		Material:   cred,
	})
	if err != nil {
		t.Fatal(err)
	}
	credFile := filepath.Join(t.TempDir(), "credential.yaml")
	if err := os.WriteFile(credFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	c := &capture{}
	rt, err := transporthttpsig.NewRoundTripper(transporthttpsig.Config{
		Algorithm:      string(httpsig.HMACSHA256),
		CredentialFile: credFile,
		KeyDerivation:  clientLadder(t, ladder),
	}, c)
	if err != nil {
		t.Fatalf("building a derived-signing client: %v", err)
	}
	return rt, c
}

// TestDerivedKeyVerification covers every pairing of root and rung across the
// two sides. The equivalence invariant says they all verify: any stage of the
// same ladder with the same values produces the same signing key.
func TestDerivedKeyVerification(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	now := time.Now()
	dir := t.TempDir()

	rung, rungStage := deriveRung(t, secret, now)
	rootFile := filepath.Join(dir, "root.secret")
	if err := os.WriteFile(rootFile, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rungFile := filepath.Join(dir, "rung.secret")
	if err := os.WriteFile(rungFile, []byte(base64.StdEncoding.EncodeToString(rung)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	rootScope := map[string]string{"cell": "cell-a", "purpose": "apiserver"}

	rootCred := transporthttpsig.Material{
		KeyID:  testKeyID,
		Secret: secret,
		Stage:  &transporthttpsig.Stage{Scope: rootScope},
	}
	rungCred := transporthttpsig.Material{
		KeyID:        testKeyID,
		SecretBase64: base64.StdEncoding.EncodeToString(rung),
		Stage:        rungStage,
	}

	rootKey := apiserver.HTTPSignatureKey{
		KeyID:      testKeyID,
		Algorithm:  string(httpsig.HMACSHA256),
		SecretFile: rootFile,
		Stage:      &apiserver.HTTPSignatureKeyStage{Scope: rootScope},
		User:       apiserver.HTTPSignatureUser{Username: testUser},
	}
	rungKey := apiserver.HTTPSignatureKey{
		KeyID:      testKeyID,
		Algorithm:  string(httpsig.HMACSHA256),
		SecretFile: rungFile,
		Stage:      &apiserver.HTTPSignatureKeyStage{From: rungStage.From, Scope: rungStage.Scope},
		User:       apiserver.HTTPSignatureUser{Username: testUser},
	}

	for _, tc := range []struct {
		name   string
		client transporthttpsig.Material
		server apiserver.HTTPSignatureKey
	}{
		{name: "root at client, root at server", client: rootCred, server: rootKey},
		{name: "rung at client, root at server", client: rungCred, server: rootKey},
		{name: "root at client, rung at server", client: rootCred, server: rungKey},
		{name: "rung at client, rung at server", client: rungCred, server: rungKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth, err := New(&apiserver.HTTPSignatureAuthenticator{
				KeyDerivation: testLadder(),
				Keys:          []apiserver.HTTPSignatureKey{tc.server},
			})
			if err != nil {
				t.Fatalf("building the authenticator: %v", err)
			}
			rt, c := derivedClient(t, testLadder(), tc.client)
			req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
			resp, ok, err := auth.AuthenticateRequest(req)
			if !ok {
				t.Fatalf("a derived signature was rejected: %v", err)
			}
			if resp.User.GetName() != testUser {
				t.Errorf("username: got %q, want %q", resp.User.GetName(), testUser)
			}
		})
	}
}

// TestDerivedKeyWrongScopeFails is the domain separation property observed at
// the verifier: a signature derived for one scope does not verify under
// another, even though both sides hold the same root secret.
func TestDerivedKeyWrongScopeFails(t *testing.T) {
	secret := "root-secret"
	dir := t.TempDir()
	rootFile := filepath.Join(dir, "root.secret")
	if err := os.WriteFile(rootFile, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}

	auth, err := New(&apiserver.HTTPSignatureAuthenticator{
		KeyDerivation: testLadder(),
		Keys: []apiserver.HTTPSignatureKey{{
			KeyID:      testKeyID,
			Algorithm:  string(httpsig.HMACSHA256),
			SecretFile: rootFile,
			Stage: &apiserver.HTTPSignatureKeyStage{Scope: map[string]string{
				"cell": "cell-a", "purpose": "apiserver",
			}},
			User: apiserver.HTTPSignatureUser{Username: testUser},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	// The client derives for a different region.
	rt, c := derivedClient(t, testLadder(), transporthttpsig.Material{
		KeyID:  testKeyID,
		Secret: secret,
		Stage: &transporthttpsig.Stage{Scope: map[string]string{
			"cell": "cell-b", "purpose": "apiserver",
		}},
	})
	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	_, ok, err := auth.AuthenticateRequest(req)
	if ok {
		t.Fatal("a signature derived for cell-b verified under the cell-a scope; domain separation is not holding")
	}
	// The diagnosability the scoped keyid exists for: the rejection names the
	// step that disagreed. Without it this failure is a bare signature
	// mismatch, indistinguishable from tampering or a drifted ladder, and the
	// operator has nothing to go on.
	if err == nil {
		t.Fatal("want an error")
	}
	if !errors.Is(err, keyscope.ErrScopeMismatch) {
		t.Errorf("want a scope mismatch, got %v", err)
	}
	var scopeErr *keyscope.ScopeError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("want a *keyscope.ScopeError, got %T: %v", err, err)
	}
	if scopeErr.Step != "cell" {
		t.Errorf("scope error names step %q, want cell", scopeErr.Step)
	}
	if scopeErr.Claimed != "cell-b" {
		t.Errorf("scope error claims %q, want cell-b", scopeErr.Claimed)
	}
	// The peer-facing message says what the peer already knows and not what the
	// server is configured for.
	if strings.Contains(err.Error(), "cell-a") {
		t.Errorf("the error text discloses the server's own scope: %v", err)
	}
	if scopeErr.Expected() != "cell-a" {
		t.Errorf("Expected() is %q, want cell-a available for logs", scopeErr.Expected())
	}
}

// TestDateScopedServerRungExpiresDaily records a limitation rather than a
// feature, because the argument for letting an API server hold a rung instead of
// the root rests on it.
//
// A rung asserted to one UTC day verifies signatures created on that day and
// nothing else. The configuration cannot hold both today's and tomorrow's rung
// for the same key, because two entries with one keyID are rejected, and the
// section is read once at startup. So a date-scoped server rung is unusable
// without an overlap mechanism: it fails every request from the moment the day
// rolls until the process restarts with fresh material.
//
// A rung scoped by cluster or service and not by date has no such cliff, which
// is the form of the blast-radius argument that holds today.
func TestDateScopedServerRungExpiresDaily(t *testing.T) {
	dir := t.TempDir()
	secret := "a-root-secret"
	today := time.Now().UTC()
	tomorrow := today.Add(24 * time.Hour)

	material, stage := deriveRung(t, secret, today)
	rungFile := filepath.Join(dir, "rung.secret")
	if err := os.WriteFile(rungFile, []byte(base64.StdEncoding.EncodeToString(material)), 0600); err != nil {
		t.Fatal(err)
	}
	serverKey := apiserver.HTTPSignatureKey{
		KeyID:      testKeyID,
		Algorithm:  string(httpsig.HMACSHA256),
		SecretFile: rungFile,
		Stage:      &apiserver.HTTPSignatureKeyStage{From: stage.From, Scope: stage.Scope},
		User:       apiserver.HTTPSignatureUser{Username: testUser},
	}

	auth, err := New(&apiserver.HTTPSignatureAuthenticator{
		KeyDerivation: testLadder(),
		Keys:          []apiserver.HTTPSignatureKey{serverKey},
		MaxAge:        &metav1.Duration{Duration: 48 * time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Today: the rung verifies.
	rt, c := derivedClient(t, testLadder(), transporthttpsig.Material{
		KeyID:  testKeyID,
		Secret: secret,
		Stage: &transporthttpsig.Stage{Scope: map[string]string{
			"cell": "cell-a", "purpose": "apiserver",
		}},
	})
	if _, ok, err := auth.AuthenticateRequest(signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)); !ok {
		t.Fatalf("a same-day rung failed: %v", err)
	}

	// Tomorrow: the same server key rejects a signature the client derived
	// correctly for that day. MaxAge is 48h here, so the age policy is not what
	// refuses it; the rung's own date assertion is.
	clientKey, err := keyscope.New(*clientLadder(t, testLadder()), keyscope.Stage{
		Name:  testKeyID,
		Scope: map[string]string{"cell": "cell-a", "purpose": "apiserver"},
	}, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := clientKey.Signer(tomorrow)
	if err != nil {
		t.Fatal(err)
	}
	keyid, err := clientKey.KeyID(tomorrow)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := httpsig.Sign(req, signer, httpsig.SignOptions{
		Components: transporthttpsig.FloorComponents,
		KeyID:      keyid,
		Nonce:      "tomorrow-nonce",
		Created:    tomorrow,
		IncludeAlg: true,
	}); err != nil {
		t.Fatal(err)
	}
	_, ok, err := auth.AuthenticateRequest(asServerRequest(req))
	if ok {
		t.Fatal("a date-scoped server rung verified a signature from another day; the limitation this test records has changed")
	}
	// At least the failure is diagnosable: it names the date step rather than
	// reporting a signature mismatch.
	var scopeErr *keyscope.ScopeError
	if !errors.As(err, &scopeErr) {
		t.Fatalf("want a scope error naming the date step, got %T: %v", err, err)
	}
	if scopeErr.Step != "day" {
		t.Errorf("scope error names step %q, want day", scopeErr.Step)
	}

	// And the configuration cannot express both days, which is what makes the
	// cliff unavoidable rather than merely awkward.
	tomorrowMaterial, tomorrowStage := deriveRung(t, secret, tomorrow)
	tomorrowFile := filepath.Join(dir, "rung-tomorrow.secret")
	if err := os.WriteFile(tomorrowFile, []byte(base64.StdEncoding.EncodeToString(tomorrowMaterial)), 0600); err != nil {
		t.Fatal(err)
	}
	second := serverKey
	second.SecretFile = tomorrowFile
	second.Stage = &apiserver.HTTPSignatureKeyStage{From: tomorrowStage.From, Scope: tomorrowStage.Scope}
	_, err = New(&apiserver.HTTPSignatureAuthenticator{
		KeyDerivation: testLadder(),
		Keys:          []apiserver.HTTPSignatureKey{serverKey, second},
	})
	if err == nil {
		t.Fatal("two rungs for one keyID were accepted; an overlap window may now be expressible")
	}
	if !strings.Contains(err.Error(), "duplicate keyID") {
		t.Errorf("want a duplicate keyID error, got %v", err)
	}
}

// TestLadderShapeIsArbitrary is the evidence for a claim the design makes and
// Kubernetes policy requires: the derivation mechanism is not built for any
// particular provider's scheme. Nothing treats a step name, a secret prefix, or
// a literal as meaningful, and a ladder need not resemble the one this mechanism
// was modeled on.
//
// The ladders below share no step name, no prefix, no step count, and no
// terminator convention with SigV4 or with each other. Each has to work end to
// end, client to verifier, with the claimed scope checked.
func TestLadderShapeIsArbitrary(t *testing.T) {
	step := func(name string) apiserver.HTTPSignatureKeyDerivationStep {
		return apiserver.HTTPSignatureKeyDerivationStep{Name: name, Scope: true}
	}
	literal := func(name, value string) apiserver.HTTPSignatureKeyDerivationStep {
		return apiserver.HTTPSignatureKeyDerivationStep{Name: name, Literal: value}
	}
	for _, tc := range []struct {
		name   string
		ladder *apiserver.HTTPSignatureKeyDerivation
		scope  map[string]string
		// wrong is a scope that must be rejected, and the step that must be named.
		wrong     map[string]string
		wrongStep string
	}{{
		name: "one literal step, no prefix, no scope, no date",
		ladder: &apiserver.HTTPSignatureKeyDerivation{
			Kind: "hmac-ladder", Hash: "sha-256",
			Steps: []apiserver.HTTPSignatureKeyDerivationStep{
				literal("binding", "kubernetes-api"),
			},
		},
	}, {
		name: "single scope dimension named nothing like a cloud",
		ladder: &apiserver.HTTPSignatureKeyDerivation{
			Kind: "hmac-ladder", Hash: "sha-512", SecretPrefix: "ZZZ",
			Steps: []apiserver.HTTPSignatureKeyDerivationStep{
				step("tenant"),
			},
		},
		scope:     map[string]string{"tenant": "tenant-7"},
		wrong:     map[string]string{"tenant": "tenant-8"},
		wrongStep: "tenant",
	}, {
		name: "six steps, a dashed date in the middle, two literals",
		ladder: &apiserver.HTTPSignatureKeyDerivation{
			Kind: "hmac-ladder", Hash: "sha-256",
			Steps: []apiserver.HTTPSignatureKeyDerivationStep{
				step("fleet"),
				{Name: "epoch", Date: "YYYY-MM-DD"},
				step("shard"),
				literal("v", "2"),
				step("workload"),
				literal("suffix", "end"),
			},
		},
		scope: map[string]string{
			"fleet": "f1", "shard": "s9", "workload": "controller",
		},
		wrong: map[string]string{
			"fleet": "f1", "shard": "s9", "workload": "kubelet",
		},
		wrongStep: "workload",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			secret := "shared-root-secret"
			secretFile := filepath.Join(dir, "root.secret")
			if err := os.WriteFile(secretFile, []byte(secret), 0600); err != nil {
				t.Fatal(err)
			}
			auth, err := New(&apiserver.HTTPSignatureAuthenticator{
				KeyDerivation: tc.ladder,
				Keys: []apiserver.HTTPSignatureKey{{
					KeyID:      testKeyID,
					Algorithm:  string(httpsig.HMACSHA256),
					SecretFile: secretFile,
					Stage:      &apiserver.HTTPSignatureKeyStage{Scope: tc.scope},
					User:       apiserver.HTTPSignatureUser{Username: testUser},
				}},
			})
			if err != nil {
				t.Fatalf("building the authenticator: %v", err)
			}

			rt, c := derivedClient(t, tc.ladder, transporthttpsig.Material{
				KeyID:  testKeyID,
				Secret: secret,
				Stage:  &transporthttpsig.Stage{Scope: tc.scope},
			})
			resp, ok, err := auth.AuthenticateRequest(
				signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil))
			if !ok {
				t.Fatalf("a signature derived through this ladder was rejected: %v", err)
			}
			if resp.User.GetName() != testUser {
				t.Errorf("username: got %q, want %q", resp.User.GetName(), testUser)
			}

			if tc.wrong == nil {
				return
			}
			// A different scope on the same ladder must not verify, and the
			// error must name the step that disagreed.
			wrongRT, wrongC := derivedClient(t, tc.ladder, transporthttpsig.Material{
				KeyID:  testKeyID,
				Secret: secret,
				Stage:  &transporthttpsig.Stage{Scope: tc.wrong},
			})
			_, ok, err = auth.AuthenticateRequest(
				signedRequest(t, wrongRT, wrongC, "GET", "https://"+testAuthort+"/api/v1/pods", nil))
			if ok {
				t.Fatal("a signature derived for a different scope verified")
			}
			var scopeErr *keyscope.ScopeError
			if !errors.As(err, &scopeErr) {
				t.Fatalf("want a scope error, got %T: %v", err, err)
			}
			if scopeErr.Step != tc.wrongStep {
				t.Errorf("scope error names step %q, want %q", scopeErr.Step, tc.wrongStep)
			}
		})
	}
}
