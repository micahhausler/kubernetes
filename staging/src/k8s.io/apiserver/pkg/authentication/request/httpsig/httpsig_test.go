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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig/keyscope"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	nettesting "k8s.io/apimachinery/pkg/util/net/testing"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/request/httpsig/metrics"
	resolvertesting "k8s.io/apiserver/pkg/authentication/request/httpsig/testing"
	transporthttpsig "k8s.io/client-go/transport/httpsig"
	externalhttpsig "k8s.io/externalhttpsig/apis/v1alpha1"
)

const (
	// testDialTimeout bounds the first metadata call in tests. Short because a test
	// resolver is listening before the authenticator is built, so anything longer
	// only slows a failure down.
	testDialTimeout = 10 * time.Second

	testKeyID   = "alice-key"
	testUser    = "alice"
	testGroup   = "signers"
	testAuthort = "api.example.com"
)

// newResolver starts a resolver on a socket unique to this test.
func newTestResolver(t *testing.T, name string) *resolvertesting.Resolver {
	t.Helper()
	socket := nettesting.MakeSocketNameForTest(t, fmt.Sprintf("httpsig-%s-%d.sock", name, time.Now().UnixNano()))
	return resolvertesting.New(t, socket)
}

// authenticatorFor builds an Authenticator over the given resolvers, and tears
// down its connections when the test ends.
func authenticatorFor(t *testing.T, configs ...apiserver.HTTPSignatureAuthenticator) *Authenticator {
	t.Helper()
	a, err := newAuthenticator(t, signatureConfig(configs...))
	if err != nil {
		t.Fatalf("building the authenticator: %v", err)
	}
	return a
}

// authenticatorWithSkew builds an Authenticator with a clock skew allowance, which
// is a property of the section rather than of one authenticator.
func authenticatorWithSkew(t *testing.T, config apiserver.HTTPSignatureAuthenticator, skew *metav1.Duration) *Authenticator {
	t.Helper()
	c := signatureConfig(config)
	c.MaxClockSkew = skew
	a, err := newAuthenticator(t, c)
	if err != nil {
		t.Fatalf("building the authenticator: %v", err)
	}
	return a
}

// newAuthenticator builds an Authenticator and returns the error, for the cases
// that are about construction failing.
func newAuthenticator(t *testing.T, config *apiserver.HTTPSignatureConfig) (*Authenticator, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return New(ctx, config, nil, "test-apiserver", testDialTimeout)
}

// signatureConfig wraps authenticators in an HTTPSignatureConfig, naming any the
// caller did not name. Most tests are about one resolver's behaviour and have no
// reason to state a name.
func signatureConfig(as ...apiserver.HTTPSignatureAuthenticator) *apiserver.HTTPSignatureConfig {
	for i := range as {
		if as[i].Name == "" {
			as[i].Name = fmt.Sprintf("resolver-%d", i)
		}
	}
	return &apiserver.HTTPSignatureConfig{Authenticators: as}
}

// ed25519Client returns a signing round tripper and the PKIX public key a
// resolver would answer with.
func ed25519Client(t *testing.T, keyID string) (http.RoundTripper, *capture, []byte) {
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
	c := &capture{}
	rt, err := transporthttpsig.NewRoundTripper(transporthttpsig.Config{
		Algorithm: string(httpsig.Ed25519),
		KeyID:     keyID,
		KeyFile:   keyFile,
	}, c)
	if err != nil {
		t.Fatal(err)
	}
	return rt, c, pubDER
}

// ed25519Answer is the response a resolver gives for an ed25519 key.
func ed25519Answer(pubDER []byte, username string) *externalhttpsig.ResolveKeyResponse {
	return &externalhttpsig.ResolveKeyResponse{
		Algorithm:       string(httpsig.Ed25519),
		Material:        &externalhttpsig.ResolveKeyResponse_PublicKey{PublicKey: pubDER},
		User:            &externalhttpsig.UserInfo{Username: username, Uid: "uid-1", Groups: []string{testGroup}},
		CacheTtlSeconds: 300,
	}
}

// signerFor wires the common case: one resolver serving one ed25519 key.
func signerFor(t *testing.T) (http.RoundTripper, *capture, *resolvertesting.Resolver, apiserver.HTTPSignatureAuthenticator) {
	t.Helper()
	rt, c, pubDER := ed25519Client(t, testKeyID)
	r := newTestResolver(t, "keys")
	r.SetKey(testKeyID, ed25519Answer(pubDER, testUser))
	return rt, c, r, apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}}
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
	rt, c, r, config := signerFor(t)
	a := authenticatorFor(t, config)

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods?limit=1", nil)
	resp, ok, err := a.AuthenticateRequest(req)
	if err != nil || !ok {
		t.Fatalf("AuthenticateRequest: ok=%v err=%v", ok, err)
	}
	if got := resp.User.GetName(); got != testUser {
		t.Errorf("username: got %q, want %q", got, testUser)
	}
	if got := resp.User.GetUID(); got != "uid-1" {
		t.Errorf("uid: got %q, want %q", got, "uid-1")
	}
	if got := resp.User.GetGroups(); len(got) != 1 || got[0] != testGroup {
		t.Errorf("groups: got %v, want [%s]", got, testGroup)
	}

	// The signature fields are cleared so nothing downstream reads them as a
	// credential.
	if len(req.Header.Values("Signature")) != 0 || len(req.Header.Values("Signature-Input")) != 0 {
		t.Errorf("signature fields survived authentication: %v", req.Header)
	}

	resolveCalls, nonceCalls, _ := r.Counts()
	if resolveCalls != 1 {
		t.Errorf("ResolveKey calls: got %d, want 1", resolveCalls)
	}
	if nonceCalls != 1 {
		t.Errorf("ConsumeNonce calls: got %d, want 1", nonceCalls)
	}
}

func TestNoOpinionWithoutSignature(t *testing.T) {
	_, _, _, config := signerFor(t)
	a := authenticatorFor(t, config)

	req, err := http.NewRequest("GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, ok, err := a.AuthenticateRequest(req)
	if resp != nil || ok || err != nil {
		t.Fatalf("a request with no signature should draw no opinion: resp=%v ok=%v err=%v", resp, ok, err)
	}
}

// ed25519KeyPair returns a PEM private key and the matching PKIX public key.
func ed25519KeyPair(t *testing.T) (privPEM string, pubDER []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})), pubDER
}

// relayClient builds a signing client that covers one extra header and carries a
// value for it, which is what makes the value relayable.
func relayClient(t *testing.T, privPEM, keyID, header, value string) (http.RoundTripper, *capture) {
	t.Helper()
	c := &capture{}
	rt, err := transporthttpsig.NewRoundTripper(transporthttpsig.Config{
		Algorithm: string(httpsig.Ed25519),
		Credential: &transporthttpsig.Material{
			KeyID:         keyID,
			PrivateKey:    privPEM,
			SignedHeaders: map[string]string{header: value},
		},
		SignedHeaders: []transporthttpsig.Header{{Name: header}},
	}, c)
	if err != nil {
		t.Fatal(err)
	}
	return rt, c
}

// TestRelayedHeaderIsSent asserts a covered value reaches the resolver and nothing
// else about the request does.
func TestRelayedHeaderIsSent(t *testing.T) {
	privPEM, pubDER := ed25519KeyPair(t)
	rt, c := relayClient(t, privPEM, testKeyID, "X-Session-Token", "session-value")
	r := newTestResolver(t, "relay")
	r.SetKey(testKeyID, ed25519Answer(pubDER, testUser))
	a := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{
		Resolver: &apiserver.HTTPSignatureResolver{
			Endpoint:       r.Endpoint(),
			RelayedHeaders: []string{"X-Session-Token"},
		},
	})

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
		t.Fatalf("AuthenticateRequest: ok=%v err=%v", ok, err)
	}

	resolve, _ := r.LastRequests()
	if got := resolve.GetRelayedHeaders()["x-session-token"]; got != "session-value" {
		t.Errorf("relayed value: got %q, want %q", got, "session-value")
	}
	if len(resolve.GetRelayedHeaders()) != 1 {
		t.Errorf("only the configured header should be relayed, got %v", resolve.GetRelayedHeaders())
	}
}

// TestRelayedHeaderRotationBustsTheCache is why the cache key covers the relayed
// values and not the key ID alone. Both clients hold the same signing key and the
// same key ID, and differ only in the token they cover, so an entry keyed on the key
// ID would answer the second from cache and the rotation would be ignored.
func TestRelayedHeaderRotationBustsTheCache(t *testing.T) {
	privPEM, pubDER := ed25519KeyPair(t)
	first, c1 := relayClient(t, privPEM, testKeyID, "X-Session-Token", "first-value")
	second, c2 := relayClient(t, privPEM, testKeyID, "X-Session-Token", "second-value")

	r := newTestResolver(t, "rotate")
	r.SetKey(testKeyID, ed25519Answer(pubDER, testUser))
	a := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{
		Resolver: &apiserver.HTTPSignatureResolver{
			Endpoint:       r.Endpoint(),
			RelayedHeaders: []string{"X-Session-Token"},
		},
	})

	req := signedRequest(t, first, c1, "GET", "https://"+testAuthort+"/api/v1/pods?n=1", nil)
	if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
		t.Fatalf("first request: ok=%v err=%v", ok, err)
	}
	req = signedRequest(t, first, c1, "GET", "https://"+testAuthort+"/api/v1/pods?n=2", nil)
	if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
		t.Fatalf("second request with the same token: ok=%v err=%v", ok, err)
	}
	if calls, _, _ := r.Counts(); calls != 1 {
		t.Fatalf("ResolveKey calls with an unchanged token: got %d, want 1", calls)
	}

	req = signedRequest(t, second, c2, "GET", "https://"+testAuthort+"/api/v1/pods?n=3", nil)
	if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
		t.Fatalf("request with a rotated token: ok=%v err=%v", ok, err)
	}
	if calls, _, _ := r.Counts(); calls != 2 {
		t.Errorf("a rotated relayed value should reach the resolver: ResolveKey calls got %d, want 2", calls)
	}
	resolve, _ := r.LastRequests()
	if got := resolve.GetRelayedHeaders()["x-session-token"]; got != "second-value" {
		t.Errorf("relayed value after rotation: got %q, want %q", got, "second-value")
	}
}

// TestRelayedHeaderMustBeCovered is the injection defense: a value an intermediary
// could have set must not select a key.
func TestRelayedHeaderMustBeCovered(t *testing.T) {
	rt, c, r, config := signerFor(t)
	config.Resolver.RelayedHeaders = []string{"X-Session-Token"}
	a := authenticatorFor(t, config)

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	req.Header.Set("X-Session-Token", "injected")
	_, ok, err := a.AuthenticateRequest(req)
	if ok {
		t.Fatal("an uncovered relayed header was accepted")
	}
	if err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Errorf("error should name the coverage failure, got: %v", err)
	}
	if calls, _, _ := r.Counts(); calls != 0 {
		t.Errorf("the resolver was called %d times for a request rejected before lookup", calls)
	}
}

// TestRelayedHeaderRepeatedIsRefused covers the ambiguity: two values for one
// relayed header have no correct combination, so neither is invented.
func TestRelayedHeaderRepeatedIsRefused(t *testing.T) {
	rt, c, r, config := signerFor(t)
	config.Resolver.RelayedHeaders = []string{"X-Session-Token"}
	a := authenticatorFor(t, config)

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	req.Header.Add("X-Session-Token", "one")
	req.Header.Add("X-Session-Token", "two")
	_, _, err := a.AuthenticateRequest(req)
	if err == nil || !strings.Contains(err.Error(), "no correct way to combine") {
		t.Fatalf("expected a repeated relayed header to be refused, got: %v", err)
	}
	if calls, _, _ := r.Counts(); calls != 0 {
		t.Errorf("the resolver was called %d times for a request rejected before lookup", calls)
	}
}

// TestUnknownKeyIDFallsThrough covers ordered resolution: the first resolver says
// it does not serve the key ID and the second one answers.
func TestUnknownKeyIDFallsThrough(t *testing.T) {
	rt, c, pubDER := ed25519Client(t, testKeyID)
	first := newTestResolver(t, "first")
	second := newTestResolver(t, "second")
	second.SetKey(testKeyID, ed25519Answer(pubDER, testUser))

	a := authenticatorFor(t,
		apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: first.Endpoint()}},
		apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: second.Endpoint()}},
	)

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
		t.Fatalf("AuthenticateRequest: ok=%v err=%v", ok, err)
	}
	if calls, _, _ := first.Counts(); calls != 1 {
		t.Errorf("first resolver ResolveKey calls: got %d, want 1", calls)
	}
	if calls, _, _ := second.Counts(); calls != 1 {
		t.Errorf("second resolver ResolveKey calls: got %d, want 1", calls)
	}
}

// TestKeyIDPrefixesSkipResolver is the point of the prefix selector: a resolver
// whose prefixes do not admit a key ID is never called.
func TestKeyIDPrefixesSkipResolver(t *testing.T) {
	rt, c, pubDER := ed25519Client(t, testKeyID)
	other := newTestResolver(t, "other")
	mine := newTestResolver(t, "mine")
	mine.SetKey(testKeyID, ed25519Answer(pubDER, testUser))

	a := authenticatorFor(t,
		apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: other.Endpoint(), KeyIDPrefixes: []string{"bob-key"}}},
		apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: mine.Endpoint(), KeyIDPrefixes: []string{testKeyID}}},
	)

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
		t.Fatalf("AuthenticateRequest: ok=%v err=%v", ok, err)
	}
	if calls, _, _ := other.Counts(); calls != 0 {
		t.Errorf("a resolver whose prefixes exclude the keyID was called %d times", calls)
	}
}

// TestKeyCaching asserts a second request reuses the resolved key, and that a
// resolver stating a zero cache duration is obeyed rather than given a floor.
func TestKeyCaching(t *testing.T) {
	for _, tc := range []struct {
		name         string
		cacheTTL     int64
		wantResolves int
	}{
		{name: "cached", cacheTTL: 300, wantResolves: 1},
		{name: "resolver says do not cache", cacheTTL: 0, wantResolves: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, c, pubDER := ed25519Client(t, testKeyID)
			r := newTestResolver(t, "cache-"+tc.name)
			answer := ed25519Answer(pubDER, testUser)
			answer.CacheTtlSeconds = tc.cacheTTL
			r.SetKey(testKeyID, answer)
			a := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}})

			for i := 0; i < 3; i++ {
				req := signedRequest(t, rt, c, "GET", fmt.Sprintf("https://%s/api/v1/pods?n=%d", testAuthort, i), nil)
				if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
					t.Fatalf("request %d: ok=%v err=%v", i, ok, err)
				}
			}
			if calls, _, _ := r.Counts(); calls != tc.wantResolves {
				t.Errorf("ResolveKey calls: got %d, want %d", calls, tc.wantResolves)
			}
		})
	}
}

// TestNegativeCaching asserts an unserved key ID is remembered, so a peer that
// retries it does not cost a lookup per request.
func TestNegativeCaching(t *testing.T) {
	rt, c, _ := ed25519Client(t, testKeyID)
	r := newTestResolver(t, "negative")
	a := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{
		Resolver: &apiserver.HTTPSignatureResolver{
			Endpoint: r.Endpoint(),
			Cache:    &apiserver.HTTPSignatureResolverCache{NegativeMaxAge: &metav1.Duration{Duration: time.Minute}},
		},
	})

	for i := 0; i < 3; i++ {
		req := signedRequest(t, rt, c, "GET", fmt.Sprintf("https://%s/api/v1/pods?n=%d", testAuthort, i), nil)
		if _, ok, err := a.AuthenticateRequest(req); ok || err == nil {
			t.Fatalf("request %d should have been rejected: ok=%v err=%v", i, ok, err)
		}
	}
	if calls, _, _ := r.Counts(); calls != 1 {
		t.Errorf("ResolveKey calls for a repeated unknown keyID: got %d, want 1", calls)
	}
}

// TestResolverFailureIsNotCached is the other half: an outage must not outlive
// itself, so a failed lookup is retried rather than remembered.
func TestResolverFailureIsNotCached(t *testing.T) {
	rt, c, pubDER := ed25519Client(t, testKeyID)
	r := newTestResolver(t, "flaky")
	r.SetKey(testKeyID, ed25519Answer(pubDER, testUser))
	r.SetErrors(nil, status.Error(codes.Unavailable, "resolver is busy"), nil)

	a := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}})

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods?n=1", nil)
	if _, ok, _ := a.AuthenticateRequest(req); ok {
		t.Fatal("a request whose key could not be resolved should be rejected")
	}

	r.SetErrors(nil, nil, nil)
	req = signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods?n=2", nil)
	if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
		t.Fatalf("the same keyID should resolve once the resolver recovers: ok=%v err=%v", ok, err)
	}
}

// TestResolverFailureIsScopedToItsKeys asserts one broken resolver does not take
// authentication down for another's keys.
func TestResolverFailureIsScopedToItsKeys(t *testing.T) {
	rt, c, pubDER := ed25519Client(t, testKeyID)
	broken := newTestResolver(t, "broken")
	working := newTestResolver(t, "working")
	working.SetKey(testKeyID, ed25519Answer(pubDER, testUser))
	broken.SetErrors(nil, status.Error(codes.Internal, "resolver is broken"), nil)

	a := authenticatorFor(t,
		apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: broken.Endpoint()}},
		apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: working.Endpoint()}},
	)

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
		t.Fatalf("a working resolver should still authenticate its own keys: ok=%v err=%v", ok, err)
	}
}

// TestRejectsMalformedResolvedIdentity covers what a resolver's answer is refused
// for unconditionally: a missing username, and the three names the server asserts
// itself. These are checked at lookup time, before the signature has verified,
// because they are constant-time and a malformed answer is worth failing fast on.
//
// The "system:" prefix is deliberately not in this list. It used to be, as one
// hardcoded rule on this path while the certificate path expressed the same
// invariant as a configurable rule. See TestResolvedIdentityIsSubjectToUserRules.
func TestRejectsMalformedResolvedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		user *externalhttpsig.UserInfo
		want string
	}{
		{name: "no username", user: &externalhttpsig.UserInfo{}, want: "no username"},
		{name: "no user at all", user: nil, want: "no username"},
		{name: "empty group", user: &externalhttpsig.UserInfo{Username: testUser, Groups: []string{""}}, want: "empty group name"},
		{
			name: "anonymous username",
			user: &externalhttpsig.UserInfo{Username: "system:anonymous"},
			want: "anonymous authenticator asserts about a request that carried no credential",
		},
		{
			name: "authenticated group",
			user: &externalhttpsig.UserInfo{Username: testUser, Groups: []string{"system:authenticated"}},
			want: "the server adds according to whether authentication succeeded",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, c, pubDER := ed25519Client(t, testKeyID)
			r := newTestResolver(t, "identity")
			answer := ed25519Answer(pubDER, testUser)
			answer.User = tc.user
			r.SetKey(testKeyID, answer)
			a := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}})

			req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
			_, ok, err := a.AuthenticateRequest(req)
			if ok {
				t.Fatal("expected the request to be rejected")
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should contain %q, got: %v", tc.want, err)
			}
		})
	}
}

// TestResolvedIdentityIsSubjectToUserRules covers the change of mechanism for the
// "system:" prefix on a resolver-resolved identity.
//
// It used to be banned in Go, unconditionally, on this path only, while the
// certificate path left the same invariant to a rule an operator writes. Both paths
// now use the rule. The first case states the cost of that plainly: with no rule
// configured, a resolver may claim system:masters. The socket is the trust boundary,
// so a cluster that does not run its own resolver states the rule.
func TestResolvedIdentityIsSubjectToUserRules(t *testing.T) {
	const systemPrefixRule = `!user.username.startsWith("system:") && !user.groups.exists(g, g.startsWith("system:"))`

	for _, tc := range []struct {
		name    string
		user    *externalhttpsig.UserInfo
		rules   []apiserver.UserValidationRule
		wantOK  bool
		wantErr string
	}{{
		name:   "no rule configured admits a system: name",
		user:   &externalhttpsig.UserInfo{Username: "system:masters-user"},
		wantOK: true,
	}, {
		name:    "the prefix rule refuses a system: username",
		user:    &externalhttpsig.UserInfo{Username: "system:masters-user"},
		rules:   []apiserver.UserValidationRule{{Expression: systemPrefixRule, Message: "no system: identities here"}},
		wantErr: "no system: identities here",
	}, {
		name:    "the prefix rule refuses a system: group",
		user:    &externalhttpsig.UserInfo{Username: testUser, Groups: []string{"system:masters"}},
		rules:   []apiserver.UserValidationRule{{Expression: systemPrefixRule, Message: "no system: identities here"}},
		wantErr: "no system: identities here",
	}, {
		name:   "the prefix rule admits an ordinary identity",
		user:   &externalhttpsig.UserInfo{Username: testUser, Groups: []string{"builders"}},
		rules:  []apiserver.UserValidationRule{{Expression: systemPrefixRule}},
		wantOK: true,
	}, {
		name:    "a rule may constrain anything about the identity",
		user:    &externalhttpsig.UserInfo{Username: "outsider"},
		rules:   []apiserver.UserValidationRule{{Expression: `user.username.endsWith("@example.com")`}},
		wantErr: "returned false",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			rt, c, pubDER := ed25519Client(t, testKeyID)
			r := newTestResolver(t, "identity")
			answer := ed25519Answer(pubDER, testUser)
			answer.User = tc.user
			r.SetKey(testKeyID, answer)
			a := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{
				Resolver:            &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()},
				UserValidationRules: tc.rules,
			})

			req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
			resp, ok, err := a.AuthenticateRequest(req)
			switch {
			case tc.wantOK && (!ok || err != nil):
				t.Fatalf("expected the request to be authenticated: ok=%v err=%v", ok, err)
			case tc.wantOK:
				if got := resp.User.GetName(); got != tc.user.Username {
					t.Errorf("username: got %q, want %q", got, tc.user.Username)
				}
			case ok:
				t.Fatal("expected the request to be rejected")
			case err == nil || !strings.Contains(err.Error(), tc.wantErr):
				t.Errorf("error should contain %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

// TestRejectedIdentityDoesNotConsumeNonce keeps the rules ahead of the nonce
// record. A refused request that had burned its nonce would make the same request
// fail for a different reason on a retry, which reads as a flake.
func TestRejectedIdentityDoesNotConsumeNonce(t *testing.T) {
	rt, c, pubDER := ed25519Client(t, testKeyID)
	r := newTestResolver(t, "identity")
	answer := ed25519Answer(pubDER, testUser)
	answer.User = &externalhttpsig.UserInfo{Username: "system:masters-user"}
	r.SetKey(testKeyID, answer)
	a := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{
		Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()},
		UserValidationRules: []apiserver.UserValidationRule{{
			Expression: `!user.username.startsWith("system:")`,
		}},
	})

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if _, ok, _ := a.AuthenticateRequest(req); ok {
		t.Fatal("expected the request to be rejected")
	}
	if _, nonce := r.LastRequests(); nonce != nil {
		t.Errorf("a rejected identity consumed a nonce (%q); the rules have to run first", nonce.GetNonce())
	}
}

// TestRejectsMaterialAlgorithmMismatch covers the confusion class: a resolver
// naming hmac-sha256 while handing back a public key must not have that public
// key used as a shared secret.
func TestRejectsMaterialAlgorithmMismatch(t *testing.T) {
	for _, tc := range []struct {
		name   string
		answer func(pubDER []byte) *externalhttpsig.ResolveKeyResponse
		want   string
	}{
		{
			name: "hmac algorithm with a public key",
			answer: func(pubDER []byte) *externalhttpsig.ResolveKeyResponse {
				return &externalhttpsig.ResolveKeyResponse{
					Algorithm: string(httpsig.HMACSHA256),
					Material:  &externalhttpsig.ResolveKeyResponse_PublicKey{PublicKey: pubDER},
					User:      &externalhttpsig.UserInfo{Username: testUser},
				}
			},
			want: "verifies with a shared secret",
		},
		{
			name: "asymmetric algorithm with a secret",
			answer: func([]byte) *externalhttpsig.ResolveKeyResponse {
				return &externalhttpsig.ResolveKeyResponse{
					Algorithm: string(httpsig.Ed25519),
					Material:  &externalhttpsig.ResolveKeyResponse_Secret{Secret: []byte("not a key")},
					User:      &externalhttpsig.UserInfo{Username: testUser},
				}
			},
			want: "verifies with a public key",
		},
		{
			name: "no algorithm stated",
			answer: func(pubDER []byte) *externalhttpsig.ResolveKeyResponse {
				return &externalhttpsig.ResolveKeyResponse{
					Material: &externalhttpsig.ResolveKeyResponse_PublicKey{PublicKey: pubDER},
					User:     &externalhttpsig.UserInfo{Username: testUser},
				}
			},
			want: "states no algorithm",
		},
		{
			name: "no material at all",
			answer: func([]byte) *externalhttpsig.ResolveKeyResponse {
				return &externalhttpsig.ResolveKeyResponse{
					Algorithm: string(httpsig.Ed25519),
					User:      &externalhttpsig.UserInfo{Username: testUser},
				}
			},
			want: "no key material",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, c, pubDER := ed25519Client(t, testKeyID)
			r := newTestResolver(t, "confusion")
			r.SetKey(testKeyID, tc.answer(pubDER))
			a := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}})

			req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
			_, ok, err := a.AuthenticateRequest(req)
			if ok {
				t.Fatal("expected the request to be rejected")
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should contain %q, got: %v", tc.want, err)
			}
		})
	}
}

// TestReplayIsRejected covers the whole reason nonces leave this process: the
// resolver records the nonce, so the second copy of one request is refused.
func TestReplayIsRejected(t *testing.T) {
	rt, c, r, config := signerFor(t)
	a := authenticatorFor(t, config)

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	// Copied before the first authentication, because a successful one clears the
	// signature fields so nothing downstream reads them as a credential.
	replay := replayOf(req)
	if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
		t.Fatalf("first request: ok=%v err=%v", ok, err)
	}

	// The same signed bytes again. Everything about it verifies; only the nonce
	// record makes it fail.
	_, ok, err := a.AuthenticateRequest(replay)
	if ok {
		t.Fatal("a replayed request was accepted")
	}
	if err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Errorf("error should name the nonce, got: %v", err)
	}
	if _, nonceCalls, _ := r.Counts(); nonceCalls != 2 {
		t.Errorf("ConsumeNonce calls: got %d, want 2", nonceCalls)
	}
}

// TestNonceFailureRejects covers fail-closed. A resolver that cannot record the
// nonce means the request cannot be shown not to be a replay, so it is refused.
func TestNonceFailureRejects(t *testing.T) {
	rt, c, r, config := signerFor(t)
	r.SetErrors(nil, nil, status.Error(codes.Unavailable, "nonce store is down"))
	a := authenticatorFor(t, config)

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	_, ok, err := a.AuthenticateRequest(req)
	if ok {
		t.Fatal("a request whose nonce could not be recorded was accepted")
	}
	if err == nil || !strings.Contains(err.Error(), "recording signature nonce") {
		t.Errorf("error should name the nonce call, got: %v", err)
	}
}

// TestNonceExpiryIsTheReplayWindow asserts the resolver is told when it may forget
// a nonce, and that the value is the window a signature is accepted in.
func TestNonceExpiryIsTheReplayWindow(t *testing.T) {
	rt, c, r, config := signerFor(t)
	config.MaxAge = &metav1.Duration{Duration: 2 * time.Minute}
	a := authenticatorWithSkew(t, config, &metav1.Duration{Duration: 30 * time.Second})

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
		t.Fatalf("AuthenticateRequest: ok=%v err=%v", ok, err)
	}

	_, nonce := r.LastRequests()
	if nonce == nil {
		t.Fatal("no ConsumeNonce request was made")
	}
	created := nonce.GetCreated().AsTime()
	want := created.Add(2*time.Minute + 30*time.Second)
	if got := nonce.GetExpiresAt().AsTime(); !got.Equal(want) {
		t.Errorf("nonce expiry: got %v, want created+maxAge+maxClockSkew = %v", got, want)
	}
}

// TestVerifyBeforeConsumingNonce is the ordering assertion. A caller who cannot
// produce a valid signature must not reach the resolver's nonce store, or the
// store becomes a thing an unauthenticated caller can fill.
func TestVerifyBeforeConsumingNonce(t *testing.T) {
	rt, c, r, config := signerFor(t)
	a := authenticatorFor(t, config)

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	// Tampering with the path breaks the signature base, so verification fails.
	req.URL.Path = "/api/v1/secrets"
	req.RequestURI = req.URL.RequestURI()

	if _, ok, _ := a.AuthenticateRequest(req); ok {
		t.Fatal("a tampered request was accepted")
	}
	if _, nonceCalls, _ := r.Counts(); nonceCalls != 0 {
		t.Errorf("ConsumeNonce was called %d times for a signature that did not verify", nonceCalls)
	}
}

// TestStaleSignatureIsRejectedBeforeLookup covers the other ordering rule: age is
// bounded before a key is resolved, so an ancient timestamp cannot drive a call.
func TestStaleSignatureIsRejectedBeforeLookup(t *testing.T) {
	rt, c, r, config := signerFor(t)
	config.MaxAge = &metav1.Duration{Duration: time.Nanosecond}
	a := authenticatorFor(t, config)

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	time.Sleep(2 * time.Millisecond)
	_, ok, err := a.AuthenticateRequest(req)
	if ok {
		t.Fatal("a stale signature was accepted")
	}
	if err == nil || !strings.Contains(err.Error(), "maximum age") {
		t.Errorf("error should name the age bound, got: %v", err)
	}
	if calls, _, _ := r.Counts(); calls != 0 {
		t.Errorf("the resolver was called %d times for a signature rejected on age", calls)
	}
}

// TestResolverNarrowsMaxAge asserts a resolver can tighten the accepted age and
// that the narrowed value is what the nonce expiry uses.
func TestResolverNarrowsMaxAge(t *testing.T) {
	rt, c, pubDER := ed25519Client(t, testKeyID)
	r := newTestResolver(t, "narrow")
	answer := ed25519Answer(pubDER, testUser)
	answer.MaxSignatureAgeSeconds = 1
	r.SetKey(testKeyID, answer)

	config := apiserver.HTTPSignatureAuthenticator{
		Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()},
		MaxAge:   &metav1.Duration{Duration: time.Hour},
	}
	a := authenticatorFor(t, config)

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
		t.Fatalf("a fresh signature should be accepted: ok=%v err=%v", ok, err)
	}
	_, nonce := r.LastRequests()
	want := nonce.GetCreated().AsTime().Add(time.Second)
	if got := nonce.GetExpiresAt().AsTime(); !got.Equal(want) {
		t.Errorf("nonce expiry should use the narrowed age: got %v, want %v", got, want)
	}
}

// TestRejectsSignatureMissingFloorComponents pins the first of the two rules the
// package doc calls the whole security argument: the covered component set is
// required by this verifier and never read from the signature.
//
// A signature declares what it covers. A verifier that only checked "valid for
// the components it names" would accept one covering nothing, because an attacker
// signs a component list of their own choosing with their own key.
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
			r := newTestResolver(t, "floor")
			r.SetKey(testKeyID, ed25519Answer(pubDER, testUser))
			auth := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}})

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
			// The signature is otherwise valid: made by the resolved key, with a
			// nonce and a created. So it has to be rejected for the missing
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

// TestAcceptsCoveredProtectedHeader is the positive half of the protected header
// rule. Without it, a verifier that rejected every protected header, covered or
// not, would pass the injection test while breaking impersonation entirely.
func TestAcceptsCoveredProtectedHeader(t *testing.T) {
	rt, c, _, config := signerFor(t)
	auth := authenticatorFor(t, config)
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

func stripCreated(t *testing.T, req *http.Request) *http.Request {
	t.Helper()
	input := req.Header.Get("Signature-Input")
	stripped := regexp.MustCompile(`;created=\d+`).ReplaceAllString(input, "")
	if stripped == input {
		t.Fatalf("Signature-Input carries no created parameter to remove: %q", input)
	}
	req.Header.Set("Signature-Input", stripped)
	return req
}

// TestRejectsMissingCreated pins a requirement that no single site states.
// Configuration cannot express it: maxAge is either unset and defaulted to five
// minutes, or validated as positive, and a signature with no created cannot be
// aged. The requirement therefore holds through the interaction of several places,
// and this is what fails if any of them moves.
//
// The rejection here comes from this package's own pre-lookup age check, before
// the resolver is called, which is the point: an unauthenticated caller must not
// be able to drive a network call with an unageable signature.
func TestRejectsMissingCreated(t *testing.T) {
	rt, c, r, config := signerFor(t)
	auth := authenticatorFor(t, config)
	req := stripCreated(t, signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil))

	_, ok, err := auth.AuthenticateRequest(req)
	if ok {
		t.Fatal("a signature with no created parameter was accepted, so its age could not have been bounded")
	}
	if err == nil || !strings.Contains(err.Error(), "created") {
		t.Errorf("want an error naming the missing created parameter, got %v", err)
	}
	if resolves, _, _ := r.Counts(); resolves != 0 {
		t.Errorf("the resolver was called %d times for a signature that could not be aged; the age check exists to happen first", resolves)
	}
}

func TestRejectsInjectedProtectedHeader(t *testing.T) {
	rt, c, _, config := signerFor(t)
	a := authenticatorFor(t, config)

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	// An intermediary appending impersonation to a request that carried none. The
	// signature still verifies, so only the coverage check catches it.
	req.Header.Set("Impersonate-User", "system:admin")

	_, ok, err := a.AuthenticateRequest(req)
	if ok {
		t.Fatal("an injected protected header was accepted")
	}
	if err == nil || !strings.Contains(err.Error(), "Impersonate-User") {
		t.Errorf("error should name the header, got: %v", err)
	}
}

func TestBodyDigest(t *testing.T) {
	rt, c, _, config := signerFor(t)
	a := authenticatorFor(t, config)

	req := signedRequest(t, rt, c, "POST", "https://"+testAuthort+"/api/v1/pods", strings.NewReader(`{"a":1}`))
	if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
		t.Fatalf("a signed body should be accepted: ok=%v err=%v", ok, err)
	}
	// The body is readable by the handler chain after the digest check.
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"a":1}` {
		t.Errorf("body after digest check: got %q", body)
	}

	tampered := signedRequest(t, rt, c, "POST", "https://"+testAuthort+"/api/v1/pods?n=2", strings.NewReader(`{"a":1}`))
	tampered.Body = io.NopCloser(strings.NewReader(`{"a":2}`))
	if _, ok, _ := a.AuthenticateRequest(tampered); ok {
		t.Fatal("a body that does not match its signed digest was accepted")
	}
}

func TestAuthorityOverride(t *testing.T) {
	rt, c, pubDER := ed25519Client(t, testKeyID)
	r := newTestResolver(t, "authority")
	r.SetKey(testKeyID, ed25519Answer(pubDER, testUser))

	// The client signs the external authority; the server is reached under another.
	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	req.Host = "10.0.0.1:6443"

	a, err := newAuthenticator(t, &apiserver.HTTPSignatureConfig{
		Authority:      testAuthort,
		Scheme:         "https",
		Authenticators: []apiserver.HTTPSignatureAuthenticator{{Name: "authority", Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}}},
	})
	if err != nil {
		t.Fatalf("building the authenticator: %v", err)
	}
	if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
		t.Fatalf("stating the external authority should let the signature verify: ok=%v err=%v", ok, err)
	}

	// Without the override the same request fails, which is what says the
	// authority is covered.
	plain := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}})
	again := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods?n=2", nil)
	again.Host = "10.0.0.1:6443"
	if _, ok, _ := plain.AuthenticateRequest(again); ok {
		t.Fatal("a signature over a different authority was accepted")
	}
}

func TestNewErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("nil config", func(t *testing.T) {
		if _, err := New(ctx, nil, nil, "test", testDialTimeout); err == nil {
			t.Fatal("a nil configuration should be rejected; the caller decides whether the section is absent")
		}
	})

	t.Run("no authenticators", func(t *testing.T) {
		_, err := New(ctx, &apiserver.HTTPSignatureConfig{}, nil, "test", testDialTimeout)
		if err == nil || !strings.Contains(err.Error(), "at least one authenticator is required") {
			t.Fatalf("expected an empty authenticator list to be rejected, got: %v", err)
		}
	})

	t.Run("duplicate names", func(t *testing.T) {
		r := newTestResolver(t, "dupnames")
		_, err := New(ctx, signatureConfig(
			apiserver.HTTPSignatureAuthenticator{Name: "same", Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}},
			apiserver.HTTPSignatureAuthenticator{Name: "same", Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}},
		), nil, "test", testDialTimeout)
		if err == nil || !strings.Contains(err.Error(), "duplicate name") {
			t.Fatalf("expected duplicate authenticator names to be rejected, got: %v", err)
		}
	})

	t.Run("bad endpoint", func(t *testing.T) {
		_, err := New(ctx, signatureConfig(apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "tcp://127.0.0.1:1234"}}), nil, "test", testDialTimeout)
		if err == nil || !strings.Contains(err.Error(), "unsupported scheme") {
			t.Fatalf("expected the endpoint scheme to be rejected, got: %v", err)
		}
	})

	t.Run("neither resolver nor x509", func(t *testing.T) {
		_, err := New(ctx, signatureConfig(apiserver.HTTPSignatureAuthenticator{}), nil, "test", testDialTimeout)
		if err == nil || !strings.Contains(err.Error(), "one of resolver or x509 is required") {
			t.Fatalf("expected an authenticator naming neither to be rejected, got: %v", err)
		}
	})

	t.Run("resolver metadata fails", func(t *testing.T) {
		r := newTestResolver(t, "metafail")
		r.SetErrors(status.Error(codes.Internal, "not ready"), nil, nil)
		_, err := New(ctx, signatureConfig(apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}}), nil, "test", testDialTimeout)
		if err == nil || !strings.Contains(err.Error(), "fetching metadata") {
			t.Fatalf("expected a resolver that cannot answer Metadata to fail server start, got: %v", err)
		}
	})

	t.Run("malformed ladder", func(t *testing.T) {
		r := newTestResolver(t, "badladder")
		r.SetMetadata(&externalhttpsig.MetadataResponse{
			KeyDerivation: &externalhttpsig.KeyDerivation{Kind: "not-a-kind"},
		})
		_, err := New(ctx, signatureConfig(apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}}), nil, "test", testDialTimeout)
		if err == nil || !strings.Contains(err.Error(), "malformed key derivation ladder") {
			t.Fatalf("expected a malformed ladder to fail server start, got: %v", err)
		}
	})
}

// --- shared secret and derived keys ---

const testSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"

func hmacClient(t *testing.T, cred transporthttpsig.Material, ladder *keyscope.Derivation) (http.RoundTripper, *capture) {
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
		KeyDerivation:  ladder,
	}, c)
	if err != nil {
		t.Fatalf("building an HMAC signing client: %v", err)
	}
	return rt, c
}

func TestSharedSecretKey(t *testing.T) {
	rt, c := hmacClient(t, transporthttpsig.Material{KeyID: testKeyID, Secret: testSecret}, nil)
	r := newTestResolver(t, "secret")
	r.SetKey(testKeyID, &externalhttpsig.ResolveKeyResponse{
		Algorithm:       string(httpsig.HMACSHA256),
		Material:        &externalhttpsig.ResolveKeyResponse_Secret{Secret: []byte(testSecret)},
		User:            &externalhttpsig.UserInfo{Username: testUser},
		CacheTtlSeconds: 300,
	})
	a := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}})

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	resp, ok, err := a.AuthenticateRequest(req)
	if err != nil || !ok {
		t.Fatalf("AuthenticateRequest: ok=%v err=%v", ok, err)
	}
	if got := resp.User.GetName(); got != testUser {
		t.Errorf("username: got %q, want %q", got, testUser)
	}
}

// protoLadder is the ladder as a resolver states it.
func protoLadder() *externalhttpsig.KeyDerivation {
	return &externalhttpsig.KeyDerivation{
		Kind:         "hmac-ladder",
		Hash:         "sha-256",
		SecretPrefix: "K8SDEMO1",
		Steps: []*externalhttpsig.KeyDerivationStep{
			{Name: "day", Date: "YYYYMMDD"},
			{Name: "cell", Scope: true},
			{Name: "purpose", Scope: true},
			{Name: "terminator", Literal: "k8sdemo1_request"},
		},
	}
}

// clientLadder is the same ladder as a client states it. The two are declared in
// different type systems, and the digests agreeing is what says they mean the same
// thing.
func clientLadder(t *testing.T) *keyscope.Derivation {
	t.Helper()
	d, _, err := derivationFrom(protoLadder())
	if err != nil {
		t.Fatal(err)
	}
	return &d
}

// deriveRung is the broker's half: fold the ladder down to the purpose step and
// hand the rung out, using the signing library's own hand-off operation.
func deriveRung(t *testing.T, secret string, at time.Time) ([]byte, keyscope.Stage) {
	t.Helper()
	root, err := keyscope.New(*clientLadder(t), keyscope.Stage{
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
	return material, stage
}

// TestDerivedKeyVerification covers every pairing of root and rung across the two
// sides. Any stage of the same ladder with the same values produces the same
// signing key, so all four combinations verify.
func TestDerivedKeyVerification(t *testing.T) {
	now := time.Now()
	rung, rungStage := deriveRung(t, testSecret, now)
	rootScope := map[string]string{"cell": "cell-a", "purpose": "apiserver"}

	for _, tc := range []struct {
		name     string
		clientAt transporthttpsig.Material
		server   *externalhttpsig.DerivedKey
	}{
		{
			name:     "client root, server root",
			clientAt: transporthttpsig.Material{KeyID: testKeyID, Secret: testSecret, Stage: &transporthttpsig.Stage{Scope: rootScope}},
			server:   &externalhttpsig.DerivedKey{Key: []byte(testSecret), Scope: rootScope},
		},
		{
			name:     "client root, server rung",
			clientAt: transporthttpsig.Material{KeyID: testKeyID, Secret: testSecret, Stage: &transporthttpsig.Stage{Scope: rootScope}},
			server:   &externalhttpsig.DerivedKey{Key: rung, From: rungStage.From, Scope: rungStage.Scope},
		},
		{
			name: "client rung, server root",
			clientAt: transporthttpsig.Material{
				KeyID: testKeyID, SecretBase64: encodeBase64(rung),
				Stage: &transporthttpsig.Stage{From: rungStage.From, Scope: rungStage.Scope},
			},
			server: &externalhttpsig.DerivedKey{Key: []byte(testSecret), Scope: rootScope},
		},
		{
			name: "client rung, server rung",
			clientAt: transporthttpsig.Material{
				KeyID: testKeyID, SecretBase64: encodeBase64(rung),
				Stage: &transporthttpsig.Stage{From: rungStage.From, Scope: rungStage.Scope},
			},
			server: &externalhttpsig.DerivedKey{Key: rung, From: rungStage.From, Scope: rungStage.Scope},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, c := hmacClient(t, tc.clientAt, clientLadder(t))
			r := newTestResolver(t, "derived")
			r.SetMetadata(&externalhttpsig.MetadataResponse{KeyDerivation: protoLadder()})
			r.SetKey(testKeyID, &externalhttpsig.ResolveKeyResponse{
				Algorithm:       string(httpsig.HMACSHA256),
				Material:        &externalhttpsig.ResolveKeyResponse_DerivedKey{DerivedKey: tc.server},
				User:            &externalhttpsig.UserInfo{Username: testUser},
				CacheTtlSeconds: 300,
			})
			a := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}})

			req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
			if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
				t.Fatalf("AuthenticateRequest: ok=%v err=%v", ok, err)
			}
			// The keyid the client sent carries its claimed scope, and the resolver
			// is handed it whole.
			resolve, _ := r.LastRequests()
			if !strings.HasPrefix(resolve.GetKeyId(), testKeyID+"/") {
				t.Errorf("keyID should carry the claimed scope, got %q", resolve.GetKeyId())
			}
		})
	}
}

// TestDerivedKeyWithoutLadder covers the mismatch: a rung cannot be folded without
// the ladder it is a rung of, and that has to be reported as the mismatch it is
// rather than as a signature that does not verify.
func TestDerivedKeyWithoutLadder(t *testing.T) {
	now := time.Now()
	rung, rungStage := deriveRung(t, testSecret, now)
	rt, c := hmacClient(t, transporthttpsig.Material{
		KeyID: testKeyID, SecretBase64: encodeBase64(rung),
		Stage: &transporthttpsig.Stage{From: rungStage.From, Scope: rungStage.Scope},
	}, clientLadder(t))

	r := newTestResolver(t, "noladder")
	// Metadata states no ladder at all.
	r.SetKey(testKeyID, &externalhttpsig.ResolveKeyResponse{
		Algorithm: string(httpsig.HMACSHA256),
		Material: &externalhttpsig.ResolveKeyResponse_DerivedKey{
			DerivedKey: &externalhttpsig.DerivedKey{Key: rung, From: rungStage.From, Scope: rungStage.Scope},
		},
		User: &externalhttpsig.UserInfo{Username: testUser},
	})
	a := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}})

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	_, ok, err := a.AuthenticateRequest(req)
	if ok {
		t.Fatal("expected the request to be rejected")
	}
	if err == nil || !strings.Contains(err.Error(), "states no key derivation ladder") {
		t.Errorf("error should name the missing ladder, got: %v", err)
	}
}

// TestDerivedKeyWrongScopeFails covers the scope assertion: a request claiming a
// scope the resolver's material does not cover is refused, and the error names the
// step rather than reporting a bare signature mismatch.
func TestDerivedKeyWrongScopeFails(t *testing.T) {
	now := time.Now()
	rung, rungStage := deriveRung(t, testSecret, now)

	// The client claims a different cell than the server's material is scoped to.
	clientScope := map[string]string{"cell": "cell-b", "purpose": "apiserver"}
	rt, c := hmacClient(t, transporthttpsig.Material{
		KeyID: testKeyID, Secret: testSecret, Stage: &transporthttpsig.Stage{Scope: clientScope},
	}, clientLadder(t))

	r := newTestResolver(t, "wrongscope")
	r.SetMetadata(&externalhttpsig.MetadataResponse{KeyDerivation: protoLadder()})
	r.SetKey(testKeyID, &externalhttpsig.ResolveKeyResponse{
		Algorithm: string(httpsig.HMACSHA256),
		Material: &externalhttpsig.ResolveKeyResponse_DerivedKey{
			DerivedKey: &externalhttpsig.DerivedKey{Key: rung, From: rungStage.From, Scope: rungStage.Scope},
		},
		User: &externalhttpsig.UserInfo{Username: testUser},
	})
	a := authenticatorFor(t, apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: r.Endpoint()}})

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	_, ok, err := a.AuthenticateRequest(req)
	if ok {
		t.Fatal("a signature claiming a scope the key does not cover was accepted")
	}
	if err == nil || !strings.Contains(err.Error(), "outside the key's scope") {
		t.Errorf("error should name the scope disagreement, got: %v", err)
	}
	if !strings.Contains(err.Error(), "cell-b") {
		t.Errorf("error should name the claimed value, got: %v", err)
	}
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// replayOf rebuilds a request from one already shaped as the server sees it, so a
// test can present the same signed bytes twice. Everything about the copy verifies;
// only the nonce record distinguishes it.
func replayOf(req *http.Request) *http.Request {
	copied := req.Clone(req.Context())
	copied.Host = req.Host
	copied.RequestURI = req.RequestURI
	copied.Body = http.NoBody
	return copied
}

// TestNonceHandlingIgnore covers the configured escape hatch. With it set, a replay is
// accepted and the resolver is never asked, which is the whole point: the alternative
// was a resolver whose ConsumeNonce always says yes, costing a round trip and leaving
// nothing in the configuration to say replay protection is off.
func TestNonceHandlingIgnore(t *testing.T) {
	rt, c, r, config := signerFor(t)
	config.Resolver.NonceHandling = apiserver.NonceHandlingIgnore
	a := authenticatorFor(t, config)

	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	replay := replayOf(req)
	if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
		t.Fatalf("first request: ok=%v err=%v", ok, err)
	}
	if _, ok, err := a.AuthenticateRequest(replay); err != nil || !ok {
		t.Fatalf("with nonces ignored the same signature should be accepted again: ok=%v err=%v", ok, err)
	}
	if _, nonceCalls, _ := r.Counts(); nonceCalls != 0 {
		t.Errorf("ConsumeNonce was called %d times with nonceHandling: Ignore; the point is to skip the call, not to have the resolver answer yes", nonceCalls)
	}
	// The key is still resolved, so this setting gates one thing and not two.
	if resolveCalls, _, _ := r.Counts(); resolveCalls != 1 {
		t.Errorf("ResolveKey calls: got %d, want 1", resolveCalls)
	}
}

// TestNonceHandlingConsumeIsTheDefault pins the zero value to the safe behavior. There
// is no defaulting pass for AuthenticationConfiguration, so this is a property of the
// code rather than of a scheme, and it is the one worth a test of its own.
func TestNonceHandlingConsumeIsTheDefault(t *testing.T) {
	for _, tc := range []struct {
		name     string
		handling apiserver.NonceHandling
	}{
		{name: "unset", handling: ""},
		{name: "explicit Consume", handling: apiserver.NonceHandlingConsume},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, c, r, config := signerFor(t)
			config.Resolver.NonceHandling = tc.handling
			a := authenticatorFor(t, config)

			req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
			replay := replayOf(req)
			if _, ok, err := a.AuthenticateRequest(req); err != nil || !ok {
				t.Fatalf("first request: ok=%v err=%v", ok, err)
			}
			if _, ok, _ := a.AuthenticateRequest(replay); ok {
				t.Error("a replay was accepted, so replay protection is not on by default")
			}
			if _, nonceCalls, _ := r.Counts(); nonceCalls != 2 {
				t.Errorf("ConsumeNonce calls: got %d, want 2", nonceCalls)
			}
		})
	}
}

// TestNonceStillRequiredWhenIgnored covers the deliberate asymmetry: ignoring nonces
// does not stop requiring them, so turning recording on is a change to this server
// alone and not to every client.
//
// The client transport always sets a nonce, so this asserts the rule where it is
// stated rather than through a request. A signature without one cannot be produced
// here without hand-signing, which is the same gap the recorded-nonce path has.
func TestNonceStillRequiredWhenIgnored(t *testing.T) {
	r := &resolverBackend{consumeNonces: false}
	// A zero Signature carries no nonce, which is the case under test; nothing else
	// about it is reached, because the nonce check comes first.
	err := r.consumeNonce(context.Background(), &httpsig.Signature{}, &verifierKey{})
	if err == nil {
		t.Fatal("a signature with no nonce was accepted while nonces were being ignored")
	}
	if !strings.Contains(err.Error(), "no nonce") {
		t.Errorf("error should name the missing nonce, got: %v", err)
	}
}

// TestStaleSignatureIsCountedAsExpiredNotBadSignature is half of what makes an unset
// maxClockSkew defensible.
//
// Unset means zero, so a signer whose clock differs from this server's is refused.
// That failure reaches an operator as intermittent 401s, and it is the most expensive
// thing here to diagnose if it cannot be told apart from a forged signature. A
// signature that verified and fell outside its window is a clock or a configuration
// problem; one that did not verify is forged or corrupted. They are counted apart.
func TestStaleSignatureIsCountedAsExpiredNotBadSignature(t *testing.T) {
	rt, c, _, config := signerFor(t)
	config.MaxAge = &metav1.Duration{Duration: time.Nanosecond}
	// Named here rather than read back, because signatureConfig generates a name for
	// an unnamed authenticator and the metric is labelled with whatever it chose.
	config.Name = "aging"
	a := authenticatorFor(t, config)
	const name = "aging"

	before := outcomeCounts(t)
	req := signedRequest(t, rt, c, "GET", "https://"+testAuthort+"/api/v1/pods", nil)
	time.Sleep(2 * time.Millisecond)
	if _, ok, _ := a.AuthenticateRequest(req); ok {
		t.Fatal("a stale signature was accepted")
	}
	after := outcomeCounts(t)

	if got := after[name+"/"+metrics.OutcomeExpired] - before[name+"/"+metrics.OutcomeExpired]; got != 1 {
		t.Errorf("expired rose by %d, want 1", got)
	}
	if got := after[name+"/"+metrics.OutcomeBadSignature] - before[name+"/"+metrics.OutcomeBadSignature]; got != 0 {
		t.Errorf("bad_signature rose by %d; a signature that verified and aged out is not a forged one", got)
	}
}

// TestTimeFailuresAreClassified covers the other half, the future-skew case, and the
// mapping from either failure to its outcome.
//
// This is not end to end, and the reason is a missing test seam rather than a property
// of the world: the signer in k8s.io/client-go/transport/httpsig takes created from
// time.Now with no override, so a future-dated signature cannot be produced without a
// clock that differs. That signer is ours, so the seam is closable, and closing it
// would let the clock_skew case be driven through a real client the way the expired
// case already is.
//
// What is checked here is that both conditions are distinguishable at the point the
// outcome is chosen, and that the pre-lookup age check and the authoritative one inside
// Verify agree on which is which rather than the answer depending on whichever
// rejected first.
func TestTimeFailuresAreClassified(t *testing.T) {
	const maxAge = time.Minute
	for _, tc := range []struct {
		name    string
		created time.Time
		skew    time.Duration
		want    string
		wantErr string
	}{
		{"ahead of this server", time.Now().Add(30 * time.Second), 0, metrics.OutcomeClockSkew, "in the future"},
		{"ahead but inside the allowance", time.Now().Add(10 * time.Second), time.Minute, "", ""},
		{"older than maxAge", time.Now().Add(-30 * time.Minute), 0, metrics.OutcomeExpired, "older than"},
		{"fresh", time.Now(), 0, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "https://"+testAuthort+"/api/v1/pods", nil)
			if err != nil {
				t.Fatal(err)
			}
			sig := (&stubSignature{keyID: "k", created: tc.created}).parse(t, req)

			err = checkAge(sig, maxAge, tc.skew)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("expected the signature to be inside its window: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected the signature to be outside its window")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error should contain %q, got: %v", tc.wantErr, err)
			}
			// The classification an operator reads. otherwise is deliberately a value
			// neither branch can return, so a miss shows up rather than defaulting.
			if got := timeAwareOutcome(err, "unclassified"); got != tc.want {
				t.Errorf("outcome = %q, want %q", got, tc.want)
			}
		})
	}
}
