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

package exec

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig/keyscope"

	clientfeatures "k8s.io/client-go/features"
	clientfeaturestesting "k8s.io/client-go/features/testing"
	"k8s.io/client-go/pkg/apis/clientauthentication"
	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/transport"
	transporthttpsig "k8s.io/client-go/transport/httpsig"
)

// These tests cover the exec plugin returning HTTP message signature key
// material instead of a credential that transits. What the signature itself
// covers, and how derivation works, is tested where those live; what is tested
// here is the handover: what the plugin is told, what it is allowed to answer,
// and that the answer ends up signing requests.

const (
	signingKeyID = "AKIAEXAMPLE"
	signingAlg   = "hmac-sha256"
)

// signingLadder is a neutral derivation ladder. Step names are arbitrary labels,
// so these are the dimensions an example deployment would have.
func signingLadder() *keyscope.Derivation {
	return &keyscope.Derivation{
		Kind:         "hmac-ladder",
		Hash:         "sha-256",
		SecretPrefix: "EXAMPLE1",
		Steps: []keyscope.Step{
			{Name: "day", Date: "YYYYMMDD"},
			{Name: "cell", Scope: true},
			{Name: "terminator", Literal: "example1_request"},
		},
	}
}

// signingAuthenticator builds an authenticator whose plugin prints whatever the
// test tells it to, and returns the environment the plugin was handed so a test
// can assert what it was told.
func signingAuthenticator(t *testing.T, signing *transporthttpsig.Config, status string) (*Authenticator, *bytes.Buffer) {
	t.Helper()
	clientfeaturestesting.SetFeatureDuringTest(t, clientfeatures.ClientsAllowHTTPSignature, true)
	a, err := GetSigningAuthenticator(&api.ExecConfig{
		Command:         "./testdata/test-plugin.sh",
		APIVersion:      "client.authentication.k8s.io/v1",
		InteractiveMode: api.NeverExecInteractiveMode,
	}, nil, signing)
	if err != nil {
		t.Fatal(err)
	}
	// The plugin echoes what it was given on stderr, which is how a test sees the
	// spec without a purpose-built plugin.
	stderr := &bytes.Buffer{}
	a.stderr = stderr
	a.environ = func() []string { return []string{"TEST_OUTPUT=" + status} }
	return a, stderr
}

// execCredential renders a plugin's answer.
func execCredential(t *testing.T, status string) string {
	t.Helper()
	return `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{` + status + `}}`
}

// signedRequest drives one request through the authenticator's transport and
// returns what reached the wire.
func signedRequest(t *testing.T, a *Authenticator) (*http.Request, error) {
	t.Helper()
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	conf := &transport.Config{}
	if err := a.UpdateTransportConfig(conf); err != nil {
		return nil, err
	}
	rt, err := transport.HTTPWrappersForConfig(conf, http.DefaultTransport)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", srv.URL+"/api/v1/nodes", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return got, nil
}

// TestSigningPluginEndToEnd checks that material from a plugin signs requests,
// and that the plugin is told what the material has to satisfy.
func TestSigningPluginEndToEnd(t *testing.T) {
	secret := "a-shared-secret"
	signing := &transporthttpsig.Config{
		Algorithm:     signingAlg,
		SignedHeaders: []transporthttpsig.Header{{Name: "X-Session-Token"}},
		KeyDerivation: signingLadder(),
	}
	a, stderr := signingAuthenticator(t, signing, execCredential(t, `
		"expirationTimestamp":"`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`",
		"httpSignature":{
			"keyID":"`+signingKeyID+`",
			"secret":"`+secret+`",
			"stage":{"scope":{"cell":"cell-a"}},
			"signedHeaders":{"X-Session-Token":"from-the-plugin"}
		}`))

	req, err := signedRequest(t, a)
	if err != nil {
		t.Fatalf("signing a request with material from the plugin: %v", err)
	}
	input := req.Header.Get("Signature-Input")
	if input == "" {
		t.Fatal("the request carries no signature")
	}
	// The header the plugin supplied a value for is on the wire and covered, so
	// the value is bound to the request rather than merely accompanying it.
	if got := req.Header.Get("X-Session-Token"); got != "from-the-plugin" {
		t.Errorf("X-Session-Token: got %q, want the plugin's value", got)
	}
	if !strings.Contains(input, `"x-session-token"`) {
		t.Errorf("the plugin's header is not covered by the signature: %s", input)
	}
	// The key ID carries the scope the client claims, so a verifier can name the
	// step that disagrees instead of reporting a bare mismatch.
	if !strings.Contains(input, signingKeyID+"/") || !strings.Contains(input, "/cell-a/example1_request") {
		t.Errorf("keyid does not carry the derived scope: %s", input)
	}

	// What the plugin was told. Without the ladder a plugin cannot hand back an
	// intermediate rung, and without the header names it has to guess.
	var passed clientauthentication.ExecCredential
	if err := json.Unmarshal([]byte(firstJSON(stderr.String())), &passed); err != nil {
		t.Fatalf("the plugin was passed something that is not an ExecCredential: %v", err)
	}
	if passed.Spec.HTTPSignature == nil {
		t.Fatal("the plugin was not told what signature to produce material for")
	}
	if got := passed.Spec.HTTPSignature.Algorithm; got != signingAlg {
		t.Errorf("algorithm passed to the plugin: got %q, want %q", got, signingAlg)
	}
	if len(passed.Spec.HTTPSignature.SignedHeaders) != 1 ||
		passed.Spec.HTTPSignature.SignedHeaders[0].Name != "X-Session-Token" {
		t.Errorf("covered headers passed to the plugin: %+v", passed.Spec.HTTPSignature.SignedHeaders)
	}
	ladder := passed.Spec.HTTPSignature.KeyDerivation
	if ladder == nil {
		t.Fatal("the plugin was not told the ladder, so it could not derive a rung")
	}
	if ladder.SecretPrefix != "EXAMPLE1" || len(ladder.Steps) != 3 || ladder.Steps[0].Date != "YYYYMMDD" {
		t.Errorf("the ladder passed to the plugin does not match the client's: %+v", ladder)
	}
}

// TestSigningPluginDerivesFromARung is the brokered deployment over the exec
// protocol: the plugin holds the root secret, derives a rung, and hands out only
// that. The signature has to verify against a key the holder of the root derives
// independently, which is what says the client folded the rest of the ladder
// correctly.
func TestSigningPluginDerivesFromARung(t *testing.T) {
	root := "a-root-secret-the-plugin-holds"
	now := time.Now().UTC()
	ladder := signingLadder()

	// The broker's half, which in a deployment happens inside the plugin.
	rootKey, err := keyscope.New(*ladder, keyscope.Stage{
		Name:  signingKeyID,
		Scope: map[string]string{"cell": "cell-a"},
	}, []byte(root))
	if err != nil {
		t.Fatal(err)
	}
	rung, stage, err := rootKey.Derive("cell", now)
	if err != nil {
		t.Fatal(err)
	}
	stageJSON, err := json.Marshal(map[string]any{"from": stage.From, "scope": stage.Scope})
	if err != nil {
		t.Fatal(err)
	}

	a, _ := signingAuthenticator(t, &transporthttpsig.Config{
		Algorithm:     signingAlg,
		KeyDerivation: ladder,
	}, execCredential(t, `
		"httpSignature":{
			"keyID":"`+signingKeyID+`",
			"secretBase64":"`+base64.StdEncoding.EncodeToString(rung)+`",
			"stage":`+string(stageJSON)+`
		}`))

	req, err := signedRequest(t, a)
	if err != nil {
		t.Fatalf("signing with a rung from the plugin: %v", err)
	}
	sigs, err := httpsig.ParseSignatures(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 {
		t.Fatalf("want one signature, got %d", len(sigs))
	}
	// The verifier holds the root and re-derives, which is the deployment this
	// mode exists for: the client never sees the root and the server never sees
	// the rung.
	verifier, err := rootKey.Verifier(sigs[0].KeyID(), sigs[0].Created())
	if err != nil {
		t.Fatalf("the claimed scope did not match the root's: %v", err)
	}
	if err := sigs[0].Verify(verifier, httpsig.Policy{MaxAge: time.Minute}); err != nil {
		t.Errorf("a signature made with the plugin's rung does not verify against the root: %v", err)
	}
	// And the rung is not the root: signing with the root secret directly would
	// mean nothing was derived.
	rootVerifier, err := httpsig.NewVerifier(httpsig.HMACSHA256, []byte(root))
	if err != nil {
		t.Fatal(err)
	}
	if err := sigs[0].Verify(rootVerifier, httpsig.Policy{MaxAge: time.Minute}); err == nil {
		t.Error("the signature verifies against the root secret, so nothing was derived")
	}
}

// TestSigningPluginAnswerIsChecked covers the answers a plugin must not give.
// Each has to fail when the plugin runs, naming what is wrong with the
// credential, rather than becoming a signature the server rejects for no stated
// reason.
func TestSigningPluginAnswerIsChecked(t *testing.T) {
	signing := &transporthttpsig.Config{
		Algorithm:     signingAlg,
		SignedHeaders: []transporthttpsig.Header{{Name: "X-Session-Token"}},
	}
	material := `"httpSignature":{"keyID":"` + signingKeyID + `","secret":"s",
		"signedHeaders":{"X-Session-Token":"v"}}`

	for _, tc := range []struct {
		name    string
		signing *transporthttpsig.Config
		status  string
		want    string
	}{{
		// Both would be sent, and the server would authenticate whichever its
		// authenticator chain reached first, so the identity would depend on
		// server ordering rather than on this configuration.
		name:    "a token alongside the material",
		signing: signing,
		status:  `"token":"a-bearer-token",` + material,
		want:    "alternatives rather than additions",
	}, {
		// A certificate and key material are both ways of signing, so this is not
		// the same conflict as a token: it is a request to sign under two keys at
		// once, and there is no basis for choosing one.
		name:    "a certificate alongside the material",
		signing: signing,
		status:  `"clientCertificateData":"cert","clientKeyData":"key",` + material,
		want:    "a signature is made under one key",
	}, {
		// A plugin that answers with signing material for a client that is not
		// configured to sign has misread what it was asked for.
		name:    "material a client did not ask for",
		signing: nil,
		status:  material,
		want:    "not configured to sign requests",
	}, {
		// A signing client asked for a credential it does not send, and got one
		// that transits. Reported as the token being wrong rather than as material
		// being absent, because that is the more specific of the two facts.
		name:    "a token when the client signs",
		signing: signing,
		status:  `"token":"a-bearer-token"`,
		want:    "configured to sign requests rather than to send a credential",
	}, {
		name:    "nothing at all",
		signing: signing,
		status:  `"expirationTimestamp":"2030-01-01T00:00:00Z"`,
		want:    "didn't return a token, a cert/key pair, or signing key material",
	}, {
		// The covered header set is the client's, and a credential that leaves one
		// unset would put an uncovered value on the wire or none at all.
		name:    "a covered header left unset",
		signing: signing,
		status:  `"httpSignature":{"keyID":"` + signingKeyID + `","secret":"s"}`,
		want:    `sets no value for signed header "x-session-token"`,
	}, {
		name:    "a header the client does not cover",
		signing: signing,
		status:  `"httpSignature":{"keyID":"` + signingKeyID + `","secret":"s","signedHeaders":{"X-Session-Token":"v","X-Other":"v"}}`,
		want:    "not declared as signed",
	}, {
		name:    "no key identifier",
		signing: signing,
		status:  `"httpSignature":{"secret":"s","signedHeaders":{"X-Session-Token":"v"}}`,
		want:    "sets no keyID",
	}, {
		// A stage says where material sits on a ladder, so it means nothing to a
		// client that derives through none.
		name:    "a stage with no ladder",
		signing: signing,
		status:  `"httpSignature":{"keyID":"` + signingKeyID + `","secret":"s","stage":{"scope":{"cell":"cell-a"}},"signedHeaders":{"X-Session-Token":"v"}}`,
		want:    "configured with no ladder",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			var a *Authenticator
			if tc.signing == nil {
				// This client asked for a token, so it goes through the ordinary
				// constructor rather than the signing one.
				clientfeaturestesting.SetFeatureDuringTest(t, clientfeatures.ClientsAllowHTTPSignature, true)
				var err error
				a, err = GetAuthenticator(&api.ExecConfig{
					Command:         "./testdata/test-plugin.sh",
					APIVersion:      "client.authentication.k8s.io/v1",
					InteractiveMode: api.NeverExecInteractiveMode,
				}, nil)
				if err != nil {
					t.Fatal(err)
				}
				a.stderr = io.Discard
				a.environ = func() []string { return []string{"TEST_OUTPUT=" + execCredential(t, tc.status)} }
			} else {
				a, _ = signingAuthenticator(t, tc.signing, execCredential(t, tc.status))
			}
			_, err := a.getCreds()
			if err == nil {
				t.Fatalf("want an error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want an error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

// TestSigningRequiresFeatureGate checks that the client will not ask a plugin for
// material through an alpha field unless the gate is on. Failing at construction
// means the configuration is rejected while the client is being built rather than
// on the first request.
func TestSigningRequiresFeatureGate(t *testing.T) {
	clientfeaturestesting.SetFeatureDuringTest(t, clientfeatures.ClientsAllowHTTPSignature, false)
	_, err := GetSigningAuthenticator(&api.ExecConfig{
		Command:         "./testdata/test-plugin.sh",
		APIVersion:      "client.authentication.k8s.io/v1",
		InteractiveMode: api.NeverExecInteractiveMode,
	}, nil, &transporthttpsig.Config{Algorithm: signingAlg})
	if err == nil {
		t.Fatal("signing over exec was configured with the feature gate off")
	}
	if !strings.Contains(err.Error(), string(clientfeatures.ClientsAllowHTTPSignature)) {
		t.Errorf("the error does not name the gate that would allow it: %v", err)
	}
}

// TestSigningCredentialExpiry covers the two halves of expiry: it drives the
// plugin to run again, because a controller outlives its credentials and nothing
// else here would notice, and it fails the request rather than producing a
// signature the server would reject.
func TestSigningCredentialExpiry(t *testing.T) {
	runs := 0
	a, _ := signingAuthenticator(t, &transporthttpsig.Config{Algorithm: signingAlg}, "")
	a.environ = func() []string {
		runs++
		// Every answer is already expired, so no answer is ever reusable.
		return []string{"TEST_OUTPUT=" + execCredential(t, `
			"expirationTimestamp":"`+time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)+`",
			"httpSignature":{"keyID":"`+signingKeyID+`","secret":"s"}`)}
	}

	if _, err := a.getCreds(); err != nil {
		t.Fatalf("fetching a credential: %v", err)
	}
	if runs != 1 {
		t.Fatalf("the plugin ran %d times for the first credential, want 1", runs)
	}
	if _, err := a.getCreds(); err != nil {
		t.Fatalf("fetching a credential: %v", err)
	}
	if runs != 2 {
		t.Errorf("the plugin ran %d times, want 2: an expired credential has to drive a refresh", runs)
	}

	// Fail closed. The plugin has already had its chance to produce something
	// usable, so signing anyway would only move the rejection to the server.
	source := &signingSource{a}
	if _, err := source.Credential(time.Now()); err == nil {
		t.Error("an expired credential was used to sign")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Errorf("the error does not say the credential expired: %v", err)
	}
}

// TestSigningCacheKeyDistinguishesConfigs checks that two clients naming the same
// command but covering different headers do not share an authenticator. Sharing
// one would hand a credential built for one client's rules to another's.
func TestSigningCacheKeyDistinguishesConfigs(t *testing.T) {
	conf := &api.ExecConfig{
		Command:         "./testdata/test-plugin.sh",
		APIVersion:      "client.authentication.k8s.io/v1",
		InteractiveMode: api.NeverExecInteractiveMode,
	}
	first := cacheKey(conf, nil, &transporthttpsig.Config{
		Algorithm:     signingAlg,
		SignedHeaders: []transporthttpsig.Header{{Name: "X-Session-Token"}},
	})
	second := cacheKey(conf, nil, &transporthttpsig.Config{
		Algorithm:     signingAlg,
		SignedHeaders: []transporthttpsig.Header{{Name: "X-Other"}},
	})
	if first == second {
		t.Error("two signing configurations share a cache key, so one client would get the other's credential")
	}
	if token := cacheKey(conf, nil, nil); token == first {
		t.Error("a signing client shares a cache key with a token client")
	}
	// A ladder is part of what the credential has to satisfy, so it counts too.
	withLadder := cacheKey(conf, nil, &transporthttpsig.Config{
		Algorithm:     signingAlg,
		SignedHeaders: []transporthttpsig.Header{{Name: "X-Session-Token"}},
		KeyDerivation: signingLadder(),
	})
	if withLadder == first {
		t.Error("a derivation ladder does not affect the cache key")
	}
}

// firstJSON returns the first JSON object in a stream, which is how the spec is
// recovered from a plugin that echoes it to stderr.
func firstJSON(s string) string {
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end < start {
		return ""
	}
	return s[start : end+1]
}
