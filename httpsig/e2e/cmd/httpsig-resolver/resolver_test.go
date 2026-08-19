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

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/micahhausler/httpsig/keyscope"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	externalhttpsig "k8s.io/externalhttpsig/apis/v1alpha1"
)

// publicKeyPEM returns a PEM public key of the given kind, as a person would write it
// into a key file.
func publicKeyPEM(t *testing.T, kind string) string {
	t.Helper()
	var pub any
	switch kind {
	case "ed25519":
		p, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub = p
	case "ecdsa":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub = &k.PublicKey
	default:
		t.Fatalf("publicKeyPEM does not handle %s", kind)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func writeKeys(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func indented(s, pad string) string {
	return pad + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n"+pad)
}

// TestLoadRejects covers what a key file may not say. Every case here is a mistake a
// person makes while editing, and each one has to fail at load naming the key rather
// than at request time as a signature that does not verify.
func TestLoadRejects(t *testing.T) {
	pubPEM := publicKeyPEM(t, "ed25519")
	for _, tc := range []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "unknown algorithm",
			yaml: "keys:\n  ed25519-ish:\n    k:\n      publicKey: x\n      user: {username: a}\n",
			want: "unknown algorithm",
		},
		{
			// A misspelling that is not merely a case difference. encoding/json binds
			// field names case-insensitively, so "publickey" would be accepted; this
			// is the class strictness can actually catch.
			name: "unknown field",
			yaml: "keys:\n  ed25519:\n    k:\n      publicKeyy: x\n      user: {username: a}\n",
			want: "unknown field",
		},
		{
			name: "no keys at all",
			yaml: "keys: {}\n",
			want: "holds no keys",
		},
		{
			name: "no material",
			yaml: "keys:\n  ed25519:\n    k:\n      user: {username: a}\n",
			want: "exactly one of publicKey, secret, or secretBase64, not 0",
		},
		{
			name: "two material forms",
			yaml: "keys:\n  hmac-sha256:\n    k:\n      secret: a\n      secretBase64: YQ==\n      user: {username: a}\n",
			want: "exactly one of publicKey, secret, or secretBase64, not 2",
		},
		{
			name: "public key under an hmac algorithm",
			yaml: "keys:\n  hmac-sha256:\n    k:\n      publicKey: |\n" + indented(pubPEM, "        ") + "\n      user: {username: a}\n",
			want: "verifies with a shared secret",
		},
		{
			name: "secret under an asymmetric algorithm",
			yaml: "keys:\n  ed25519:\n    k:\n      secret: a\n      user: {username: a}\n",
			want: "verifies with a public key",
		},
		{
			name: "unparseable public key",
			yaml: "keys:\n  ed25519:\n    k:\n      publicKey: not-pem\n      user: {username: a}\n",
			want: "no PEM block",
		},
		{
			name: "no username",
			yaml: "keys:\n  hmac-sha256:\n    k:\n      secret: a\n      user: {}\n",
			want: "user.username is required",
		},
		{
			name: "system username",
			yaml: "keys:\n  hmac-sha256:\n    k:\n      secret: a\n      user: {username: 'system:masters-user'}\n",
			want: "reserved for identities Kubernetes issues",
		},
		{
			name: "system group",
			yaml: "keys:\n  hmac-sha256:\n    k:\n      secret: a\n      user: {username: a, groups: ['system:masters']}\n",
			want: "reserved for groups Kubernetes issues",
		},
		{
			name: "stage without a ladder",
			yaml: "keys:\n  hmac-sha256:\n    k:\n      secretBase64: YQ==\n      stage: {from: day}\n      user: {username: a}\n",
			want: "requires a top-level keyDerivation",
		},
		{
			name: "stage on an asymmetric key",
			yaml: "keyDerivation:\n  kind: hmac-ladder\n  steps: [{name: day, date: YYYYMMDD}]\nkeys:\n  ed25519:\n    k:\n      publicKey: |\n" + indented(pubPEM, "        ") + "\n      stage: {from: day}\n      user: {username: a}\n",
			want: "an asymmetric key is not derived",
		},
		{
			name: "a rung written as a plain string",
			yaml: "keyDerivation:\n  kind: hmac-ladder\n  steps: [{name: day, date: YYYYMMDD}]\nkeys:\n  hmac-sha256:\n    k:\n      secret: raw-bytes-would-be-mangled\n      stage: {from: day, scope: {day: '20260101'}}\n      user: {username: a}\n",
			want: "use secretBase64 rather than secret",
		},
		{
			name: "bad base64",
			yaml: "keys:\n  hmac-sha256:\n    k:\n      secretBase64: '!!!'\n      user: {username: a}\n",
			want: "decoding secretBase64",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadKeys(writeKeys(t, tc.yaml))
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected an error containing %q, got: %v", tc.want, err)
			}
		})
	}
}

// TestPublicKeyIsConvertedToDER asserts the file's PEM becomes the encoding the wire
// takes, and that a PKCS#1 key arrives as PKIX like every other answer.
func TestPublicKeyIsConvertedToDER(t *testing.T) {
	pubPEM := publicKeyPEM(t, "ecdsa")
	set, err := loadKeys(writeKeys(t, "keys:\n  ecdsa-p256-sha256:\n    k:\n      publicKey: |\n"+indented(pubPEM, "        ")+"\n      user: {username: a}\n"))
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := set.lookup("k")
	if len(keys) != 1 {
		t.Fatalf("lookup: got %d keys, want 1", len(keys))
	}
	if _, err := x509.ParsePKIXPublicKey(keys[0].publicKeyDER); err != nil {
		t.Errorf("the loaded key is not PKIX DER: %v", err)
	}
	// PEM must not reach the wire: a block type is a second statement of the key kind.
	if strings.Contains(string(keys[0].publicKeyDER), "BEGIN") {
		t.Error("the loaded key still looks like PEM")
	}
}

const testLadder = `keyDerivation:
  kind: hmac-ladder
  hash: sha-256
  secretPrefix: DEMO1
  steps:
  - {name: day, date: YYYYMMDD}
  - {name: cell, scope: true}
  - {name: terminator, literal: demo1_request}
`

// TestLookupUsesTheLadderToParseKeyID is the division of labor. kube-apiserver hands
// the key ID over whole; decomposing a derived key's claimed scope is this resolver's
// job because this resolver is the party that holds the ladder.
func TestLookupUsesTheLadderToParseKeyID(t *testing.T) {
	set, err := loadKeys(writeKeys(t, testLadder+
		"keys:\n  hmac-sha256:\n    demo-key:\n      secret: a-root-secret\n      stage: {scope: {cell: cell-a}}\n      user: {username: demo}\n"))
	if err != nil {
		t.Fatal(err)
	}

	scoped := "demo-key/20260101/cell-a/demo1_request"
	keys, name := set.lookup(scoped)
	if len(keys) != 1 {
		t.Fatalf("a scoped key ID should resolve to the key it names: got %d keys", len(keys))
	}
	if name != "demo-key" {
		t.Errorf("resolved name: got %q, want %q", name, "demo-key")
	}

	// A key ID with the wrong segment count does not parse. Falling back to the plain
	// cut still finds the key, and the API server then rejects the claimed scope,
	// which is where that check belongs.
	keys, name = set.lookup("demo-key/nonsense")
	if len(keys) != 1 || name != "demo-key" {
		t.Errorf("an unparseable key ID should still fall back to the name: got %d keys, name %q", len(keys), name)
	}

	if keys, _ := set.lookup("someone-else/20260101/cell-a/demo1_request"); len(keys) != 0 {
		t.Errorf("a key ID naming another key should not resolve: got %d keys", len(keys))
	}
}

// TestRungIsVendedWithItsLadderPosition covers the hand-off shape: the material is a
// rung and the position travels with it, because the bytes cannot say what was folded
// into them.
func TestRungIsVendedWithItsLadderPosition(t *testing.T) {
	ladder := keyscope.Derivation{
		Kind: "hmac-ladder", Hash: "sha-256", SecretPrefix: "DEMO1",
		Steps: []keyscope.Step{
			{Name: "day", Date: "YYYYMMDD"},
			{Name: "cell", Scope: true},
			{Name: "terminator", Literal: "demo1_request"},
		},
	}
	root, err := keyscope.New(ladder, keyscope.Stage{Name: "demo-key", Scope: map[string]string{"cell": "cell-a"}}, []byte("a-root-secret"))
	if err != nil {
		t.Fatal(err)
	}
	rung, stage, err := root.Derive("cell", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	path := writeKeys(t, fmt.Sprintf(testLadder+
		"keys:\n  hmac-sha256:\n    demo-key:\n      secretBase64: %s\n      stage:\n        from: %s\n        scope: {day: '%s', cell: '%s'}\n      user: {username: demo}\n      cacheTTL: 5m\n",
		base64.StdEncoding.EncodeToString(rung), stage.From, stage.Scope["day"], stage.Scope["cell"]))

	r, err := newResolver(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := r.ResolveKey(context.Background(), &externalhttpsig.ResolveKeyRequest{
		KeyId:     "demo-key/" + stage.Scope["day"] + "/cell-a/demo1_request",
		Algorithm: "hmac-sha256",
	})
	if err != nil {
		t.Fatal(err)
	}
	derived, ok := resp.GetMaterial().(*externalhttpsig.ResolveKeyResponse_DerivedKey)
	if !ok {
		t.Fatalf("a staged key should be vended as a derived key, got %T", resp.GetMaterial())
	}
	if string(derived.DerivedKey.GetKey()) != string(rung) {
		t.Error("the vended rung is not the material in the file")
	}
	if derived.DerivedKey.GetFrom() != stage.From {
		t.Errorf("from: got %q, want %q", derived.DerivedKey.GetFrom(), stage.From)
	}
	if derived.DerivedKey.GetScope()["cell"] != "cell-a" {
		t.Errorf("scope: got %v", derived.DerivedKey.GetScope())
	}
	if resp.GetCacheTtlSeconds() != 300 {
		t.Errorf("cacheTtlSeconds: got %d, want 300", resp.GetCacheTtlSeconds())
	}
	// Metadata has to state the ladder, or the API server cannot fold the rung.
	meta, err := r.Metadata(context.Background(), &externalhttpsig.MetadataRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if meta.GetKeyDerivation().GetSecretPrefix() != "DEMO1" {
		t.Errorf("metadata ladder: got %+v", meta.GetKeyDerivation())
	}
}

// TestNotFoundIsAStatus asserts absence is a gRPC status rather than a response with
// fields, which is what keeps a mishandled field from authenticating a request.
func TestNotFoundIsAStatus(t *testing.T) {
	r, err := newResolver(writeKeys(t, "keys:\n  hmac-sha256:\n    known:\n      secret: a\n      user: {username: a}\n"), 100)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.ResolveKey(context.Background(), &externalhttpsig.ResolveKeyRequest{KeyId: "unknown"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("an unknown key ID: got %v, want a NotFound status", err)
	}
}

// TestAlgorithmSelectsAmongKeysSharingAName covers the request's algorithm being a
// hint. Two keys share a name under different algorithms, and the claim chooses.
func TestAlgorithmSelectsAmongKeysSharingAName(t *testing.T) {
	pubPEM := publicKeyPEM(t, "ed25519")
	r, err := newResolver(writeKeys(t,
		"keys:\n  ed25519:\n    shared:\n      publicKey: |\n"+indented(pubPEM, "        ")+
			"\n      user: {username: asymmetric}\n  hmac-sha256:\n    shared:\n      secret: a\n      user: {username: symmetric}\n"), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ algorithm, wantUser string }{
		{"ed25519", "asymmetric"},
		{"hmac-sha256", "symmetric"},
	} {
		resp, err := r.ResolveKey(context.Background(), &externalhttpsig.ResolveKeyRequest{KeyId: "shared", Algorithm: tc.algorithm})
		if err != nil {
			t.Fatalf("%s: %v", tc.algorithm, err)
		}
		if got := resp.GetUser().GetUsername(); got != tc.wantUser {
			t.Errorf("%s: username got %q, want %q", tc.algorithm, got, tc.wantUser)
		}
		// The response's algorithm is this resolver's own, not an echo of the claim.
		if got := resp.GetAlgorithm(); got != tc.algorithm {
			t.Errorf("%s: response algorithm got %q", tc.algorithm, got)
		}
	}
	if _, err := r.ResolveKey(context.Background(), &externalhttpsig.ResolveKeyRequest{KeyId: "shared", Algorithm: "rsa-pss-sha512"}); status.Code(err) != codes.NotFound {
		t.Errorf("an algorithm no key under that name uses: got %v, want NotFound", err)
	}
}

// TestRequiredHeadersNarrowTheAnswer covers a resolver deciding identity from a relayed
// value rather than from the key ID, and refusing to leak the expected value when it
// does not match.
func TestRequiredHeadersNarrowTheAnswer(t *testing.T) {
	r, err := newResolver(writeKeys(t, `keys:
  hmac-sha256:
    session-key:
      secret: a-shared-secret
      requiredHeaders: {X-Session-Token: the-right-token}
      user: {username: session-user}
      cacheTTL: 0s
`), 100)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := r.ResolveKey(context.Background(), &externalhttpsig.ResolveKeyRequest{
		KeyId:          "session-key",
		RelayedHeaders: map[string]string{"x-session-token": "the-right-token"},
	})
	if err != nil {
		t.Fatalf("the matching token should resolve: %v", err)
	}
	if got := resp.GetUser().GetUsername(); got != "session-user" {
		t.Errorf("username: got %q", got)
	}
	// An identity that depends on a rotating value must not be cached.
	if resp.GetCacheTtlSeconds() != 0 {
		t.Errorf("cacheTtlSeconds: got %d, want 0", resp.GetCacheTtlSeconds())
	}

	for _, tc := range []struct {
		name    string
		relayed map[string]string
	}{
		{name: "wrong value", relayed: map[string]string{"x-session-token": "the-wrong-token"}},
		{name: "absent", relayed: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := r.ResolveKey(context.Background(), &externalhttpsig.ResolveKeyRequest{KeyId: "session-key", RelayedHeaders: tc.relayed})
			if status.Code(err) != codes.NotFound {
				t.Fatalf("got %v, want NotFound", err)
			}
			// The error reaches the API server's log. It must not carry the token.
			if strings.Contains(err.Error(), "the-right-token") {
				t.Errorf("the error discloses the expected token: %v", err)
			}
		})
	}
}

// TestConsumeNonce covers the contract the RPC exists for: the same nonce twice is
// refused, and the same value under a different key is a different fact.
func TestConsumeNonce(t *testing.T) {
	r, err := newResolver(writeKeys(t, "keys:\n  hmac-sha256:\n    k:\n      secret: a\n      user: {username: a}\n"), 100)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	req := func(keyID, nonce string) *externalhttpsig.ConsumeNonceRequest {
		now := time.Now()
		return &externalhttpsig.ConsumeNonceRequest{
			KeyId: keyID, Nonce: nonce,
			Created:   timestamppb.New(now),
			ExpiresAt: timestamppb.New(now.Add(5 * time.Minute)),
		}
	}

	first, err := r.ConsumeNonce(ctx, req("k", "nonce-1"))
	if err != nil || !first.GetAccepted() {
		t.Fatalf("first use: accepted=%v err=%v", first.GetAccepted(), err)
	}
	second, err := r.ConsumeNonce(ctx, req("k", "nonce-1"))
	if err != nil {
		t.Fatal(err)
	}
	if second.GetAccepted() {
		t.Error("the same nonce was accepted twice")
	}
	if !strings.Contains(second.GetReason(), "already been used") {
		t.Errorf("reason: got %q", second.GetReason())
	}

	// Per key, so one client's traffic cannot reject another's.
	other, err := r.ConsumeNonce(ctx, req("other-key", "nonce-1"))
	if err != nil || !other.GetAccepted() {
		t.Errorf("the same nonce under another key should be accepted: accepted=%v err=%v", other.GetAccepted(), err)
	}
}

// TestConsumeNonceRequiresAnExpiry covers the field without which the store cannot
// know when to forget, and a store that never forgets eventually stops accepting.
func TestConsumeNonceRequiresAnExpiry(t *testing.T) {
	r, err := newResolver(writeKeys(t, "keys:\n  hmac-sha256:\n    k:\n      secret: a\n      user: {username: a}\n"), 100)
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.ConsumeNonce(context.Background(), &externalhttpsig.ConsumeNonceRequest{KeyId: "k", Nonce: "n"})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("a request with no expiry: got %v, want InvalidArgument", err)
	}
}

// TestNonceStoreSweepsThenRefuses is the bound. Expired records go first; a store still
// full after that refuses rather than evicting, because evicting a record permits the
// replay it was preventing.
func TestNonceStoreSweepsThenRefuses(t *testing.T) {
	s := newNonceStore(2)
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Minute)

	if ok, _ := s.consume("k", "expired-1", past); !ok {
		t.Fatal("first record should be accepted")
	}
	if ok, _ := s.consume("k", "expired-2", past); !ok {
		t.Fatal("second record should be accepted")
	}
	if s.size() != 2 {
		t.Fatalf("size: got %d, want 2", s.size())
	}

	// Full, but both records are expired, so the sweep makes room.
	if ok, reason := s.consume("k", "live-1", future); !ok {
		t.Fatalf("a full store of expired records should sweep and accept: %s", reason)
	}

	// Now fill with live records and confirm it refuses rather than evicting.
	if ok, _ := s.consume("k", "live-2", future); !ok {
		t.Fatal("second live record should be accepted")
	}
	ok, reason := s.consume("k", "live-3", future)
	if ok {
		t.Fatal("a full store of live records accepted another, so a record was evicted and its request can be replayed")
	}
	if !strings.Contains(reason, "limit") {
		t.Errorf("reason: got %q", reason)
	}
	// The records it already held are still there and still refuse a replay.
	if ok, _ := s.consume("k", "live-1", future); ok {
		t.Error("a record was lost while the store was under pressure")
	}
}

// TestReloadOnFileChange covers revocation: a key removed from the file stops
// resolving, without restarting anything.
func TestReloadOnFileChange(t *testing.T) {
	path := writeKeys(t, "keys:\n  hmac-sha256:\n    doomed:\n      secret: a\n      user: {username: a}\n")
	r, err := newResolver(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := r.ResolveKey(ctx, &externalhttpsig.ResolveKeyRequest{KeyId: "doomed"}); err != nil {
		t.Fatalf("the key should resolve before it is revoked: %v", err)
	}

	// Rewritten with a different size, so the stamp changes regardless of filesystem
	// timestamp granularity. A test that relied on mtime alone would be flaky on a
	// filesystem with one-second timestamps.
	if err := os.WriteFile(path, []byte("keys:\n  hmac-sha256:\n    survivor:\n      secret: bbbbbbbbbb\n      user: {username: b}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveKey(ctx, &externalhttpsig.ResolveKeyRequest{KeyId: "doomed"}); status.Code(err) != codes.NotFound {
		t.Errorf("a revoked key: got %v, want NotFound", err)
	}
	if _, err := r.ResolveKey(ctx, &externalhttpsig.ResolveKeyRequest{KeyId: "survivor"}); err != nil {
		t.Errorf("a key added by the same edit should resolve: %v", err)
	}
}

// TestReloadKeepsKeysWhenTheFileGoesBad is the other half. A half-written or deleted
// file must not log out every client.
func TestReloadKeepsKeysWhenTheFileGoesBad(t *testing.T) {
	path := writeKeys(t, "keys:\n  hmac-sha256:\n    k:\n      secret: a\n      user: {username: a}\n")
	r, err := newResolver(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := os.WriteFile(path, []byte("this: is: not: valid: yaml: at: all\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveKey(ctx, &externalhttpsig.ResolveKeyRequest{KeyId: "k"}); err != nil {
		t.Errorf("a broken key file should leave the loaded keys serving: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ResolveKey(ctx, &externalhttpsig.ResolveKeyRequest{KeyId: "k"}); err != nil {
		t.Errorf("a deleted key file should leave the loaded keys serving: %v", err)
	}
}

// TestREADMEExampleLoads reads the first YAML block out of README.md and loads it.
//
// An example that does not parse is worse than no example: it is copied. This is also
// the only thing keeping the documented schema honest as the code changes, since the
// README is the schema's only other description.
func TestREADMEExampleLoads(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	const fence = "```yaml\n"
	start := strings.Index(string(readme), fence)
	if start < 0 {
		t.Fatal("README.md has no yaml block; if the example moved, move this test with it")
	}
	rest := string(readme)[start+len(fence):]
	end := strings.Index(rest, "```")
	if end < 0 {
		t.Fatal("README.md has an unterminated yaml block")
	}
	example := rest[:end]

	// The first block is the kube-apiserver configuration snippet rather than a key
	// file, so find the one that has keys in it.
	if !strings.Contains(example, "keys:") {
		next := strings.Index(rest[end:], fence)
		if next < 0 {
			t.Fatal("README.md has no yaml block holding a key file")
		}
		rest = rest[end+next+len(fence):]
		end = strings.Index(rest, "```")
		if end < 0 {
			t.Fatal("README.md has an unterminated yaml block")
		}
		example = rest[:end]
	}

	set, err := loadKeys(writeKeys(t, example))
	if err != nil {
		t.Fatalf("the README's example key file does not load: %v", err)
	}

	// Every key the example documents resolves, so a key that stops being loadable is
	// caught rather than merely a file that parses.
	for _, keyID := range []string{"alice-key", "AKIABOBEXAMPLE", "scoped-key", "session-key"} {
		if keys, _ := set.lookup(keyID); len(keys) == 0 {
			t.Errorf("the README documents %q but it does not load", keyID)
		}
	}
	if set.derivation == nil {
		t.Error("the README documents a keyDerivation but it did not load")
	}
}
