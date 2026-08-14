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

// Package httpsig authenticates requests carrying an HTTP message signature
// (RFC 9421). A client signs each request over its method, authority, path,
// query, body digest, and selected headers. Nothing reusable is sent, so a
// captured request is a record of one request rather than a credential.
//
// Two rules in here are the whole security argument, and both are easy to leave
// out of an implementation that still appears to work:
//
// The covered component set is required by this verifier, not read from the
// signature. RFC 9421 signatures declare what they cover. A verifier that only
// checks "this signature is valid for the components it names" accepts a
// signature covering nothing at all, because an attacker signs a component list
// of their own choosing with their own key.
//
// A protected header present on a request must be covered by the signature.
// Coverage stops a header being removed for free, since a signature base that
// cannot be reconstructed does not verify. It does not stop one being added: an
// intermediary can append Impersonate-User to a signed request that carried no
// impersonation and the signature still verifies. Checking presence against the
// covered set is the only defense against that.
package httpsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/micahhausler/httpsig"

	"github.com/micahhausler/httpsig/keyscope"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"

	transporthttpsig "k8s.io/client-go/transport/httpsig"
	"k8s.io/klog/v2"
)

const (
	// defaultMaxAge bounds signature age when configuration does not. It also
	// bounds replay: a captured request can be resent until it ages out.
	defaultMaxAge = 5 * time.Minute

	// defaultMaxNoncesPerKey bounds the nonces remembered for one key.
	defaultMaxNoncesPerKey = 1024

	// maxBodyBytes caps the body read to check a Content-Digest. It matches the
	// API server's default request body limit, so a request this verifier
	// rejects for size is one the server would have rejected anyway.
	maxBodyBytes = int64(3 * 1024 * 1024)
)

// errNoSignature reports a request carrying no signature at all. The union
// authenticator moves on, so this never reaches a client.
var errNoSignature = errors.New("request carries no HTTP message signature")

// key is one configured verification key and the identity it authenticates.
type key struct {
	// verifier is set for keys that verify the same way on every request. For a
	// derived key it is nil and a verifier is built per request, because the
	// derived key depends on the created timestamp the signature carries and
	// on the scope the keyid claims.
	verifier httpsig.Verifier
	// scoped is set for a derived key: material bound to its position on the
	// ladder, which derives a verifier per signature.
	scoped *keyscope.Key
	info   *user.DefaultInfo
	// nonces holds recently seen nonces for this key. Buckets are per key
	// rather than one shared set: a shared set keyed on client-chosen values
	// lets one noisy or hostile client evict every other client's entries,
	// which turns replay tracking into a replay enabling mechanism.
	nonces *cache.LRUExpireCache
}

// Authenticator verifies HTTP message signatures on incoming requests.
type Authenticator struct {
	keys      map[string]*key
	policy    httpsig.Policy
	parseOpts *httpsig.ParseOptions
	// nonceTTL is how long a nonce is remembered: long enough that a signature
	// can never outlive its own record.
	nonceTTL time.Duration
}

var _ authenticator.Request = &Authenticator{}

// New builds an Authenticator from configuration. Key material is parsed here,
// so a malformed key fails at server start rather than on a request.
func New(config *apiserver.HTTPSignatureAuthenticator) (*Authenticator, error) {
	if config == nil {
		return nil, fmt.Errorf("httpsig: configuration is required")
	}
	maxAge := defaultMaxAge
	if config.MaxAge != nil {
		maxAge = config.MaxAge.Duration
	}
	var tolerance time.Duration
	if config.Tolerance != nil {
		tolerance = config.Tolerance.Duration
	}
	maxNonces := defaultMaxNoncesPerKey
	if config.MaxNoncesPerKey != nil {
		maxNonces = int(*config.MaxNoncesPerKey)
	}

	a := &Authenticator{
		keys: make(map[string]*key, len(config.Keys)),
		policy: httpsig.Policy{
			// The floor is stated here, by this verifier, and not taken from
			// the signature.
			RequiredComponents: transporthttpsig.FloorComponents,
			MaxAge:             maxAge,
			Tolerance:          tolerance,
		},
		// A nonce is remembered for as long as a signature bearing it could
		// still be accepted.
		nonceTTL: maxAge + tolerance,
	}
	if config.Scheme != "" || config.Authority != "" {
		a.parseOpts = &httpsig.ParseOptions{Scheme: config.Scheme, Authority: config.Authority}
	}

	for i, k := range config.Keys {
		built, err := buildKey(k, config.KeyDerivation)
		if err != nil {
			return nil, fmt.Errorf("httpsig: keys[%d]: %w", i, err)
		}
		if _, dup := a.keys[k.KeyID]; dup {
			return nil, fmt.Errorf("httpsig: keys[%d]: duplicate keyID %q", i, k.KeyID)
		}
		built.info = &user.DefaultInfo{
			Name:   k.User.Username,
			UID:    k.User.UID,
			Groups: k.User.Groups,
		}
		built.nonces = cache.NewLRUExpireCache(maxNonces)
		a.keys[k.KeyID] = built
	}
	return a, nil
}

// verifierFor returns the verifier for one signature. A static key holds one; a
// derived key builds one per request, checking the scope the keyid claims
// against its own configuration first, so a request signed under the wrong
// scope, whatever dimensions the ladder scopes by, is rejected with an error
// naming the disagreeing step rather than a bare signature mismatch. The verifier never derives with its
// own clock: it uses the created timestamp the signature carries, which is
// covered by the signature and bounded by the maximum age policy.
func (k *key) verifierFor(sig *httpsig.Signature) (httpsig.Verifier, error) {
	if k.scoped == nil {
		return k.verifier, nil
	}
	created := sig.Created()
	if created.IsZero() {
		return nil, fmt.Errorf("the signature carries no created parameter, and this key's verification key is derived from it")
	}
	return k.scoped.Verifier(sig.KeyID(), created)
}

// AuthenticateRequest verifies the request's signatures. It returns no opinion
// when the request carries none, so the next authenticator in the chain runs.
//
// A request is authenticated when at least one of its signatures satisfies
// everything here. Requiring every signature to verify would be trivially
// defeated by appending a garbage one.
func (a *Authenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	if len(req.Header.Values("Signature-Input")) == 0 && len(req.Header.Values("Signature")) == 0 {
		return nil, false, nil
	}

	sigs, err := httpsig.ParseSignatures(req, a.parseOpts)
	if err != nil {
		return nil, false, fmt.Errorf("parsing HTTP message signature: %w", err)
	}

	var errs []error
	for _, sig := range sigs {
		resp, err := a.authenticateSignature(req, sig)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// The signature fields have served their purpose. Clearing them keeps
		// anything downstream from treating them as credentials, the way the
		// bearer token and front proxy authenticators clear theirs.
		req.Header.Del("Signature")
		req.Header.Del("Signature-Input")
		return resp, true, nil
	}
	if len(errs) == 0 {
		errs = append(errs, errNoSignature)
	}
	return nil, false, fmt.Errorf("no valid HTTP message signature: %w", errors.Join(errs...))
}

func (a *Authenticator) authenticateSignature(req *http.Request, sig *httpsig.Signature) (*authenticator.Response, error) {
	// KeyID is an unverified claim until Verify succeeds. It is used only to
	// select a key, never to grant anything. A derived key's keyid carries its
	// claimed scope after the name, joined by slashes, so the
	// lookup falls back to the segment before the first slash; the claimed
	// scope itself is checked by the key, not here.
	keyID := sig.KeyID()
	k, ok := a.keys[keyID]
	if !ok {
		if name, _, found := strings.Cut(keyID, "/"); found {
			k, ok = a.keys[name]
		}
	}
	if !ok {
		return nil, fmt.Errorf("signature %q: unknown keyID", sig.Label())
	}

	verifier, err := k.verifierFor(sig)
	if err != nil {
		return nil, fmt.Errorf("signature %q: %w", sig.Label(), err)
	}

	// Verify before anything that costs work: the signature base is built from
	// headers alone, so an unauthenticated caller cannot make this server read
	// a body or touch a cache.
	if err := sig.Verify(verifier, a.policy); err != nil {
		return nil, fmt.Errorf("signature %q: %w", sig.Label(), err)
	}

	if err := checkProtectedHeaders(req, sig); err != nil {
		return nil, fmt.Errorf("signature %q: %w", sig.Label(), err)
	}
	if err := checkBodyDigest(req, sig); err != nil {
		return nil, fmt.Errorf("signature %q: %w", sig.Label(), err)
	}
	// Consumed last, so a request rejected for any other reason does not use up
	// the nonce of a legitimate request it copied.
	if err := a.consumeNonce(k, sig); err != nil {
		return nil, fmt.Errorf("signature %q: %w", sig.Label(), err)
	}

	klog.V(4).InfoS("Authenticated request by HTTP message signature",
		"keyID", sig.KeyID(), "username", k.info.Name, "components", len(sig.Components()))
	return &authenticator.Response{User: k.info}, nil
}

// checkProtectedHeaders rejects a request carrying a protected header the
// signature does not cover. Without this, appending a header to a signed request
// is unnoticed.
func checkProtectedHeaders(req *http.Request, sig *httpsig.Signature) error {
	covered := make(map[string]bool, len(sig.Components()))
	for _, c := range sig.Components() {
		covered[c.Name] = true
	}
	var uncovered []string
	for name := range req.Header {
		if !transporthttpsig.IsProtectedHeader(name) {
			continue
		}
		if !covered[strings.ToLower(name)] {
			uncovered = append(uncovered, name)
		}
	}
	if len(uncovered) > 0 {
		return fmt.Errorf("request carries protected headers the signature does not cover: %s", strings.Join(uncovered, ", "))
	}
	return nil
}

// checkBodyDigest binds the body to the signature. A signed Content-Digest whose
// value nothing compares against the body is worth nothing: the header cannot be
// altered, but the body it describes can.
//
// The body is read here and replaced, so the handler chain still sees it.
func checkBodyDigest(req *http.Request, sig *httpsig.Signature) error {
	digests := req.Header.Values("Content-Digest")
	covered := false
	for _, c := range sig.Components() {
		if c.Name == "content-digest" {
			covered = true
			break
		}
	}

	if req.Body == nil || req.Body == http.NoBody {
		// No body to bind. A Content-Digest on a bodiless request is checked
		// below only if one was sent, so an empty request cannot smuggle one.
		if len(digests) > 0 {
			return checkDigestValues(req, digests, covered, nil)
		}
		return nil
	}

	body, err := readBody(req)
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))

	if len(body) == 0 && len(digests) == 0 {
		return nil
	}
	return checkDigestValues(req, digests, covered, body)
}

func checkDigestValues(req *http.Request, digests []string, covered bool, body []byte) error {
	if len(digests) == 0 {
		return fmt.Errorf("request has a body but no Content-Digest, so the body is not bound to the signature")
	}
	if !covered {
		return fmt.Errorf("request has a Content-Digest the signature does not cover, so the body is not bound to the signature")
	}
	if err := transporthttpsig.VerifyContentDigest(digests, body); err != nil {
		return err
	}
	return nil
}

func readBody(req *http.Request) ([]byte, error) {
	limited := io.LimitReader(req.Body, maxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("reading request body to check its digest: %w", err)
	}
	if int64(len(body)) > maxBodyBytes {
		return nil, fmt.Errorf("request body exceeds the %d byte limit for digest verification", maxBodyBytes)
	}
	return body, nil
}

// consumeNonce rejects a nonce this server has already seen for this key.
//
// The guarantee is bounded and worth stating exactly: a nonce is remembered by
// one API server process, so with more than one API server and no shared state,
// a captured request can be replayed once against each server that has not seen
// it, until its signature ages out.
func (a *Authenticator) consumeNonce(k *key, sig *httpsig.Signature) error {
	nonce := sig.Nonce()
	if nonce == "" {
		return fmt.Errorf("signature carries no nonce")
	}
	if _, seen := k.nonces.Get(nonce); seen {
		return fmt.Errorf("signature nonce has already been used")
	}
	k.nonces.Add(nonce, struct{}{}, a.nonceTTL)
	return nil
}

// ValidateKey reports whether one configured key is usable. It is exported so
// configuration validation can reject unusable key material, ladder documents,
// and stages without repeating the rules, which live here and in the signing
// library.
func ValidateKey(k apiserver.HTTPSignatureKey, ladder *apiserver.HTTPSignatureKeyDerivation) error {
	_, err := buildKey(k, ladder)
	return err
}

// buildKey loads one configured key: parses its material, loads its ladder, and
// validates its stage. Everything that can fail does so here, at server start,
// rather than on a request.
func buildKey(k apiserver.HTTPSignatureKey, ladder *apiserver.HTTPSignatureKeyDerivation) (*key, error) {
	alg := httpsig.Algorithm(k.Algorithm)
	if k.Algorithm == "" {
		return nil, fmt.Errorf("algorithm is required")
	}
	if k.KeyID == "" {
		return nil, fmt.Errorf("keyID is required")
	}

	if alg != httpsig.HMACSHA256 {
		if k.SecretFile != "" {
			return nil, fmt.Errorf("algorithm %s uses a public key, not secretFile", alg)
		}
		if ladder != nil && k.Stage != nil {
			return nil, fmt.Errorf("stage names a position on a derivation ladder, which applies to hmac-sha256 only; an asymmetric key is not derived")
		}
		if k.Stage != nil {
			return nil, fmt.Errorf("stage applies to hmac-sha256 only")
		}
		if k.PublicKey == "" {
			return nil, fmt.Errorf("algorithm %s requires publicKey", alg)
		}
		pub, err := parsePublicKey(k.PublicKey)
		if err != nil {
			return nil, err
		}
		verifier, err := httpsig.NewVerifier(alg, pub)
		if err != nil {
			return nil, err
		}
		return &key{verifier: verifier}, nil
	}

	if k.PublicKey != "" {
		return nil, fmt.Errorf("algorithm %s uses a shared secret, not publicKey", alg)
	}
	if k.SecretFile == "" {
		return nil, fmt.Errorf("algorithm %s requires secretFile", alg)
	}
	if k.Stage != nil && ladder == nil {
		return nil, fmt.Errorf("stage names a position on a ladder, so it requires httpSignature.keyDerivation")
	}
	raw, err := os.ReadFile(k.SecretFile)
	if err != nil {
		return nil, fmt.Errorf("reading secretFile: %w", err)
	}
	var material []byte
	if k.Stage != nil && k.Stage.From != "" {
		// An intermediate rung is raw hash output. The newline trim applied to
		// a plain secret would corrupt a rung that ends in a newline byte, so a
		// rung-holding secretFile holds base64. A root secret is a printable
		// string even when a stage carries scope values, so it stays plain.
		material, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("secretFile must hold base64 when stage.from is set, because a derived rung is raw bytes: %w", err)
		}
	} else {
		// A trailing newline is what an editor or `echo` leaves behind, and a
		// secret that differs by one byte fails with no clue why.
		material = bytes.TrimRight(raw, "\r\n")
	}

	if ladder == nil {
		verifier, err := httpsig.NewVerifier(alg, material)
		if err != nil {
			return nil, err
		}
		return &key{verifier: verifier}, nil
	}

	derivation, digest, err := transporthttpsig.DerivationFrom(ladder)
	if err != nil {
		return nil, err
	}
	// The digest is the drift check: the client logs the same value for its
	// copy, and a mismatch otherwise surfaces as a bare signature failure.
	klog.V(2).InfoS("Loaded key derivation ladder", "keyID", k.KeyID, "sha256", digest)
	var stage *transporthttpsig.Stage
	if k.Stage != nil {
		stage = &transporthttpsig.Stage{From: k.Stage.From, Scope: k.Stage.Scope}
	}
	// Binding the material to its position validates the stage, so a scope typo
	// fails at server start rather than on a request.
	scoped, err := keyscope.New(derivation, transporthttpsig.KeyscopeStage(k.KeyID, stage), material)
	if err != nil {
		return nil, err
	}
	return &key{scoped: scoped}, nil
}

// parsePublicKey reads a PEM-encoded public key. Both the SubjectPublicKeyInfo
// and PKCS#1 encodings are accepted, which covers what openssl emits.
func parsePublicKey(data string) (any, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, fmt.Errorf("publicKey holds no PEM block")
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing publicKey: %w", err)
		}
		switch pub.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			return pub, nil
		default:
			return nil, fmt.Errorf("publicKey holds an unsupported key type %T", pub)
		}
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("publicKey holds an unsupported PEM block %q", block.Type)
	}
}
