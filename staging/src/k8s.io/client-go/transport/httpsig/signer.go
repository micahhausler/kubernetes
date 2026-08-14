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
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/micahhausler/httpsig"

	"github.com/micahhausler/httpsig/keyscope"

	utilnet "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/klog/v2"
)

// Tag is the tag parameter set on every signature Kubernetes clients produce.
// It lets a verifier select the client's signature when a request carries more
// than one, for instance when an intermediary annotates requests. The value is
// on the wire from the first release so a later verifier can require it;
// starting without it and adding it later would break existing clients.
const Tag = "kubernetes"

// defaultMaxBodyBytes caps the body a client will buffer in order to compute a
// Content-Digest. It matches the API server's own default request body limit,
// ServerRunOptions.MaxRequestBodyBytes, because a body the server will not
// accept does not need to be signable.
const defaultMaxBodyBytes = int64(3 * 1024 * 1024)

// nonceBytes is the length of the random nonce attached to each signature. A
// nonce only has to be unique per key within the verifier's acceptance window;
// 128 bits makes collision by chance not worth reasoning about.
const nonceBytes = 16

// Config is a resolved client signing configuration. It holds what does not
// change about a signing identity; what does change lives in the credential the
// configured source produces.
type Config struct {
	// Algorithm is the signing algorithm, named as in the IANA "HTTP
	// Signature Algorithms" registry.
	Algorithm string

	// KeyID is the name the server knows the key by. It is set only with
	// KeyFile; with CredentialFile the key ID rotates with the key and comes
	// from the credential.
	KeyID string

	// Credential is signing material held in memory, for a caller that already
	// has it. This is the analogue of rest.Config.BearerToken: a credential
	// stated directly rather than read from somewhere. Nothing rotates it, so a
	// caller whose material expires supplies a CredentialSource instead.
	Credential *Material

	// KeyFile is a PEM-encoded private key, re-read when it changes.
	// CredentialFile is a credential document maintained by something else,
	// also re-read when it changes. This is the analogue of
	// rest.Config.BearerTokenFile, and it is what a projected volume or a
	// sidecar produces.
	KeyFile        string
	CredentialFile string

	// KeyDerivation is a key derivation ladder (see DerivationFrom): the signing
	// key is derived from the credential's secret through the ladder rather than
	// being the secret itself. Valid only with hmac-sha256.
	KeyDerivation *keyscope.Derivation

	// SignedHeaders are the names of headers set on every request and covered
	// by the signature. Their values come from the credential, so a header
	// carrying a session token needs no place in the kubeconfig.
	SignedHeaders []Header

	// TTL sets the signature expires parameter. Zero omits it.
	TTL time.Duration

	// MaxBodyBytes caps body buffering. Zero means defaultMaxBodyBytes.
	MaxBodyBytes int64
}

// Header is a header set on each request and covered by the signature. Only the
// name is configuration; the value comes from the credential.
type Header struct {
	Name string
}

// roundTripper signs each request and delegates to a base round tripper.
type roundTripper struct {
	base   http.RoundTripper
	source CredentialSource
	ttl    time.Duration

	extraHeaderNames []string
	maxBody          int64
}

// NewRoundTripper returns a round tripper that signs every request per cfg.
// A nil base means http.DefaultTransport.
//
// Configuration errors surface here rather than on the first request: an
// unreadable key file or an algorithm this build does not implement fails when
// the client is built.
func NewRoundTripper(cfg Config, base http.RoundTripper) (http.RoundTripper, error) {
	if base == nil {
		base = http.DefaultTransport
	}
	if cfg.Algorithm == "" {
		return nil, fmt.Errorf("httpsig: algorithm is required")
	}
	alg := httpsig.Algorithm(cfg.Algorithm)

	rt := &roundTripper{base: base, ttl: cfg.TTL, maxBody: cfg.MaxBodyBytes}
	if rt.maxBody == 0 {
		rt.maxBody = defaultMaxBodyBytes
	}

	declared := map[string]bool{}
	for _, h := range cfg.SignedHeaders {
		if h.Name == "" {
			return nil, fmt.Errorf("httpsig: signed header name is required")
		}
		if IsReservedHeader(h.Name) {
			return nil, fmt.Errorf("httpsig: signed header %q is reserved and cannot be set by configuration", h.Name)
		}
		name := canonicalHeaderName(h.Name)
		if declared[name] {
			return nil, fmt.Errorf("httpsig: signed header %q is listed more than once", h.Name)
		}
		declared[name] = true
		rt.extraHeaderNames = append(rt.extraHeaderNames, name)
	}

	// A ladder describes a derivation, and every path below that can derive
	// needs it, so it is resolved once here.
	ladder := cfg.KeyDerivation
	if ladder != nil {
		if alg != httpsig.HMACSHA256 {
			return nil, fmt.Errorf("httpsig: keyDerivation applies to hmac-sha256 only")
		}
		// The digest is the drift check: the verifier logs the same value for
		// its copy, and a mismatch is otherwise a bare signature failure with
		// nothing to say why.
		klog.V(2).InfoS("Using key derivation ladder", "sha256", CanonicalDigest(*ladder))
	}

	sources := 0
	for _, set := range []bool{cfg.Credential != nil, cfg.KeyFile != "", cfg.CredentialFile != ""} {
		if set {
			sources++
		}
	}
	switch {
	case sources != 1:
		return nil, fmt.Errorf("httpsig: exactly one of credential, keyFile, or credentialFile is required; a credential that arrives some other way needs NewRoundTripperWithSource")

	case cfg.Credential != nil:
		// Held in memory and never re-read, so it is validated here and then
		// answered from unchanged. Anything that rotates arrives as a source.
		bound, err := NewBoundCredential(*cfg.Credential, "the client configuration", alg, ladder, declared)
		if err != nil {
			return nil, err
		}
		rt.source = &staticSource{bound: bound}

	case cfg.KeyFile != "":
		// A key file carries no key ID, no header values, and no expiry, so it
		// cannot serve the algorithms or deployments that need those.
		if alg == httpsig.HMACSHA256 {
			return nil, fmt.Errorf("httpsig: algorithm %s uses a shared secret, so it requires credentialFile rather than keyFile", alg)
		}
		if cfg.KeyID == "" {
			return nil, fmt.Errorf("httpsig: keyID is required with keyFile")
		}
		if len(cfg.SignedHeaders) > 0 {
			return nil, fmt.Errorf("httpsig: signed header values come from a credential, so signedHeaders requires credentialFile rather than keyFile")
		}
		rt.source = &keyFileSource{
			watcher:   &fileWatcher{path: cfg.KeyFile},
			keyID:     cfg.KeyID,
			algorithm: alg,
		}

	default:
		if cfg.KeyID != "" {
			return nil, fmt.Errorf("httpsig: keyID comes from the credential, so it must not be set alongside credentialFile")
		}
		rt.source = &credentialFileSource{
			watcher:         &fileWatcher{path: cfg.CredentialFile},
			algorithm:       alg,
			declaredHeaders: declared,
			ladder:          ladder,
		}
	}

	// Load once here, so an unreadable or malformed credential is reported when
	// the client is built rather than on the first request.
	if _, err := rt.source.Credential(time.Now()); err != nil {
		return nil, err
	}
	return rt, nil
}

// NewRoundTripperWithSource returns a round tripper that signs with credentials
// from source, for implementations that live outside this package: a hardware
// token, a platform keystore, or a credential broker's own protocol. What the
// source hands back is a signer, never key material, so a key that cannot leave
// its holder is expressible.
//
// extraHeaders are the names of headers the source's credentials carry values
// for; they are set on every request and covered by the signature.
func NewRoundTripperWithSource(source CredentialSource, extraHeaders []string, ttl time.Duration, base http.RoundTripper) (http.RoundTripper, error) {
	if source == nil {
		return nil, fmt.Errorf("httpsig: a credential source is required")
	}
	if base == nil {
		base = http.DefaultTransport
	}
	rt := &roundTripper{base: base, source: source, ttl: ttl, maxBody: defaultMaxBodyBytes}
	for _, name := range extraHeaders {
		if IsReservedHeader(name) {
			return nil, fmt.Errorf("httpsig: signed header %q is reserved and cannot be set by configuration", name)
		}
		rt.extraHeaderNames = append(rt.extraHeaderNames, canonicalHeaderName(name))
	}
	return rt, nil
}

// RoundTrip signs the request and sends it. The caller's request is not
// modified; headers are set on a clone.
//
// RoundTrip is re-entered on redirects, so each hop is signed separately. It
// signs whatever authority the request carries: a client that follows a
// redirect to a host it did not intend to talk to signs for that host. Rejecting
// unexpected authorities belongs at a layer that knows the intended server, and
// the API server does not redirect API requests.
func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// One timestamp serves the whole request: the source derives with it and
	// the signature carries it as created, so a date-scoped key and the date
	// the verifier re-derives from cannot disagree.
	now := time.Now()

	// The source is asked on every request, so a credential rewritten by
	// whatever maintains it is picked up without restarting the client. This is
	// the difference that matters for a controller, which outlives its
	// credentials.
	cred, err := rt.source.Credential(now)
	if err != nil {
		return nil, err
	}
	if cred.Signer == nil {
		return nil, fmt.Errorf("httpsig: the credential source returned no signer")
	}
	if !cred.NotAfter.IsZero() && now.After(cred.NotAfter) {
		return nil, fmt.Errorf("httpsig: the credential expired at %s and has not been refreshed", cred.NotAfter.Format(time.RFC3339))
	}

	clone := utilnet.CloneRequest(req)
	for _, name := range rt.extraHeaderNames {
		value, ok := lookupHeader(cred.SignedHeaders, name)
		if !ok {
			return nil, fmt.Errorf("httpsig: the credential has no value for signed header %q", name)
		}
		clone.Header.Set(name, value)
	}

	body, err := rt.readBody(req)
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		setBody(clone, body)
		digest, err := ContentDigestValue(body)
		if err != nil {
			return nil, err
		}
		clone.Header.Set("Content-Digest", digest)
	}

	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("httpsig: generating nonce: %w", err)
	}

	opts := httpsig.SignOptions{
		Components: Components(clone, len(body) > 0, rt.extraHeaderNames),
		KeyID:      cred.KeyID,
		Tag:        Tag,
		Created:    now,
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		// The algorithm travels with the signature and the verifier rejects
		// a signature whose alg disagrees with the key it looked up. That
		// closes algorithm confusion in the wire format rather than in
		// documentation.
		IncludeAlg: true,
	}
	if rt.ttl > 0 {
		opts.Expires = now.Add(rt.ttl)
	}
	if err := httpsig.Sign(clone, cred.Signer, opts); err != nil {
		return nil, fmt.Errorf("httpsig: signing request: %w", err)
	}
	return rt.base.RoundTrip(clone)
}

// readBody buffers the request body so it can be digested. The body is consumed
// from the original request, which is why the request being sent is a clone with
// a fresh body.
func (rt *roundTripper) readBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	defer req.Body.Close()
	limited := io.LimitReader(req.Body, rt.maxBody+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("httpsig: reading request body to sign: %w", err)
	}
	if int64(len(body)) > rt.maxBody {
		return nil, fmt.Errorf("httpsig: request body exceeds the %d byte signing limit", rt.maxBody)
	}
	return body, nil
}

// setBody gives the clone a rewindable body, so a transport that retries or
// follows a redirect resends the same bytes the signature covers.
func setBody(req *http.Request, body []byte) {
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
}

// WrappedRoundTripper returns the base round tripper, so callers can walk the
// transport chain.
func (rt *roundTripper) WrappedRoundTripper() http.RoundTripper { return rt.base }

// parsePrivateKey reads a PEM-encoded private key. It accepts PKCS#8, PKCS#1,
// and SEC1 encodings, which covers what openssl and ssh-keygen emit for the key
// types the signature algorithms use. The source is named only for error
// messages.
func parsePrivateKey(source string, data []byte) (any, error) {
	block, _ := pem.Decode(trimSecret(data))
	if block == nil {
		return nil, fmt.Errorf("httpsig: %s holds no PEM block", source)
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("httpsig: parsing %s: %w", source, err)
		}
		switch key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("httpsig: %s holds an unsupported key type %T", source, key)
		}
	default:
		return nil, fmt.Errorf("httpsig: %s holds an unsupported PEM block %q", source, block.Type)
	}
}

// DeepCopy returns a copy that shares no mutable state with the original.
// rest.CopyConfig hands the result to an independently mutable Config, so a
// shared SignedHeaders slice would let one config's edit reach the other.
func (c *Config) DeepCopy() *Config {
	if c == nil {
		return nil
	}
	out := *c
	if c.Credential != nil {
		material := *c.Credential
		if c.Credential.SignedHeaders != nil {
			material.SignedHeaders = make(map[string]string, len(c.Credential.SignedHeaders))
			for k, v := range c.Credential.SignedHeaders {
				material.SignedHeaders[k] = v
			}
		}
		if c.Credential.Stage != nil {
			stage := *c.Credential.Stage
			if c.Credential.Stage.Scope != nil {
				stage.Scope = make(map[string]string, len(c.Credential.Stage.Scope))
				for k, v := range c.Credential.Stage.Scope {
					stage.Scope[k] = v
				}
			}
			material.Stage = &stage
		}
		out.Credential = &material
	}
	if c.SignedHeaders != nil {
		out.SignedHeaders = make([]Header, len(c.SignedHeaders))
		copy(out.SignedHeaders, c.SignedHeaders)
	}
	return &out
}

var _ fmt.Stringer = new(Config)
var _ fmt.GoStringer = new(Config)

// GoString implements fmt.GoStringer and sanitizes sensitive fields of Config
// to prevent accidental leaking via logs.
func (c *Config) GoString() string {
	return c.String()
}

// String implements fmt.Stringer. A Config holds an algorithm, header names, and
// paths, none of which is sensitive, and it may hold a credential inline, which
// is. The credential redacts itself, so there is nothing to remember here.
func (c *Config) String() string {
	if c == nil {
		return "<nil>"
	}
	names := make([]string, 0, len(c.SignedHeaders))
	for _, h := range c.SignedHeaders {
		names = append(names, h.Name)
	}
	credential := "<nil>"
	if c.Credential != nil {
		credential = c.Credential.String()
	}
	derivation := "<none>"
	if c.KeyDerivation != nil {
		// The ladder itself is not secret, but it is long; the digest is what a
		// reader compares against the server's anyway.
		derivation = CanonicalDigest(*c.KeyDerivation)
	}
	return fmt.Sprintf("httpsig.Config{Algorithm: %q, KeyID: %q, Credential: %s, KeyFile: %q, CredentialFile: %q, KeyDerivation: %s, SignedHeaders: [%s], TTL: %s, MaxBodyBytes: %d}",
		c.Algorithm, c.KeyID, credential, c.KeyFile, c.CredentialFile, derivation, strings.Join(names, ", "), c.TTL, c.MaxBodyBytes)
}

// canonicalHeaderName lowercases a header name. Signature components use
// lowercase field names, so this is the form both sides compare on.
func canonicalHeaderName(name string) string { return strings.ToLower(name) }

// CanonicalHeaderName is canonicalHeaderName for callers that build the declared
// header set themselves, such as the exec credential plugin. Both sides have to
// index header names the same way or a declared header looks unsupplied.
func CanonicalHeaderName(name string) string { return canonicalHeaderName(name) }
