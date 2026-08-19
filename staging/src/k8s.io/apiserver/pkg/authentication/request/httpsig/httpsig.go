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
// Keys are not configured here. A resolver answers for a key ID with the key
// that verifies signatures bearing it and the identity it authenticates, and
// records the nonces those signatures carry. See resolver.go for that seam and
// remote.go for the gRPC implementation of it.
//
// Three rules in here are the whole security argument, and all three are easy to
// leave out of an implementation that still appears to work:
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
//
// Work is ordered by what it costs an unauthenticated caller. Signature age is
// checked before a key is resolved, so a caller with an ancient timestamp cannot
// drive a lookup. The signature is verified before the body is read and before a
// nonce is consumed, so a caller who cannot produce a valid signature cannot make
// this server read a body or call a resolver twice.
//
// Replay is closed by the resolver recording nonces, which configuration can turn
// off. With it off the replay window is the maximum signature age, and nothing here
// narrows it; see apiserver.NonceHandling for why that is a stated option rather
// than something to fake with a resolver that always says yes.
package httpsig

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/micahhausler/httpsig"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/httpsig/metrics"

	transporthttpsig "k8s.io/client-go/transport/httpsig"
	"k8s.io/klog/v2"
)

const (
	// DefaultMaxAge bounds signature age when configuration does not. It also
	// sets how long a resolver is asked to remember a nonce.
	DefaultMaxAge = 5 * time.Minute

	// maxBodyBytes caps the body read to check a Content-Digest. It matches the
	// API server's default request body limit, so a request this verifier
	// rejects for size is one the server would have rejected anyway.
	maxBodyBytes = int64(3 * 1024 * 1024)

	// maxKeyIDLen bounds the keyid this server will act on. A keyid is
	// peer-chosen and becomes a cache key, a resolver argument, and part of an
	// error message, so it is bounded before any of those. The value is the one
	// the signing library's own keyid parser accepts, so a longer keyid could
	// not have verified anyway.
	maxKeyIDLen = 512
)

// errNoSignature reports a request carrying no signature at all. The union
// authenticator moves on, so this never reaches a client.
var errNoSignature = errors.New("request carries no HTTP message signature")

// resolverEntry is one configured resolver and the policy applied to the keys it
// vends.
type resolverEntry struct {
	// prefixes admit a keyid by the segment before its first slash. Empty means
	// every keyid.
	prefixes []string

	// relayedHeaders are the lowercase names of headers relayed with a lookup.
	relayedHeaders []string

	keys *keyCache

	// consumeNonces is false when configuration says to ignore them. It gates one
	// thing only: whether the resolver is asked to record the nonce. The signature
	// is still required to carry one either way, so turning this on later needs no
	// change at any client.
	consumeNonces bool

	// maxAge and tolerance are this entry's configured bounds. A resolver may
	// narrow maxAge, per resolver or per key; nothing widens it.
	maxAge    time.Duration
	tolerance time.Duration
}

// Authenticator verifies HTTP message signatures on incoming requests.
type Authenticator struct {
	entries []*resolverEntry

	// parseOpts states the external scheme and authority clients sign, for a
	// server behind an intermediary that rewrites Host. It is shared across
	// entries because it describes this server rather than any resolver: the
	// authority goes into the signature base, so two entries disagreeing about it
	// would make the same request verify under one and not the other.
	// Configuration is rejected if entries disagree.
	parseOpts *httpsig.ParseOptions
}

var _ authenticator.Request = &Authenticator{}

// New builds an Authenticator from configuration. It dials each resolver and
// fetches its metadata, so a resolver that is absent or unusable fails at server
// start rather than on a request.
//
// An empty list is valid and produces an authenticator with no opinion about any
// request. That is what lets a resolver be added by reloading the configuration
// file: the authenticator has to already be in the chain for a later generation to
// replace it.
//
// The connections and each resolver's metadata refresh live for as long as
// lifecycle. dialTimeout bounds the first metadata call to each resolver, and the
// resolvers are dialed concurrently, so it bounds this function rather than being
// multiplied by the number of them.
func New(lifecycle context.Context, configs []apiserver.HTTPSignatureAuthenticator, apiServerID string, dialTimeout time.Duration) (*Authenticator, error) {
	a := &Authenticator{}
	if len(configs) == 0 {
		return a, nil
	}

	if configs[0].Scheme != "" || configs[0].Authority != "" {
		a.parseOpts = &httpsig.ParseOptions{Scheme: configs[0].Scheme, Authority: configs[0].Authority}
	}
	for i, c := range configs {
		if c.Scheme != configs[0].Scheme || c.Authority != configs[0].Authority {
			return nil, fmt.Errorf("httpsig: httpSignature[%d] states a different scheme or authority than httpSignature[0]; both describe this server rather than a resolver, so every entry has to state the same values", i)
		}
	}

	// Dialed concurrently. Sequentially, a list of resolvers that are all absent
	// would take the dial budget times the length of the list to report, which for
	// a server start means an unbounded-looking hang rather than an error.
	a.entries = make([]*resolverEntry, len(configs))
	errs := make([]error, len(configs))
	var wg sync.WaitGroup
	for i, c := range configs {
		wg.Add(1)
		go func(i int, c apiserver.HTTPSignatureAuthenticator) {
			defer wg.Done()
			entry, err := newResolverEntry(lifecycle, c, apiServerID, dialTimeout)
			if err != nil {
				errs[i] = fmt.Errorf("httpSignature[%d]: %w", i, err)
				return
			}
			a.entries[i] = entry
		}(i, c)
	}
	wg.Wait()

	if err := utilerrors.NewAggregate(errs); err != nil {
		return nil, fmt.Errorf("httpsig: %w", err)
	}
	return a, nil
}

func newResolverEntry(lifecycle context.Context, c apiserver.HTTPSignatureAuthenticator, apiServerID string, dialTimeout time.Duration) (*resolverEntry, error) {
	maxAge := DefaultMaxAge
	if c.MaxAge != nil {
		maxAge = c.MaxAge.Duration
	}
	var tolerance time.Duration
	if c.Tolerance != nil {
		tolerance = c.Tolerance.Duration
	}

	remote, err := newRemote(lifecycle, c.Endpoint, apiServerID, dialTimeout)
	if err != nil {
		return nil, err
	}

	relayed := make([]string, 0, len(c.RelayedHeaders))
	for _, name := range c.RelayedHeaders {
		relayed = append(relayed, strings.ToLower(name))
	}

	// The zero value means Consume, so replay protection is on unless configuration
	// turns it off in so many words. This does not rely on a defaulting pass having
	// run, because AuthenticationConfiguration has none and a caller building this
	// struct directly should still get the safe behavior.
	consumeNonces := c.NonceHandling != apiserver.NonceHandlingIgnore
	if !consumeNonces {
		// Logged at default verbosity, and named, because a cluster running without
		// replay protection should be discoverable without reading a configuration
		// file off a control plane node.
		klog.InfoS("HTTP signature nonces will not be recorded; a captured request can be replayed within the maximum signature age",
			"resolver", c.Endpoint, "maxAge", maxAge, "tolerance", tolerance)
	}
	metrics.RecordNonceHandling(c.Endpoint, consumeNonces)

	return &resolverEntry{
		prefixes:       c.KeyIDPrefixes,
		relayedHeaders: relayed,
		keys:           newKeyCache(remote, c.Cache),
		consumeNonces:  consumeNonces,
		maxAge:         maxAge,
		tolerance:      tolerance,
	}, nil
}

// HealthChecks returns one checker per configured resolver.
func (a *Authenticator) HealthChecks() []func() error {
	checks := make([]func() error, 0, len(a.entries))
	for _, entry := range a.entries {
		checks = append(checks, entry.keys.resolver.Check)
	}
	return checks
}

// admits reports whether this entry is asked about a keyid.
func (e *resolverEntry) admits(keyName string) bool {
	if len(e.prefixes) == 0 {
		return true
	}
	for _, p := range e.prefixes {
		if keyName == p {
			return true
		}
	}
	return false
}

// policyFor returns the verification policy for one resolved key. The effective
// maximum age is the smallest of this entry's configured bound and whatever the
// resolver narrowed it to, so a resolver can tighten the window and never widen
// it.
func (e *resolverEntry) policyFor(k *verifierKey) httpsig.Policy {
	maxAge := e.maxAge
	if k.maxAge > 0 && k.maxAge < maxAge {
		maxAge = k.maxAge
	}
	return httpsig.Policy{
		// The floor is stated here, by this verifier, and not taken from the
		// signature.
		RequiredComponents: transporthttpsig.FloorComponents,
		// A positive maximum age is also what makes the created parameter
		// mandatory: the verifier rejects a signature it cannot age. Configuration
		// cannot reach a non-positive value, because maxAge is either unset and
		// defaulted or validated as positive, and a resolver can only narrow it.
		MaxAge:    maxAge,
		Tolerance: e.tolerance,
	}
}

// AuthenticateRequest verifies the request's signatures. It returns no opinion
// when the request carries none, so the next authenticator in the chain runs.
//
// A request is authenticated when at least one of its signatures satisfies
// everything here. Requiring every signature to verify would be trivially
// defeated by appending a garbage one.
func (a *Authenticator) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	// With no resolvers configured there is nothing that could resolve a key, so
	// this draws no opinion even about a request carrying a signature, and the rest
	// of the chain runs. Returning an error instead would make a stray Signature
	// header break authentication that has nothing to do with signatures.
	if len(a.entries) == 0 {
		return nil, false, nil
	}
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
	ctx := req.Context()

	// The keyid is an unverified claim until Verify succeeds. It is used only to
	// select a resolver and as an argument to it, never to grant anything. It is
	// bounded first, before it becomes a cache key or a resolver argument.
	keyID := sig.KeyID()
	if keyID == "" {
		return nil, fmt.Errorf("signature %q: carries no keyID", sig.Label())
	}
	if len(keyID) > maxKeyIDLen {
		return nil, fmt.Errorf("signature %q: keyID is %d bytes, limit %d", sig.Label(), len(keyID), maxKeyIDLen)
	}
	// A derived key's keyid carries its claimed scope after the name, joined by
	// slashes. Selection uses the name; the claimed scope is checked by the key
	// the resolver returns, not here.
	keyName, _, _ := strings.Cut(keyID, "/")

	var errs []error
	for _, entry := range a.entries {
		if !entry.admits(keyName) {
			continue
		}

		// Age is checked against this entry's widest bound before the resolver is
		// called, so a caller who has authenticated nothing cannot drive a lookup
		// with an ancient or future timestamp. Verify checks it again against the
		// effective bound, which a resolver may have narrowed, and that check is
		// the authoritative one.
		if err := checkAge(sig, entry.maxAge, entry.tolerance); err != nil {
			errs = append(errs, fmt.Errorf("signature %q: %w", sig.Label(), err))
			continue
		}

		relayed, err := collectRelayedHeaders(req, sig, entry.relayedHeaders)
		if err != nil {
			errs = append(errs, fmt.Errorf("signature %q: %w", sig.Label(), err))
			continue
		}

		key, err := entry.keys.get(ctx, ResolveRequest{
			KeyID:          keyID,
			Algorithm:      string(sig.Alg()),
			Created:        sig.Created(),
			RelayedHeaders: relayed,
		})
		switch {
		case errors.Is(err, ErrKeyNotFound):
			// This resolver does not serve this keyid. Try the next one.
			continue
		case err != nil:
			// A resolver that failed takes down only its own keys. Another
			// resolver may still serve this keyid.
			errs = append(errs, fmt.Errorf("signature %q: %w", sig.Label(), err))
			continue
		}

		resp, err := a.verify(ctx, req, sig, entry, key)
		if err != nil {
			errs = append(errs, fmt.Errorf("signature %q: %w", sig.Label(), err))
			continue
		}
		return resp, nil
	}

	if len(errs) == 0 {
		return nil, fmt.Errorf("signature %q: unknown keyID", sig.Label())
	}
	return nil, errors.Join(errs...)
}

// verify runs everything that has to hold for a resolved key to authenticate a
// request. The order is the security argument: the signature base is built from
// headers alone, so verification comes before anything that reads a body or calls
// out.
func (a *Authenticator) verify(ctx context.Context, req *http.Request, sig *httpsig.Signature, entry *resolverEntry, key *verifierKey) (*authenticator.Response, error) {
	verifier, err := key.verifierFor(sig)
	if err != nil {
		return nil, err
	}

	// The verifier carries the algorithm the resolver stated, and Verify rejects a
	// signature whose own alg parameter disagrees with it. That is what closes
	// algorithm confusion, and it is why the resolver's algorithm is authoritative
	// and the signature's is advisory.
	if err := sig.Verify(verifier, entry.policyFor(key)); err != nil {
		return nil, err
	}

	if err := checkProtectedHeaders(req, sig); err != nil {
		return nil, err
	}
	if err := checkBodyDigest(req, sig); err != nil {
		return nil, err
	}

	// Consumed last, so a request rejected for any other reason does not use up
	// the nonce of a legitimate request it copied, and so that a caller who cannot
	// produce a valid signature cannot reach the resolver's nonce store at all.
	if err := a.consumeNonce(ctx, entry, sig, key); err != nil {
		return nil, err
	}

	klog.V(4).InfoS("Authenticated request by HTTP message signature",
		"keyID", sig.KeyID(), "username", key.info.Name, "components", len(sig.Components()))
	return &authenticator.Response{User: key.info}, nil
}

// checkAge rejects a signature outside the accepted time window. It duplicates
// what the signing library's policy enforces, deliberately: this runs before a
// key is resolved and the library's runs after, and the point of the first is to
// keep an unauthenticated caller from driving a network call.
func checkAge(sig *httpsig.Signature, maxAge, tolerance time.Duration) error {
	created := sig.Created()
	if created.IsZero() {
		return errors.New("signature carries no created parameter, so its age cannot be bounded")
	}
	now := time.Now()
	if created.After(now.Add(tolerance)) {
		return fmt.Errorf("signature was created at %v, which is in the future", created)
	}
	if now.After(created.Add(maxAge + tolerance)) {
		return fmt.Errorf("signature was created at %v, older than the %v maximum age", created, maxAge)
	}
	return nil
}

// collectRelayedHeaders gathers the values a resolver is configured to see.
//
// A named header present on the request but not covered by the signature rejects
// the request without a lookup. Coverage is what stops an intermediary injecting
// a value that selects a different key, and the covered set is readable from
// Signature-Input without verifying anything, so this check is available before
// there is a key to verify with.
//
// A named header with more than one value is rejected rather than joined.
// Joining would invent a value nobody signed.
func collectRelayedHeaders(req *http.Request, sig *httpsig.Signature, names []string) (map[string]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	covered := coveredComponents(sig)
	out := make(map[string]string, len(names))
	for _, name := range names {
		values := req.Header.Values(name)
		switch {
		case len(values) == 0:
			// Absent is allowed. A resolver that needs the value says so by
			// failing to resolve without it.
			continue
		case len(values) > 1:
			return nil, fmt.Errorf("request carries %d values for the relayed header %s; a single value is required because there is no correct way to combine them", len(values), name)
		case !covered[name]:
			return nil, fmt.Errorf("request carries the relayed header %s, which the signature does not cover, so an intermediary could have set it", name)
		}
		out[name] = values[0]
	}
	return out, nil
}

// consumeNonce records the signature's nonce with the resolver.
//
// A resolver that fails rejects the request. Configuration can say not to record
// nonces at all, but it cannot say to accept a request whose nonce this server tried
// and failed to record: anti-replay that switches off when a call fails is not
// anti-replay, and an outage is not a policy decision.
//
// The nonce is required whether or not it is recorded. Requiring it costs a client
// nothing, it is covered by the signature either way, and it means turning recording
// on is a change to this server alone rather than to every client.
func (a *Authenticator) consumeNonce(ctx context.Context, entry *resolverEntry, sig *httpsig.Signature, key *verifierKey) error {
	nonce := sig.Nonce()
	if nonce == "" {
		return errors.New("signature carries no nonce")
	}
	if !entry.consumeNonces {
		return nil
	}
	created := sig.Created()
	maxAge := entry.maxAge
	if key.maxAge > 0 && key.maxAge < maxAge {
		maxAge = key.maxAge
	}
	return entry.keys.resolver.ConsumeNonce(ctx, NonceRequest{
		KeyID:   sig.KeyID(),
		Nonce:   nonce,
		Created: created,
		// The resolver may forget the nonce once no signature bearing it could be
		// accepted, which is the same bound Verify applied.
		ExpiresAt: created.Add(maxAge + entry.tolerance),
	})
}

func coveredComponents(sig *httpsig.Signature) map[string]bool {
	components := sig.Components()
	covered := make(map[string]bool, len(components))
	for _, c := range components {
		covered[c.Name] = true
	}
	return covered
}

// checkProtectedHeaders rejects a request carrying a protected header the
// signature does not cover. Without this, appending a header to a signed request
// is unnoticed.
func checkProtectedHeaders(req *http.Request, sig *httpsig.Signature) error {
	covered := coveredComponents(sig)
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
	covered := coveredComponents(sig)["content-digest"]

	if req.Body == nil || req.Body == http.NoBody {
		// No body to bind. A Content-Digest on a bodiless request is checked
		// below only if one was sent, so an empty request cannot smuggle one.
		if len(digests) > 0 {
			return checkDigestValues(digests, covered, nil)
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
	return checkDigestValues(digests, covered, body)
}

func checkDigestValues(digests []string, covered bool, body []byte) error {
	if len(digests) == 0 {
		return fmt.Errorf("request has a body but no Content-Digest, so the body is not bound to the signature")
	}
	if !covered {
		return fmt.Errorf("request has a Content-Digest the signature does not cover, so the body is not bound to the signature")
	}
	return transporthttpsig.VerifyContentDigest(digests, body)
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
