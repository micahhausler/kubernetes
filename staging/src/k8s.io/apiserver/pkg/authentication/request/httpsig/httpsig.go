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
//
// # Resolving a signature to an identity
//
// Everything above is about checking a signature. Deciding whose signature it is
// is a separate question, and it has more than one answer, so it sits behind the
// resolver seam rather than inline. A resolver takes a signature and returns a
// verifier plus a way to name the signer.
//
// Two backends are built in, and neither states an identity in configuration. The
// resolver backend asks a process, over a local socket, which answers for a keyID
// with a key and the identity it authenticates as, and which records the nonces
// accepted signatures carry. The certificate backend takes key and identity from an
// X.509 certificate the request carries, which the configured trust anchors have to
// validate.
//
// The difference that matters is what the server depends on at request time. The
// resolver backend depends on a process being reachable, and gets revocation and
// replay protection across API servers from it. The certificate backend depends on
// nothing beyond a trust anchor bundle, and gets neither: a certificate's lifetime
// is the withdrawal window, and nothing records nonces.
//
// Which backend handles a signature is decided before any work is done for it,
// never by whether an unsigned header happens to be present. For a resolver it is
// the keyid, and a signature's parameters are always the last line of its signature
// base, so a keyid is covered by every signature that carries one. That is also what
// binds a certificate to the signature made with it, and it is why the certificate
// header's own coverage is belt and braces rather than the mechanism. For a
// certificate it is the presented leaf's authorityKeyIdentifier, which names the
// trust anchor that issued it and so names the one backend configured to validate
// it.
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
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/pkg/authentication/request/httpsig/metrics"

	transporthttpsig "k8s.io/client-go/transport/httpsig"
	"k8s.io/klog/v2"
)

const (
	// defaultMaxAge bounds signature age when configuration does not. It also
	// bounds replay: a captured request can be resent until it ages out.
	defaultMaxAge = 5 * time.Minute

	// maxBodyBytes caps the body read to check a Content-Digest. It matches the
	// API server's default request body limit, so a request this verifier
	// rejects for size is one the server would have rejected anyway.
	maxBodyBytes = int64(3 * 1024 * 1024)

	// maxSignatures caps how many signatures on one request are considered.
	//
	// A request may legitimately carry more than one, which is what the tag
	// parameter exists to disambiguate, but the count is chosen by the sender and
	// each one costs a signature base and possibly a signature verification. The
	// signing library imposes no bound of its own. Four is well past any use this
	// verifier has: a client produces one, and an intermediary annotating a request
	// produces one more.
	maxSignatures = 4

	// maxKeyIDLen bounds the keyID before it is used for anything. It reaches a
	// cache key and a resolver argument, and it is chosen by a caller who has
	// authenticated nothing.
	maxKeyIDLen = 256
)

// errNoSignature reports a request carrying no signature at all. The union
// authenticator moves on, so this never reaches a client.
var errNoSignature = errors.New("request carries no HTTP message signature")

// A backend decides whose signature a signature is: it produces a verifier to check
// it with, and a way to name the signer once it has checked out.
//
// One per way of doing that, which is what the API's resolver and x509 select
// between. "backend" rather than "resolver" because resolver is one of the two, and
// the word cannot mean both the pair and one of the pair.
//
// This is the seam a remote resolution scheme plugs into. It exists as an interface
// rather than as branches through one function because a certificate authority and a
// key broker differ only here, and everything around them, the coverage rules, the
// digest check, the replay window, is the same either way.
type backend interface {
	// name is the configured authenticator name, used in errors and as a metric
	// label. It never appears on the wire.
	name() string

	// handles reports whether this backend claims a signature, and it is asked
	// before any work is done for it.
	//
	// presented is the certificate the request carries, nil when it carries none. A
	// resolver decides on the keyid alone, which is covered by the signature. A
	// certificate backend decides on the presented leaf's authorityKeyIdentifier,
	// which is not covered, but that is a routing hint rather than a trust decision:
	// the chain build still has to succeed against this backend's own anchors.
	//
	// At most one certificate backend claims a signature. More than one resolver
	// may: keyid prefixes are unique across resolvers, but one may omit them and be
	// asked about every keyid.
	handles(sig *httpsig.Signature, presented *presentedCertificate) bool

	// resolve returns what is needed to check the signature and name its signer.
	// It runs before the signature has been checked, so anything expensive
	// belongs in the returned resolution's identify rather than here.
	//
	// It is called only for a signature this backend claimed.
	resolve(req *http.Request, sig *httpsig.Signature, presented *presentedCertificate) (*resolution, error)
}

// A resolution is one resolver's answer for one signature.
type resolution struct {
	// verifier checks the signature.
	verifier httpsig.Verifier

	// policy is the coverage, age, and skew policy the signature is held to.
	policy httpsig.Policy

	// identify names the signer. It runs only after the signature has verified,
	// which is what lets a resolver put work here that an unauthenticated caller
	// must not be able to cause: proof of possession comes first, trust second.
	identify func(context.Context) (*authenticator.Response, error)
}

// Authenticator verifies HTTP message signatures on incoming requests.
type Authenticator struct {
	backends  []backend
	parseOpts *httpsig.ParseOptions
}

var _ authenticator.Request = &Authenticator{}

// New builds an Authenticator from configuration. Trust anchors and CEL
// expressions are parsed and compiled here, and each resolver process is dialed
// and asked for its metadata, so a malformed configuration or an absent resolver
// fails at server start rather than on a request.
//
// The connections and each resolver's metadata refresh live for as long as
// lifecycle. dialTimeout bounds the first metadata call to each resolver.
// Backends are built concurrently, so it bounds this function
// rather than being multiplied by the number of them: built sequentially, a list
// of resolvers that were all absent would take the dial budget times the length of
// the list to report, which at server start reads as a hang rather than an error.
func New(lifecycle context.Context, config *apiserver.HTTPSignatureConfig, compiler authenticationcel.Compiler, apiServerID string, dialTimeout time.Duration) (*Authenticator, error) {
	if config == nil {
		return nil, fmt.Errorf("httpsig: configuration is required")
	}
	if compiler == nil {
		compiler = authenticationcel.NewDefaultCompiler()
	}
	metrics.RegisterMetrics()

	a := &Authenticator{}
	// Authority and scheme are read once, here, because they are consumed when a
	// request's signatures are parsed, before any resolver has been chosen. That
	// is why they are configured for the server rather than per authenticator.
	if config.Scheme != "" || config.Authority != "" {
		a.parseOpts = &httpsig.ParseOptions{Scheme: config.Scheme, Authority: config.Authority}
	}

	// Read once, for the same reason as authority and scheme: it describes this
	// server rather than any one authenticator.
	var maxClockSkew time.Duration
	if config.MaxClockSkew != nil {
		maxClockSkew = config.MaxClockSkew.Duration
	}

	seen := map[string]bool{}
	for i, c := range config.Authenticators {
		if seen[c.Name] {
			return nil, fmt.Errorf("httpsig: authenticators[%d]: duplicate name %q", i, c.Name)
		}
		seen[c.Name] = true
	}

	a.backends = make([]backend, len(config.Authenticators))
	errs := make([]error, len(config.Authenticators))
	var wg sync.WaitGroup
	for i, c := range config.Authenticators {
		wg.Add(1)
		go func(i int, c apiserver.HTTPSignatureAuthenticator) {
			defer wg.Done()
			r, err := newBackend(lifecycle, c, maxClockSkew, compiler, apiServerID, dialTimeout)
			if err != nil {
				errs[i] = fmt.Errorf("authenticators[%d] (%s): %w", i, c.Name, err)
				return
			}
			a.backends[i] = r
		}(i, c)
	}
	wg.Wait()
	if err := utilerrors.NewAggregate(errs); err != nil {
		return nil, fmt.Errorf("httpsig: %w", err)
	}

	if len(a.backends) == 0 {
		return nil, fmt.Errorf("httpsig: at least one authenticator is required for this authenticator to authenticate anything")
	}
	if err := checkAnchorsAreNotShared(a.backends); err != nil {
		return nil, fmt.Errorf("httpsig: %w", err)
	}
	return a, nil
}

// checkAnchorsAreNotShared refuses two certificate authenticators holding one
// authority key.
//
// A presented certificate names its issuer by key identifier and that is what
// selects an authenticator, so two holding the same one would both be selected and
// which identity the certificate received would depend on list order. Configuration
// validation refuses this too. It is checked again here for the same reason
// duplicate names are: a caller building this struct directly has run no validation,
// and the failure this prevents is a silent, order-dependent choice of identity
// rather than an error.
func checkAnchorsAreNotShared(backends []backend) error {
	// Each records who claimed a value and which of their certificates carried it,
	// so a collision names both sides rather than only the one found second.
	byIdentifier := map[string]anchorClaim{}
	byKey := map[string]anchorClaim{}
	for _, b := range backends {
		c, ok := b.(*x509Backend)
		if !ok {
			continue
		}
		// Two certificates for one key held by one authenticator is a certificate
		// authority mid-rollover, which is one trust decision, so a repeat under the
		// same name is not a conflict.
		for _, shared := range []struct {
			owners map[string]anchorClaim
			claims map[string]anchorClaim
			what   string
			why    string
		}{
			{byIdentifier, c.anchorSKIs, "the same subjectKeyIdentifier",
				"a presented certificate names its issuer by that identifier, so both would be selected by the same certificate"},
			{byKey, c.anchorKeys, "the same public key",
				"one authority key can be stamped with two different subjectKeyIdentifiers, so both bundles would validate the same certificate"},
		} {
			for value, claim := range shared.claims {
				claim.authenticator = c.authenticatorName
				if held, taken := shared.owners[value]; taken && held.authenticator != c.authenticatorName {
					// Both sides are named, because naming one sends the operator to
					// whichever bundle happened to be enumerated first. The likeliest
					// cause is one organizational root left in both, so the error
					// names the way out rather than only the collision.
					return fmt.Errorf("authenticators %q and %q hold trust anchors with %s: %s and %s; %s, and which "+
						"identity it received would depend on the order they are configured. If they share an organizational "+
						"root, put each intermediate in its own bundle and leave the root out: an entry in a bundle is a "+
						"trust anchor whether or not something above it signed it",
						held.authenticator, c.authenticatorName, shared.what, held, claim, shared.why)
				}
				shared.owners[value] = claim
			}
		}
	}
	return nil
}

// HealthChecks returns one checker per configured resolver process. A certificate
// authenticator contributes none: it calls nothing that could be unhealthy.
func (a *Authenticator) HealthChecks() []func() error {
	var checks []func() error
	for _, r := range a.backends {
		if e, ok := r.(*resolverBackend); ok {
			checks = append(checks, e.keys.resolver.Check)
		}
	}
	return checks
}

// newResolver builds the one resolver an authenticator configuration names.
//
// maxClockSkew comes from the section rather than from c: it is this server's
// allowance for its own clock, so every authenticator is held to the same one.
func newBackend(lifecycle context.Context, c apiserver.HTTPSignatureAuthenticator, maxClockSkew time.Duration, compiler authenticationcel.Compiler, apiServerID string, dialTimeout time.Duration) (backend, error) {
	policy := httpsig.Policy{
		// The floor is stated here, by this verifier, and not taken from the
		// signature.
		RequiredComponents: transporthttpsig.FloorComponents,
		MaxAge:             defaultMaxAge,
		Tolerance:          maxClockSkew,
	}
	if c.MaxAge != nil {
		policy.MaxAge = c.MaxAge.Duration
	}

	switch {
	case c.Resolver != nil && c.X509 != nil:
		return nil, fmt.Errorf("resolver and x509 are alternatives: a resolver states the identity with each answer, x509 takes it from a certificate")
	case c.X509 != nil:
		return newX509Backend(c, policy, compiler)
	case c.Resolver != nil:
		return newResolverBackend(lifecycle, c, policy, compiler, apiServerID, dialTimeout)
	default:
		return nil, fmt.Errorf("one of resolver or x509 is required")
	}
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
		metrics.RecordUnclaimedSignature(metrics.UnclaimedUnparseableSignature)
		return nil, false, fmt.Errorf("parsing HTTP message signature: %w", err)
	}
	if len(sigs) == 0 {
		// The fields were present but held no signature. Still an error rather
		// than no opinion: something set them, and silently ignoring that would
		// let a malformed client look like an anonymous one.
		metrics.RecordUnclaimedSignature(metrics.UnclaimedUnparseableSignature)
		return nil, false, errNoSignature
	}
	if len(sigs) > maxSignatures {
		// Refused rather than truncated. Considering the first few would let a
		// sender bury the signature they meant behind ones they did not, and the
		// request would fail for a reason nothing explains.
		metrics.RecordUnclaimedSignature(metrics.UnclaimedUnparseableSignature)
		return nil, false, fmt.Errorf("request carries %d signatures, more than the %d this server considers",
			len(sigs), maxSignatures)
	}

	// The certificate a request carries is read once, before any authenticator is
	// chosen, because which one answers is decided by the leaf's
	// authorityKeyIdentifier. A request whose signatures name no certificate never
	// touches the header.
	var presented *presentedCertificate
	if namesACertificate(sigs) {
		var err error
		if presented, err = parsePresentedCertificate(req); err != nil {
			reason := metrics.UnclaimedUnreadableCertificate
			if errors.Is(err, errNoAuthorityKeyID) {
				// A well-formed certificate this server cannot route, which is a
				// different thing to fix from a malformed one.
				reason = metrics.UnclaimedCertificateWithoutAuthorityKeyID
			}
			metrics.RecordUnclaimedSignature(reason)
			return nil, false, fmt.Errorf("the request's signature names a certificate: %w", err)
		}
	}

	var errs []error
	for _, sig := range sigs {
		for _, r := range a.backends {
			// Dispatch. At most one certificate authenticator claims a signature,
			// and a keyid a resolver holds is never offered to another, so an
			// outcome recorded below is a decision by an authenticator that owned
			// the credential rather than one that was merely asked.
			if !r.handles(sig, presented) {
				continue
			}
			resp, outcome, err := a.authenticateSignature(req, sig, r, presented)
			if err != nil {
				// A resolver that does not serve this keyid has decided nothing.
				// Recording it as a refusal would make a correct configuration
				// report one on every request, and it is already visible as a
				// negative cache hit for that resolver.
				if !errors.Is(err, ErrKeyNotFound) {
					metrics.RecordOutcome(r.name(), outcome)
				}
				errs = append(errs, fmt.Errorf("%s: %w", r.name(), err))
				continue
			}
			metrics.RecordOutcome(r.name(), metrics.OutcomeAuthenticated)
			// The signature fields and the asserted certificate have served
			// their purpose. Clearing them keeps anything downstream from
			// treating them as credentials, the way the bearer token and front
			// proxy authenticators clear theirs.
			req.Header.Del("Signature")
			req.Header.Del("Signature-Input")
			req.Header.Del(transporthttpsig.CertificateHeader)
			return resp, true, nil
		}
	}
	if len(errs) == 0 {
		// Signatures were present, but no authenticator claimed any of them.
		// Reporting this as "no signature" would send the reader looking at the
		// client's signing code instead.
		if presented != nil {
			// A certificate is selected by the anchor its authorityKeyIdentifier
			// names, so "no authenticator claimed it" means no configured bundle
			// holds that anchor. Said that way rather than as a keyid mismatch,
			// because the keyid is correct and the authority is what is missing:
			// most often a certificate authority rotation that has not reached this
			// server's configuration.
			metrics.RecordUnclaimedSignature(metrics.UnclaimedUnknownCertificateIssuer)
			// The key identifier is in the error because it is what an operator adds
			// to a bundle to fix this, and it cannot be a metric label: a peer
			// chooses it, so it is unbounded cardinality.
			return nil, false, fmt.Errorf("no configured authenticator holds the trust anchor that issued the certificate "+
				"the request carries, so nothing here can validate it: no bundle contains a certificate with "+
				"subjectKeyIdentifier %x (%s)", presented.authorityKeyID, certificateIdentifier(presented.leaf))
		}
		// No backend's prefixes admitted the keyid, so nothing was asked. That is
		// this server's configuration rather than the client's keyid, which is why
		// it is counted apart from a resolver answering that it does not serve one.
		metrics.RecordUnclaimedSignature(metrics.UnclaimedUnknownKeyID)
		keyIDs := make([]string, 0, len(sigs))
		for _, sig := range sigs {
			keyIDs = append(keyIDs, fmt.Sprintf("%q", sig.KeyID()))
		}
		return nil, false, fmt.Errorf("no configured authenticator handles the keyid of any signature on this request: %s",
			strings.Join(keyIDs, ", "))
	}
	// Every error here is a resolver that was asked and answered that it does not
	// serve the keyID, since anything else was recorded as an outcome above.
	if allKeysNotFound(errs) {
		metrics.RecordUnclaimedSignature(metrics.UnclaimedUnservedKeyID)
	}
	return nil, false, fmt.Errorf("no valid HTTP message signature: %w", errors.Join(errs...))
}

// allKeysNotFound reports whether every failure was a resolver saying it does not
// serve the keyID, as opposed to any authenticator refusing the signature.
func allKeysNotFound(errs []error) bool {
	for _, err := range errs {
		if !errors.Is(err, ErrKeyNotFound) {
			return false
		}
	}
	return len(errs) > 0
}

// timeAwareOutcome separates the two ways a signature can fall outside its accepted
// window from whatever else went wrong, returning otherwise for anything that is not
// a time failure.
func timeAwareOutcome(err error, otherwise string) string {
	switch {
	case errors.Is(err, httpsig.ErrCreatedInFuture):
		return metrics.OutcomeClockSkew
	case errors.Is(err, httpsig.ErrExpired):
		return metrics.OutcomeExpired
	default:
		return otherwise
	}
}

// anchorClaim is one certificate an authenticator holds, for naming both sides of a
// collision. The subjectKeyIdentifier is included because two certificates for one
// reissued authority usually share a subject, so the subject alone would not tell an
// operator which file to open.
type anchorClaim struct {
	authenticator string
	subject       string
	subjectKeyID  string
}

func (a anchorClaim) String() string {
	return fmt.Sprintf("%q (subjectKeyIdentifier %x)", a.subject, a.subjectKeyID)
}

// namesACertificate reports whether any signature's keyid is in the certificate
// form, which is what makes the certificate header worth reading.
func namesACertificate(sigs []*httpsig.Signature) bool {
	for _, sig := range sigs {
		if strings.HasPrefix(sig.KeyID(), transporthttpsig.CertificateKeyIDPrefix) {
			return true
		}
	}
	return false
}

// authenticateSignature checks one signature against one backend that claimed it.
// It returns the outcome alongside the error so the caller can record it, which is
// always worth doing now that a backend is only asked about a credential it owns.
func (a *Authenticator) authenticateSignature(req *http.Request, sig *httpsig.Signature, b backend, presented *presentedCertificate) (*authenticator.Response, string, error) {
	res, err := b.resolve(req, sig, presented)
	if err != nil {
		// resolve applies the age window before looking a key up, to keep an
		// unauthenticated caller from driving a network call with an ancient or
		// future timestamp, so a time failure can surface here as well as from
		// Verify. It is the same condition either way and counted the same way.
		return nil, timeAwareOutcome(err, metrics.OutcomeUnresolved), fmt.Errorf("signature %q: %w", sig.Label(), err)
	}

	// Verify before anything that costs work: the signature base is built from
	// headers alone, so an unauthenticated caller cannot make this server read a
	// body, build a certificate chain, or evaluate an expression.
	if err := sig.Verify(res.verifier, res.policy); err != nil {
		return nil, timeAwareOutcome(err, metrics.OutcomeBadSignature), fmt.Errorf("signature %q: %w", sig.Label(), err)
	}

	if err := checkProtectedHeaders(req, sig); err != nil {
		return nil, metrics.OutcomeUncoveredHeader, fmt.Errorf("signature %q: %w", sig.Label(), err)
	}
	if err := checkBodyDigest(req, sig); err != nil {
		return nil, metrics.OutcomeBadDigest, fmt.Errorf("signature %q: %w", sig.Label(), err)
	}

	// The resolver's own work, which it is only allowed to do for a caller that
	// has proved possession of the key.
	resp, err := res.identify(req.Context())
	if err != nil {
		return nil, metrics.OutcomeRejectedIdentity, fmt.Errorf("signature %q: %w", sig.Label(), err)
	}

	klog.V(4).InfoS("Authenticated request by HTTP message signature",
		"authenticator", b.name(), "keyID", sig.KeyID(), "username", resp.User.GetName(),
		"components", len(sig.Components()))
	return resp, metrics.OutcomeAuthenticated, nil
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
