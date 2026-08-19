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
// Two are built in, and neither states an identity in configuration. The endpoint
// resolver asks a resolver process, over a local socket, which answers for a keyID
// with a key and the identity it authenticates as, and which records the nonces
// accepted signatures carry. The certificate resolver takes key and identity from
// an X.509 certificate the request carries, which the configured trust anchors have
// to validate.
//
// The difference that matters is what the server depends on at request time. The
// endpoint resolver depends on a resolver being reachable, and gets revocation and
// replay protection across API servers from it. The certificate resolver depends on
// nothing beyond a trust anchor bundle, and gets neither: a certificate's lifetime
// is the withdrawal window, and nothing records nonces.
//
// Which resolver handles a signature is decided by its keyid, never by whether an
// unsigned header happens to be present. A signature's parameters are always the
// last line of its signature base, so a keyid is covered by every signature that
// carries one. That is also what binds a certificate to the signature made with
// it, and it is why the certificate header's own coverage is belt and braces
// rather than the mechanism.
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

// A resolver decides whose signature a signature is: it produces a verifier to
// check it with, and a way to name the signer once it has checked out.
//
// This is the seam a remote resolution scheme plugs into. It exists as an
// interface rather than as branches through one function because a certificate
// authority and a key broker differ only here, and everything around them, the
// coverage rules, the digest check, the replay window, is the same either way.
type resolver interface {
	// name identifies this resolver in errors and metrics. It never appears on
	// the wire.
	name() string

	// handles reports whether this resolver claims a signature, judged by its
	// keyid alone. The keyid is covered by the signature, so this decision is
	// made on signed input, and it is made before any work.
	//
	// More than one resolver may claim the same keyid, which is how several
	// certificate authorities coexist: each is tried until one resolves.
	handles(keyID string) bool

	// resolve returns what is needed to check the signature and name its signer.
	// It runs before the signature has been checked, so anything expensive
	// belongs in the returned resolution's identify rather than here.
	resolve(req *http.Request, sig *httpsig.Signature) (*resolution, error)
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
	resolvers []resolver
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
// Endpoint authenticators are built concurrently, so it bounds this function
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

	seen := map[string]bool{}
	for i, c := range config.Authenticators {
		if seen[c.Name] {
			return nil, fmt.Errorf("httpsig: authenticators[%d]: duplicate name %q", i, c.Name)
		}
		seen[c.Name] = true
	}

	a.resolvers = make([]resolver, len(config.Authenticators))
	errs := make([]error, len(config.Authenticators))
	var wg sync.WaitGroup
	for i, c := range config.Authenticators {
		wg.Add(1)
		go func(i int, c apiserver.HTTPSignatureAuthenticator) {
			defer wg.Done()
			r, err := newResolver(lifecycle, c, compiler, apiServerID, dialTimeout)
			if err != nil {
				errs[i] = fmt.Errorf("authenticators[%d] (%s): %w", i, c.Name, err)
				return
			}
			a.resolvers[i] = r
		}(i, c)
	}
	wg.Wait()
	if err := utilerrors.NewAggregate(errs); err != nil {
		return nil, fmt.Errorf("httpsig: %w", err)
	}

	if len(a.resolvers) == 0 {
		return nil, fmt.Errorf("httpsig: at least one authenticator is required for this authenticator to authenticate anything")
	}
	return a, nil
}

// HealthChecks returns one checker per configured resolver process. A certificate
// authenticator contributes none: it calls nothing that could be unhealthy.
func (a *Authenticator) HealthChecks() []func() error {
	var checks []func() error
	for _, r := range a.resolvers {
		if e, ok := r.(*endpointResolver); ok {
			checks = append(checks, e.keys.resolver.Check)
		}
	}
	return checks
}

// newResolver builds the one resolver an authenticator configuration names.
func newResolver(lifecycle context.Context, c apiserver.HTTPSignatureAuthenticator, compiler authenticationcel.Compiler, apiServerID string, dialTimeout time.Duration) (resolver, error) {
	policy := httpsig.Policy{
		// The floor is stated here, by this verifier, and not taken from the
		// signature.
		RequiredComponents: transporthttpsig.FloorComponents,
		MaxAge:             defaultMaxAge,
	}
	if c.MaxAge != nil {
		policy.MaxAge = c.MaxAge.Duration
	}
	if c.Tolerance != nil {
		policy.Tolerance = c.Tolerance.Duration
	}

	switch {
	case c.X509 != nil && len(c.Endpoint) > 0:
		return nil, fmt.Errorf("endpoint and x509 are alternatives: a resolver states the identity with each answer, x509 takes it from a certificate")
	case c.X509 != nil:
		return newCertificateResolver(c, policy, compiler)
	case len(c.Endpoint) > 0:
		return newEndpointResolver(lifecycle, c, policy, apiServerID, dialTimeout)
	default:
		return nil, fmt.Errorf("one of endpoint or x509 is required")
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
		return nil, false, fmt.Errorf("parsing HTTP message signature: %w", err)
	}
	if len(sigs) == 0 {
		// The fields were present but held no signature. Still an error rather
		// than no opinion: something set them, and silently ignoring that would
		// let a malformed client look like an anonymous one.
		return nil, false, errNoSignature
	}
	if len(sigs) > maxSignatures {
		// Refused rather than truncated. Considering the first few would let a
		// sender bury the signature they meant behind ones they did not, and the
		// request would fail for a reason nothing explains.
		return nil, false, fmt.Errorf("request carries %d signatures, more than the %d this server considers",
			len(sigs), maxSignatures)
	}

	var errs []error
	// Outcomes are buffered and recorded only if nothing authenticates the
	// request. A signature is offered to every authenticator whose keyid form it
	// matches, so with more than one certificate authenticator configured, a
	// client's certificate chains to one and fails against the rest. Recording
	// those attempts as they happen would make a correct configuration report a
	// rejection on every request, which is a metric nobody could read.
	var rejected []rejection
	authenticated := false
	defer func() {
		if authenticated {
			return
		}
		for _, r := range rejected {
			metrics.RecordOutcome(r.authenticator, r.outcome)
		}
	}()

	for _, sig := range sigs {
		for _, r := range a.resolvers {
			// The keyid decides which resolvers even look at this signature, so
			// a signature naming a key one resolver holds is never offered to
			// another.
			if !r.handles(sig.KeyID()) {
				continue
			}
			resp, outcome, err := a.authenticateSignature(req, sig, r)
			if err != nil {
				rejected = append(rejected, rejection{r.name(), outcome})
				errs = append(errs, fmt.Errorf("%s: %w", r.name(), err))
				continue
			}
			authenticated = true
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
		// Signatures were present, but no authenticator claimed any of them. The
		// keyids are named because the answer is nearly always that one is
		// misspelled, or that the authenticator holding it is not configured on
		// this server. Reporting this as "no signature" would send the reader
		// looking at the client's signing code instead.
		keyIDs := make([]string, 0, len(sigs))
		for _, sig := range sigs {
			keyIDs = append(keyIDs, fmt.Sprintf("%q", sig.KeyID()))
		}
		return nil, false, fmt.Errorf("no configured authenticator handles the keyid of any signature on this request: %s",
			strings.Join(keyIDs, ", "))
	}
	return nil, false, fmt.Errorf("no valid HTTP message signature: %w", errors.Join(errs...))
}

// rejection is one authenticator's refusal of one signature, held until the
// request's fate is known.
type rejection struct {
	authenticator string
	outcome       string
}

// authenticateSignature checks one signature against one resolver. It returns the
// outcome alongside the error so the caller can decide whether the attempt is
// worth recording: a failure against one of several certificate authenticators is
// the ordinary case, not a signal.
func (a *Authenticator) authenticateSignature(req *http.Request, sig *httpsig.Signature, r resolver) (*authenticator.Response, string, error) {
	res, err := r.resolve(req, sig)
	if err != nil {
		return nil, metrics.OutcomeUnresolved, fmt.Errorf("signature %q: %w", sig.Label(), err)
	}

	// Verify before anything that costs work: the signature base is built from
	// headers alone, so an unauthenticated caller cannot make this server read a
	// body, build a certificate chain, or evaluate an expression.
	if err := sig.Verify(res.verifier, res.policy); err != nil {
		return nil, metrics.OutcomeBadSignature, fmt.Errorf("signature %q: %w", sig.Label(), err)
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
		"authenticator", r.name(), "keyID", sig.KeyID(), "username", resp.User.GetName(),
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
