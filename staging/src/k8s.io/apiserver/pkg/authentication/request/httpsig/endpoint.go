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
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/micahhausler/httpsig"

	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/pkg/authentication/request/httpsig/metrics"
	transporthttpsig "k8s.io/client-go/transport/httpsig"
	"k8s.io/klog/v2"
)

// resolverBackend resolves a signature through a resolver process reached over a
// local socket. The resolver holds the key material and the nonce state; this
// server holds neither, and does all of the cryptography itself.
//
// Everything a resolver is told before a signature has verified is peer-chosen:
// the keyID, the claimed algorithm, the created timestamp, and any relayed header
// value. They are lookup input and never authorization. The one call that happens
// after verification, recording the nonce, is therefore the only one an
// unauthenticated caller cannot reach.
type resolverBackend struct {
	// authenticatorName is the configured authenticator name, used in errors and as a
	// metric label. It never appears on the wire.
	authenticatorName string

	// prefixes admit a keyID by the segment before its first slash. Empty means
	// every keyID.
	prefixes []string

	// relayedHeaders are the lowercase names of headers relayed with a lookup.
	relayedHeaders []string

	keys *keyCache

	// consumeNonces is false when configuration says to ignore them. It gates one
	// thing only: whether the resolver is asked to record the nonce. The signature
	// is still required to carry one either way, so turning this on later needs no
	// change at any client.
	consumeNonces bool

	// policy is the coverage, age, and skew policy from configuration. A resolver
	// may narrow the age, per resolver or per key; nothing widens it.
	policy httpsig.Policy

	// userRules are the cluster's say over what this resolver may claim, nil when
	// configuration states none. They run after the signature has verified, so an
	// unauthenticated caller cannot drive CEL evaluation, which also means they run
	// per accepted request rather than once per cached key. That is the same order
	// the certificate path uses and the cost is bounded by the authenticated
	// request rate.
	userRules authenticationcel.UserMapper
}

var _ backend = &resolverBackend{}

// newResolverBackend dials the resolver and fetches its metadata, so a resolver
// that is absent or unusable fails at server start rather than on a request.
func newResolverBackend(lifecycle context.Context, c apiserver.HTTPSignatureAuthenticator, policy httpsig.Policy, compiler authenticationcel.Compiler, apiServerID string, dialTimeout time.Duration) (*resolverBackend, error) {
	cfg := c.Resolver
	remote, err := newRemote(lifecycle, cfg.Endpoint, apiServerID, dialTimeout)
	if err != nil {
		return nil, err
	}

	relayed := make([]string, 0, len(cfg.RelayedHeaders))
	for _, name := range cfg.RelayedHeaders {
		relayed = append(relayed, strings.ToLower(name))
	}

	// The zero value means Consume, so replay protection is on unless configuration
	// turns it off in so many words. This does not rely on a defaulting pass having
	// run, because AuthenticationConfiguration has none and a caller building this
	// struct directly should still get the safe behavior.
	userRules, err := CompileUserValidationRules(compiler, c.UserValidationRules)
	if err != nil {
		return nil, err
	}

	consumeNonces := cfg.NonceHandling != apiserver.NonceHandlingIgnore
	if !consumeNonces {
		// Logged at default verbosity, and named, because a cluster running without
		// replay protection should be discoverable without reading a configuration
		// file off a control plane node.
		klog.InfoS("HTTP signature nonces will not be recorded; a captured request can be replayed within the maximum signature age",
			"authenticator", c.Name, "resolver", cfg.Endpoint, "maxAge", policy.MaxAge, "tolerance", policy.Tolerance)
	}
	metrics.RecordNonceHandling(cfg.Endpoint, consumeNonces)

	return &resolverBackend{
		authenticatorName: c.Name,
		prefixes:          cfg.KeyIDPrefixes,
		relayedHeaders:    relayed,
		keys:              newKeyCache(remote, cfg.Cache),
		consumeNonces:     consumeNonces,
		policy:            policy,
		userRules:         userRules,
	}, nil
}

func (r *resolverBackend) name() string { return r.authenticatorName }

// handles reports whether this resolver is asked about a keyID. The keyID is
// bounded here, before it becomes a cache key or a resolver argument, because it
// is chosen by a caller who has authenticated nothing.
//
// The presented certificate is ignored: a resolver answers for keyIDs, and the
// certificate keyID form is refused below whatever the configured prefixes are.
// Without that refusal, a resolver configured with no prefixes would be asked about
// every keyID including a certificate's, and which of it and a certificate
// authenticator answered a certificate-signed request would depend on the order the
// two appear in the configuration file. The reservation used to be enforced against
// the static key list; the resolver is where it has to live now, because a
// resolver's keyIDs are not in the file to be checked.
//
// A derived key's keyID carries its claimed scope after the name, joined by
// slashes. Selection uses the name; the claimed scope is checked against the key
// the resolver returns, not here.
func (r *resolverBackend) handles(sig *httpsig.Signature, _ *presentedCertificate) bool {
	keyID := sig.KeyID()
	if keyID == "" || len(keyID) > maxKeyIDLen {
		return false
	}
	if strings.HasPrefix(keyID, transporthttpsig.CertificateKeyIDPrefix) {
		return false
	}
	if len(r.prefixes) == 0 {
		return true
	}
	keyName, _, _ := strings.Cut(keyID, "/")
	for _, p := range r.prefixes {
		if keyName == p {
			return true
		}
	}
	return false
}

// resolve looks the signature's keyID up with the resolver, through the cache.
//
// The age check here duplicates what the returned policy enforces, deliberately.
// This one runs before the lookup and the policy's runs after verification; the
// point of the first is to keep an unauthenticated caller from driving a network
// call with an ancient or future timestamp. The second is the authoritative one,
// because it applies the bound the resolver may have narrowed.
func (r *resolverBackend) resolve(req *http.Request, sig *httpsig.Signature, _ *presentedCertificate) (*resolution, error) {
	if err := checkAge(sig, r.policy.MaxAge, r.policy.Tolerance); err != nil {
		return nil, err
	}

	relayed, err := collectRelayedHeaders(req, sig, r.relayedHeaders)
	if err != nil {
		return nil, err
	}

	key, err := r.keys.get(req.Context(), ResolveRequest{
		KeyID:          sig.KeyID(),
		Algorithm:      string(sig.Alg()),
		Created:        sig.Created(),
		RelayedHeaders: relayed,
	})
	if err != nil {
		return nil, err
	}

	// The verifier carries the algorithm the resolver stated, and Verify rejects a
	// signature whose own alg parameter disagrees with it. That is what closes
	// algorithm confusion, and it is why the resolver's algorithm is authoritative
	// and the signature's is advisory.
	verifier, err := key.verifierFor(sig)
	if err != nil {
		return nil, err
	}

	return &resolution{
		verifier: verifier,
		policy:   r.policyFor(key),
		identify: func(ctx context.Context) (*authenticator.Response, error) {
			// Before the nonce is recorded, so an identity the cluster refuses does
			// not consume one. A rejected request that burned a nonce would make the
			// same request fail differently on a retry.
			if r.userRules != nil {
				if err := evaluateUserRules(ctx, r.userRules, key.info); err != nil {
					return nil, err
				}
			}
			if err := r.consumeNonce(ctx, sig, key); err != nil {
				return nil, err
			}
			return &authenticator.Response{User: key.info}, nil
		},
	}, nil
}

// policyFor returns the verification policy for one resolved key. The effective
// maximum age is the smallest of the configured bound and whatever the resolver
// narrowed it to, so a resolver can tighten the window and never widen it.
func (r *resolverBackend) policyFor(k *verifierKey) httpsig.Policy {
	policy := r.policy
	if k.maxAge > 0 && k.maxAge < policy.MaxAge {
		policy.MaxAge = k.maxAge
	}
	return policy
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
func (r *resolverBackend) consumeNonce(ctx context.Context, sig *httpsig.Signature, key *verifierKey) error {
	nonce := sig.Nonce()
	if nonce == "" {
		return errors.New("signature carries no nonce")
	}
	if !r.consumeNonces {
		return nil
	}
	created := sig.Created()
	policy := r.policyFor(key)
	return r.keys.resolver.ConsumeNonce(ctx, NonceRequest{
		KeyID:   sig.KeyID(),
		Nonce:   nonce,
		Created: created,
		// The resolver may forget the nonce once no signature bearing it could be
		// accepted, which is the same bound Verify applied.
		ExpiresAt: created.Add(policy.MaxAge + policy.Tolerance),
	})
}

// checkAge rejects a signature outside the accepted time window.
func checkAge(sig *httpsig.Signature, maxAge, tolerance time.Duration) error {
	created := sig.Created()
	if created.IsZero() {
		return errors.New("signature carries no created parameter, so its age cannot be bounded")
	}
	now := time.Now()
	// The library's sentinels, so this pre-lookup check and the authoritative one
	// inside Verify classify the same way. Two vocabularies for one condition would
	// mean the metric depended on which check happened to reject first.
	if created.After(now.Add(tolerance)) {
		return fmt.Errorf("%w: signature was created at %v, which is in the future by more than the %v clock skew allowance",
			httpsig.ErrCreatedInFuture, created, tolerance)
	}
	if now.After(created.Add(maxAge + tolerance)) {
		return fmt.Errorf("%w: signature was created at %v, older than the %v maximum age",
			httpsig.ErrExpired, created, maxAge)
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
	covered := make(map[string]bool, len(sig.Components()))
	for _, c := range sig.Components() {
		covered[c.Name] = true
	}
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
