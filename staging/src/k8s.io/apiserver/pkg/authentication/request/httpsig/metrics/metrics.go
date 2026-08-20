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

// Package metrics instruments HTTP message signature authentication: the API
// server's calls to a key resolver, and the fate of the signatures themselves.
//
// Every metric here is labeled by the authenticator or resolver it describes,
// because a deployment can configure several and an aggregate that mixes them
// cannot answer the only question worth asking during an incident, which is which
// one is broken.
package metrics

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

const (
	namespace = "apiserver"
	subsystem = "httpsig"
)

// Cache lookup outcomes.
const (
	CacheResultHit         = "hit"
	CacheResultMiss        = "miss"
	CacheResultNegativeHit = "negative_hit"
)

// Signature outcomes say which check decided a signature. They are what
// distinguishes an attack from a misconfiguration: a rise in UncoveredHeader and a
// rise in BadSignature call for different investigations, and a single failure
// total would hide the difference.
//
// The set is deliberately coarse and closed. It says which check refused a
// signature, never which key, which certificate, or which user, so no label
// carries a value a peer chooses.
const (
	OutcomeAuthenticated = "authenticated"
	// OutcomeUnresolved means the authenticator claimed the signature and could not
	// produce a verifier: a resolver that could not be reached or answered
	// something unusable, or a keyID naming a different certificate than the one
	// the request carries.
	//
	// A resolver saying it does not serve a keyID is not this. That is a dispatch
	// miss rather than a decision, and it is counted by unclaimedSignatureTotal and
	// visible as a negative cache hit for that resolver.
	OutcomeUnresolved = "unresolved"
	// OutcomeBadSignature means the signature did not verify, or violated the
	// coverage or algorithm policy.
	//
	// The two time failures are counted apart from this. A signature that did not
	// verify is a forged or corrupted one; a signature that verified and fell
	// outside the accepted window is a clock or a configuration problem, and
	// conflating them makes this counter unreadable for exactly the case it is most
	// needed in.
	OutcomeBadSignature = "bad_signature"

	// OutcomeClockSkew means the signature's created parameter is in the future by
	// more than maxClockSkew.
	//
	// This is never an attack signal: predating a signature gains a caller nothing.
	// It says the signer's clock is ahead of this server's and maxClockSkew does not
	// cover the difference, which is the failure that otherwise appears as
	// intermittent 401s under load and costs an operator a day. Unset maxClockSkew
	// means zero, so this is the counter that says the default is too strict for a
	// deployment.
	OutcomeClockSkew = "clock_skew"

	// OutcomeExpired means the signature's created parameter is older than maxAge
	// plus maxClockSkew.
	//
	// Distinct from OutcomeClockSkew because it is ambiguous where that one is not:
	// a replayed capture and a signer whose clock is behind both land here. Reading
	// it alongside clock_skew is what separates them, since a clock problem is
	// usually not one-directional across a fleet.
	OutcomeExpired = "expired"
	// OutcomeUncoveredHeader means a protected header was present but not covered,
	// which is the header injection case.
	OutcomeUncoveredHeader = "uncovered_header"
	OutcomeBadDigest       = "bad_digest"
	// OutcomeRejectedIdentity means the signature was good but the identity was
	// refused: a certificate did not chain, a certificate rule failed, a mapping
	// failed, a user rule failed, or a resolver refused the nonce as a replay.
	// Distinct from BadSignature because it means a legitimate key holder was
	// turned away, which is a configuration question rather than an attack.
	OutcomeRejectedIdentity = "rejected_identity"
)

// Reasons a signature reached no authenticator. Closed, and none of them carries a
// value a peer chooses.
//
// Partitioned by who has to act on it, because that is what the reason is read for.
// An operator fixes a configuration that names no authenticator for a credential;
// a client fixes a credential no configuration was ever going to accept.
const (
	// UnclaimedUnparseableSignature means the signature fields were present and
	// could not be read, or the request carried more of them than this server
	// considers. Nothing was dispatched, so there is no authenticator to attribute
	// it to. A client problem.
	UnclaimedUnparseableSignature = "unparseable_signature"

	// UnclaimedUnknownKeyID means no resolver's keyID prefixes admitted the keyID,
	// so nothing was even asked about it. An operator problem: the authenticator
	// that serves this keyID is not configured on this server, or its prefixes do
	// not cover it.
	UnclaimedUnknownKeyID = "unknown_keyid"

	// UnclaimedUnservedKeyID means a resolver was asked and answered that it does
	// not serve the keyID. A client problem, usually a misspelled keyID or a key
	// that has not been created yet.
	//
	// Distinct from UnclaimedUnknownKeyID because the two send an operator to
	// different places: this one to the resolver's key inventory, the other to this
	// server's configuration file.
	UnclaimedUnservedKeyID = "unserved_keyid"

	// UnclaimedUnreadableCertificate means the signature named a certificate and the
	// header could not be read as one: absent, more than one, oversized, not a
	// certificate, or a certificate its own extensions say may not sign. A client
	// problem.
	UnclaimedUnreadableCertificate = "unreadable_certificate"

	// UnclaimedCertificateWithoutAuthorityKeyID means the certificate parsed and
	// carries no authorityKeyIdentifier, which is what names the trust anchor that
	// issued it and therefore selects the authenticator to validate it. A client
	// problem, and a certificate authority problem behind it: RFC 5280 requires a
	// conforming issuer to set the extension.
	//
	// Separate from UnclaimedUnreadableCertificate because the certificate is not
	// malformed. It is a well-formed certificate this server cannot route.
	UnclaimedCertificateWithoutAuthorityKeyID = "certificate_without_authority_key_id"

	// UnclaimedUnknownCertificateIssuer means the certificate is well formed and
	// names its issuer, and no authenticator holds that trust anchor. An operator
	// problem, and the one a certificate authority rotation that has not reached this
	// server's configuration produces.
	//
	// The counter says this is happening; it cannot say which authority, because a
	// key identifier is peer-chosen and would be unbounded label cardinality. The
	// error carries it.
	UnclaimedUnknownCertificateIssuer = "unknown_certificate_issuer"
)

var (
	requestTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Namespace:      namespace,
			Subsystem:      subsystem,
			Name:           "resolver_request_total",
			Help:           "Number of requests to an HTTP signature key resolver, by resolver, method, and gRPC status code.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"resolver", "method", "code"},
	)

	requestDurationSeconds = metrics.NewHistogramVec(
		&metrics.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "resolver_request_duration_seconds",
			Help:      "Latency of requests to an HTTP signature key resolver, by resolver, method, and gRPC status code.",
			// These calls are on the authentication path of every request that
			// misses the key cache, so the interesting range is single-digit
			// milliseconds over a local socket. The buckets match the external JWT
			// signer's, which is the same shape of call over the same transport.
			Buckets:        []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15, 30},
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"resolver", "method", "code"},
	)

	metadataSuccessTimestamp = metrics.NewGaugeVec(
		&metrics.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "resolver_metadata_success_timestamp",
			Help: "Unix timestamp in seconds of the last successful Metadata call to an HTTP signature key resolver. " +
				"A resolver whose keys still verify from cache but whose metadata is stale is degraded rather than failed, and this is the signal that says so.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"resolver"},
	)

	keyCacheLookupTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "key_cache_lookup_total",
			Help: "Number of key cache lookups, by resolver and outcome. " +
				"A miss rate that does not fall is a resolver returning a cache duration of zero, or a peer population larger than the cache bound.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"resolver", "result"},
	)

	keyDerivationInfo = metrics.NewGaugeVec(
		&metrics.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "resolver_key_derivation_info",
			Help: "Digest of the key derivation ladder a resolver stated, as a label. " +
				"A client that derives logs the digest of its own copy of the ladder; comparing the two is how a ladder disagreement is diagnosed, because it otherwise fails as a bare signature mismatch.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"resolver", "sha256"},
	)

	nonceHandling = metrics.NewGaugeVec(
		&metrics.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "resolver_nonce_tracking",
			Help: "1 when a resolver is asked to record the nonce of every accepted signature, 0 when configuration says to ignore nonces. " +
				"With it 0, a captured request can be replayed against every API server until its signature ages out, and nothing else detects that. " +
				"This is a gauge rather than a log line so that the question can be asked of a fleet rather than of one node's configuration file.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"resolver"},
	)

	// signatureOutcomeTotal counts signatures by which check decided them.
	signatureOutcomeTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Namespace:      namespace,
			Subsystem:      subsystem,
			Name:           "signature_outcomes_total",
			Help:           "Number of HTTP message signatures processed, by authenticator and outcome.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"authenticator", "outcome"},
	)

	// unclaimedSignatureTotal counts signatures no authenticator owned.
	//
	// Separate from signatureOutcomeTotal, and without an authenticator label,
	// because there is no authenticator to name: nothing was asked and nothing
	// decided. Folding these into the outcome counter would have meant inventing a
	// label value for "none", and would have made a refusal by an authenticator
	// indistinguishable from a request that never reached one.
	//
	// This is the counter to read when clients start failing after a certificate
	// authority is rotated or a keyID prefix is retyped: the requests do not appear
	// as any authenticator's rejection, because none of them saw one.
	unclaimedSignatureTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Namespace:      namespace,
			Subsystem:      subsystem,
			Name:           "unclaimed_signatures_total",
			Help:           "Number of HTTP message signatures that no configured authenticator claimed, by reason.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"reason"},
	)

	// certificateCacheLookupTotal is what says whether the validation cache is
	// doing anything. A miss rate near one means every request is paying for a
	// chain build and an expression evaluation, which is the case the cache exists
	// to remove and the case a too-small maxEntries produces.
	certificateCacheLookupTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Namespace:      namespace,
			Subsystem:      subsystem,
			Name:           "certificate_validation_cache_lookups_total",
			Help:           "Number of certificate validation cache lookups, by authenticator and result.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"authenticator", "result"},
	)

	registerOnce sync.Once
)

// RegisterMetrics registers the resolver metrics. It is idempotent.
func RegisterMetrics() {
	registerOnce.Do(func() {
		legacyregistry.MustRegister(requestTotal)
		legacyregistry.MustRegister(requestDurationSeconds)
		legacyregistry.MustRegister(metadataSuccessTimestamp)
		legacyregistry.MustRegister(keyCacheLookupTotal)
		legacyregistry.MustRegister(keyDerivationInfo)
		legacyregistry.MustRegister(nonceHandling)
		legacyregistry.MustRegister(signatureOutcomeTotal)
		legacyregistry.MustRegister(unclaimedSignatureTotal)
		legacyregistry.MustRegister(certificateCacheLookupTotal)
	})
}

// RecordMetadataSuccess notes a successful Metadata call.
func RecordMetadataSuccess(resolver string) {
	metadataSuccessTimestamp.WithLabelValues(resolver).SetToCurrentTime()
}

// RecordKeyCacheLookup notes a key cache lookup outcome, one of the CacheResult
// constants.
func RecordKeyCacheLookup(resolver, result string) {
	keyCacheLookupTotal.WithLabelValues(resolver, result).Inc()
}

// RecordNonceHandling publishes whether a resolver is asked to record nonces. It is
// set once per resolver when the authenticator is built, including when the answer is
// no: a series that disappears is indistinguishable from a resolver that went away,
// and "is replay protection on" has to be answerable rather than inferable.
func RecordNonceHandling(resolver string, consuming bool) {
	value := 0.0
	if consuming {
		value = 1.0
	}
	nonceHandling.WithLabelValues(resolver).Set(value)
}

// RecordKeyDerivation publishes the digest of the ladder a resolver stated.
//
// The digest is a label rather than a value because the interesting operation is
// comparing it against another party's, which a label supports and a float does
// not. Series for a resolver are reset first, so a ladder that changes leaves one
// series rather than two and an operator is not left guessing which is current.
func RecordKeyDerivation(resolver, digest string) {
	keyDerivationInfo.DeletePartialMatch(map[string]string{"resolver": resolver})
	keyDerivationInfo.WithLabelValues(resolver, digest).Set(1)
}

// RecordUnclaimedSignature notes a signature no authenticator claimed, for one of
// the Unclaimed reasons.
func RecordUnclaimedSignature(reason string) {
	unclaimedSignatureTotal.WithLabelValues(reason).Inc()
}

// RecordOutcome notes which check decided a signature, one of the Outcome
// constants.
func RecordOutcome(authenticator, outcome string) {
	signatureOutcomeTotal.WithLabelValues(authenticator, outcome).Inc()
}

// RecordCertificateCacheLookup notes a certificate validation cache lookup.
func RecordCertificateCacheLookup(authenticator string, hit bool) {
	result := CacheResultMiss
	if hit {
		result = CacheResultHit
	}
	certificateCacheLookupTotal.WithLabelValues(authenticator, result).Inc()
}

// ResetForTest clears every metric. It exists for tests and is not called from
// production code.
func ResetForTest() {
	requestTotal.Reset()
	requestDurationSeconds.Reset()
	metadataSuccessTimestamp.Reset()
	keyCacheLookupTotal.Reset()
	keyDerivationInfo.Reset()
	nonceHandling.Reset()
	signatureOutcomeTotal.Reset()
	unclaimedSignatureTotal.Reset()
	certificateCacheLookupTotal.Reset()
}

// OutboundRequestInterceptor records the outcome and latency of every resolver
// call. It is a gRPC interceptor rather than instrumentation at each call site so
// that a call added later is instrumented by construction.
func OutboundRequestInterceptor(resolver string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		start := time.Now()
		err := invoker(ctx, method, req, reply, cc, opts...)
		code := errorCode(err)
		requestTotal.WithLabelValues(resolver, method, code).Inc()
		requestDurationSeconds.WithLabelValues(resolver, method, code).Observe(time.Since(start).Seconds())
		return err
	}
}

type gRPCError interface {
	GRPCStatus() *status.Status
}

// errorCode renders a gRPC status for a metric label. Errors wrapped by fmt.Errorf
// still resolve, which matters because every layer above the interceptor wraps.
func errorCode(err error) string {
	if err == nil {
		return codes.OK.String()
	}
	var s gRPCError
	if errors.As(err, &s) {
		return s.GRPCStatus().Code().String()
	}
	// Not a gRPC error, so the call failed before the method was invoked.
	return "unknown-non-grpc"
}
