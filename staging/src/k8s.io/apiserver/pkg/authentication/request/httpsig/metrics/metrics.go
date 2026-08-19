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
	// OutcomeUnresolved means the authenticator could not produce a verifier: an
	// unknown keyID, a resolver that does not serve it or could not be reached, a
	// missing or malformed certificate header, or a keyID naming a different
	// certificate than the one carried.
	OutcomeUnresolved = "unresolved"
	// OutcomeBadSignature means the signature did not verify, or violated the
	// coverage, age, or algorithm policy.
	OutcomeBadSignature = "bad_signature"
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
