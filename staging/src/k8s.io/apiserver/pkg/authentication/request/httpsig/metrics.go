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
	"sync"

	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
)

// Outcomes a signature can reach. Every path out of authenticateSignature records
// exactly one of these, which is what makes the counter readable: a rise in
// uncovered_header and a rise in bad_signature call for different investigations,
// and a single failure total would hide the difference.
//
// The set is deliberately coarse and closed. It says which check refused a
// signature, never which certificate or which user, so no label carries a value a
// peer chooses.
const (
	outcomeAuthenticated = "authenticated"
	// The resolver could not produce a verifier: an unknown keyid, a missing or
	// malformed certificate header, or a keyid naming a different certificate
	// than the one carried.
	outcomeUnresolved = "unresolved"
	// The signature did not verify, or violated the coverage, age, or algorithm
	// policy.
	outcomeBadSignature = "bad_signature"
	// A protected header was present but not covered, which is the header
	// injection case.
	outcomeUncoveredHeader = "uncovered_header"
	outcomeBadDigest       = "bad_digest"
	// The signature was good but the identity was refused: the certificate did
	// not chain, a certificate rule failed, a mapping failed, or a user rule
	// failed. Distinct from bad_signature because it means a legitimate key
	// holder was turned away, which is a configuration question rather than an
	// attack.
	outcomeRejectedIdentity = "rejected_identity"
)

var (
	// outcomes counts signatures by which check decided them.
	outcomes = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Namespace:      "apiserver",
			Subsystem:      "httpsig",
			Name:           "signature_outcomes_total",
			Help:           "Number of HTTP message signatures processed, by authenticator and outcome.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"authenticator", "outcome"},
	)

	// certificateCacheLookups is what says whether the validation cache is doing
	// anything. A miss rate near one means every request is paying for a chain
	// build and an expression evaluation, which is the case the cache exists to
	// remove and the case a too-small maxEntries produces.
	certificateCacheLookups = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Namespace:      "apiserver",
			Subsystem:      "httpsig",
			Name:           "certificate_validation_cache_lookups_total",
			Help:           "Number of certificate validation cache lookups, by authenticator and result.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"authenticator", "result"},
	)
)

// Registration is lazy and from the constructor rather than from init, matching
// the mTLS authenticator: metric construction reads feature gates, and those have
// to be parsed first.
var registerMetricsOnce sync.Once

func registerMetrics() {
	registerMetricsOnce.Do(func() {
		legacyregistry.MustRegister(outcomes)
		legacyregistry.MustRegister(certificateCacheLookups)
	})
}

func recordOutcome(authenticator, outcome string) {
	outcomes.WithLabelValues(authenticator, outcome).Inc()
}

func recordCacheLookup(authenticator string, hit bool) {
	result := "miss"
	if hit {
		result = "hit"
	}
	certificateCacheLookups.WithLabelValues(authenticator, result).Inc()
}
