// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

// Package keyscope derives scoped HMAC signing keys. It narrows a long-term
// secret through multiple HMAC steps into tiered keys that carry only part of
// the secret's authority. Verifying parties that hold keys never have to hold
// the signing secret itself.
//
// Scoped keys exist because without scoping, symmetric verification hands
// every verifier the client's full key. For a credential used with multiple
// verifiers, this effectively means a compromised verifier could act as the
// client against all other verifiers. By using a scoped key, a compromised
// verifier can only forge within its scope. The client's true secret only
// stays with the client and the party that issues keys.
//
// Including a date stamp in the scope forces a leaked date-scoped key to
// expire when the date rolls without requiring revocation machinery. Scoping
// by time also forces rotation to be continuous rather than an infrequent or
// coordinated event. Consumers must fetch a fresh key at least each day to
// have a valid key.
//
// A derivation is a ladder of HMAC steps, each narrowing the key's authority.
// A holder of an intermediate key signs and verifies only within the scope
// already folded in.
//
// A [Derivation] is the description of the ladder. It contains no secret and
// clients and servers must use the same configuration. A [Stage] locates one
// participant's key material within the ladder: which step produced it, and
// the input values already applied. A [Key] combines the two with the key
// bytes:
//
//	chain := keyscope.Derivation{
//	    Kind: keyscope.KindHMACLadder,
//	    Hash: keyscope.HashSHA256,
//	    SecretPrefix: "KUBERNETES",
//	    Steps: []keyscope.Step{
//	        {Name: "date", Date: "YYYYMMDD"},
//	        {Name: "region", Scope: true},
//	        {Name: "cluster", Scope: true},
//	        {Name: "terminator", Literal: "k8s_request"},
//	    },
//	}
//	stage := keyscope.Stage{
//	    Name: "MY_KEY_ID",
//	    From: "cluster",
//	    Scope: map[string]string{
//	        "date":    "20120525",
//	        "region":  "us-east-1",
//	        "cluster": "prod01",
//	    },
//	}
//	key, err := keyscope.New(chain, stage, keyBytes)
//
// The signature's keyid parameter carries the claimed credential scope in the
// following format with name and step values joined by slashes:
//
//	MY_KEY_ID/20120525/us-east-1/prod01/k8s_request
//
// [Key.Verifier] compares every claim in the keyid against the key's own scope
// and the signature's created parameter before any signature math runs. A
// request signed for the wrong step or date fails with a [*ScopeError] rather
// than a bare signature mismatch. The comparison is byte-exact, never
// normalized: "US-EAST-1" does not match "us-east-1". The keyid is unverified
// input at that point, but it is a signature parameter, so a verified
// signature proves the signer claimed exactly that scope. Derivation inputs
// never come from the keyid. The verifier derives only from its own
// configuration, and a service-scoped key derives its signing key in a single
// HMAC.
//
// A server's key lookup derives the verifying key per request:
//
//	dir := server.KeyDirectoryFunc[string](
//	    func(r *http.Request, sig *httpsig.Signature) (httpsig.Verifier, string, error) {
//	        v, err := key.Verifier(sig.KeyID(), sig.Created())
//	        return v, sig.KeyID(), err
//	    },
//	)
//
// A lookup serving many credentials parses the keyid first with [ParseKeyID],
// fetches the scoped key its broker holds for that name and scope, and then
// constructs the Key. The parsed values select which key to fetch;
// [Key.Verifier] still validates the full keyid against what the broker said
// the key is scoped to.
//
// Derivation is symmetric cryptography: any holder of a scoped key can forge
// signatures within that scope, including the verifier itself. The ladder
// provides blast-radius containment, not signer non-repudiation.
// Non-repudiation requires that the verifier never hold material that can
// compute the signing key, and no symmetric scheme satisfies that. The
// containment relies on the verifier exclusively holding a scoped key and not
// the root secret. A deployment that hands a verifier the root has built the
// key hand-off and kept the blast radius. Signatures under a derived key use
// the hmac-sha256 algorithm of RFC 9421, over RFC 9421's signature base.
//
// Chains with a date step require the signature's created parameter.
// Implementations must pair the verifier with a policy that sets MaxAge and
// reject signatures without one. A date-scoped key rejects requests from any
// other UTC day, including yesterday's requests just after midnight. A
// deployment that must span the rollover holds a key for each adjacent day and
// selects in its key lookup by the date step of the [*ScopeError].
//
// [AWS SigV4] uses this method and derives signing keys with the following
// construction:
//
//	DateKey              = HMAC("AWS4"+secret, date)
//	DateRegionKey        = HMAC(DateKey, region)
//	DateRegionServiceKey = HMAC(DateRegionKey, service)
//	SigningKey           = HMAC(DateRegionServiceKey, "aws4_request")
//
// The [SigV4] preset returns a derivation ladder so keys vended by existing SigV4
// credential infrastructure could sign RFC 9421 signatures using this package.
// In the same way, callers can declare ladders with other steps such as a
// tenant, an environment, a cluster.
//
// [AWS SigV4]: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
package keyscope
