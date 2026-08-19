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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig/keyscope"

	"k8s.io/apiserver/pkg/authentication/user"
)

// ErrKeyNotFound reports that no key bears a key ID. It is distinct from every
// other resolution failure because the two are handled differently: a key ID no
// resolver serves moves on to the next resolver and is then remembered as absent,
// where a resolver that failed is not remembered at all.
var ErrKeyNotFound = errors.New("no key with that keyID")

// A KeyResolver answers the two questions this authenticator cannot answer from
// its own configuration: which key verifies signatures bearing a key ID and who
// it authenticates as, and whether a nonce has been used for that key before.
//
// Both are held by one interface because one endpoint answers both, and because
// separating them would let a deployment configure key resolution without replay
// tracking, which is not a configuration worth being able to express.
//
// A resolver returns data. It never returns a verifier and it is never asked to
// verify anything: everything that turns key material into a signature check
// lives in this package, so no resolver has to get the cryptography right and
// none can get it wrong.
type KeyResolver interface {
	// ResolveKey returns the key bearing req.KeyID, or ErrKeyNotFound.
	//
	// It is called before any signature has been verified, because verifying
	// needs the key it returns. Every field of the request is therefore an
	// unverified claim.
	ResolveKey(ctx context.Context, req ResolveRequest) (*ResolvedKey, error)

	// ConsumeNonce records that req.Nonce has been used for req.KeyID and
	// reports whether it had been used already. It returns ErrNonceReplayed for a
	// nonce that had been.
	//
	// It is called only after a signature has verified, so it is not reachable by
	// an unauthenticated caller, and it is called at most once per accepted
	// request.
	ConsumeNonce(ctx context.Context, req NonceRequest) error

	// Check reports whether this resolver is currently usable, for the API
	// server's health endpoints.
	Check() error

	// Name identifies this resolver in errors, logs, and metric labels.
	Name() string
}

// ErrNonceReplayed reports a nonce already used for its key.
var ErrNonceReplayed = errors.New("signature nonce has already been used")

// A ResolveRequest asks a resolver about one key ID.
//
// Everything in it is peer-chosen and unverified. KeyID and Algorithm are
// parameters of a signature nothing has checked yet, and RelayedHeaders holds
// values covered by that signature but not yet verified against it.
type ResolveRequest struct {
	// KeyID is the signature's keyid parameter, exactly as it arrived.
	KeyID string

	// Algorithm is the signature's alg parameter. It is advisory: the
	// authoritative algorithm is the one the resolved key states.
	Algorithm string

	// Created is the signature's created parameter, already checked against the
	// maximum age and clock tolerance, so bounded but still peer-chosen.
	Created time.Time

	// RelayedHeaders holds values for the configured relayed headers, keyed by
	// lowercase header name.
	RelayedHeaders map[string]string
}

// A NonceRequest asks a resolver to record one nonce for one key.
type NonceRequest struct {
	// KeyID is the signature's keyid parameter. Nonces are scoped per key: the
	// same value under two keys is two different facts.
	KeyID string

	// Nonce is the signature's nonce parameter. Unlike a ResolveRequest's fields
	// this arrived under a signature that has verified, so it is the value the
	// key holder chose.
	Nonce string

	// Created is the signature's created parameter.
	Created time.Time

	// ExpiresAt is when this server stops accepting any signature bearing this
	// nonce. A resolver may forget the nonce after it and still be correct.
	ExpiresAt time.Time
}

// A ResolvedKey is a resolver's answer, as data.
//
// Exactly one of PublicKey, Secret, or Derived carries the material, and which
// one is determined by Algorithm rather than by which field happens to be set.
// Disagreement between the two is an error rather than a preference, because a
// public key treated as a shared secret is the algorithm confusion attack.
type ResolvedKey struct {
	// Algorithm is the algorithm this key verifies, named as in the IANA "HTTP
	// Signature Algorithms" registry. It is authoritative, and a signature whose
	// alg parameter disagrees with it is rejected.
	Algorithm string

	// PublicKey is a public key in PKIX, ASN.1 DER form, for the asymmetric
	// algorithms.
	PublicKey []byte

	// Secret is a shared secret for hmac-sha256, used with no derivation.
	Secret []byte

	// Derived is a rung of a key derivation ladder, for hmac-sha256, from which
	// this server derives per request.
	Derived *DerivedKey

	// User is the identity a request signed by this key authenticates as. It is a
	// claim crossing a trust boundary and is validated here before use.
	User user.DefaultInfo

	// MaxAge narrows how old a signature verified by this key may be. Zero means
	// the resolver states no opinion and this server's configured maximum stands.
	// It can only narrow: a value longer than the configured maximum is ignored.
	MaxAge time.Duration

	// CacheFor is how long this answer may be reused. Zero means do not cache,
	// which is the right answer when the answer depended on a relayed header
	// whose value rotates. This server caps it by its own configured maximum.
	CacheFor time.Duration
}

// A DerivedKey is a rung of a key derivation ladder together with the ladder it
// sits on and its position in it. The bytes of derived material cannot say what
// was folded into them, so all three travel together.
type DerivedKey struct {
	// Key is the rung: the raw output of the step named by From, or the root
	// secret when From is empty.
	Key []byte

	// From names the ladder step whose output Key is. Empty means Key is the root
	// secret and the whole ladder is folded per request.
	From string

	// Scope holds values for the ladder's scope steps and assertions for the date
	// steps at or before From, keyed by step name. It must cover exactly those.
	Scope map[string]string

	// Derivation is the ladder. It travels with the material rather than being
	// held once by this server, so nothing here has to reason about which ladder
	// a key belongs to.
	Derivation keyscope.Derivation
}

// A verifierKey is a ResolvedKey compiled into what verification actually needs.
// Compiling is what validates a resolver's answer, so an answer that reaches the
// cache is one that has already been checked.
type verifierKey struct {
	algorithm string

	// verifier is set for a key that verifies the same way on every request. For
	// a derived key it is nil and a verifier is built per request, because the
	// derived key depends on the created timestamp the signature carries and on
	// the scope the keyid claims.
	verifier httpsig.Verifier

	// scoped is set for a derived key: material bound to its position on a
	// ladder, which derives a verifier per signature.
	scoped *keyscope.Key

	info *user.DefaultInfo

	// maxAge is the resolver's narrowing of signature age, or zero for none.
	maxAge time.Duration
}

// verifierFor returns the verifier for one signature. A static key holds one; a
// derived key builds one per request, checking the scope the keyid claims against
// its own configuration first, so a request signed under the wrong scope is
// rejected with an error naming the disagreeing step rather than a bare signature
// mismatch.
//
// The verifier never derives with its own clock: it uses the created timestamp the
// signature carries, which is covered by the signature and bounded by the maximum
// age policy.
func (k *verifierKey) verifierFor(sig *httpsig.Signature) (httpsig.Verifier, error) {
	if k.scoped == nil {
		return k.verifier, nil
	}
	created := sig.Created()
	if created.IsZero() {
		return nil, fmt.Errorf("the signature carries no created parameter, and this key's verification key is derived from it")
	}
	return k.scoped.Verifier(sig.KeyID(), created)
}

// compile turns a resolver's answer into a verifier and validates it on the way.
//
// Two checks here are the reason a resolver's answer is a claim rather than a
// conclusion. The material has to match the algorithm the resolver named, which
// is what stops a public key being used as an HMAC secret. And the identity has
// to be one an administrator would accept, which is what stops a resolver minting
// an identity the cluster's own authorization rules are written around.
//
// keyID is the keyid the answer is for, needed because a derived key's position on
// its ladder includes the key's public name and the keyid already carries it.
func compile(name, keyID string, k *ResolvedKey) (*verifierKey, error) {
	if k == nil {
		return nil, fmt.Errorf("resolver %s returned no key and no error", name)
	}
	if err := validateResolvedUser(&k.User); err != nil {
		return nil, fmt.Errorf("resolver %s: %w", name, err)
	}
	if k.Algorithm == "" {
		return nil, fmt.Errorf("resolver %s: response states no algorithm, so nothing constrains how the key material is used", name)
	}

	out := &verifierKey{
		algorithm: k.Algorithm,
		info: &user.DefaultInfo{
			Name:   k.User.Name,
			UID:    k.User.UID,
			Groups: k.User.Groups,
			Extra:  k.User.Extra,
		},
		maxAge: k.MaxAge,
	}

	alg := httpsig.Algorithm(k.Algorithm)
	set := 0
	for _, on := range []bool{len(k.PublicKey) > 0, len(k.Secret) > 0, k.Derived != nil} {
		if on {
			set++
		}
	}
	if set != 1 {
		return nil, fmt.Errorf("resolver %s: response must carry exactly one of a public key, a secret, or a derived key, and carries %d", name, set)
	}

	if alg != httpsig.HMACSHA256 {
		if len(k.PublicKey) == 0 {
			return nil, fmt.Errorf("resolver %s: algorithm %s verifies with a public key, and the response carries symmetric material instead", name, alg)
		}
		pub, err := parsePublicKey(k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("resolver %s: %w", name, err)
		}
		verifier, err := httpsig.NewVerifier(alg, pub)
		if err != nil {
			return nil, fmt.Errorf("resolver %s: %w", name, err)
		}
		out.verifier = verifier
		return out, nil
	}

	if len(k.PublicKey) > 0 {
		return nil, fmt.Errorf("resolver %s: algorithm %s verifies with a shared secret, and the response carries a public key instead", name, alg)
	}
	if len(k.Secret) > 0 {
		verifier, err := httpsig.NewVerifier(alg, k.Secret)
		if err != nil {
			return nil, fmt.Errorf("resolver %s: %w", name, err)
		}
		out.verifier = verifier
		return out, nil
	}

	// A derived key's material is bound to its position on its ladder here rather
	// than per request, so a scope the resolver stated wrongly fails once, at
	// resolution, instead of on every signature.
	//
	// The stage's name is taken from the keyid rather than from the resolver. The
	// name is already in the keyid, this server already used it to choose a
	// resolver, and the resolver was handed the whole keyid and chose to answer.
	// A second statement of it would only be a second thing to disagree with.
	keyName, _, _ := strings.Cut(keyID, "/")
	stage := keyscope.Stage{Name: keyName, From: k.Derived.From, Scope: k.Derived.Scope}
	scoped, err := keyscope.New(k.Derived.Derivation, stage, k.Derived.Key)
	if err != nil {
		return nil, fmt.Errorf("resolver %s: %w", name, err)
	}
	out.scoped = scoped
	return out, nil
}

// validateResolvedUser checks an identity a resolver claimed.
//
// The "system:" prefix is reserved for identities Kubernetes issues. A resolver
// that could claim one would let whoever holds the resolver's socket mint an
// identity the cluster's own authorization rules are written around, which is a
// larger grant than vending a key.
func validateResolvedUser(u *user.DefaultInfo) error {
	if u.Name == "" {
		return errors.New("response carries no username")
	}
	if strings.HasPrefix(u.Name, "system:") {
		return fmt.Errorf("response username %q begins with system:, which is reserved for identities Kubernetes issues", u.Name)
	}
	for _, group := range u.Groups {
		if group == "" {
			return errors.New("response carries an empty group name")
		}
		if strings.HasPrefix(group, "system:") {
			return fmt.Errorf("response group %q begins with system:, which is reserved for groups Kubernetes issues", group)
		}
	}
	return nil
}

// parsePublicKey reads a public key in PKIX, ASN.1 DER form. PEM is deliberately
// not accepted: a PEM block type is a second statement of the key kind and a
// second thing to disagree with the algorithm the resolver named.
func parsePublicKey(der []byte) (any, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing public key, which must be PKIX ASN.1 DER rather than PEM: %w", err)
	}
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("public key is of unsupported type %T", pub)
	}
}
