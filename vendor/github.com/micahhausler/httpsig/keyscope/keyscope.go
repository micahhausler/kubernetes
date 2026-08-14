// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package keyscope

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/micahhausler/httpsig"
)

// KindHMACLadder identifies the HMAC ladder derivation. It is the only kind
// this package implements; the field exists so a future kind can be added
// without ambiguity in stored configuration.
const KindHMACLadder = "hmac-ladder"

// Hash names for the derivation HMAC, the closed set this package
// implements. New names are added here, never by configuration.
//
// These spell the same algorithms as the Content-Digest hash registry but
// govern a different thing: they select the HMAC hash of the key ladder,
// not a body digest. They are defined here rather than shared for that
// reason, and because this package depends only on the httpsig root
// package.
const (
	HashSHA256 = "sha-256"
	HashSHA512 = "sha-512"
)

// maxKeyIDLen bounds the keyid accepted by [Key.Verifier] and [ParseKeyID].
// The keyid is peer-chosen input compared segment by segment; the bound
// keeps a hostile keyid from carrying arbitrary payload into comparisons
// and error values. SigV4 credential scopes are under 128 bytes.
const maxKeyIDLen = 512

// ErrScopeMismatch reports a request outside the key's scope: the keyid
// claims a name, date, region, or other step value that disagrees with the
// key's own scope or with the signature's created parameter. It is distinct
// from a signature mismatch so that misconfiguration is not reported as
// tampering. Every such error is a [*ScopeError]; test with [errors.Is] and
// inspect with [errors.As].
var ErrScopeMismatch = errors.New("httpsig/keyscope: request outside the key's scope")

// A ScopeError reports which step of the derivation a request's claimed
// scope disagreed on. Error() renders only the step name and the claimed
// value, both of which the peer already knows; the key's own expected value
// is available separately through [ScopeError.Expected], so a server that
// surfaces error text to clients does not disclose its configuration by
// default.
//
// Scope comparison is not constant time and does not need to be: the keyid
// is covered by the signature, so a peer that cannot produce a valid
// signature cannot convert scope probing into anything.
type ScopeError struct {
	// Step is the disagreeing step's name, or "name" for the key name
	// segment. A caller handling date rollover selects on Step == the
	// date step's name.
	Step string

	// Claimed is the peer's value: the keyid segment, or for a date
	// step, the date formatted from the signature's created parameter.
	Claimed string

	want string
}

func (e *ScopeError) Error() string {
	return fmt.Sprintf("%v: %s %q", ErrScopeMismatch, e.Step, e.Claimed)
}

// Expected returns the value the key's own scope requires. It is the
// verifier's configuration; surface it in logs, not to peers.
func (e *ScopeError) Expected() string { return e.want }

func (e *ScopeError) Unwrap() error { return ErrScopeMismatch }

// A Derivation describes an HMAC key derivation ladder. It contains no
// secret; every participant holds the same derivation, and a participant's
// position in it is stated separately by a [Stage].
type Derivation struct {
	// Kind discriminates the derivation form. Must be [KindHMACLadder].
	Kind string `json:"kind"`

	// Hash is the HMAC hash for the ladder: [HashSHA256] (the default)
	// or [HashSHA512]. The final signature algorithm is always
	// hmac-sha256, the one HMAC algorithm RFC 9421 registers; this hash
	// governs only key derivation.
	Hash string `json:"hash,omitempty"`

	// SecretPrefix is prepended to the root secret before the first
	// step. SigV4 uses "AWS4". It applies only when the key material is
	// the root secret, never to intermediate keys.
	SecretPrefix string `json:"secretPrefix,omitempty"`

	// Steps are the ladder rungs, applied in order. Each step's input
	// is fed to HMAC keyed by the previous step's output.
	Steps []Step `json:"steps"`
}

// A Step is one rung of the ladder. Exactly one of Literal, Scope, or Date
// must be set; it states where the step's input value comes from.
type Step struct {
	// Name identifies the step. Names must be unique within a
	// derivation; they key the [Stage] scope map and appear in error
	// messages, never on the wire.
	Name string `json:"name"`

	// Literal is a fixed input value, such as SigV4's terminal
	// "aws4_request".
	Literal string `json:"literal,omitempty"`

	// Scope marks the input as a deployment-scoped value, such as a
	// region or service name, supplied by each participant's [Stage].
	Scope bool `json:"scope,omitempty"`

	// Date names a date format from the closed set this package
	// defines: "YYYYMMDD" or "YYYY-MM-DD". The input is the signature's
	// created time formatted in UTC. The set is deliberately not a
	// strftime or Go layout string: a Derivation is read by
	// implementations in any language, and a format token means the
	// same thing to all of them.
	Date string `json:"date,omitempty"`
}

// dateLayouts maps the serializable date format tokens to Go layouts. The
// set is closed; new tokens are added here, never by configuration.
var dateLayouts = map[string]string{
	"YYYYMMDD":   "20060102",
	"YYYY-MM-DD": "2006-01-02",
}

// Validate reports whether the derivation is well-formed: a known kind and
// hash, and steps that are uniquely named with exactly one input source
// each. [UnmarshalJSON] and [New] both run it; call it directly only on
// derivations built in code and passed onward without either.
func (d Derivation) Validate() error {
	_, err := validateDerivation(d)
	return err
}

// UnmarshalJSON decodes and validates. A Derivation is stored and forwarded
// by parties that never derive from it — brokers, config loaders — so an
// invalid one must fail where it is read, not at some other party's [New].
func (d *Derivation) UnmarshalJSON(data []byte) error {
	type plain Derivation // shadow type: no methods, no recursion
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	if _, err := validateDerivation(Derivation(p)); err != nil {
		return err
	}
	*d = Derivation(p)
	return nil
}

// A Stage locates one participant's key material within a derivation. It
// contains no key bytes; those are supplied to [New] separately, so a Stage
// is safe to store and transmit alongside the key it describes.
type Stage struct {
	// Name is the key's public name, the first segment of the keyid.
	// For SigV4 this is the access key ID.
	Name string `json:"name"`

	// From names the step whose output this participant's key material
	// is. Empty means the root secret, before any step.
	From string `json:"from,omitempty"`

	// Scope holds step input values by step name: a value for every
	// Scope step in the derivation, and the already-applied value for
	// every Date step at or before From. Values for steps at or before
	// From are baked into the key and are recorded here to be compared
	// against requests; they cannot be changed by configuration.
	Scope map[string]string `json:"scope,omitempty"`
}

// SigV4 returns the AWS Signature Version 4 key derivation: date, region,
// and service scope steps under the "AWS4" secret prefix, terminated with
// "aws4_request".
func SigV4() Derivation {
	return Derivation{
		Kind:         KindHMACLadder,
		Hash:         HashSHA256,
		SecretPrefix: "AWS4",
		Steps: []Step{
			{Name: "date", Date: "YYYYMMDD"},
			{Name: "region", Scope: true},
			{Name: "service", Scope: true},
			{Name: "terminator", Literal: "aws4_request"},
		},
	}
}

// A Key is key material bound to its position in a derivation. It derives
// signers and verifiers for requests within its scope. A Key is safe for
// concurrent use.
type Key struct {
	d       Derivation
	s       Stage
	hashFn  func() hash.Hash
	fromIdx int // index of the step that produced the material; -1 for root
	key     []byte

	// memo holds the single most recent derivation. Scope and literal
	// inputs are fixed per Key, so derived keys vary only by date: one
	// entry is a full cache in steady state, and its cardinality is one
	// no matter what dates the wire supplies, which is what makes
	// memoizing on the unbounded created parameter safe. Anything
	// larger would be keyed on attacker-controlled input.
	memo atomic.Pointer[memoEntry]
}

// memoEntry pairs the derivation inputs with their output. Claims fully
// determine the derived key, so input equality is sufficient.
type memoEntry struct {
	claims  []string
	derived []byte
}

// New returns a Key for the given derivation, stage, and key material. The
// material is the root secret when the stage's From is empty, or the output
// of the named step otherwise. The derivation and stage are validated here;
// a Key that constructs fails later only on per-request scope mismatches.
func New(d Derivation, s Stage, key []byte) (*Key, error) {
	hashFn, err := validateDerivation(d)
	if err != nil {
		return nil, err
	}
	fromIdx, err := validateStage(d, s)
	if err != nil {
		return nil, err
	}
	if len(key) == 0 {
		return nil, errors.New("httpsig/keyscope: empty key material")
	}
	material := slices.Clone(key)
	if fromIdx < 0 && d.SecretPrefix != "" {
		material = append([]byte(d.SecretPrefix), material...)
	}
	return &Key{d: d, s: s, hashFn: hashFn, fromIdx: fromIdx, key: material}, nil
}

// KeyID returns the credential-scope keyid for a signature created at the
// given time: the key name and each step's input value joined by slashes,
// the format of SigV4's Credential field. Set it as the signature's keyid
// so the verifier can check the claimed scope.
func (k *Key) KeyID(created time.Time) (string, error) {
	claims, err := k.claims(created)
	if err != nil {
		return "", err
	}
	return strings.Join(append([]string{k.s.Name}, claims...), "/"), nil
}

// Signer derives the signing key for a signature created at the given time
// and returns an hmac-sha256 signer over it. The same created time must be
// set in the signature's SignOptions.Created; a divergence across a date
// boundary derives a key for one date and claims another.
func (k *Key) Signer(created time.Time) (httpsig.Signer, error) {
	claims, err := k.claims(created)
	if err != nil {
		return nil, err
	}
	return httpsig.NewSigner(httpsig.HMACSHA256, k.derive(claims))
}

// Verifier checks the keyid's claimed scope against this key and the
// signature's created time, then derives the verification key and returns
// an hmac-sha256 verifier over it. A scope disagreement is reported as a
// [*ScopeError] before any signature math runs.
//
// Scope comparison runs before signature verification so that a request
// with a mismatched keyid is rejected before any derivation or HMAC work,
// which keeps unauthenticated callers from driving the key schedule. The
// disclosure concern this ordering would otherwise create — scope errors
// reaching peers that have proven nothing — is closed by ScopeError's
// rendering, not by the ordering; the two decisions hold together.
//
// The keyid and created time are unverified wire claims when this runs.
// They are compared, never derived from: derivation inputs come only from
// the key's own scope, the chain's literals, and the created time's date.
// The scope comparison never selects a key; it only confirms the request
// claims exactly the scope this key holds.
func (k *Key) Verifier(keyid string, created time.Time) (httpsig.Verifier, error) {
	if len(keyid) > maxKeyIDLen {
		return nil, fmt.Errorf("httpsig/keyscope: keyid is %d bytes, limit %d", len(keyid), maxKeyIDLen)
	}
	claims, err := k.claims(created)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(keyid, "/")
	if len(parts) != 1+len(k.d.Steps) {
		return nil, fmt.Errorf("httpsig/keyscope: keyid has %d segments, derivation takes %d", len(parts), 1+len(k.d.Steps))
	}
	if parts[0] != k.s.Name {
		return nil, &ScopeError{Step: "name", Claimed: parts[0], want: k.s.Name}
	}
	for i, step := range k.d.Steps {
		if parts[i+1] != claims[i] {
			return nil, &ScopeError{Step: step.Name, Claimed: parts[i+1], want: claims[i]}
		}
	}
	return httpsig.NewVerifier(httpsig.HMACSHA256, k.derive(claims))
}

// Derive computes the key material for the step named through, using the
// given created time for any date steps, and returns it with the Stage
// describing it. It is the hand-off operation: a broker holding the root
// secret derives a scoped key for a service, which reconstructs a [Key]
// from the returned material and stage.
func (k *Key) Derive(through string, created time.Time) ([]byte, Stage, error) {
	throughIdx := slices.IndexFunc(k.d.Steps, func(s Step) bool { return s.Name == through })
	if throughIdx < 0 {
		return nil, Stage{}, fmt.Errorf("httpsig/keyscope: no step named %q", through)
	}
	if throughIdx <= k.fromIdx {
		return nil, Stage{}, fmt.Errorf("httpsig/keyscope: step %q is already applied to this key", through)
	}
	claims, err := k.claims(created)
	if err != nil {
		return nil, Stage{}, err
	}
	material := k.key
	for i := k.fromIdx + 1; i <= throughIdx; i++ {
		material = k.hmac(material, claims[i])
	}
	scope := make(map[string]string)
	for i, step := range k.d.Steps {
		if step.Scope || (step.Date != "" && i <= throughIdx) {
			scope[step.Name] = claims[i]
		}
	}
	return material, Stage{Name: k.s.Name, From: through, Scope: scope}, nil
}

// claims returns each step's input value for a signature created at the
// given time. Values come only from the key's own configuration — the stage
// scope, the chain's literals — and from created; nothing from the keyid
// ever feeds derivation, which is what keeps the scope comparison in
// Verifier an assertion check rather than a guard on the key schedule. For
// steps at or before the key's own stage, the value is the assertion
// recorded in the stage; a created time whose date disagrees with an
// asserted date is a ScopeError, because the key cannot derive for any
// other date.
func (k *Key) claims(created time.Time) ([]string, error) {
	claims := make([]string, len(k.d.Steps))
	for i, step := range k.d.Steps {
		switch {
		case step.Literal != "":
			claims[i] = step.Literal
		case step.Scope:
			claims[i] = k.s.Scope[step.Name]
		case step.Date != "":
			if created.IsZero() {
				return nil, errors.New("httpsig/keyscope: derivation has a date step but the signature has no created parameter")
			}
			day := created.UTC().Format(dateLayouts[step.Date])
			if i <= k.fromIdx {
				// This check runs before any freshness bound on
				// created: a stage key's baked date rejects other
				// days here even if the verifying policy's MaxAge
				// would have accepted the timestamp.
				if asserted := k.s.Scope[step.Name]; day != asserted {
					return nil, &ScopeError{Step: step.Name, Claimed: day, want: asserted}
				}
			}
			claims[i] = day
		}
	}
	return claims, nil
}

// derive runs the ladder from the key's stage to the end, using the
// per-step input values from claims, memoizing the single most recent
// result. The memo, not a cache keyed on the wire, is deliberate: for a key
// that is not yet date-scoped, the date input comes from the unbounded
// created parameter of the request, so a keyed cache would have
// attacker-controlled cardinality. One entry serves the steady state — same
// scope, same date, every request — and date-thrashing degrades to deriving
// every time, never to memory growth.
func (k *Key) derive(claims []string) []byte {
	if m := k.memo.Load(); m != nil && slices.Equal(m.claims, claims) {
		return m.derived
	}
	material := k.key
	for i := k.fromIdx + 1; i < len(k.d.Steps); i++ {
		material = k.hmac(material, claims[i])
	}
	k.memo.Store(&memoEntry{claims: slices.Clone(claims), derived: material})
	return material
}

func (k *Key) hmac(key []byte, input string) []byte {
	m := hmac.New(k.hashFn, key)
	m.Write([]byte(input))
	return m.Sum(nil)
}

// A Claim is the unverified credential scope a keyid asserts, parsed by
// [ParseKeyID]. Every value is peer-chosen wire input: the accessors are
// named for that, and a Claim is lookup input only — which broker key to
// fetch — never an authorization decision.
type Claim struct {
	name  string
	scope map[string]string
}

// Name returns the claimed key name, the keyid's first segment.
func (c Claim) Name() string { return c.name }

// Claimed returns the keyid's value for the named scope or date step, or
// empty for steps the derivation fixes as literals.
func (c Claim) Claimed(step string) string { return c.scope[step] }

// ParseKeyID splits a keyid into the claimed key name and step values, for
// lookups that serve many keys: the claim says which scoped key to fetch
// from a broker, and [Key.Verifier] then validates the full keyid against
// the fetched key. Literal steps are checked here and not returned.
//
// The keyid is an unverified, peer-chosen claim. Treat the returned values
// as lookup input only; do not interpret them as paths or queries.
func ParseKeyID(d Derivation, keyid string) (Claim, error) {
	if _, err := validateDerivation(d); err != nil {
		return Claim{}, err
	}
	if len(keyid) > maxKeyIDLen {
		return Claim{}, fmt.Errorf("httpsig/keyscope: keyid is %d bytes, limit %d", len(keyid), maxKeyIDLen)
	}
	parts := strings.Split(keyid, "/")
	if len(parts) != 1+len(d.Steps) {
		return Claim{}, fmt.Errorf("httpsig/keyscope: keyid has %d segments, derivation takes %d", len(parts), 1+len(d.Steps))
	}
	if parts[0] == "" {
		return Claim{}, errors.New("httpsig/keyscope: keyid has an empty key name")
	}
	scope := make(map[string]string)
	for i, step := range d.Steps {
		v := parts[i+1]
		switch {
		case step.Literal != "":
			if v != step.Literal {
				return Claim{}, fmt.Errorf("httpsig/keyscope: keyid segment %q does not match the derivation's %q", v, step.Literal)
			}
		default:
			if v == "" {
				return Claim{}, fmt.Errorf("httpsig/keyscope: keyid has an empty %s segment", step.Name)
			}
			scope[step.Name] = v
		}
	}
	return Claim{name: parts[0], scope: scope}, nil
}

func validateDerivation(d Derivation) (func() hash.Hash, error) {
	if d.Kind != KindHMACLadder {
		return nil, fmt.Errorf("httpsig/keyscope: unknown derivation kind %q (want %q)", d.Kind, KindHMACLadder)
	}
	var hashFn func() hash.Hash
	switch d.Hash {
	case "", HashSHA256:
		hashFn = sha256.New
	case HashSHA512:
		hashFn = sha512.New
	default:
		return nil, fmt.Errorf("httpsig/keyscope: unknown hash %q (want %s or %s)", d.Hash, HashSHA256, HashSHA512)
	}
	if len(d.Steps) == 0 {
		return nil, errors.New("httpsig/keyscope: derivation has no steps")
	}
	seen := make(map[string]bool, len(d.Steps))
	for _, step := range d.Steps {
		if step.Name == "" {
			return nil, errors.New("httpsig/keyscope: step with no name")
		}
		if seen[step.Name] {
			return nil, fmt.Errorf("httpsig/keyscope: duplicate step %q", step.Name)
		}
		seen[step.Name] = true
		set := 0
		for _, on := range []bool{step.Literal != "", step.Scope, step.Date != ""} {
			if on {
				set++
			}
		}
		if set != 1 {
			return nil, fmt.Errorf("httpsig/keyscope: step %q must set exactly one of literal, scope, or date", step.Name)
		}
		if strings.Contains(step.Literal, "/") {
			return nil, fmt.Errorf("httpsig/keyscope: step %q literal contains %q, the keyid separator", step.Name, "/")
		}
		if step.Date != "" {
			if _, ok := dateLayouts[step.Date]; !ok {
				return nil, fmt.Errorf("httpsig/keyscope: step %q has unknown date format %q (want YYYYMMDD or YYYY-MM-DD)", step.Name, step.Date)
			}
		}
	}
	return hashFn, nil
}

func validateStage(d Derivation, s Stage) (fromIdx int, err error) {
	if s.Name == "" || strings.Contains(s.Name, "/") {
		return 0, fmt.Errorf("httpsig/keyscope: stage name %q must be non-empty without %q", s.Name, "/")
	}
	fromIdx = -1
	if s.From != "" {
		fromIdx = slices.IndexFunc(d.Steps, func(st Step) bool { return st.Name == s.From })
		if fromIdx < 0 {
			return 0, fmt.Errorf("httpsig/keyscope: stage is from step %q, which the derivation does not have", s.From)
		}
	}
	need := make(map[string]bool)
	for i, step := range d.Steps {
		switch {
		case step.Scope:
			need[step.Name] = true
			if v := s.Scope[step.Name]; v == "" || strings.Contains(v, "/") {
				return 0, fmt.Errorf("httpsig/keyscope: stage scope %q must be non-empty without %q", step.Name, "/")
			}
		case step.Date != "" && i <= fromIdx:
			need[step.Name] = true
			v := s.Scope[step.Name]
			layout := dateLayouts[step.Date]
			t, perr := time.Parse(layout, v)
			if perr != nil || t.UTC().Format(layout) != v {
				return 0, fmt.Errorf("httpsig/keyscope: stage scope %q value %q is not a %s date", step.Name, v, step.Date)
			}
		}
	}
	for name := range s.Scope {
		if !need[name] {
			return 0, fmt.Errorf("httpsig/keyscope: stage scope has %q, which the derivation does not take from this stage", name)
		}
	}
	return fromIdx, nil
}
