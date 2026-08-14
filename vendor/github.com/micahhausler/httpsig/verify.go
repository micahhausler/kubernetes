// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package httpsig

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/micahhausler/sfv"
)

// ParseOptions control how message components are derived during
// verification.
type ParseOptions struct {
	// Scheme and Authority override the values derived from the request.
	// When empty, the scheme is inferred from the connection's TLS state
	// and the authority from the Host header. Servers behind a
	// TLS-terminating proxy must set these to the external values the
	// client signed, or valid signatures covering @scheme, @target-uri,
	// or @authority fail as if the signature bytes were wrong. The
	// X-Forwarded-* fields are untrusted input and are never consulted.
	Scheme    string
	Authority string

	// StructuredFields maps lowercase field names to their structured
	// field types, required for components with the SF flag.
	StructuredFields map[string]FieldType
}

// A Signature is one parsed signature from a request. Its accessors report
// unverified claims from the wire; they are attacker-controlled until
// [Signature.Verify] succeeds.
type Signature struct {
	label      string
	input      sfv.InnerList
	signature  []byte
	components []Component
	keyID      string
	alg        string
	nonce      string
	tag        string
	created    time.Time
	expires    time.Time
	base       []byte
	err        error
}

// Label returns the signature's label within the message.
func (s *Signature) Label() string { return s.label }

// KeyID returns the keyid parameter, or "" if absent. It is an unverified
// claim from the wire.
func (s *Signature) KeyID() string { return s.keyID }

// Alg returns the alg parameter, or "" if absent. It is an unverified claim
// from the wire; Verify rejects the signature if it disagrees with the
// verifier's algorithm.
func (s *Signature) Alg() Algorithm { return Algorithm(s.alg) }

// Nonce returns the nonce parameter, or "" if absent. Enforcing nonce
// uniqueness is the caller's responsibility.
func (s *Signature) Nonce() string { return s.nonce }

// Tag returns the application-specific tag parameter, or "" if absent.
func (s *Signature) Tag() string { return s.tag }

// Created returns the created parameter, or the zero time if absent.
func (s *Signature) Created() time.Time { return s.created }

// Expires returns the expires parameter, or the zero time if absent.
func (s *Signature) Expires() time.Time { return s.expires }

// Components returns the covered components in order.
func (s *Signature) Components() []Component { return slices.Clone(s.components) }

// ParseSignatures parses the signatures of a request and constructs their
// signature bases from the message as it currently stands. A nil opts is
// equivalent to the zero value.
//
// An error is returned only if the Signature or Signature-Input fields
// cannot be parsed. Defects confined to one signature, such as a covered
// component missing from the message, are reported by that signature's
// Verify method, so one bad signature cannot invalidate the others. A
// request with no signatures yields an empty slice.
//
// Duplicate labels resolve to the last value, per RFC 9651 dictionary
// parsing. An appended duplicate therefore replaces the original signature,
// which then fails to verify. This cannot produce a false accept, and it
// grants an intermediary nothing it does not already have: whoever can
// append header fields can drop the Signature field entirely.
func ParseSignatures(req *http.Request, opts *ParseOptions) ([]*Signature, error) {
	if opts == nil {
		opts = &ParseOptions{}
	}
	inputs, err := sfv.ParseDictionary(req.Header.Values("Signature-Input")...)
	if err != nil {
		return nil, syntaxErrorf("Signature-Input: %v", err)
	}
	sigs, err := sfv.ParseDictionary(req.Header.Values("Signature")...)
	if err != nil {
		return nil, syntaxErrorf("Signature: %v", err)
	}

	t := newTarget(req, opts.Scheme, opts.Authority, opts.StructuredFields)
	var out []*Signature
	for _, m := range inputs {
		s := &Signature{label: m.Key}
		out = append(out, s)
		input, ok := m.Value.(sfv.InnerList)
		if !ok {
			s.err = syntaxErrorf("signature %q: input is not an inner list", m.Key)
			continue
		}
		s.input = input
		sigMember, ok := sigs.Get(m.Key)
		if !ok {
			s.err = syntaxErrorf("signature %q: no Signature field value", m.Key)
			continue
		}
		item, ok := sigMember.(sfv.Item)
		if !ok {
			s.err = syntaxErrorf("signature %q: value is not an item", m.Key)
			continue
		}
		sig, ok := item.Value.(sfv.Bytes)
		if !ok {
			s.err = syntaxErrorf("signature %q: value is not a byte sequence", m.Key)
			continue
		}
		s.signature = sig
		s.parse(t)
	}
	for _, m := range sigs {
		if _, ok := inputs.Get(m.Key); !ok {
			out = append(out, &Signature{
				label: m.Key,
				err:   syntaxErrorf("signature %q: no Signature-Input field value", m.Key),
			})
		}
	}
	return out, nil
}

// parse extracts the signature parameters and covered components from the
// wire inner list and eagerly constructs the signature base, pinning the
// verified semantics to the message as parsed.
func (s *Signature) parse(t *target) {
	for _, p := range s.input.Params {
		var err error
		switch p.Key {
		case "created":
			s.created, err = paramTime(p)
		case "expires":
			s.expires, err = paramTime(p)
		case "nonce":
			s.nonce, err = paramString(p)
		case "alg":
			s.alg, err = paramString(p)
		case "keyid":
			s.keyID, err = paramString(p)
		case "tag":
			s.tag, err = paramString(p)
		default:
			// Unknown metadata parameters are covered by the
			// signature base and need no interpretation here.
		}
		if err != nil {
			s.err = syntaxErrorf("signature %q: %v", s.label, err)
			return
		}
	}
	ids := make([]covered, len(s.input.Items))
	s.components = make([]Component, len(s.input.Items))
	for i, item := range s.input.Items {
		c, err := parseComponent(item)
		if err != nil {
			s.err = syntaxErrorf("signature %q: %v", s.label, err)
			return
		}
		ids[i] = covered{id: item, c: c}
		s.components[i] = c
	}
	base, err := signatureBase(t, ids, s.input)
	if err != nil {
		s.err = syntaxErrorf("signature %q: %v", s.label, err)
		return
	}
	s.base = base
}

func paramTime(p sfv.Parameter) (time.Time, error) {
	v, ok := p.Value.(sfv.Integer)
	if !ok {
		return time.Time{}, fmt.Errorf("%s parameter is not an integer", p.Key)
	}
	return time.Unix(int64(v), 0), nil
}

func paramString(p sfv.Parameter) (string, error) {
	v, ok := p.Value.(sfv.String)
	if !ok {
		return "", fmt.Errorf("%s parameter is not a string", p.Key)
	}
	return string(v), nil
}

// A Policy sets the application requirements a signature must meet, per
// [RFC 9421 Section 3.2.1]. The zero value enforces only the requirements of
// the RFC itself: the expires parameter, if present, must not have passed,
// and the created parameter, if present, must not be in the future.
//
// [RFC 9421 Section 3.2.1]: https://datatracker.ietf.org/doc/html/rfc9421#section-3.2.1
type Policy struct {
	// RequiredComponents are components the signature must cover.
	// Signatures may cover more.
	RequiredComponents []Component

	// MaxAge is the maximum accepted signature age, measured from the
	// created parameter. If positive, signatures without a created
	// parameter are rejected.
	MaxAge time.Duration

	// Tolerance is added to time comparisons to allow for clock skew
	// between signer and verifier.
	Tolerance time.Duration

	// Now returns the verification time. If nil, time.Now is used.
	Now func() time.Time
}

// Verify checks the signature against the key and policy. A [*SyntaxError]
// reports that the signature or its covered components could not be parsed
// from the message; a [*VerificationError] reports a signature that does not
// meet the policy or does not verify. A nil error means the signature is
// valid and meets the policy.
//
// If the signature carries an alg parameter, it must agree with the
// verifier's algorithm. Nonce uniqueness is not checked; callers needing
// replay protection must track values from [Signature.Nonce] themselves.
func (s *Signature) Verify(key Verifier, policy Policy) error {
	if s.err != nil {
		return s.err
	}
	if s.alg != "" && Algorithm(s.alg) != key.Algorithm() {
		return s.fail(fmt.Errorf("%w: signature has %q, verifier has %q",
			ErrAlgorithmMismatch, s.alg, key.Algorithm()))
	}
	now := time.Now()
	if policy.Now != nil {
		now = policy.Now()
	}
	if !s.expires.IsZero() && now.After(s.expires.Add(policy.Tolerance)) {
		return s.fail(fmt.Errorf("%w: expired at %v", ErrExpired, s.expires))
	}
	if !s.created.IsZero() && s.created.After(now.Add(policy.Tolerance)) {
		return s.fail(fmt.Errorf("%w: created at %v", ErrCreatedInFuture, s.created))
	}
	if policy.MaxAge > 0 {
		if s.created.IsZero() {
			return s.fail(ErrMissingCreated)
		}
		if now.After(s.created.Add(policy.MaxAge + policy.Tolerance)) {
			return s.fail(fmt.Errorf("%w: created at %v, older than %v", ErrExpired, s.created, policy.MaxAge))
		}
	}
	for _, rc := range policy.RequiredComponents {
		if !slices.Contains(s.components, rc) {
			return s.fail(fmt.Errorf("%w: %q", ErrMissingComponent, rc.Name))
		}
	}
	if err := key.Verify(s.base, s.signature); err != nil {
		return s.fail(err)
	}
	return nil
}

func (s *Signature) fail(err error) error {
	return &VerificationError{Err: err, SignatureBase: s.base}
}
