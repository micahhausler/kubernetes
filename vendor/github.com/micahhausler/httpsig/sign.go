// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package httpsig

import (
	"net/http"
	"strings"
	"time"

	"github.com/micahhausler/sfv"
)

// SignOptions control how a request signature is created.
type SignOptions struct {
	// Components are the message components to cover. If nil, the
	// signature covers @method and @target-uri. An empty, non-nil slice
	// covers no components, which [RFC 9421 Section 7.2.1] discourages.
	//
	// [RFC 9421 Section 7.2.1]: https://datatracker.ietf.org/doc/html/rfc9421#section-7.2.1
	Components []Component

	// Label identifies the signature within the message. It defaults to
	// "sig1".
	Label string

	// Created is the signature creation time, truncated to seconds. The
	// zero value means the current time.
	Created time.Time

	// Expires is the signature expiration time, truncated to seconds.
	// The zero value omits the expires parameter.
	Expires time.Time

	// KeyID sets the keyid parameter. Empty omits it.
	KeyID string

	// Nonce sets the nonce parameter. Empty omits it.
	Nonce string

	// Tag sets the application-specific tag parameter. Empty omits it.
	Tag string

	// IncludeAlg includes the signer's algorithm as the alg parameter.
	IncludeAlg bool

	// Scheme and Authority override the values derived from the request,
	// for use with derived components such as @target-uri.
	Scheme    string
	Authority string

	// StructuredFields maps lowercase field names to their structured
	// field types, required for components with the SF flag.
	StructuredFields map[string]FieldType
}

// Sign signs req and adds the signature to its Signature-Input and Signature
// header fields, merging with any signatures already present.
func Sign(req *http.Request, key Signer, opts SignOptions) error {
	comps := opts.Components
	if comps == nil {
		comps = []Component{{Name: "@method"}, {Name: "@target-uri"}}
	}
	ids := make([]covered, len(comps))
	items := make([]sfv.Item, len(comps))
	for i, c := range comps {
		c.Name = strings.ToLower(c.Name)
		if err := c.validate(); err != nil {
			return err
		}
		ids[i] = covered{id: c.identifier(), c: c}
		items[i] = ids[i].id
	}

	created := opts.Created
	if created.IsZero() {
		created = time.Now()
	}
	params := sfv.Parameters{{Key: "created", Value: sfv.Integer(created.Unix())}}
	if !opts.Expires.IsZero() {
		params = append(params, sfv.Parameter{Key: "expires", Value: sfv.Integer(opts.Expires.Unix())})
	}
	if opts.Nonce != "" {
		params = append(params, sfv.Parameter{Key: "nonce", Value: sfv.String(opts.Nonce)})
	}
	if opts.IncludeAlg {
		params = append(params, sfv.Parameter{Key: "alg", Value: sfv.String(key.Algorithm())})
	}
	if opts.KeyID != "" {
		params = append(params, sfv.Parameter{Key: "keyid", Value: sfv.String(opts.KeyID)})
	}
	if opts.Tag != "" {
		params = append(params, sfv.Parameter{Key: "tag", Value: sfv.String(opts.Tag)})
	}
	input := sfv.InnerList{Items: items, Params: params}

	t := newTarget(req, opts.Scheme, opts.Authority, opts.StructuredFields)
	base, err := signatureBase(t, ids, input)
	if err != nil {
		return err
	}
	sig, err := key.Sign(base)
	if err != nil {
		return err
	}

	label := opts.Label
	if label == "" {
		label = "sig1"
	}
	return addSignature(req.Header, label, input, sig)
}

// addSignature merges a labeled signature into the Signature-Input and
// Signature dictionaries of h.
func addSignature(h http.Header, label string, input sfv.InnerList, sig []byte) error {
	inputs, err := sfv.ParseDictionary(h.Values("Signature-Input")...)
	if err != nil {
		return syntaxErrorf("Signature-Input: %v", err)
	}
	sigs, err := sfv.ParseDictionary(h.Values("Signature")...)
	if err != nil {
		return syntaxErrorf("Signature: %v", err)
	}
	if _, ok := inputs.Get(label); ok {
		return syntaxErrorf("signature label %q already present", label)
	}
	if _, ok := sigs.Get(label); ok {
		return syntaxErrorf("signature label %q already present", label)
	}
	inputs = append(inputs, sfv.DictMember{Key: label, Value: input})
	sigs = append(sigs, sfv.DictMember{Key: label, Value: sfv.Item{Value: sfv.Bytes(sig)}})

	b, err := inputs.MarshalText()
	if err != nil {
		return syntaxErrorf("Signature-Input: %v", err)
	}
	h.Set("Signature-Input", string(b))
	b, err = sigs.MarshalText()
	if err != nil {
		return syntaxErrorf("Signature: %v", err)
	}
	h.Set("Signature", string(b))
	return nil
}
