// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package httpsig

import (
	"strings"

	"github.com/micahhausler/sfv"
)

// A covered pairs a component identifier as it appears on the wire with its
// parsed form. The identifier is reserialized verbatim into the signature
// base so that signer and verifier produce identical bytes.
type covered struct {
	id sfv.Item
	c  Component
}

// signatureBase builds the signature base per [RFC 9421 Section 2.5].
// params is the @signature-params inner list, whose items must be the
// identifiers in ids.
//
// [RFC 9421 Section 2.5]: https://datatracker.ietf.org/doc/html/rfc9421#section-2.5
func signatureBase(t *target, ids []covered, params sfv.InnerList) ([]byte, error) {
	var base []byte
	for i, cc := range ids {
		for _, prev := range ids[:i] {
			if prev.c == cc.c {
				return nil, syntaxErrorf("duplicate component %q", cc.c.Name)
			}
		}
		line, err := cc.id.MarshalText()
		if err != nil {
			return nil, syntaxErrorf("component %q: %v", cc.c.Name, err)
		}
		value, err := t.componentValue(cc.c)
		if err != nil {
			return nil, err
		}
		if err := checkValue(cc.c.Name, value); err != nil {
			return nil, err
		}
		base = append(base, line...)
		base = append(base, ':', ' ')
		base = append(base, value...)
		base = append(base, '\n')
	}
	base = append(base, `"@signature-params": `...)
	b, err := sfv.List{params}.MarshalText()
	if err != nil {
		return nil, syntaxErrorf("signature parameters: %v", err)
	}
	return append(base, b...), nil
}

// checkValue rejects component values that would corrupt the signature base:
// newlines and non-ASCII bytes.
func checkValue(name, value string) error {
	if strings.ContainsAny(value, "\r\n") {
		return syntaxErrorf("component %q value contains a newline", name)
	}
	for i := 0; i < len(value); i++ {
		if value[i] > 0x7f {
			return syntaxErrorf("component %q value contains a non-ASCII byte", name)
		}
	}
	return nil
}
