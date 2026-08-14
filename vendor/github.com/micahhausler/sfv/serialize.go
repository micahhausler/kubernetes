// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package sfv

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"
)

// MarshalText implements [encoding.TextMarshaler], serializing the Item per
// RFC 9651 Section 4.1.
func (i Item) MarshalText() ([]byte, error) { return i.AppendText(nil) }

// AppendText implements [encoding.TextAppender].
func (i Item) AppendText(b []byte) ([]byte, error) {
	return appendItem(b, i)
}

// MarshalText implements [encoding.TextMarshaler], serializing the List per
// RFC 9651 Section 4.1. An empty List serializes to no text at all: the
// caller should omit the field entirely.
func (l List) MarshalText() ([]byte, error) { return l.AppendText(nil) }

// AppendText implements [encoding.TextAppender].
func (l List) AppendText(b []byte) ([]byte, error) {
	var err error
	for i, m := range l {
		if i > 0 {
			b = append(b, ',', ' ')
		}
		b, err = appendMember(b, m)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

// MarshalText implements [encoding.TextMarshaler], serializing the
// Dictionary per RFC 9651 Section 4.1. An empty Dictionary serializes to no
// text at all: the caller should omit the field entirely.
func (d Dictionary) MarshalText() ([]byte, error) { return d.AppendText(nil) }

// AppendText implements [encoding.TextAppender].
func (d Dictionary) AppendText(b []byte) ([]byte, error) {
	var err error
	for i, m := range d {
		// Dictionaries are ordered maps; duplicate keys are not
		// representable in the data model.
		for _, prev := range d[:i] {
			if prev.Key == m.Key {
				return nil, fmt.Errorf("sfv: duplicate dictionary key %q", m.Key)
			}
		}
		if i > 0 {
			b = append(b, ',', ' ')
		}
		b, err = appendKey(b, m.Key)
		if err != nil {
			return nil, err
		}
		// A member whose value is Boolean true omits the value.
		if item, ok := m.Value.(Item); ok && item.Value == Bool(true) {
			b, err = appendParams(b, item.Params)
		} else {
			b = append(b, '=')
			b, err = appendMember(b, m.Value)
		}
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

func appendMember(b []byte, m Member) ([]byte, error) {
	switch m := m.(type) {
	case Item:
		return appendItem(b, m)
	case InnerList:
		return appendInnerList(b, m)
	}
	return nil, fmt.Errorf("sfv: cannot serialize member of type %T", m)
}

// appendInnerList implements Section 4.1.1.1.
func appendInnerList(b []byte, l InnerList) ([]byte, error) {
	var err error
	b = append(b, '(')
	for i, item := range l.Items {
		if i > 0 {
			b = append(b, ' ')
		}
		b, err = appendItem(b, item)
		if err != nil {
			return nil, err
		}
	}
	b = append(b, ')')
	return appendParams(b, l.Params)
}

// appendParams implements Section 4.1.1.2.
func appendParams(b []byte, params Parameters) ([]byte, error) {
	var err error
	for i, p := range params {
		// Parameters are ordered maps; duplicate keys are not
		// representable in the data model.
		for _, prev := range params[:i] {
			if prev.Key == p.Key {
				return nil, fmt.Errorf("sfv: duplicate parameter key %q", p.Key)
			}
		}
		b = append(b, ';')
		b, err = appendKey(b, p.Key)
		if err != nil {
			return nil, err
		}
		// A parameter whose value is Boolean true omits the value.
		if p.Value == Bool(true) {
			continue
		}
		b = append(b, '=')
		b, err = appendBareItem(b, p.Value)
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

// appendKey implements Section 4.1.1.3.
func appendKey(b []byte, key string) ([]byte, error) {
	if key == "" {
		return nil, errors.New("sfv: empty key")
	}
	if c := key[0]; !isLCAlpha(c) && c != '*' {
		return nil, fmt.Errorf("sfv: key %q must begin with lowercase letter or %q", key, "*")
	}
	for i := 0; i < len(key); i++ {
		if !isKeyChar(key[i]) {
			return nil, fmt.Errorf("sfv: invalid character in key %q", key)
		}
	}
	return append(b, key...), nil
}

// appendItem implements Section 4.1.3.
func appendItem(b []byte, i Item) ([]byte, error) {
	b, err := appendBareItem(b, i.Value)
	if err != nil {
		return nil, err
	}
	return appendParams(b, i.Params)
}

// appendBareItem implements Section 4.1.3.1.
func appendBareItem(b []byte, v Value) ([]byte, error) {
	switch v := v.(type) {
	case Integer:
		return appendInteger(b, int64(v))
	case Decimal:
		return appendDecimal(b, float64(v))
	case String:
		return appendString(b, string(v))
	case Token:
		return appendToken(b, string(v))
	case Bytes:
		b = append(b, ':')
		b = base64.StdEncoding.AppendEncode(b, v)
		return append(b, ':'), nil
	case Bool:
		if v {
			return append(b, '?', '1'), nil
		}
		return append(b, '?', '0'), nil
	case Date:
		return appendInteger(append(b, '@'), int64(v))
	case DisplayString:
		return appendDisplayString(b, string(v))
	}
	return nil, fmt.Errorf("sfv: cannot serialize value of type %T", v)
}

// appendInteger implements Section 4.1.4.
func appendInteger(b []byte, n int64) ([]byte, error) {
	if n < -999_999_999_999_999 || n > 999_999_999_999_999 {
		return nil, fmt.Errorf("sfv: integer %d out of range", n)
	}
	return strconv.AppendInt(b, n, 10), nil
}

// appendDecimal implements Section 4.1.5. The fractional component is
// rounded to three decimal places, ties to even.
func appendDecimal(b []byte, f float64) ([]byte, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil, fmt.Errorf("sfv: decimal %v is not a number", f)
	}
	scaled := math.RoundToEven(f * 1000)
	// For any parser-producible decimal (at most 12 integer and 3
	// fractional digits), scaled recovers the exact value: |f| <
	// 10¹², so representing the decimal as a float64 contributes
	// error below 6.2e-5×1000, the multiplication rounds with error
	// at most half an ulp (0.0625 below 10¹⁵), and the target
	// integer itself is exactly representable, being below 2⁵³.
	// The combined error is under 0.13, well inside the 0.5 that
	// rounding to nearest tolerates.
	if math.Abs(scaled) >= 1e15 {
		return nil, fmt.Errorf("sfv: decimal %v out of range", f)
	}
	n := int64(scaled)
	if n < 0 {
		b = append(b, '-')
		n = -n
	}
	b = strconv.AppendInt(b, n/1000, 10)
	b = append(b, '.')
	frac := n % 1000
	if frac == 0 {
		return append(b, '0'), nil
	}
	digits := strconv.AppendInt(nil, 1000+frac, 10)[1:] // zero-padded to 3
	for len(digits) > 1 && digits[len(digits)-1] == '0' {
		digits = digits[:len(digits)-1]
	}
	return append(b, digits...), nil
}

// appendString implements Section 4.1.6.
func appendString(b []byte, s string) ([]byte, error) {
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			return nil, fmt.Errorf("sfv: invalid character in string %q", s)
		}
		if c == '\\' || c == '"' {
			b = append(b, '\\')
		}
		b = append(b, c)
	}
	return append(b, '"'), nil
}

// appendToken implements Section 4.1.7.
func appendToken(b []byte, t string) ([]byte, error) {
	if t == "" {
		return nil, errors.New("sfv: empty token")
	}
	if c := t[0]; !isAlpha(c) && c != '*' {
		return nil, fmt.Errorf("sfv: token %q must begin with a letter or %q", t, "*")
	}
	for i := 0; i < len(t); i++ {
		if !isTokenChar(t[i]) {
			return nil, fmt.Errorf("sfv: invalid character in token %q", t)
		}
	}
	return append(b, t...), nil
}

// appendDisplayString implements Section 4.1.11.
func appendDisplayString(b []byte, s string) ([]byte, error) {
	if !utf8.ValidString(s) {
		return nil, fmt.Errorf("sfv: display string %q is not valid UTF-8", s)
	}
	b = append(b, '%', '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' || c == '"' || c < 0x20 || c > 0x7e {
			const hex = "0123456789abcdef"
			b = append(b, '%', hex[c>>4], hex[c&0xf])
		} else {
			b = append(b, c)
		}
	}
	return append(b, '"'), nil
}
