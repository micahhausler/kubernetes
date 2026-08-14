// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

// Package sfv implements HTTP Structured Field Values as defined in RFC 9651.
//
// Structured Field Values are a typed syntax for HTTP field values. A field
// is defined as one of three top-level types: an [Item], a [List], or a
// [Dictionary]. Lists and Dictionaries contain Items and Inner Lists, and
// Items and Inner Lists can carry Parameters.
//
// Parse field values with [ParseItem], [ParseList], and [ParseDictionary],
// choosing the function that matches the field's definition. Bare values are
// represented by concrete types implementing [Value]; consume them with a
// type switch:
//
//	item, err := sfv.ParseItem(header.Values("Example")...)
//	if err != nil {
//		// The field must be ignored, per RFC 9651 Section 4.2.
//	}
//	switch v := item.Value.(type) {
//	case sfv.Token:
//		// ...
//	case sfv.Integer:
//		// ...
//	}
//
// Serialize with the MarshalText or AppendText methods on [Item], [List],
// and [Dictionary].
package sfv

import "time"

// A Value is a bare item: one of [Integer], [Decimal], [String], [Token],
// [Bytes], [Bool], [Date], or [DisplayString]. It appears as the value of an
// [Item] or a [Parameter].
type Value interface {
	isValue()
}

// An Integer is an integer between -999,999,999,999,999 and
// 999,999,999,999,999 inclusive.
type Integer int64

// A Decimal is a number with an integer component of at most 12 digits and a
// fractional component of at most three digits. Serialization rounds the
// fractional component to three decimal places, rounding ties to even.
type Decimal float64

// A String is a sequence of printable ASCII characters (0x20 to 0x7E).
type String string

// A Token is a short textual word beginning with an alphabetic character or
// "*", followed by characters from the HTTP token rule plus ":" and "/".
type Token string

// Bytes is a sequence of octets, serialized as base64 between colons.
//
// Because Bytes is a slice, values containing it are not comparable with ==.
type Bytes []byte

// A Bool is a boolean value.
type Bool bool

// A Date is an instant in time, expressed in seconds since the Unix epoch
// (excluding leap seconds). It may be negative.
type Date int64

// DateOf returns the Date at which t occurs, truncating sub-second precision.
func DateOf(t time.Time) Date { return Date(t.Unix()) }

// Time returns the time represented by d in UTC.
func (d Date) Time() time.Time { return time.Unix(int64(d), 0).UTC() }

// A DisplayString is a sequence of Unicode code points, intended for display
// to end users. Unlike [String], it may carry non-ASCII content.
type DisplayString string

func (Integer) isValue()       {}
func (Decimal) isValue()       {}
func (String) isValue()        {}
func (Token) isValue()         {}
func (Bytes) isValue()         {}
func (Bool) isValue()          {}
func (Date) isValue()          {}
func (DisplayString) isValue() {}

// A Member is a member of a [List] or [Dictionary]: either an [Item] or an
// [InnerList].
type Member interface {
	isMember()
}

// An Item is a bare [Value] with optional [Parameters].
type Item struct {
	Value  Value
	Params Parameters
}

// An InnerList is a sequence of Items with optional [Parameters].
type InnerList struct {
	Items  []Item
	Params Parameters
}

func (Item) isMember()      {}
func (InnerList) isMember() {}

// A Parameter is a single key-value pair in [Parameters]. Keys consist of
// lowercase letters, digits, "_", "-", ".", and "*", and must begin with a
// lowercase letter or "*".
type Parameter struct {
	Key   string
	Value Value
}

// Parameters is an ordered sequence of key-value pairs associated with an
// [Item] or [InnerList]. Keys are unique within a Parameters.
type Parameters []Parameter

// Get returns the value of the parameter with the given key, and reports
// whether it was found.
func (p Parameters) Get(key string) (Value, bool) {
	for _, param := range p {
		if param.Key == key {
			return param.Value, true
		}
	}
	return nil, false
}

// A List is an ordered sequence of Items and Inner Lists.
//
// An empty List is represented in HTTP by omitting the field entirely, so
// fields defined as Lists have a default empty value.
type List []Member

// A DictMember is a single key-value pair in a [Dictionary]. Keys follow the
// same rules as [Parameter] keys.
type DictMember struct {
	Key   string
	Value Member
}

// A Dictionary is an ordered map from keys to Items and Inner Lists. Keys are
// unique within a Dictionary.
//
// An empty Dictionary is represented in HTTP by omitting the field entirely,
// so fields defined as Dictionaries have a default empty value.
type Dictionary []DictMember

// Get returns the member with the given key, and reports whether it was
// found.
func (d Dictionary) Get(key string) (Member, bool) {
	for _, m := range d {
		if m.Key == key {
			return m.Value, true
		}
	}
	return nil, false
}
