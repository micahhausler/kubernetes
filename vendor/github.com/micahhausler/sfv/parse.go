// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package sfv

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// A SyntaxError describes where parsing of a structured field value failed.
// The offset is relative to the combined field value: when multiple field
// lines are parsed together, they are joined with ", " first.
type SyntaxError struct {
	Offset int    // byte offset where the error was detected
	Msg    string // description of the error
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("sfv: %s at offset %d", e.Msg, e.Offset)
}

// ParseItem parses field values defined as an Item, per RFC 9651 Section
// 4.2. Multiple field lines are combined before parsing, per Section 5.2 of
// RFC 9110.
//
// If parsing fails, the entire field must be ignored.
func ParseItem(fields ...string) (Item, error) {
	p := &parser{s: combine(fields)}
	p.skipSP()
	item, err := p.parseItem()
	if err != nil {
		return Item{}, err
	}
	if err := p.finish(); err != nil {
		return Item{}, err
	}
	return item, nil
}

// ParseList parses field values defined as a List, per RFC 9651 Section 4.2.
// Multiple field lines are combined before parsing, per Section 5.2 of RFC
// 9110. An absent field (no lines) is an empty List.
//
// If parsing fails, the entire field must be ignored.
func ParseList(fields ...string) (List, error) {
	p := &parser{s: combine(fields)}
	p.skipSP()
	list, err := p.parseList()
	if err != nil {
		return nil, err
	}
	if err := p.finish(); err != nil {
		return nil, err
	}
	return list, nil
}

// ParseDictionary parses field values defined as a Dictionary, per RFC 9651
// Section 4.2. Multiple field lines are combined before parsing, per Section
// 5.2 of RFC 9110. An absent field (no lines) is an empty Dictionary.
//
// If parsing fails, the entire field must be ignored.
func ParseDictionary(fields ...string) (Dictionary, error) {
	p := &parser{s: combine(fields)}
	p.skipSP()
	dict, err := p.parseDictionary()
	if err != nil {
		return nil, err
	}
	if err := p.finish(); err != nil {
		return nil, err
	}
	return dict, nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (i *Item) UnmarshalText(text []byte) error {
	item, err := ParseItem(string(text))
	if err != nil {
		return err
	}
	*i = item
	return nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (l *List) UnmarshalText(text []byte) error {
	list, err := ParseList(string(text))
	if err != nil {
		return err
	}
	*l = list
	return nil
}

// UnmarshalText implements [encoding.TextUnmarshaler].
func (d *Dictionary) UnmarshalText(text []byte) error {
	dict, err := ParseDictionary(string(text))
	if err != nil {
		return err
	}
	*d = dict
	return nil
}

func combine(fields []string) string {
	return strings.Join(fields, ", ")
}

type parser struct {
	s string
	i int
}

func (p *parser) err(msg string) *SyntaxError {
	return &SyntaxError{Offset: p.i, Msg: msg}
}

func (p *parser) eof() bool { return p.i >= len(p.s) }

// peek returns the next byte, or 0 at end of input.
func (p *parser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.s[p.i]
}

func (p *parser) skipSP() {
	for !p.eof() && p.s[p.i] == ' ' {
		p.i++
	}
}

func (p *parser) skipOWS() {
	for !p.eof() && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

// finish implements the trailing steps of Section 4.2: discard trailing SP
// and fail if input remains.
func (p *parser) finish() error {
	p.skipSP()
	if !p.eof() {
		return p.err("unexpected trailing characters")
	}
	return nil
}

// parseList implements Section 4.2.1.
func (p *parser) parseList() (List, error) {
	var members List
	for !p.eof() {
		m, err := p.parseItemOrInnerList()
		if err != nil {
			return nil, err
		}
		members = append(members, m)
		p.skipOWS()
		if p.eof() {
			return members, nil
		}
		if p.s[p.i] != ',' {
			return nil, p.err("expected \",\" between list members")
		}
		p.i++
		p.skipOWS()
		if p.eof() {
			return nil, p.err("trailing comma in list")
		}
	}
	return members, nil
}

// parseItemOrInnerList implements Section 4.2.1.1.
func (p *parser) parseItemOrInnerList() (Member, error) {
	if p.peek() == '(' {
		return p.parseInnerList()
	}
	return p.parseItem()
}

// parseInnerList implements Section 4.2.1.2.
func (p *parser) parseInnerList() (InnerList, error) {
	if p.peek() != '(' {
		return InnerList{}, p.err("expected \"(\" to begin inner list")
	}
	p.i++
	var items []Item
	for !p.eof() {
		p.skipSP()
		if p.peek() == ')' {
			p.i++
			params, err := p.parseParameters()
			if err != nil {
				return InnerList{}, err
			}
			return InnerList{Items: items, Params: params}, nil
		}
		item, err := p.parseItem()
		if err != nil {
			return InnerList{}, err
		}
		items = append(items, item)
		if c := p.peek(); c != ' ' && c != ')' {
			return InnerList{}, p.err("expected space or \")\" after inner list item")
		}
	}
	return InnerList{}, p.err("unterminated inner list")
}

// parseDictionary implements Section 4.2.2.
func (p *parser) parseDictionary() (Dictionary, error) {
	var dict Dictionary
	for !p.eof() {
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		var member Member
		if p.peek() == '=' {
			p.i++
			member, err = p.parseItemOrInnerList()
			if err != nil {
				return nil, err
			}
		} else {
			params, err := p.parseParameters()
			if err != nil {
				return nil, err
			}
			member = Item{Value: Bool(true), Params: params}
		}
		// Duplicate keys: the last value wins, in the first key's position.
		found := false
		for j := range dict {
			if dict[j].Key == key {
				dict[j].Value = member
				found = true
				break
			}
		}
		if !found {
			dict = append(dict, DictMember{Key: key, Value: member})
		}
		p.skipOWS()
		if p.eof() {
			return dict, nil
		}
		if p.s[p.i] != ',' {
			return nil, p.err("expected \",\" between dictionary members")
		}
		p.i++
		p.skipOWS()
		if p.eof() {
			return nil, p.err("trailing comma in dictionary")
		}
	}
	return dict, nil
}

// parseItem implements Section 4.2.3.
func (p *parser) parseItem() (Item, error) {
	v, err := p.parseBareItem()
	if err != nil {
		return Item{}, err
	}
	params, err := p.parseParameters()
	if err != nil {
		return Item{}, err
	}
	return Item{Value: v, Params: params}, nil
}

// parseBareItem implements Section 4.2.3.1.
func (p *parser) parseBareItem() (Value, error) {
	switch c := p.peek(); {
	case c == '-' || isDigit(c):
		return p.parseNumber()
	case c == '"':
		return p.parseString()
	case isAlpha(c) || c == '*':
		return p.parseToken()
	case c == ':':
		return p.parseBytes()
	case c == '?':
		return p.parseBool()
	case c == '@':
		return p.parseDate()
	case c == '%':
		return p.parseDisplayString()
	default:
		return nil, p.err("unrecognized item type")
	}
}

// parseParameters implements Section 4.2.3.2.
func (p *parser) parseParameters() (Parameters, error) {
	var params Parameters
	for p.peek() == ';' {
		p.i++
		p.skipSP()
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		var value Value = Bool(true)
		if p.peek() == '=' {
			p.i++
			value, err = p.parseBareItem()
			if err != nil {
				return nil, err
			}
		}
		// Duplicate keys: the last value wins, in the first key's position.
		found := false
		for j := range params {
			if params[j].Key == key {
				params[j].Value = value
				found = true
				break
			}
		}
		if !found {
			params = append(params, Parameter{Key: key, Value: value})
		}
	}
	return params, nil
}

// parseKey implements Section 4.2.3.3.
func (p *parser) parseKey() (string, error) {
	if c := p.peek(); !isLCAlpha(c) && c != '*' {
		return "", p.err("key must begin with lowercase letter or \"*\"")
	}
	start := p.i
	for !p.eof() && isKeyChar(p.s[p.i]) {
		p.i++
	}
	return p.s[start:p.i], nil
}

// parseNumber implements Section 4.2.4 (Parsing an Integer or Decimal).
func (p *parser) parseNumber() (Value, error) {
	start := p.i
	if p.peek() == '-' {
		p.i++
	}
	if p.eof() {
		return nil, p.err("empty number")
	}
	if !isDigit(p.peek()) {
		return nil, p.err("number must begin with a digit")
	}
	numStart := p.i
	decimal := false
	dot := 0
	for !p.eof() {
		c := p.s[p.i]
		switch {
		case isDigit(c):
			p.i++
		case !decimal && c == '.':
			if p.i-numStart > 12 {
				return nil, p.err("integer component of decimal too long")
			}
			decimal = true
			dot = p.i
			p.i++
		default:
			goto done
		}
		if !decimal && p.i-numStart > 15 {
			return nil, p.err("integer too long")
		}
		if decimal && p.i-numStart > 16 {
			return nil, p.err("decimal too long")
		}
	}
done:
	if !decimal {
		n, err := strconv.ParseInt(p.s[start:p.i], 10, 64)
		if err != nil {
			return nil, p.err("invalid integer")
		}
		return Integer(n), nil
	}
	if dot == p.i-1 {
		return nil, p.err("decimal ends in \".\"")
	}
	if p.i-dot-1 > 3 {
		return nil, p.err("too many digits after decimal point")
	}
	f, err := strconv.ParseFloat(p.s[start:p.i], 64)
	if err != nil {
		return nil, p.err("invalid decimal")
	}
	return Decimal(f), nil
}

// parseString implements Section 4.2.5.
func (p *parser) parseString() (String, error) {
	if p.peek() != '"' {
		return "", p.err("expected DQUOTE to begin string")
	}
	p.i++
	var sb strings.Builder
	for !p.eof() {
		c := p.s[p.i]
		p.i++
		switch {
		case c == '\\':
			if p.eof() {
				return "", p.err("unterminated escape sequence")
			}
			next := p.s[p.i]
			p.i++
			if next != '"' && next != '\\' {
				return "", p.err("invalid escape sequence")
			}
			sb.WriteByte(next)
		case c == '"':
			return String(sb.String()), nil
		case c < 0x20 || c > 0x7e:
			return "", p.err("invalid character in string")
		default:
			sb.WriteByte(c)
		}
	}
	return "", p.err("unterminated string")
}

// parseToken implements Section 4.2.6.
func (p *parser) parseToken() (Token, error) {
	if c := p.peek(); !isAlpha(c) && c != '*' {
		return "", p.err("token must begin with a letter or \"*\"")
	}
	start := p.i
	for !p.eof() && isTokenChar(p.s[p.i]) {
		p.i++
	}
	return Token(p.s[start:p.i]), nil
}

// parseBytes implements Section 4.2.7 (Parsing a Byte Sequence).
func (p *parser) parseBytes() (Bytes, error) {
	if p.peek() != ':' {
		return nil, p.err("expected \":\" to begin byte sequence")
	}
	p.i++
	start := p.i
	end := strings.IndexByte(p.s[start:], ':')
	if end < 0 {
		return nil, p.err("unterminated byte sequence")
	}
	b64 := p.s[start : start+end]
	p.i = start + end + 1
	for j := 0; j < len(b64); j++ {
		if c := b64[j]; !isAlpha(c) && !isDigit(c) && c != '+' && c != '/' && c != '=' {
			p.i = start + j
			return nil, p.err("invalid character in byte sequence")
		}
	}
	// Synthesize padding, as recommended by Section 4.2.7.
	if n := len(b64) % 4; n != 0 {
		b64 += "===="[n:]
	}
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		p.i = start
		return nil, p.err("invalid base64 in byte sequence")
	}
	return Bytes(decoded), nil
}

// parseBool implements Section 4.2.8 (Parsing a Boolean).
func (p *parser) parseBool() (Bool, error) {
	if p.peek() != '?' {
		return false, p.err("expected \"?\" to begin boolean")
	}
	p.i++
	switch p.peek() {
	case '1':
		p.i++
		return true, nil
	case '0':
		p.i++
		return false, nil
	}
	return false, p.err("boolean must be \"?0\" or \"?1\"")
}

// parseDate implements Section 4.2.9.
func (p *parser) parseDate() (Date, error) {
	if p.peek() != '@' {
		return 0, p.err("expected \"@\" to begin date")
	}
	p.i++
	n, err := p.parseNumber()
	if err != nil {
		return 0, err
	}
	i, ok := n.(Integer)
	if !ok {
		return 0, p.err("date must be an integer")
	}
	return Date(i), nil
}

// parseDisplayString implements Section 4.2.10.
func (p *parser) parseDisplayString() (DisplayString, error) {
	if p.eof() || !strings.HasPrefix(p.s[p.i:], `%"`) {
		return "", p.err("expected \"%\" and DQUOTE to begin display string")
	}
	p.i += 2
	var sb strings.Builder
	for !p.eof() {
		c := p.s[p.i]
		p.i++
		switch {
		case c < 0x20 || c > 0x7e:
			return "", p.err("invalid character in display string")
		case c == '%':
			if len(p.s)-p.i < 2 {
				return "", p.err("truncated percent escape in display string")
			}
			hi, ok1 := hexVal(p.s[p.i])
			lo, ok2 := hexVal(p.s[p.i+1])
			if !ok1 || !ok2 {
				return "", p.err("invalid percent escape in display string")
			}
			p.i += 2
			sb.WriteByte(hi<<4 | lo)
		case c == '"':
			s := sb.String()
			if !utf8.ValidString(s) {
				return "", p.err("display string is not valid UTF-8")
			}
			return DisplayString(s), nil
		default:
			sb.WriteByte(c)
		}
	}
	return "", p.err("unterminated display string")
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

func isDigit(c byte) bool   { return c >= '0' && c <= '9' }
func isLCAlpha(c byte) bool { return c >= 'a' && c <= 'z' }
func isAlpha(c byte) bool   { return isLCAlpha(c) || (c >= 'A' && c <= 'Z') }

func isKeyChar(c byte) bool {
	return isLCAlpha(c) || isDigit(c) || c == '_' || c == '-' || c == '.' || c == '*'
}

// isTokenChar reports whether c is in tchar (RFC 9110), ":", or "/".
func isTokenChar(c byte) bool {
	if isAlpha(c) || isDigit(c) {
		return true
	}
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~', ':', '/':
		return true
	}
	return false
}
