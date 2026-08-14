// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package httpsig

import (
	"net/http"
	"strings"

	"github.com/micahhausler/sfv"
)

// A Component identifies a message component covered by a signature: an HTTP
// field or a derived component, per [RFC 9421 Section 2].
//
// [RFC 9421 Section 2]: https://datatracker.ietf.org/doc/html/rfc9421#section-2
type Component struct {
	// Name is the lowercase HTTP field name, or a derived component name
	// beginning with "@".
	Name string

	// SF requires strict structured field serialization of the field
	// value (the sf parameter). The field's type must be registered in
	// the StructuredFields option.
	SF bool

	// Key selects a single member of a dictionary structured field (the
	// key parameter).
	Key string

	// BS wraps each field value as a byte sequence before combination
	// (the bs parameter).
	BS bool

	// QueryParam names the query parameter for the @query-param derived
	// component (the name parameter), in its encoded form.
	QueryParam string
}

// A FieldType is the structured field type of an HTTP field, used to
// serialize components with the SF flag.
type FieldType int

const (
	FieldTypeItem FieldType = iota + 1
	FieldTypeList
	FieldTypeDictionary
)

// Derived component names defined by [RFC 9421 Section 2.2] that apply to
// requests.
//
// [RFC 9421 Section 2.2]: https://datatracker.ietf.org/doc/html/rfc9421#section-2.2
var derivedNames = map[string]bool{
	"@method":         true,
	"@target-uri":     true,
	"@authority":      true,
	"@scheme":         true,
	"@request-target": true,
	"@path":           true,
	"@query":          true,
	"@query-param":    true,
}

// validate checks the component's name and parameter combinations for use
// with a request message.
func (c Component) validate() error {
	if c.Name == "" {
		return syntaxErrorf("empty component name")
	}
	if strings.HasPrefix(c.Name, "@") {
		if c.Name == "@status" {
			return syntaxErrorf("@status applies only to responses")
		}
		if c.Name == "@signature-params" {
			return syntaxErrorf("@signature-params cannot be a covered component")
		}
		if !derivedNames[c.Name] {
			return syntaxErrorf("unknown derived component %q", c.Name)
		}
		if c.SF || c.Key != "" || c.BS {
			return syntaxErrorf("field parameters are not valid on %q", c.Name)
		}
		if c.Name == "@query-param" {
			if c.QueryParam == "" {
				return syntaxErrorf("@query-param requires a name parameter")
			}
		} else if c.QueryParam != "" {
			return syntaxErrorf("name parameter is not valid on %q", c.Name)
		}
		return nil
	}
	if c.Name != strings.ToLower(c.Name) {
		return syntaxErrorf("component name %q is not lowercase", c.Name)
	}
	if c.QueryParam != "" {
		return syntaxErrorf("name parameter is not valid on field %q", c.Name)
	}
	if c.BS && (c.SF || c.Key != "") {
		return syntaxErrorf("bs parameter is incompatible with sf and key")
	}
	return nil
}

// identifier returns the component identifier as a structured field item.
func (c Component) identifier() sfv.Item {
	item := sfv.Item{Value: sfv.String(c.Name)}
	if c.SF {
		item.Params = append(item.Params, sfv.Parameter{Key: "sf", Value: sfv.Bool(true)})
	}
	if c.Key != "" {
		item.Params = append(item.Params, sfv.Parameter{Key: "key", Value: sfv.String(c.Key)})
	}
	if c.BS {
		item.Params = append(item.Params, sfv.Parameter{Key: "bs", Value: sfv.Bool(true)})
	}
	if c.QueryParam != "" {
		item.Params = append(item.Params, sfv.Parameter{Key: "name", Value: sfv.String(c.QueryParam)})
	}
	return item
}

// ParseComponent parses a component identifier in the wire syntax of
// [RFC 9421 Section 2.1]: a quoted string followed by optional parameters,
// such as `"@method"` or `"@query-param";name="q"`. It accepts exactly the
// identifiers valid in a Signature-Input field for a request.
//
// [RFC 9421 Section 2.1]: https://datatracker.ietf.org/doc/html/rfc9421#section-2.1
func ParseComponent(s string) (Component, error) {
	item, err := sfv.ParseItem(s)
	if err != nil {
		return Component{}, syntaxErrorf("component identifier %q: %v", s, err)
	}
	return parseComponent(item)
}

// parseComponent interprets a structured field item from a Signature-Input
// inner list as a component identifier.
func parseComponent(item sfv.Item) (Component, error) {
	name, ok := item.Value.(sfv.String)
	if !ok {
		return Component{}, syntaxErrorf("component identifier is not a string")
	}
	c := Component{Name: string(name)}
	for _, p := range item.Params {
		switch p.Key {
		case "sf":
			if p.Value != sfv.Bool(true) {
				return Component{}, syntaxErrorf("sf parameter must be true")
			}
			c.SF = true
		case "key":
			key, ok := p.Value.(sfv.String)
			if !ok {
				return Component{}, syntaxErrorf("key parameter must be a string")
			}
			c.Key = string(key)
		case "bs":
			if p.Value != sfv.Bool(true) {
				return Component{}, syntaxErrorf("bs parameter must be true")
			}
			c.BS = true
		case "name":
			qp, ok := p.Value.(sfv.String)
			if !ok {
				return Component{}, syntaxErrorf("name parameter must be a string")
			}
			c.QueryParam = string(qp)
		case "req":
			return Component{}, syntaxErrorf("req parameter is not valid for a request")
		case "tr":
			return Component{}, syntaxErrorf("tr parameter is not supported")
		default:
			return Component{}, syntaxErrorf("unknown component parameter %q", p.Key)
		}
	}
	if err := c.validate(); err != nil {
		return Component{}, err
	}
	return c, nil
}

// A target is a request message with its scheme and authority resolved, the
// context component values are derived from.
type target struct {
	req       *http.Request
	scheme    string
	authority string
	sfTypes   map[string]FieldType
}

// newTarget resolves the request's scheme and authority. Overrides take
// precedence; otherwise outbound requests use the request URL and inbound
// requests use the Host and TLS state.
func newTarget(req *http.Request, scheme, authority string, sfTypes map[string]FieldType) *target {
	if scheme == "" {
		scheme = req.URL.Scheme
	}
	if scheme == "" {
		if req.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	if authority == "" {
		authority = req.URL.Host
	}
	if authority == "" {
		authority = req.Host
	}
	return &target{
		req:       req,
		scheme:    strings.ToLower(scheme),
		authority: normalizeAuthority(authority, strings.ToLower(scheme)),
		sfTypes:   sfTypes,
	}
}

// normalizeAuthority lowercases the host and strips the scheme's default
// port, per [RFC 9110 Section 4.2.3].
//
// [RFC 9110 Section 4.2.3]: https://datatracker.ietf.org/doc/html/rfc9110#section-4.2.3
func normalizeAuthority(authority, scheme string) string {
	authority = strings.ToLower(authority)
	switch scheme {
	case "http":
		authority = strings.TrimSuffix(authority, ":80")
	case "https":
		authority = strings.TrimSuffix(authority, ":443")
	}
	return authority
}

// componentValue derives the canonical value for a covered component, per
// RFC 9421 Sections [2.1] and [2.2]. The component must have been validated.
//
// [2.1]: https://datatracker.ietf.org/doc/html/rfc9421#section-2.1
// [2.2]: https://datatracker.ietf.org/doc/html/rfc9421#section-2.2
func (t *target) componentValue(c Component) (string, error) {
	if !strings.HasPrefix(c.Name, "@") {
		return t.fieldValue(c)
	}
	switch c.Name {
	case "@method":
		if t.req.Method == "" {
			return "GET", nil
		}
		return t.req.Method, nil
	case "@target-uri":
		return t.scheme + "://" + t.authority + t.path() + t.rawQuery(), nil
	case "@authority":
		return t.authority, nil
	case "@scheme":
		return t.scheme, nil
	case "@request-target":
		if t.req.RequestURI != "" {
			return t.req.RequestURI, nil
		}
		return t.path() + t.rawQuery(), nil
	case "@path":
		return t.path(), nil
	case "@query":
		return "?" + t.req.URL.RawQuery, nil
	case "@query-param":
		return t.queryParam(c.QueryParam)
	}
	return "", syntaxErrorf("unknown derived component %q", c.Name)
}

func (t *target) path() string {
	if p := t.req.URL.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

func (t *target) rawQuery() string {
	if q := t.req.URL.RawQuery; q != "" {
		return "?" + q
	}
	return ""
}

// fieldValue canonicalizes an HTTP field value per [RFC 9421 Section 2.1].
//
// [RFC 9421 Section 2.1]: https://datatracker.ietf.org/doc/html/rfc9421#section-2.1
func (t *target) fieldValue(c Component) (string, error) {
	values := t.req.Header.Values(c.Name)
	if len(values) == 0 && c.Name == "host" && t.req.Host != "" {
		// net/http carries the Host header in Request.Host.
		values = []string{t.req.Host}
	}
	if len(values) == 0 {
		return "", syntaxErrorf("field %q is not present in the message", c.Name)
	}
	// Header.Values returns the underlying slice; do not mutate it.
	canonical := make([]string, len(values))
	for i, v := range values {
		canonical[i] = canonicalFieldValue(v)
	}
	values = canonical
	switch {
	case c.BS:
		list := make(sfv.List, len(values))
		for i, v := range values {
			list[i] = sfv.Item{Value: sfv.Bytes(v)}
		}
		b, err := list.MarshalText()
		if err != nil {
			return "", syntaxErrorf("field %q: %v", c.Name, err)
		}
		return string(b), nil
	case c.Key != "":
		dict, err := sfv.ParseDictionary(values...)
		if err != nil {
			return "", syntaxErrorf("field %q is not a dictionary: %v", c.Name, err)
		}
		member, ok := dict.Get(c.Key)
		if !ok {
			return "", syntaxErrorf("field %q has no member %q", c.Name, c.Key)
		}
		b, err := sfv.List{member}.MarshalText()
		if err != nil {
			return "", syntaxErrorf("field %q member %q: %v", c.Name, c.Key, err)
		}
		return string(b), nil
	case c.SF:
		return t.strictFieldValue(c.Name, values)
	}
	return strings.Join(values, ", "), nil
}

// strictFieldValue reserializes a structured field value per
// [RFC 9421 Section 2.1.1]. The field's type must be registered in sfTypes.
//
// [RFC 9421 Section 2.1.1]: https://datatracker.ietf.org/doc/html/rfc9421#section-2.1.1
func (t *target) strictFieldValue(name string, values []string) (string, error) {
	ft, ok := t.sfTypes[name]
	if !ok {
		return "", syntaxErrorf("structured field type of %q is not known", name)
	}
	var (
		b   []byte
		err error
	)
	switch ft {
	case FieldTypeItem:
		var item sfv.Item
		if item, err = sfv.ParseItem(values...); err == nil {
			b, err = item.MarshalText()
		}
	case FieldTypeList:
		var list sfv.List
		if list, err = sfv.ParseList(values...); err == nil {
			b, err = list.MarshalText()
		}
	case FieldTypeDictionary:
		var dict sfv.Dictionary
		if dict, err = sfv.ParseDictionary(values...); err == nil {
			b, err = dict.MarshalText()
		}
	default:
		return "", syntaxErrorf("invalid structured field type for %q", name)
	}
	if err != nil {
		return "", syntaxErrorf("field %q: %v", name, err)
	}
	return string(b), nil
}

// canonicalFieldValue strips leading and trailing whitespace and replaces
// obsolete line folding with a single space.
func canonicalFieldValue(v string) string {
	v = strings.Trim(v, " \t")
	if !strings.Contains(v, "\r\n") {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\r' && i+1 < len(v) && v[i+1] == '\n' {
			b.WriteByte(' ')
			i++
			for i+1 < len(v) && (v[i+1] == ' ' || v[i+1] == '\t') {
				i++
			}
			continue
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

// queryParam derives the value of a named query parameter per
// [RFC 9421 Section 2.2.8]. The name is matched in its encoded form.
//
// [RFC 9421 Section 2.2.8]: https://datatracker.ietf.org/doc/html/rfc9421#section-2.2.8
func (t *target) queryParam(name string) (string, error) {
	var (
		value string
		found int
	)
	for _, pair := range strings.Split(t.req.URL.RawQuery, "&") {
		if pair == "" {
			continue
		}
		rawName, rawValue, _ := strings.Cut(pair, "=")
		if formEncode(formDecode(rawName)) != name {
			continue
		}
		found++
		value = formEncode(formDecode(rawValue))
	}
	switch found {
	case 0:
		return "", syntaxErrorf("query parameter %q is not present", name)
	case 1:
		return value, nil
	}
	// Section 2.2.8: repeated parameters must not be included.
	return "", syntaxErrorf("query parameter %q occurs %d times", name, found)
}

// formDecode decodes an application/x-www-form-urlencoded string per the
// WHATWG URL specification. Invalid escapes pass through undecoded.
func formDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '+':
			b.WriteByte(' ')
		case s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			b.WriteByte(hexVal(s[i+1])<<4 | hexVal(s[i+2]))
			i += 2
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// formEncode percent-encodes a string per the WHATWG URL specification's
// application/x-www-form-urlencoded percent-encode set, except that spaces
// are encoded as %20 per [RFC 9421 Section 2.2.8].
//
// [RFC 9421 Section 2.2.8]: https://datatracker.ietf.org/doc/html/rfc9421#section-2.2.8
func formEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '*' || c == '-' || c == '.' || c == '_' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0xf])
	}
	return b.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
