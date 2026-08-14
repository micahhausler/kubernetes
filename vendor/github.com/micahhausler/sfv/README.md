# sfv

[![Go Reference](https://pkg.go.dev/badge/github.com/micahhausler/sfv.svg)](https://pkg.go.dev/github.com/micahhausler/sfv)

Package `sfv` implements HTTP Structured Field Values, as defined in
[RFC 9651](https://www.rfc-editor.org/rfc/rfc9651).

Structured Field Values are a typed syntax for HTTP field values. A field is
defined as one of three top-level types: an Item, a List, or a Dictionary.
This package parses field values into plain Go types and serializes them back,
following the RFC algorithms exactly.

## Usage

Parse with the function that matches the field's definition. Bare values are
concrete types behind the `Value` interface; consume them with a type switch.

```go
list, err := sfv.ParseList(header.Values("Example")...)
if err != nil {
    // The field must be ignored, per RFC 9651 Section 4.2.
}
for _, member := range list {
    switch m := member.(type) {
    case sfv.Item:
        if tok, ok := m.Value.(sfv.Token); ok {
            fmt.Println(tok)
        }
    case sfv.InnerList:
        // ...
    }
}
```

Construct values with composite literals and serialize with `MarshalText`:

```go
dict := sfv.Dictionary{
    {Key: "a", Value: sfv.Item{Value: sfv.Bool(true)}},
    {Key: "b", Value: sfv.Item{
        Value:  sfv.Token("jpeg"),
        Params: sfv.Parameters{{Key: "q", Value: sfv.Decimal(0.5)}},
    }},
}
text, err := dict.MarshalText() // a, b=jpeg;q=0.5
```

## Conformance

The full [httpwg/structured-field-tests](https://github.com/httpwg/structured-field-tests)
suite is vendored as a git submodule under `testdata/` and runs as part of
`go test`. All tests pass, including the optional (`can_fail`) cases. Fuzz
targets check that every parsed value serializes to a canonical form that
reparses to the same structure.

To run the tests:

```
git submodule update --init
go test ./...
```

## License

Apache-2.0
