# httpsig

A Go implementation of HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)).

The root package provides the wire-level primitives: sign a request with a
key, parse the signatures on a request, and verify one against a key and
policy. Key distribution, signature selection, and nonce replay tracking
belong to the application.

These packages build on the primitives:

- [`sigconfig`](./sigconfig) — serializable configuration: a client's
  `SigningProfile` and a server's `VerifyPolicy`
- [`client`](./client) — an `http.RoundTripper` that signs requests per a
  profile
- [`server`](./server) — `http.Handler` middleware that verifies requests
  per a policy
- [`contentdigest`](./contentdigest) — the `Content-Digest` field of RFC
  9530, which binds a request body to a signature
- [`keyscope`](./keyscope) — scoped HMAC signing keys, so a verifier holds a
  key limited to one scope rather than a long-term secret

```
go get github.com/micahhausler/httpsig
```

## Signing

```go
signer, err := httpsig.NewSigner(httpsig.Ed25519, privateKey)
if err != nil {
	return err
}
err = httpsig.Sign(req, signer, httpsig.SignOptions{
	Components: []httpsig.Component{
		{Name: "@method"}, {Name: "@target-uri"}, {Name: "content-digest"},
	},
	KeyID: "my-key",
})
```

`Sign` adds the `Signature-Input` and `Signature` fields to the request,
merging with any signatures already present. Algorithms are always explicit;
nothing is inferred from the key type.

## Verifying

Verification is two-phase. `ParseSignatures` parses the signatures and builds
each signature base from the message as received. The caller then looks up
the key, by `KeyID` or however it likes, and checks each signature against a
policy:

```go
sigs, err := httpsig.ParseSignatures(req, nil)
if err != nil {
	// Malformed message.
}
for _, sig := range sigs {
	key, err := lookupKey(sig.KeyID()) // application-defined
	if err != nil {
		continue
	}
	err = sig.Verify(key, httpsig.Policy{
		RequiredComponents: []httpsig.Component{
			{Name: "@method"}, {Name: "@target-uri"}, {Name: "content-digest"},
		},
		MaxAge: 5 * time.Minute,
	})
	if err == nil {
		// Verified.
	}
}
```

Accessors such as `KeyID` report unverified claims from the wire until
`Verify` succeeds. Express requirements positively: accept a request when at
least one signature with the expected tag or key verifies. Anyone can attach
a signature to a request, so a policy that requires every signature to verify
is trivially broken by appending a garbage one. For the same reason, a defect
confined to one signature is reported by that signature's `Verify`, not by
`ParseSignatures`.

Verification errors come in two classes. A `*SyntaxError` means the message
or signature could not be parsed; servers usually answer 400. A
`*VerificationError` means the signature parsed but is not valid for the
message, key, or policy; servers usually answer 401. The wrapped sentinel
errors (`ErrSignatureMismatch`, `ErrExpired`, and so on) are testable with
`errors.Is`.

Servers behind a TLS-terminating proxy must set `ParseOptions.Scheme` and
`ParseOptions.Authority` to the external values the client signed. The
`X-Forwarded-*` fields are untrusted input and are never consulted.

## Content-Digest

The `httpsig` package never reads a body. A body is bound to a signature
through `Content-Digest` (RFC 9530), and covering the `content-digest`
component binds only that field's *value*. Binding the value to the body is a
separate step, in `contentdigest`:

```go
value, err := contentdigest.Value(contentdigest.SHA256, body)
req.Header.Set("Content-Digest", value) // before Sign, so the signature covers it

// on the verifying side, in addition to sig.Verify:
err = contentdigest.Verify(r.Header.Values("Content-Digest"), body, contentdigest.Supported())
```

Neither step implies the other. A verifier that requires the component and
skips `contentdigest.Verify` accepts any body the sender chooses, and the
signature still verifies, so the omission is silent. Every entry with a
supported algorithm must match the body, and a field carrying only unknown
algorithms is rejected rather than treated as absent.

The `server` package does both steps from one policy, and is the shorter path
for any request with a body.

## Client and server

The `client` and `server` packages handle the mechanics above, driven by
config that can live in a file. RFC 9421 gives a server no way to tell
clients what to sign, so coordination is out-of-band: the client's profile
and the server's policy are written separately, and agree on the covered
components. Components are written in the RFC's own wire syntax, so a config
file diffs directly against the `Signature-Input` header on a request:

```yaml
# profile.yaml (client)              # policy.yaml (server)
components:                          # components:
  - '"@method"'                      #   - '"@method"'
  - '"@authority"'                   #   - '"@authority"'
  - '"@path"'                        #   - '"@path"'
keyId: acct-42                       # maxAge: 5m
ttl: 30s                             # algorithms: [ed25519]
```

The body is bound to the signature through `Content-Digest` (RFC 9530),
governed by the `contentDigest` mode rather than the component list, because
bodies come and go per request: with the default `when-body`, a POST's body
is digested and covered while a GET signs without one — and a request that
arrives with a body but no covered digest is rejected. One profile serves
both request shapes.

```go
rt, err := client.NewTransport(nil, signer, profile)
// http.Client{Transport: rt} signs every request
```

The server side wraps a handler. The application supplies the key lookup and
gets a typed identity back; the lookup sees the whole request, so key
material carried in a request header (a session token, for example) needs no
side channel:

```go
dir := server.KeyDirectoryFunc[User](func(r *http.Request, sig *httpsig.Signature) (httpsig.Verifier, User, error) {
	return lookup(sig.KeyID()) // application-defined
})
mw, err := server.New(dir, policy)
mux.Handle("/", mw.Wrap(handler))
// in the handler:
v, ok := server.FromRequest[User](r)
```

The types carry json tags only; for YAML files, decode with a converter that
honors them, such as `sigs.k8s.io/yaml`.

## Algorithms

| Registry name       | Key types                            |
|---------------------|--------------------------------------|
| `rsa-pss-sha512`    | `*rsa.PrivateKey`, `*rsa.PublicKey`  |
| `rsa-v1_5-sha256`   | `*rsa.PrivateKey`, `*rsa.PublicKey`  |
| `hmac-sha256`       | `[]byte`                             |
| `ecdsa-p256-sha256` | `*ecdsa.PrivateKey`, `*ecdsa.PublicKey` |
| `ecdsa-p384-sha384` | `*ecdsa.PrivateKey`, `*ecdsa.PublicKey` |
| `ed25519`           | `ed25519.PrivateKey`, `ed25519.PublicKey` |

If a signature carries an `alg` parameter that disagrees with the verifier's
algorithm, verification fails. This closes the algorithm-confusion class of
attack in the primitive rather than in documentation.

## Scope

Request messages only. Not supported: response signing, the `req` and `tr`
component parameters, `@status`, JSON Web Signature algorithms, and the
`Accept-Signature` field. Unsupported components and parameters are rejected
with specific errors rather than skipped. In `Content-Digest`, only
`sha-256` and `sha-512` are supported; the deprecated registry entries are
deliberately absent.

## Testing

The test suite includes the RFC 9421 [Appendix B](https://datatracker.ietf.org/doc/html/rfc9421#appendix-B) vectors: signature bases are
compared byte for byte against the strings printed in the RFC, the RFC's
signature values are verified against the RFC's keys, and the deterministic
`hmac-sha256` and `ed25519` vectors reproduce the exact `Signature-Input`
and `Signature` fields. Benchmarks for signing and verification run with
`go test -bench .`.

## License

Apache-2.0
