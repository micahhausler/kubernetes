// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

// Package httpsig implements HTTP message signatures as defined in
// [RFC 9421].
//
// A client signs a request with [Sign], choosing the covered components and
// signature parameters:
//
//	signer, err := httpsig.NewSigner(httpsig.Ed25519, privateKey)
//	if err != nil {
//		// ...
//	}
//	err = httpsig.Sign(req, signer, httpsig.SignOptions{
//		Components: []httpsig.Component{
//			{Name: "@method"}, {Name: "@target-uri"}, {Name: "content-digest"},
//		},
//		KeyID: "my-key",
//	})
//
// A server parses the signatures of an incoming request with
// [ParseSignatures], looks up the verification key using the unverified
// [Signature.KeyID] claim, and checks the signature with [Signature.Verify]:
//
//	sigs, err := httpsig.ParseSignatures(req, nil)
//	if err != nil {
//		// Malformed message.
//	}
//	for _, sig := range sigs {
//		key := lookup(sig.KeyID()) // application-defined
//		err := sig.Verify(key, httpsig.Policy{
//			RequiredComponents: []httpsig.Component{{Name: "@method"}},
//			MaxAge:             5 * time.Minute,
//		})
//		// ...
//	}
//
// Key distribution, signature selection among multiple signatures, and nonce
// replay tracking are application concerns and are left to the caller.
//
// This package is the wire layer. The module's other packages build on it:
//
//   - [github.com/micahhausler/httpsig/client] signs outgoing requests from
//     a serializable profile, as an http.RoundTripper.
//   - [github.com/micahhausler/httpsig/server] verifies incoming requests
//     against a policy and hands the wrapped handler a typed identity.
//   - [github.com/micahhausler/httpsig/sigconfig] holds the profile and
//     policy those two share, as types that load from a config file.
//   - [github.com/micahhausler/httpsig/contentdigest] computes and verifies
//     the Content-Digest field of RFC 9530, which is what binds a request
//     body to a signature.
//   - [github.com/micahhausler/httpsig/keyscope] derives scoped HMAC keys,
//     so a verifier holds a key limited to one scope rather than a
//     long-term secret.
//
// This package does not read message bodies. A body is bound to a signature
// through the Content-Digest field of RFC 9530, and covering the
// content-digest component binds only that field's value: nothing here checks
// that value against the body. Verifying a request with a body therefore
// takes a second step, from package
// [github.com/micahhausler/httpsig/contentdigest]. A verifier that requires
// the component and skips that step accepts any body the sender chooses, and
// the signature still verifies, so the omission is silent. The middleware in
// [github.com/micahhausler/httpsig/server] does both steps from one policy
// and is the shorter path.
//
// Anyone who can reach a server can attach a signature to a request, so
// express verification requirements positively: accept a request when at
// least one signature with the expected tag or key verifies under a
// sufficient [Policy]. Do not require that every signature present verifies;
// that policy is trivially broken by appending a garbage signature.
//
// This package signs and verifies request messages. Response signing, the
// req and tr component parameters, and JSON Web Signature algorithms are not
// supported.
//
// [RFC 9421]: https://datatracker.ietf.org/doc/html/rfc9421
package httpsig
