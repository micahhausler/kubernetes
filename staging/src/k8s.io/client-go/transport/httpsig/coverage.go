/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package httpsig holds the coverage rules shared by the client that signs
// Kubernetes API requests and the server that verifies them, together with the
// signing round tripper.
//
// Coverage is not configurable. RFC 9421 signatures declare what they cover, so
// a verifier that checks only "this signature is valid for the components it
// names" accepts a signature covering nothing: an attacker signs a component
// list of their own choosing with their own key. The covered set is therefore
// server policy, and the client rules here exist so that a client produces
// something the server accepts.
//
// Three classes of coverage:
//
//   - The floor, in FloorComponents, is covered on every request.
//   - Content-Digest is covered when the request has a body, which binds the
//     body to the signature. A request that arrives with a body and no covered
//     digest is rejected by the verifier.
//   - Protected headers, in ProtectedHeaders, are covered when present.
//     Coverage prevents their removal for free, because a signature base that
//     cannot be reconstructed does not verify. It does not prevent their
//     addition: an intermediary can append Impersonate-User to a signed request
//     that carried none and the signature still verifies. The verifier closes
//     that by requiring every protected header present on a request to be
//     covered.
//
// Configuration may add covered headers. Nothing removes from the floor.
package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig/contentdigest"
)

// FloorComponents are covered by every signature, in this order.
//
// The query string is covered because Kubernetes API semantics live there:
// dryRun, watch, fieldSelector, resourceVersion. A signature that leaves the
// query uncovered lets a bystander turn a dry run into a real write.
//
// @authority is covered so a signature cannot be replayed against a different
// API server. A TLS-terminating intermediary that rewrites the Host header
// breaks this; a verifier behind such an intermediary states the external
// authority the client signed rather than reading X-Forwarded-Host, which is
// unsigned input.
var FloorComponents = []httpsig.Component{
	{Name: "@method"},
	{Name: "@authority"},
	{Name: "@path"},
	{Name: "@query"},
}

// ContentDigestComponent binds the request body to the signature. It is covered
// when the request has a body.
var ContentDigestComponent = httpsig.Component{Name: "content-digest"}

// CertificateHeader carries the X.509 certificate a signature is made under,
// when the client's identity is asserted by a certificate rather than named by a
// configured key. The value is the leaf's DER encoding, base64 encoded as an RFC
// 9651 byte sequence, so `:MIIB...:`.
//
// The name is not configurable, for the same reason coverage is not: the verifier
// has to read the assertion from a place a signature cannot relocate.
//
// RFC 9440 registers Client-Cert with this exact syntax, and it is deliberately
// not reused. That field means "a proxy asserts this certificate was used on the
// TLS connection", which is a different claim from "the client asserts this is
// the identity it signed with". A deployment running such a proxy in front of the
// API server would have the two collide, which would not grant anything, since
// the signature then fails to verify, but would fail in a way nobody could read.
const CertificateHeader = "Signature-Certificate"

// MaxCertificateHeaderBytes caps the certificate an unauthenticated caller can
// make the verifier parse. A leaf with an RSA 4096 key and a handful of subject
// alternative names is a few kilobytes; this leaves room without letting the
// header be a way to spend the verifier's memory.
const MaxCertificateHeaderBytes = 16 * 1024

// ProtectedHeaders are covered when present on the request, in this order.
// Names are lowercase.
//
// Content-Type is here because Content-Digest binds the bytes of a body but not
// their interpretation: the API server parses the same bytes as JSON, YAML, or
// protobuf depending on this header.
//
// Signature-Certificate is here as belt and braces rather than as the binding
// mechanism. What actually binds the certificate to the signature is the keyid,
// which names the certificate's digest and which every signature covers whether
// it wants to or not: a signature's parameters are always the last line of its
// signature base. Covering the header as well costs a few kilobytes in that base
// and closes reasoning nobody should have to redo. Note what coverage alone would
// not have bought: substituting a certificate is self-defeating, because the
// signature has to verify against the key the certificate names, and so is adding
// one to a request that carried none.
//
// Authorization is deliberately absent. A request authenticated by signature has
// its Authorization header discarded by the authentication filter, so an
// injected one has no effect, and covering it would mean signing over a
// credential that should not have been sent.
var ProtectedHeaders = []string{
	"impersonate-user",
	"impersonate-uid",
	"impersonate-group",
	"audit-id",
	"accept",
	"content-type",
	"user-agent",
	"signature-certificate",
}

// ProtectedHeaderPrefixes are header name prefixes treated as protected. The
// names under a prefix are not fixed, so they are matched rather than listed.
var ProtectedHeaderPrefixes = []string{
	"impersonate-extra-",
}

// IsProtectedHeader reports whether name is a protected header. Comparison is
// case insensitive.
func IsProtectedHeader(name string) bool {
	lower := strings.ToLower(name)
	for _, h := range ProtectedHeaders {
		if lower == h {
			return true
		}
	}
	for _, p := range ProtectedHeaderPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// ReservedHeaders may not be set by configuration. The signature fields are
// reserved because writing them corrupts signing; Authorization and the
// impersonation headers are reserved because they have their own configuration
// paths, and a header injection mechanism that can write them is a way to
// bypass those paths. Signature-Certificate is reserved because the signer
// writes it from the credential's own certificate: a configured value would let
// a request assert a certificate whose key it does not hold, which produces a
// signature the verifier rejects, with an error naming neither cause. Names are
// lowercase, and the prefixes in ProtectedHeaderPrefixes are reserved as well.
var ReservedHeaders = []string{
	"authorization",
	"signature",
	"signature-input",
	"content-digest",
	"signature-certificate",
	"impersonate-user",
	"impersonate-uid",
	"impersonate-group",
}

// IsReservedHeader reports whether configuration may set name. Comparison is
// case insensitive.
func IsReservedHeader(name string) bool {
	lower := strings.ToLower(name)
	for _, h := range ReservedHeaders {
		if lower == h {
			return true
		}
	}
	for _, p := range ProtectedHeaderPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// RSA key size bounds for a certificate-asserted key.
//
// A verifier takes the key from a certificate it has not yet decided to trust, so
// the cost of one verification is set by bytes an unauthenticated caller chose.
// Neither Go's certificate parser nor its RSA package bounds a modulus from above:
// the parser reads any positive integer, and crypto/rsa enforces a 1024-bit floor
// and no ceiling. A fabricated 65536-bit modulus fits in an 8.4 kB certificate,
// which is well inside the header limit, and costs about 158 ms of CPU to verify
// against, per request, for a caller holding nothing.
//
// So the size is bounded here, before a verifier exists. The band is what
// Kubernetes' own certificate machinery issues: PodCertificateRequest offers RSA
// 3072 and 4096, and 2048 remains the common floor elsewhere. A deployment needing
// something outside it gets an error naming the bound rather than a slow server.
const (
	MinRSAKeyBits = 2048
	MaxRSAKeyBits = 4096

	// MaxRSAPublicExponent bounds the other half of the modexp. Go's parser
	// requires the exponent to be positive and nothing more, and a large one is
	// expensive for the same reason a large modulus is. Every certificate in
	// practice uses 65537.
	MaxRSAPublicExponent = 65537
)

// CertificateAlgorithm returns the signature algorithm used with a certificate
// whose public key is pub.
//
// There is exactly one algorithm per key type, which is why the certificate flow
// does not configure one. Elsewhere this client requires the algorithm to be
// stated and never infers it from the key, so that a key cannot be used under an
// algorithm its holder did not intend. That reasoning does not apply here,
// because there is no other algorithm the verifier would accept for the key: the
// mapping is fixed on both sides. It also puts rsa-v1_5-sha256 out of reach,
// which is the point of choosing rather than accepting either RSA form.
//
// This is also the gate on how much work a key may cost to verify against, which
// is why a verifier calls it before building a verifier rather than after.
func CertificateAlgorithm(pub crypto.PublicKey) (httpsig.Algorithm, error) {
	switch key := pub.(type) {
	case ed25519.PublicKey:
		return httpsig.Ed25519, nil
	case *ecdsa.PublicKey:
		// The curve is pinned by the algorithm, so an unlisted curve is refused
		// rather than verified against.
		switch key.Curve {
		case elliptic.P256():
			return httpsig.ECDSAP256SHA256, nil
		case elliptic.P384():
			return httpsig.ECDSAP384SHA384, nil
		default:
			return "", fmt.Errorf("certificate holds an ECDSA key on curve %s, and no HTTP signature algorithm is defined for it; use P-256 or P-384",
				key.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		if key.N == nil {
			return "", fmt.Errorf("certificate holds an RSA key with no modulus")
		}
		if bits := key.N.BitLen(); bits < MinRSAKeyBits || bits > MaxRSAKeyBits {
			return "", fmt.Errorf("certificate holds a %d-bit RSA key, outside the accepted %d to %d bits; "+
				"an oversized modulus costs the verifier work before it has decided to trust the certificate",
				bits, MinRSAKeyBits, MaxRSAKeyBits)
		}
		if key.E < 3 || key.E > MaxRSAPublicExponent || key.E%2 == 0 {
			return "", fmt.Errorf("certificate holds an RSA key with public exponent %d, outside the accepted odd values from 3 to %d",
				key.E, MaxRSAPublicExponent)
		}
		return httpsig.RSAPSSSHA512, nil
	default:
		return "", fmt.Errorf("certificate holds an unsupported key type %T; use Ed25519, ECDSA on P-256 or P-384, or RSA", pub)
	}
}

// DigestAlgorithm is the Content-Digest hash this client computes, from the IANA
// "Hash Algorithms for HTTP Digest Fields" registry. A verifier accepts any hash
// the signing library implements, so this choice binds the client only.
const DigestAlgorithm = contentdigest.SHA256

// CertificateKeyIDPrefix begins the keyid of every signature made under a
// certificate. The rest is the lowercase hex SHA-256 digest of the leaf's DER
// encoding, as CertificateKeyID builds it.
//
// The prefix is what makes the certificate flow self-declaring. A verifier
// selects on it, so which kind of authenticator handles a signature is stated
// inside the signature base rather than inferred from whether an unsigned header
// happens to be present. It also means a configured key cannot be named such
// that a certificate signature would select it, which configuration validation
// enforces.
const CertificateKeyIDPrefix = "x509-sha256:"

// CertificateKeyID returns the keyid for a signature made under the leaf
// certificate whose DER encoding is der.
//
// This is the whole binding between a certificate and the signature made with
// it. A signature's parameters are always part of its signature base, so a keyid
// naming the certificate's digest is covered by every signature that carries it,
// with no coverage rule involved. The verifier recomputes this from the bytes it
// received rather than trusting the claim, which turns a substituted certificate
// into an error naming the mismatch instead of a bare signature failure.
//
// Both sides call this, so the two cannot disagree about the encoding.
func CertificateKeyID(der []byte) string {
	sum := sha256.Sum256(der)
	return CertificateKeyIDPrefix + hex.EncodeToString(sum[:])
}

// CertificateHeaderValue returns the Signature-Certificate field value carrying
// the leaf certificate whose DER encoding is der: an RFC 9651 byte sequence.
func CertificateHeaderValue(der []byte) string {
	return ":" + base64.StdEncoding.EncodeToString(der) + ":"
}

// ParseCertificateHeader returns the DER encoding of the leaf certificate a
// Signature-Certificate field value carries.
//
// Exactly one value is accepted. More than one is rejected rather than resolved,
// because two assertions on one request is a question about which the request
// meant, and every answer to it is a guess.
func ParseCertificateHeader(values []string) ([]byte, error) {
	switch len(values) {
	case 1:
	case 0:
		return nil, fmt.Errorf("request carries no %s header, which a signature with an %s keyid requires",
			CertificateHeader, CertificateKeyIDPrefix)
	default:
		return nil, fmt.Errorf("request carries %d %s headers; exactly one certificate may be asserted",
			len(values), CertificateHeader)
	}
	value := strings.TrimSpace(values[0])
	if len(value) > MaxCertificateHeaderBytes {
		return nil, fmt.Errorf("%s header is %d bytes, over the %d byte limit",
			CertificateHeader, len(value), MaxCertificateHeaderBytes)
	}
	if len(value) < 2 || value[0] != ':' || value[len(value)-1] != ':' {
		return nil, fmt.Errorf("%s header is not a byte sequence; the value must be the certificate's DER encoding in base64, delimited by colons",
			CertificateHeader)
	}
	der, err := base64.StdEncoding.DecodeString(value[1 : len(value)-1])
	if err != nil {
		return nil, fmt.Errorf("%s header is not valid base64: %w", CertificateHeader, err)
	}
	if len(der) == 0 {
		return nil, fmt.Errorf("%s header carries no certificate", CertificateHeader)
	}
	return der, nil
}

// ContentDigestValue returns a Content-Digest field value for body, such as
// `sha-256=:...:`.
func ContentDigestValue(body []byte) (string, error) {
	return contentdigest.Value(DigestAlgorithm, body)
}

// VerifyContentDigest checks the Content-Digest field values against body. Every
// entry whose algorithm is understood must match, and at least one understood
// entry must be present: a field carrying only unknown algorithms is rejected
// rather than ignored, because ignoring it accepts an unbound body.
func VerifyContentDigest(values []string, body []byte) error {
	return contentdigest.Verify(values, body, contentdigest.Supported())
}

// Components returns the components a signature over req must cover: the floor,
// Content-Digest when hasBody, then every protected header present on req and
// every name in extraHeaders, in a stable order.
//
// Both the signer and the verifier call this, so the two sides cannot disagree
// about the covered set.
func Components(req *http.Request, hasBody bool, extraHeaders []string) []httpsig.Component {
	comps := make([]httpsig.Component, 0, len(FloorComponents)+1+len(ProtectedHeaders)+len(extraHeaders))
	comps = append(comps, FloorComponents...)
	if hasBody {
		comps = append(comps, ContentDigestComponent)
	}
	for _, name := range ProtectedHeaders {
		if len(req.Header.Values(name)) > 0 {
			comps = append(comps, httpsig.Component{Name: name})
		}
	}
	// Prefixed protected headers have unbounded names, so they are collected
	// from the request and sorted for a stable signing order.
	var prefixed []string
	for name := range req.Header {
		lower := strings.ToLower(name)
		for _, p := range ProtectedHeaderPrefixes {
			if strings.HasPrefix(lower, p) {
				prefixed = append(prefixed, lower)
				break
			}
		}
	}
	slices.Sort(prefixed)
	for _, name := range prefixed {
		comps = append(comps, httpsig.Component{Name: name})
	}
	for _, name := range extraHeaders {
		comps = append(comps, httpsig.Component{Name: strings.ToLower(name)})
	}
	return comps
}
