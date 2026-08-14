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

// ProtectedHeaders are covered when present on the request, in this order.
// Names are lowercase.
//
// Content-Type is here because Content-Digest binds the bytes of a body but not
// their interpretation: the API server parses the same bytes as JSON, YAML, or
// protobuf depending on this header.
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
// bypass those paths. Names are lowercase, and the prefixes in
// ProtectedHeaderPrefixes are reserved as well.
var ReservedHeaders = []string{
	"authorization",
	"signature",
	"signature-input",
	"content-digest",
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

// DigestAlgorithm is the Content-Digest hash this client computes, from the IANA
// "Hash Algorithms for HTTP Digest Fields" registry. A verifier accepts any hash
// the signing library implements, so this choice binds the client only.
const DigestAlgorithm = contentdigest.SHA256

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
