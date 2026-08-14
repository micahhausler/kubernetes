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

package httpsig

import (
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/micahhausler/httpsig/keyscope"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// The derivation mechanics live in the signing library: the ladder chain, the key
// ID format, staged entry, scope checking, and the published SigV4 vectors are
// tested there. These tests cover only what Kubernetes adds: converting a ladder
// stated in a Kubernetes API type into the library's form, and the digest two
// parties compare.

// sigv4Ladder is AWS's key derivation chain expressed as a Kubernetes API ladder.
func sigv4Ladder() *clientcmdapi.HTTPSignatureKeyDerivation {
	return &clientcmdapi.HTTPSignatureKeyDerivation{
		Kind:         "hmac-ladder",
		Hash:         "sha-256",
		SecretPrefix: "AWS4",
		Steps: []clientcmdapi.HTTPSignatureKeyDerivationStep{
			{Name: "date", Date: "YYYYMMDD"},
			{Name: "region", Scope: true},
			{Name: "service", Scope: true},
			{Name: "terminator", Literal: "aws4_request"},
		},
	}
}

// TestDerivationFromProducesPublishedKey checks the conversion end to end against
// AWS's published example. A ladder stated in a kubeconfig has to derive the same
// key the scheme documents, or interoperability with material vended elsewhere is
// a claim rather than a fact.
func TestDerivationFromProducesPublishedKey(t *testing.T) {
	ladder, _, err := DerivationFrom(sigv4Ladder())
	if err != nil {
		t.Fatalf("DerivationFrom: %v", err)
	}
	created := time.Date(2012, 2, 15, 0, 0, 0, 0, time.UTC)
	key, err := keyscope.New(ladder, keyscope.Stage{
		Name:  "AKIAIOSFODNN7EXAMPLE",
		Scope: map[string]string{"region": "us-east-1", "service": "iam"},
	}, []byte("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"))
	if err != nil {
		t.Fatal(err)
	}

	// Derive through the last step to see the signing key itself, and compare it
	// with the value the scheme's documentation prints for these inputs.
	material, _, err := key.Derive("terminator", created)
	if err != nil {
		t.Fatal(err)
	}
	const want = "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
	if got := hex.EncodeToString(material); got != want {
		t.Errorf("the key derived from the API type does not match the published one:\ngot  %s\nwant %s", got, want)
	}

	// And the key ID the client will send carries the claimed scope.
	keyID, err := key.KeyID(created)
	if err != nil {
		t.Fatal(err)
	}
	if want := "AKIAIOSFODNN7EXAMPLE/20120215/us-east-1/iam/aws4_request"; keyID != want {
		t.Errorf("keyID:\ngot  %s\nwant %s", keyID, want)
	}
}

// TestDerivationFromValidates checks that converting is also checking. The
// library owns these rules; what this asserts is that Kubernetes routes ladders
// through them rather than accepting a ladder it cannot use and failing later as
// a signature mismatch.
func TestDerivationFromValidates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*clientcmdapi.HTTPSignatureKeyDerivation)
		want   string
	}{{
		name:   "wrong kind",
		mutate: func(d *clientcmdapi.HTTPSignatureKeyDerivation) { d.Kind = "hmac-chain" },
		want:   "kind",
	}, {
		name:   "no steps",
		mutate: func(d *clientcmdapi.HTTPSignatureKeyDerivation) { d.Steps = nil },
		want:   "steps",
	}, {
		name:   "unknown hash",
		mutate: func(d *clientcmdapi.HTTPSignatureKeyDerivation) { d.Hash = "sha-1" },
		want:   "hash",
	}, {
		// A Go layout looks plausible and derives a different key, so the closed
		// set of format names is what stops a silent mismatch.
		name:   "a date layout rather than a format name",
		mutate: func(d *clientcmdapi.HTTPSignatureKeyDerivation) { d.Steps[0].Date = "20060102" },
		want:   "date",
	}, {
		name: "two input sources on one step",
		mutate: func(d *clientcmdapi.HTTPSignatureKeyDerivation) {
			d.Steps[1].Literal = "x"
		},
		want: "step",
	}, {
		name: "duplicate step names",
		mutate: func(d *clientcmdapi.HTTPSignatureKeyDerivation) {
			d.Steps[1].Name = "date"
		},
		want: "date",
	}, {
		// Step values are joined by slashes into the key ID, so a literal
		// carrying one could split a segment and claim a scope it was not given.
		// Step names are exempt because they never reach the wire.
		name: "a slash in a literal",
		mutate: func(d *clientcmdapi.HTTPSignatureKeyDerivation) {
			d.Steps[3].Literal = "aws4/request"
		},
		want: "/",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			ladder := sigv4Ladder()
			tc.mutate(ladder)
			_, _, err := DerivationFrom(ladder)
			if err == nil {
				t.Fatalf("want an error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want an error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

// TestCanonicalDigest covers the property that makes the digest worth logging:
// it depends on what a ladder means, not on how it was written or which API type
// it arrived in. A digest that reported drift for a formatting difference would
// be a diagnostic nobody reads.
func TestCanonicalDigest(t *testing.T) {
	ladder, digest, err := DerivationFrom(sigv4Ladder())
	if err != nil {
		t.Fatal(err)
	}
	if len(digest) != 64 {
		t.Errorf("digest %q is not a hex sha-256", digest)
	}
	if again := CanonicalDigest(ladder); again != digest {
		t.Errorf("digest is not stable: %s then %s", digest, again)
	}

	// The same ladder reached through a different API group's type has to produce
	// the same digest, because the client and the server state theirs in
	// different configuration files and compare the results.
	other := &struct {
		Kind         string `json:"kind"`
		Hash         string `json:"hash,omitempty"`
		SecretPrefix string `json:"secretPrefix,omitempty"`
		Steps        []struct {
			Name    string `json:"name"`
			Literal string `json:"literal,omitempty"`
			Scope   bool   `json:"scope,omitempty"`
			Date    string `json:"date,omitempty"`
		} `json:"steps"`
	}{Kind: "hmac-ladder", Hash: "sha-256", SecretPrefix: "AWS4"}
	for _, step := range sigv4Ladder().Steps {
		other.Steps = append(other.Steps, struct {
			Name    string `json:"name"`
			Literal string `json:"literal,omitempty"`
			Scope   bool   `json:"scope,omitempty"`
			Date    string `json:"date,omitempty"`
		}{step.Name, step.Literal, step.Scope, step.Date})
	}
	_, fromOther, err := DerivationFrom(other)
	if err != nil {
		t.Fatal(err)
	}
	if fromOther != digest {
		t.Errorf("the same ladder from another API type digests differently:\n%s\n%s", digest, fromOther)
	}

	// A ladder that means something different must not.
	changed := sigv4Ladder()
	changed.SecretPrefix = "AWS5"
	_, other2, err := DerivationFrom(changed)
	if err != nil {
		t.Fatal(err)
	}
	if other2 == digest {
		t.Error("a different secret prefix produced the same digest")
	}
	changed = sigv4Ladder()
	changed.Steps[1], changed.Steps[2] = changed.Steps[2], changed.Steps[1]
	_, reordered, err := DerivationFrom(changed)
	if err != nil {
		t.Fatal(err)
	}
	if reordered == digest {
		t.Error("reordering steps produced the same digest, but it derives a different key")
	}
}

// TestLadderAPIMirrorsLibrary guards the one thing nine declarations of a schema
// can get wrong: drifting from the schema they mirror. The Kubernetes ladder
// types are converted by their JSON encoding, so a field the library gains and
// Kubernetes does not is a derivation Kubernetes cannot express, and a field
// whose name differs silently stops being carried.
//
// This fails when the signing library grows a field, which is the event worth
// hearing about rather than a periodic review.
func TestLadderAPIMirrorsLibrary(t *testing.T) {
	tags := func(v any) []string {
		typ := reflect.TypeOf(v)
		out := make([]string, 0, typ.NumField())
		for i := range typ.NumField() {
			tag := typ.Field(i).Tag.Get("json")
			if tag == "" {
				t.Fatalf("%s.%s has no json tag, so it cannot round trip", typ.Name(), typ.Field(i).Name)
			}
			out = append(out, tag)
		}
		return out
	}
	if got, want := tags(clientcmdapi.HTTPSignatureKeyDerivation{}), tags(keyscope.Derivation{}); !reflect.DeepEqual(got, want) {
		t.Errorf("the Kubernetes ladder type no longer mirrors the library's:\ngot  %v\nwant %v", got, want)
	}
	if got, want := tags(clientcmdapi.HTTPSignatureKeyDerivationStep{}), tags(keyscope.Step{}); !reflect.DeepEqual(got, want) {
		t.Errorf("the Kubernetes ladder step type no longer mirrors the library's:\ngot  %v\nwant %v", got, want)
	}
}

// TestKeyscopeStage checks the conversion that keeps the key's name out of the
// serialized stage. The name lives in the credential's key ID, and a second place
// to write it would be a second place for the two to disagree.
func TestKeyscopeStage(t *testing.T) {
	got := KeyscopeStage("AKIAEXAMPLE", &Stage{
		From:  "service",
		Scope: map[string]string{"date": "20260830", "region": "us-east-1"},
	})
	if got.Name != "AKIAEXAMPLE" || got.From != "service" {
		t.Errorf("conversion lost fields: %+v", got)
	}
	if got.Scope["date"] != "20260830" || got.Scope["region"] != "us-east-1" {
		t.Errorf("conversion lost scope: %+v", got.Scope)
	}

	// A nil stage is the root: only the name travels.
	root := KeyscopeStage("AKIAEXAMPLE", nil)
	if root.Name != "AKIAEXAMPLE" || root.From != "" || root.Scope != nil {
		t.Errorf("nil stage conversion: %+v", root)
	}
}

// TestContentDigest covers the two wrappers this package keeps over the signing
// library's digest primitives, because the client computes one and the verifier
// checks it.
func TestContentDigest(t *testing.T) {
	body := []byte(`{"kind":"Pod"}`)
	value, err := ContentDigestValue(body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(value, DigestAlgorithm+"=:") {
		t.Errorf("digest %q does not name the algorithm this client computes", value)
	}
	if err := VerifyContentDigest([]string{value}, body); err != nil {
		t.Errorf("a digest this client computed does not verify: %v", err)
	}
	if err := VerifyContentDigest([]string{value}, []byte("different body")); err == nil {
		t.Error("a digest verified against the wrong body")
	}
	// A field naming only algorithms nothing implements is rejected rather than
	// ignored, because ignoring it would accept a body bound to nothing.
	if err := VerifyContentDigest([]string{"md5=:d41d8cd98f00b204e9800998ecf8427e=:"}, body); err == nil {
		t.Error("a digest with no supported algorithm was accepted")
	}
}
