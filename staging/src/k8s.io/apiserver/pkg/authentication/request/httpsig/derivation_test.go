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
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	transporthttpsig "k8s.io/client-go/transport/httpsig"
	externalhttpsig "k8s.io/externalhttpsig/apis/v1alpha1"
)

// TestDerivationConversionReadsEveryField is the drift guard.
//
// derivationFrom copies field by field, so a field added to the proto and not
// added there would be dropped without an error, and a dropped derivation input
// produces a key nobody can explain. This sets every field to a value that changes
// the digest, so a field the converter does not read shows up as two ladders whose
// digests match when they should not.
func TestDerivationConversionReadsEveryField(t *testing.T) {
	// Guard the guard: if the proto grows a field, the counts below stop matching
	// and this test says so rather than silently checking less than it should.
	// protoc-gen-go's own bookkeeping fields are unexported, so these lists are the
	// messages' declared fields exactly.
	assertFieldCount(t, &externalhttpsig.KeyDerivation{}, []string{"Kind", "Hash", "SecretPrefix", "Steps"})
	assertFieldCount(t, &externalhttpsig.KeyDerivationStep{}, []string{"Name", "Literal", "Scope", "Date"})

	base := &externalhttpsig.KeyDerivation{
		Kind:         "hmac-ladder",
		Hash:         "sha-512",
		SecretPrefix: "PREFIX1",
		Steps: []*externalhttpsig.KeyDerivationStep{
			{Name: "day", Date: "YYYYMMDD"},
			{Name: "cell", Scope: true},
			{Name: "terminator", Literal: "terminal_value"},
		},
	}
	_, baseDigest, err := derivationFrom(base)
	if err != nil {
		t.Fatalf("converting the base ladder: %v", err)
	}

	for _, tc := range []struct {
		field  string
		mutate func(*externalhttpsig.KeyDerivation)
	}{
		{field: "hash", mutate: func(d *externalhttpsig.KeyDerivation) { d.Hash = "sha-256" }},
		{field: "secretPrefix", mutate: func(d *externalhttpsig.KeyDerivation) { d.SecretPrefix = "PREFIX2" }},
		{field: "steps[].name", mutate: func(d *externalhttpsig.KeyDerivation) { d.Steps[1].Name = "region" }},
		{field: "steps[].literal", mutate: func(d *externalhttpsig.KeyDerivation) { d.Steps[2].Literal = "other_value" }},
		{field: "steps[].date", mutate: func(d *externalhttpsig.KeyDerivation) { d.Steps[0].Date = "YYYY-MM-DD" }},
		{field: "steps[].scope", mutate: func(d *externalhttpsig.KeyDerivation) {
			// Swapping a scope step for a literal changes what the step folds in,
			// which is only visible if the converter reads scope.
			d.Steps[1].Scope = false
			d.Steps[1].Literal = "fixed"
		}},
		{field: "steps length", mutate: func(d *externalhttpsig.KeyDerivation) {
			d.Steps = append(d.Steps, &externalhttpsig.KeyDerivationStep{Name: "extra", Literal: "extra_value"})
		}},
	} {
		t.Run(tc.field, func(t *testing.T) {
			mutated := proto.Clone(base).(*externalhttpsig.KeyDerivation)
			tc.mutate(mutated)
			_, digest, err := derivationFrom(mutated)
			if err != nil {
				t.Fatalf("converting a ladder differing in %s: %v", tc.field, err)
			}
			if digest == baseDigest {
				t.Errorf("changing %s did not change the digest, so derivationFrom is not reading it", tc.field)
			}
		})
	}

	// Kind is the one field that cannot be varied this way: any value other than
	// hmac-ladder is rejected rather than converted, which is itself the check.
	t.Run("kind", func(t *testing.T) {
		mutated := proto.Clone(base).(*externalhttpsig.KeyDerivation)
		mutated.Kind = "something-else"
		if _, _, err := derivationFrom(mutated); err == nil {
			t.Error("an unknown kind should be rejected")
		}
	})
}

// assertFieldCount fails if a message has fields beyond those named, so a proto
// change forces a look at the converter.
func assertFieldCount(t *testing.T, msg proto.Message, named []string) {
	t.Helper()
	typ := reflect.TypeOf(msg).Elem()
	var exported []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.IsExported() {
			exported = append(exported, f.Name)
		}
	}
	if len(exported) != len(named) {
		t.Errorf("%s has exported fields %v, but the converter is written for %v; add the new field to derivationFrom and to this list",
			typ.Name(), exported, named)
	}
}

// TestDerivationDigestMatchesTheClientHelper asserts the digest a resolver's ladder
// produces is the same value a client computes for its own copy. Comparing the two
// is the only diagnostic for a ladder disagreement, so a digest computed a second
// way here would make that comparison meaningless.
func TestDerivationDigestMatchesTheClientHelper(t *testing.T) {
	in := &externalhttpsig.KeyDerivation{
		Kind:         "hmac-ladder",
		Hash:         "sha-256",
		SecretPrefix: "K8SDEMO1",
		Steps: []*externalhttpsig.KeyDerivationStep{
			{Name: "day", Date: "YYYYMMDD"},
			{Name: "cell", Scope: true},
			{Name: "terminator", Literal: "k8sdemo1_request"},
		},
	}
	derivation, digest, err := derivationFrom(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := transporthttpsig.CanonicalDigest(derivation); digest != want {
		t.Errorf("digest: got %q, want the shared helper's %q", digest, want)
	}
	if digest == "" || len(digest) != 64 || strings.ContainsAny(digest, "ghijklmnopqrstuvwxyz") {
		t.Errorf("digest should be a hex sha256, got %q", digest)
	}
}

// TestDerivationFromNil covers the one caller that can pass nil: a resolver that
// states no ladder at all.
func TestDerivationFromNil(t *testing.T) {
	if _, _, err := derivationFrom(nil); err == nil {
		t.Error("a nil ladder should be an error rather than an empty derivation")
	}
}
