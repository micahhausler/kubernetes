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

package install

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	v1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	"k8s.io/apiserver/pkg/apis/apiserver/v1alpha1"
	"k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
)

// TestHTTPSignatureExternalVersionsAgree requires v1, v1beta1 and v1alpha1 to
// describe the httpSignature section identically, down to json field names.
//
// The three are one section maintained as three copies, so the mistake this catches
// is a field renamed, retyped, reordered or omitted in one file and not the others.
// Nothing else catches it: the compiler is satisfied by three unrelated structs,
// and the conversion generator is satisfied as long as each external version
// converts to internal, which it does field by field if it has to.
//
// It deliberately does not compare an external version against the internal type.
// That is already covered, twice and more loudly. Adding a field to the internal
// type and forgetting an external version makes the conversion generator print
// "the following fields need manual conversion" and emit no Convert function, and
// the package then fails to compile. Asserting it here as well would only add a
// third report of a failure nobody can miss, and would additionally fail on a
// harmless field reordering, which the generator handles by emitting field-by-field
// conversion instead of a cast.
func TestHTTPSignatureExternalVersionsAgree(t *testing.T) {
	for _, tc := range []struct {
		name     string
		versions []any
	}{
		{"HTTPSignatureConfig",
			[]any{v1.HTTPSignatureConfig{}, v1beta1.HTTPSignatureConfig{}, v1alpha1.HTTPSignatureConfig{}}},
		{"HTTPSignatureAuthenticator",
			[]any{v1.HTTPSignatureAuthenticator{}, v1beta1.HTTPSignatureAuthenticator{}, v1alpha1.HTTPSignatureAuthenticator{}}},
		{"HTTPSignatureResolver",
			[]any{v1.HTTPSignatureResolver{}, v1beta1.HTTPSignatureResolver{}, v1alpha1.HTTPSignatureResolver{}}},
		{"HTTPSignatureResolverCache",
			[]any{v1.HTTPSignatureResolverCache{}, v1beta1.HTTPSignatureResolverCache{}, v1alpha1.HTTPSignatureResolverCache{}}},
		{"HTTPSignatureX509",
			[]any{v1.HTTPSignatureX509{}, v1beta1.HTTPSignatureX509{}, v1alpha1.HTTPSignatureX509{}}},
		{"HTTPSignatureX509Cache",
			[]any{v1.HTTPSignatureX509Cache{}, v1beta1.HTTPSignatureX509Cache{}, v1alpha1.HTTPSignatureX509Cache{}}},
		{"HTTPSignatureClaimMappings",
			[]any{v1.HTTPSignatureClaimMappings{}, v1beta1.HTTPSignatureClaimMappings{}, v1alpha1.HTTPSignatureClaimMappings{}}},
		{"HTTPSignatureClaimExpression",
			[]any{v1.HTTPSignatureClaimExpression{}, v1beta1.HTTPSignatureClaimExpression{}, v1alpha1.HTTPSignatureClaimExpression{}}},
		{"CertificateValidationRule",
			[]any{v1.CertificateValidationRule{}, v1beta1.CertificateValidationRule{}, v1alpha1.CertificateValidationRule{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := reflect.TypeOf(tc.versions[0])
			want := shape(first)
			for _, other := range tc.versions[1:] {
				otherType := reflect.TypeOf(other)
				if got := shape(otherType); got != want {
					t.Errorf("%s and %s describe the same section differently, so one configuration would not decode the same in both.\n %s:\n  %s\n %s:\n  %s",
						first.PkgPath(), otherType.PkgPath(), first.PkgPath(), want, otherType.PkgPath(), got)
				}
			}
		})
	}
}

// TestShapeIsLive checks shape() can tell structs apart.
//
// A comparison that returned a constant would pass every case above and prove
// nothing, so each thing shape() is supposed to notice gets one input pair that
// differs only in that.
func TestShapeIsLive(t *testing.T) {
	type base struct {
		Endpoint string   `json:"endpoint"`
		Prefixes []string `json:"keyIDPrefixes,omitempty"`
	}
	for _, tc := range []struct {
		difference string
		other      any
	}{
		{"a missing field", struct {
			Endpoint string `json:"endpoint"`
		}{}},
		{"a renamed json tag", struct {
			Endpoint string   `json:"endPoint"`
			Prefixes []string `json:"keyIDPrefixes,omitempty"`
		}{}},
		{"a dropped omitempty", struct {
			Endpoint string   `json:"endpoint"`
			Prefixes []string `json:"keyIDPrefixes"`
		}{}},
		{"a changed go type", struct {
			Endpoint string `json:"endpoint"`
			Prefixes string `json:"keyIDPrefixes,omitempty"`
		}{}},
		{"a reordered field", struct {
			Prefixes []string `json:"keyIDPrefixes,omitempty"`
			Endpoint string   `json:"endpoint"`
		}{}},
		{"a renamed go field", struct {
			Endpoint      string   `json:"endpoint"`
			KeyIDPrefixes []string `json:"keyIDPrefixes,omitempty"`
		}{}},
	} {
		t.Run(tc.difference, func(t *testing.T) {
			if shape(reflect.TypeOf(base{})) == shape(reflect.TypeOf(tc.other)) {
				t.Errorf("shape() does not notice %s, so the check above would not either", tc.difference)
			}
		})
	}
}

// shape renders a struct's fields in declaration order with their json tags and Go
// types, recursively through structs reached by value.
//
// Named types are rendered by name without their package, so v1.HTTPSignatureX509
// and v1beta1.HTTPSignatureX509 compare equal where they should. Pointers, slices
// and maps render their element shape, because a field being *X in one version and
// *Y in another is exactly the kind of divergence this is looking for.
func shape(t reflect.Type) string {
	var b strings.Builder
	writeShape(&b, t, 0)
	return b.String()
}

// maxShapeDepth stops the walk on a type that reaches itself. None of these types
// is recursive today; the bound is here so that adding one produces a comparison
// that still terminates rather than a stack overflow in a test.
const maxShapeDepth = 12

func writeShape(b *strings.Builder, t reflect.Type, depth int) {
	if depth > maxShapeDepth {
		b.WriteString("...")
		return
	}
	switch t.Kind() {
	case reflect.Struct:
		fmt.Fprintf(b, "%s{", t.Name())
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if i > 0 {
				b.WriteString(" ")
			}
			fmt.Fprintf(b, "%s`%s`:", f.Name, f.Tag.Get("json"))
			writeShape(b, f.Type, depth+1)
		}
		b.WriteString("}")
	case reflect.Ptr:
		b.WriteString("*")
		writeShape(b, t.Elem(), depth+1)
	case reflect.Slice:
		b.WriteString("[]")
		writeShape(b, t.Elem(), depth+1)
	case reflect.Map:
		b.WriteString("map[")
		writeShape(b, t.Key(), depth+1)
		b.WriteString("]")
		writeShape(b, t.Elem(), depth+1)
	default:
		// Name() is empty for unnamed types, so the kind is always included: it is
		// what distinguishes a named string from a named int.
		fmt.Fprintf(b, "%s(%s)", t.Name(), t.Kind())
	}
}
