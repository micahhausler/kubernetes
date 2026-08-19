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
	"fmt"

	"github.com/micahhausler/httpsig/keyscope"

	transporthttpsig "k8s.io/client-go/transport/httpsig"
	externalhttpsig "k8s.io/externalhttpsig/apis/v1alpha1"
)

// derivationFrom converts the ladder a resolver stated into the signing library's
// form, and returns the digest two parties compare.
//
// This is field by field rather than through the JSON round trip that
// k8s.io/client-go/transport/httpsig.DerivationFrom uses for the Kubernetes API
// types. That function's contract is any type whose JSON encoding matches the
// ladder schema, and a protobuf-generated type is not one: protoc-gen-go writes
// the proto field name into the Go json tag, so secret_prefix would not be read as
// secretPrefix and the prefix would be dropped without an error. A conversion that
// can silently drop a derivation input is a conversion that produces a key nobody
// can explain.
//
// Every field of the proto messages is read here. The drift guard is a test that
// counts their fields, because a field added to the proto and not added here would
// fail the same silent way.
func derivationFrom(in *externalhttpsig.KeyDerivation) (keyscope.Derivation, string, error) {
	if in == nil {
		return keyscope.Derivation{}, "", fmt.Errorf("no key derivation")
	}
	out := keyscope.Derivation{
		Kind:         in.GetKind(),
		Hash:         in.GetHash(),
		SecretPrefix: in.GetSecretPrefix(),
	}
	for _, step := range in.GetSteps() {
		out.Steps = append(out.Steps, keyscope.Step{
			Name:    step.GetName(),
			Literal: step.GetLiteral(),
			Scope:   step.GetScope(),
			Date:    step.GetDate(),
		})
	}
	// Validate here rather than on first use. A resolver states its ladder once at
	// startup, and a malformed one should fail there instead of on a request.
	if err := out.Validate(); err != nil {
		return keyscope.Derivation{}, "", err
	}
	// The digest comes from the shared helper rather than a second
	// implementation, so a client's digest and this one are comparable by
	// construction.
	return out, transporthttpsig.CanonicalDigest(out), nil
}
