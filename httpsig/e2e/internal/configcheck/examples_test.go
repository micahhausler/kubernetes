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

package configcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/apis/apiserver/validation"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
)

// examplesDir is the reference configuration an operator copies from, relative to
// this package.
const examplesDir = "../../../examples"

// TestExamplesAreAccepted validates every example configuration with the decode and
// validation kube-apiserver performs at startup.
//
// A reference configuration nobody runs is a reference configuration that is wrong,
// and wrong in the worst way: it is what an operator copies. The two defects found
// while writing the demo generator were an under-indented block and a message value
// containing ": ", which YAML reads as a nested mapping. Both are invisible to
// inspection, and an operator who copied either would learn about it as an API
// server that refuses to start.
func TestExamplesAreAccepted(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.HTTPSignatureAuthentication, true)

	entries, err := filepath.Glob(filepath.Join(examplesDir, "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatalf("no examples found under %s; this test is the reason they can be trusted, so an empty directory is a defect rather than a pass", examplesDir)
	}

	for _, path := range entries {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			config, err := decodeAuthenticationConfiguration(data)
			if err != nil {
				t.Fatalf("the example does not decode: %v", err)
			}
			if errs := validation.ValidateAuthenticationConfiguration(authenticationcel.NewDefaultCompiler(), config, nil); len(errs) > 0 {
				t.Fatalf("the API server would refuse to start with this example: %v", errs.ToAggregate())
			}

			// Being valid is not enough for a reference: it also has to demonstrate
			// the thing it is a reference for.
			if config.HTTPSignature == nil {
				t.Fatal("the example configures no httpSignature section")
			}
			var resolvers, certs int
			for _, a := range config.HTTPSignature.Authenticators {
				if a.Resolver != nil {
					resolvers++
				}
				if a.X509 != nil {
					certs++
				}
				// Required on both backends, because the server has no default rule
				// and neither backend states its identities in this file.
				//
				// The escalation is reachable and was demonstrated against a live
				// cluster: a mapping deriving groups from the certificate's subject
				// lets whoever can request a certificate name system:masters and
				// receive cluster administrator. A resolver is more direct still,
				// since whoever serves on the socket names the identity outright. An
				// example missing the rule is an example that teaches that.
				if !mentionsSystemPrefixRule(a) {
					t.Errorf("authenticator %q states no userValidationRules refusing the system: prefix; "+
						"there is no default rule, so an operator copying this would let %s choose their own groups",
						a.Name, whoChoosesTheIdentity(a))
				}
			}
			if resolvers == 0 || certs == 0 {
				t.Errorf("got %d resolver authenticators and %d certificate authenticators, want at least one of each: "+
					"the example exists to show both ways of resolving a signature", resolvers, certs)
			}
		})
	}
}

// mentionsSystemPrefixRule reports whether an authenticator has a user validation
// rule constraining the system: prefix.
//
// It matches on the expression text, which is coarse: a rule that mentions the
// prefix without actually refusing it would satisfy this. That is acceptable here
// because the rule's behavior is asserted separately, against a running verifier, in
// the authenticator's own tests. What this catches is the example losing the rule.
func mentionsSystemPrefixRule(a apiserver.HTTPSignatureAuthenticator) bool {
	for _, rule := range a.UserValidationRules {
		if strings.Contains(rule.Expression, `"system:"`) || strings.Contains(rule.Expression, `'system:'`) {
			return true
		}
	}
	return false
}

// whoChoosesTheIdentity names the party a missing rule hands the choice to, so the
// failure says who is being trusted rather than only which field is absent.
func whoChoosesTheIdentity(a apiserver.HTTPSignatureAuthenticator) string {
	if a.Resolver != nil {
		return "whoever can serve on the resolver's socket"
	}
	return "whoever can request a certificate"
}
