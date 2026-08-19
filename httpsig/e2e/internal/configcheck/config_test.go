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

// Package configcheck validates the authentication configuration gen-fixtures.sh
// writes, using the same decode and validation the API server runs at startup.
//
// It exists because the alternative feedback loop is bad. A configuration the
// server refuses shows up as kubeadm reporting a connection refused twenty seconds
// into up.sh, from an API server that logged its complaint inside a container that
// no longer exists. Two defects found the first time this ran were an
// under-indented block and a message value containing ": ", which YAML reads as a
// nested mapping; both are invisible to inspection and neither says anything
// recognizable when a cluster fails to come up.
package configcheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/apis/apiserver/validation"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/pkg/features"
	utilfeature "k8s.io/apiserver/pkg/util/feature"
	featuregatetesting "k8s.io/component-base/featuregate/testing"
)

// TestGeneratedConfigIsAccepted decodes the generated file and runs the validation
// kube-apiserver runs at startup.
func TestGeneratedConfigIsAccepted(t *testing.T) {
	featuregatetesting.SetFeatureGateDuringTest(t, utilfeature.DefaultFeatureGate, features.HTTPSignatureAuthentication, true)

	path := os.Getenv("HTTPSIG_CONFIG")
	if path == "" {
		t.Skip("HTTPSIG_CONFIG is unset; gen-fixtures.sh sets it")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Paths in the file are the node's, because that is where the API server reads
	// them. Rewritten to the host's copy so the files a key references are the ones
	// checked for being readable, which is part of what validation does.
	if nodeDir := os.Getenv("HTTPSIG_NODE_DIR"); nodeDir != "" {
		abs, err := filepath.Abs(nodeDir)
		if err != nil {
			t.Fatal(err)
		}
		data = []byte(strings.ReplaceAll(string(data), "/httpsig/", abs+"/"))
	}

	config, err := decodeAuthenticationConfiguration(data)
	if err != nil {
		t.Fatalf("the generated configuration does not decode: %v", err)
	}
	if errs := validation.ValidateAuthenticationConfiguration(authenticationcel.NewDefaultCompiler(), config, nil); len(errs) > 0 {
		t.Fatalf("the API server would refuse to start with the generated configuration: %v", errs.ToAggregate())
	}

	// The demo is only demonstrating what it says it is if both ways of resolving a
	// signature are present.
	var resolvers, certs int
	for _, a := range config.HTTPSignature.Authenticators {
		if len(a.Endpoint) > 0 {
			resolvers++
		}
		if a.X509 != nil {
			certs++
		}
	}
	if resolvers == 0 || certs == 0 {
		t.Errorf("got %d resolver authenticators and %d certificate authenticators, want at least one of each", resolvers, certs)
	}
}
