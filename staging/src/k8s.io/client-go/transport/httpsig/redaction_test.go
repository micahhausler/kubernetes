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
	"strings"
	"testing"
	"time"

	"github.com/micahhausler/httpsig"
)

// leaked reports whether out reveals want in any rendering fmt can produce.
// Checking for the string alone is not enough: a secret reached through an
// interface field is printed as the byte slice the implementation holds, which
// is how the Signer field leaked while a substring check called it clean.
func leaked(t *testing.T, out, want string) bool {
	t.Helper()
	for _, form := range []string{
		want,
		fmt.Sprintf("%v", []byte(want)), // [83 85 80 ...]
		strings.Trim(fmt.Sprintf("%v", []byte(want)), "[]"), // ... inside a larger value
		fmt.Sprintf("%x", want),
	} {
		if strings.Contains(out, form) {
			return true
		}
	}
	return false
}

// TestNothingHoldingKeyMaterialPrintsIt covers every exported type in this
// package that can hold key material, in every verb that reaches a different
// method: %v and %s reach String, %#v reaches GoString, and a type that
// implements only one of them leaks through the other.
func TestNothingHoldingKeyMaterialPrintsIt(t *testing.T) {
	const (
		secret       = "SUPERSECRETHMAC"
		privateKey   = "PEMPRIVATEKEYSECRET"
		headerSecret = "SESSIONTOKENSECRET"
	)
	// A covered header value is credential material: it is why the client
	// refuses to send a header it does not cover.
	hmacMaterial := Material{
		KeyID:         "k",
		Secret:        secret,
		SignedHeaders: map[string]string{"x-session-token": headerSecret},
	}
	asymMaterial := Material{KeyID: "k", PrivateKey: privateKey}

	bound, err := NewBoundCredential(hmacMaterial, "probe", httpsig.Algorithm("hmac-sha256"), nil,
		map[string]bool{"x-session-token": true})
	if err != nil {
		t.Fatalf("binding credential: %v", err)
	}
	cred, err := bound.At(time.Now())
	if err != nil {
		t.Fatalf("credential: %v", err)
	}

	cases := map[string]any{
		"Material":              hmacMaterial,
		"Material pointer":      &hmacMaterial,
		"Material asymmetric":   asymMaterial,
		"SigningCredential":     SigningCredential{APIVersion: SigningCredentialAPIVersion, Kind: SigningCredentialKind, Material: hmacMaterial},
		"Credential":            cred,
		"BoundCredential":       bound,
		"Config inline":         &Config{Algorithm: "hmac-sha256", Credential: &hmacMaterial},
		"Config asymmetric":     &Config{Algorithm: "ecdsa-p256-sha256", Credential: &asymMaterial},
		"Config in a container": struct{ Signing *Config }{&Config{Algorithm: "hmac-sha256", Credential: &hmacMaterial}},
	}
	for name, value := range cases {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			out := fmt.Sprintf(verb, value)
			for what, want := range map[string]string{
				"secret":       secret,
				"private key":  privateKey,
				"header value": headerSecret,
			} {
				if leaked(t, out, want) {
					t.Errorf("%s printed with %s leaks the %s: %s", name, verb, what, out)
				}
			}
			// A redaction that printed nothing would pass the check above, so
			// require the key ID, which is what makes the output worth logging.
			if !strings.Contains(out, `"k"`) {
				t.Errorf("%s printed with %s names no key ID, so it is useless in a log: %s", name, verb, out)
			}
		}
	}
}
