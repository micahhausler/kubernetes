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

package validation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/apis/apiserver"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
)

func testPublicKeyPEM(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func validHTTPSignatureConfig(t *testing.T) *apiserver.HTTPSignatureConfig {
	t.Helper()
	return &apiserver.HTTPSignatureConfig{
		Authenticators: []apiserver.HTTPSignatureAuthenticator{{
			Name: "static-keys",
			Keys: []apiserver.HTTPSignatureKey{{
				KeyID:     "alice-key",
				Algorithm: "ed25519",
				PublicKey: testPublicKeyPEM(t),
				User: apiserver.HTTPSignatureUser{
					Username: "alice",
					Groups:   []string{"signers"},
				},
			}},
		}},
	}
}

// TestValidateHTTPSignatureFeatureGate covers the rule that keeps an alpha
// section from taking effect by accident: the field exists in the served config
// versions, so the gate is the only thing standing between a configuration file
// and a live authenticator.
func TestValidateHTTPSignatureFeatureGate(t *testing.T) {
	config := validHTTPSignatureConfig(t)

	errs := validateHTTPSignature(authenticationcel.NewDefaultCompiler(), config, nil, false)
	if len(errs) == 0 {
		t.Fatal("want an error when the feature gate is disabled")
	}
	if !strings.Contains(errs.ToAggregate().Error(), "feature gate is disabled") {
		t.Errorf("error does not name the feature gate: %v", errs.ToAggregate())
	}

	if errs := validateHTTPSignature(authenticationcel.NewDefaultCompiler(), config, nil, true); len(errs) != 0 {
		t.Errorf("want no errors for a valid config with the gate enabled, got %v", errs.ToAggregate())
	}

	// An absent section is not an error whether the gate is on or off, otherwise
	// enabling the gate would be required to run at all.
	if errs := validateHTTPSignature(authenticationcel.NewDefaultCompiler(), nil, nil, false); len(errs) != 0 {
		t.Errorf("an absent httpSignature section must not be an error: %v", errs.ToAggregate())
	}
}

func TestValidateHTTPSignatureAuthenticator(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretFile, []byte("shared-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	// A ladder scoping by cell, with no date step, so these cases test scope
	// handling rather than expiry.
	ladder := func() *apiserver.HTTPSignatureKeyDerivation {
		return &apiserver.HTTPSignatureKeyDerivation{
			Kind: "hmac-ladder",
			Hash: "sha-256",
			Steps: []apiserver.HTTPSignatureKeyDerivationStep{
				{Name: "cell", Scope: true},
				{Name: "terminator", Literal: "k8s_request"},
			},
		}
	}
	pubPEM := testPublicKeyPEM(t)

	for _, tc := range []struct {
		name   string
		mutate func(*apiserver.HTTPSignatureConfig)
		want   string
	}{{
		name:   "valid",
		mutate: func(*apiserver.HTTPSignatureConfig) {},
	}, {
		name: "valid hmac key",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].Keys[0].Algorithm = "hmac-sha256"
			c.Authenticators[0].Keys[0].PublicKey = ""
			c.Authenticators[0].Keys[0].SecretFile = secretFile
		},
	}, {
		name:   "no keys",
		mutate: func(c *apiserver.HTTPSignatureConfig) { c.Authenticators[0].Keys = nil },
		want:   "one of keys or x509 is required",
	}, {
		name: "too many keys",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			for i := 0; i < maxHTTPSignatureKeys+1; i++ {
				c.Authenticators[0].Keys = append(c.Authenticators[0].Keys, apiserver.HTTPSignatureKey{
					KeyID:     "k" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
					Algorithm: "ed25519", PublicKey: pubPEM,
					User: apiserver.HTTPSignatureUser{Username: "u" + string(rune('a'+i%26)) + string(rune('a'+i/26))},
				})
			}
		},
		want: "Too many",
	}, {
		name:   "no keyID",
		mutate: func(c *apiserver.HTTPSignatureConfig) { c.Authenticators[0].Keys[0].KeyID = "" },
		want:   "keyID",
	}, {
		name: "duplicate keyID",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			second := c.Authenticators[0].Keys[0]
			second.User.Username = "bob"
			c.Authenticators[0].Keys = append(c.Authenticators[0].Keys, second)
		},
		want: "Duplicate value",
	}, {
		name: "duplicate username",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			second := c.Authenticators[0].Keys[0]
			second.KeyID = "bob-key"
			c.Authenticators[0].Keys = append(c.Authenticators[0].Keys, second)
		},
		want: "Duplicate value",
	}, {
		name:   "no username",
		mutate: func(c *apiserver.HTTPSignatureConfig) { c.Authenticators[0].Keys[0].User.Username = "" },
		want:   "username",
	}, {
		name: "system username",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].Keys[0].User.Username = "system:masters-impostor"
		},
		want: "may not start with system:",
	}, {
		name: "system group",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].Keys[0].User.Groups = []string{"system:masters"}
		},
		want: "may not start with system:",
	}, {
		name:   "empty group",
		mutate: func(c *apiserver.HTTPSignatureConfig) { c.Authenticators[0].Keys[0].User.Groups = []string{""} },
		want:   "groups[0]",
	}, {
		name:   "zero maxAge",
		mutate: func(c *apiserver.HTTPSignatureConfig) { c.Authenticators[0].MaxAge = &metav1.Duration{} },
		want:   "must be positive",
	}, {
		name: "negative maxAge",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].MaxAge = &metav1.Duration{Duration: -time.Minute}
		},
		want: "must be positive",
	}, {
		name: "negative tolerance",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].Tolerance = &metav1.Duration{Duration: -time.Second}
		},
		want: "must not be negative",
	}, {
		name:   "unknown scheme",
		mutate: func(c *apiserver.HTTPSignatureConfig) { c.Scheme = "ftp" },
		want:   "must be http or https",
	}, {
		name: "malformed public key",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].Keys[0].PublicKey = "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n"
		},
		want: "publicKey",
	}, {
		name:   "unknown algorithm",
		mutate: func(c *apiserver.HTTPSignatureConfig) { c.Authenticators[0].Keys[0].Algorithm = "ed448" },
		want:   "ed448",
	}, {
		// A ladder describes the deployment, so an asymmetric key sitting beside
		// one is fine: the ladder simply does not apply to it. Claiming a
		// position on the ladder is what an asymmetric key cannot do.
		name: "a ladder alongside an asymmetric key",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].KeyDerivation = ladder()
		},
	}, {
		name: "an asymmetric key claiming a position on the ladder",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].KeyDerivation = ladder()
			c.Authenticators[0].Keys[0].Stage = &apiserver.HTTPSignatureKeyStage{
				Scope: map[string]string{"cell": "cell-a"},
			}
		},
		want: "hmac-sha256 only",
	}, {
		name: "stage without a derivation",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].Keys[0].Algorithm = "hmac-sha256"
			c.Authenticators[0].Keys[0].PublicKey = ""
			c.Authenticators[0].Keys[0].SecretFile = secretFile
			c.Authenticators[0].Keys[0].Stage = &apiserver.HTTPSignatureKeyStage{Scope: map[string]string{"cell": "a"}}
		},
		want: "requires keyDerivation",
	}, {
		name: "valid derivation from the root secret",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].Keys[0].Algorithm = "hmac-sha256"
			c.Authenticators[0].Keys[0].PublicKey = ""
			c.Authenticators[0].Keys[0].SecretFile = secretFile
			c.Authenticators[0].KeyDerivation = ladder()
			c.Authenticators[0].Keys[0].Stage = &apiserver.HTTPSignatureKeyStage{Scope: map[string]string{"cell": "cell-a"}}
		},
	}, {
		name: "derivation with a scope the ladder does not take",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].Keys[0].Algorithm = "hmac-sha256"
			c.Authenticators[0].Keys[0].PublicKey = ""
			c.Authenticators[0].Keys[0].SecretFile = secretFile
			c.Authenticators[0].KeyDerivation = ladder()
			c.Authenticators[0].Keys[0].Stage = &apiserver.HTTPSignatureKeyStage{Scope: map[string]string{
				"cell": "cell-a", "zone": "z1",
			}}
		},
		want: "does not take from this stage",
	}, {
		name: "derivation missing a scope value",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].Keys[0].Algorithm = "hmac-sha256"
			c.Authenticators[0].Keys[0].PublicKey = ""
			c.Authenticators[0].Keys[0].SecretFile = secretFile
			c.Authenticators[0].KeyDerivation = ladder()
		},
		want: "must be non-empty",
	}, {
		// The ladder is validated where it is stated, so a server operator learns
		// their ladder is wrong at startup rather than from rejected requests.
		name: "invalid derivation",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].Keys[0].Algorithm = "hmac-sha256"
			c.Authenticators[0].Keys[0].PublicKey = ""
			c.Authenticators[0].Keys[0].SecretFile = secretFile
			bad := ladder()
			bad.Steps[0].Date = "20060102"
			c.Authenticators[0].KeyDerivation = bad
		},
		want: "date",
	}, {
		// A rung is raw bytes, so its file holds base64. A plain secret would
		// decode to something arbitrary and fail as a signature mismatch.
		name: "staged secret file that is not base64",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].Keys[0].Algorithm = "hmac-sha256"
			c.Authenticators[0].Keys[0].PublicKey = ""
			c.Authenticators[0].Keys[0].SecretFile = secretFile
			c.Authenticators[0].KeyDerivation = ladder()
			c.Authenticators[0].Keys[0].Stage = &apiserver.HTTPSignatureKeyStage{
				From:  "cell",
				Scope: map[string]string{"cell": "cell-a"},
			}
		},
		want: "must hold base64",
	}, {
		name: "hmac with an unreadable secret file",
		mutate: func(c *apiserver.HTTPSignatureConfig) {
			c.Authenticators[0].Keys[0].Algorithm = "hmac-sha256"
			c.Authenticators[0].Keys[0].PublicKey = ""
			c.Authenticators[0].Keys[0].SecretFile = "/nonexistent/secret"
		},
		want: "reading secretFile",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			config := validHTTPSignatureConfig(t)
			tc.mutate(config)
			errs := validateHTTPSignature(authenticationcel.NewDefaultCompiler(), config, nil, true)
			if tc.want == "" {
				if len(errs) != 0 {
					t.Fatalf("want no errors, got %v", errs.ToAggregate())
				}
				return
			}
			if len(errs) == 0 {
				t.Fatalf("want an error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(errs.ToAggregate().Error(), tc.want) {
				t.Errorf("error %v does not mention %q", errs.ToAggregate(), tc.want)
			}
		})
	}
}
