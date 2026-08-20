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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/apis/apiserver"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
)

func validHTTPSignatureConfig() *apiserver.HTTPSignatureConfig {
	return config(apiserver.HTTPSignatureAuthenticator{
		Name:     "resolver",
		Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///var/run/httpsig-resolver.sock"},
	})
}

// config wraps authenticators in an HTTPSignatureConfig, naming any that the case
// did not name. Most cases are about one field and would otherwise repeat a name
// that has nothing to do with what they are testing.
func config(as ...apiserver.HTTPSignatureAuthenticator) *apiserver.HTTPSignatureConfig {
	for i := range as {
		if as[i].Name == "" {
			as[i].Name = "resolver-" + strconv.Itoa(i)
		}
	}
	return &apiserver.HTTPSignatureConfig{Authenticators: as}
}

func int32Ptr(i int32) *int32 { return &i }

func testCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// caPEMForKey builds a certificate authority certificate for a given key, so two
// can be produced that differ in their bytes and agree in their
// subjectKeyIdentifier, which Go derives from the public key.
func caPEMForKey(t *testing.T, key *ecdsa.PrivateKey, commonName string, serial int64) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// leafPEM builds a certificate that is not a certificate authority, which is how a
// certificate with no subjectKeyIdentifier is produced: Go generates one only for a
// CA template.
func leafPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "not-an-authority"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestValidateHTTPSignature(t *testing.T) {
	caPEM := testCAPEM(t)
	validX509 := func() apiserver.HTTPSignatureAuthenticator {
		return apiserver.HTTPSignatureAuthenticator{
			Name: "certs",
			X509: &apiserver.HTTPSignatureX509{
				CertificateAuthority: caPEM,
				ClaimMappings:        &apiserver.HTTPSignatureClaimMappings{Username: apiserver.HTTPSignatureClaimExpression{Expression: "cert.subject.commonName"}},
			},
		}
	}

	for _, tc := range []struct {
		name   string
		config *apiserver.HTTPSignatureConfig
		gate   bool
		// wantErr is a substring of the expected error, or empty for no error.
		wantErr string
	}{
		{
			name:   "valid",
			config: validHTTPSignatureConfig(),
			gate:   true,
		},
		{
			name:   "absent section is fine with the gate off",
			config: nil,
			gate:   false,
		},
		{
			name:    "present section needs the gate",
			config:  validHTTPSignatureConfig(),
			gate:    false,
			wantErr: "HTTPSignatureAuthentication feature gate is disabled",
		},
		{
			name:    "neither resolver nor x509",
			config:  config(apiserver.HTTPSignatureAuthenticator{}),
			gate:    true,
			wantErr: "one of resolver or x509 is required",
		},
		{
			name:    "resolver endpoint must be a unix socket",
			config:  config(apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "https://resolver.example.com"}}),
			gate:    true,
			wantErr: "unsupported scheme",
		},
		{
			name: "abstract socket is accepted",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///@httpsig-resolver"}},
			),
			gate: true,
		},
		{
			name: "duplicate endpoints",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"one"}}},
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"two"}}},
			),
			gate:    true,
			wantErr: "Duplicate value",
		},
		{
			name: "two catch-all resolvers fan out",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock"}},
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///b.sock"}},
			),
			gate:    true,
			wantErr: "at most one authenticator may omit resolver.keyIDPrefixes",
		},
		{
			name: "one catch-all alongside a prefixed resolver is fine",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"corp"}}},
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///b.sock"}},
			),
			gate: true,
		},
		{
			name: "duplicate prefix across resolvers",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"corp"}}},
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///b.sock", KeyIDPrefixes: []string{"corp"}}},
			),
			gate:    true,
			wantErr: "Duplicate value",
		},
		{
			name: "prefix with a slash can never match",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"corp/cell-a"}}},
			),
			gate:    true,
			wantErr: "can never match",
		},
		{
			name: "empty prefix",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{""}}},
			),
			gate:    true,
			wantErr: "omit keyIDPrefixes",
		},
		{
			// Scheme and authority describe this server, so they sit on the config
			// rather than on each authenticator. There is no longer a state in
			// which two entries disagree about the authority that goes into every
			// signature base.
			name: "scheme and authority are stated once",
			config: &apiserver.HTTPSignatureConfig{
				Scheme:    "https",
				Authority: "api.example.com",
				Authenticators: []apiserver.HTTPSignatureAuthenticator{
					{Name: "a", Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"one"}}},
					{Name: "b", Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///b.sock", KeyIDPrefixes: []string{"two"}}},
				},
			},
			gate: true,
		},
		{
			name: "bad scheme",
			config: &apiserver.HTTPSignatureConfig{
				Scheme:         "ftp",
				Authenticators: []apiserver.HTTPSignatureAuthenticator{{Name: "a", Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock"}}},
			},
			gate:    true,
			wantErr: "must be http or https",
		},
		{
			name:    "no authenticators",
			config:  &apiserver.HTTPSignatureConfig{},
			gate:    true,
			wantErr: "at least one authenticator is required",
		},
		{
			name:    "unnamed authenticator",
			config:  &apiserver.HTTPSignatureConfig{Authenticators: []apiserver.HTTPSignatureAuthenticator{{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock"}}}},
			gate:    true,
			wantErr: "a name is required",
		},
		{
			name: "duplicate authenticator names",
			config: &apiserver.HTTPSignatureConfig{Authenticators: []apiserver.HTTPSignatureAuthenticator{
				{Name: "same", Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"one"}}},
				{Name: "same", Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///b.sock", KeyIDPrefixes: []string{"two"}}},
			}},
			gate:    true,
			wantErr: "Duplicate value",
		},
		{
			name:   "valid x509",
			config: config(validX509()),
			gate:   true,
		},
		{
			// The two ways of resolving a keyid are alternatives, not layers. One
			// configuration naming both would leave which of them answered a
			// signature depending on nothing stated in the file.
			name: "resolver and x509 together",
			config: func() *apiserver.HTTPSignatureConfig {
				a := validX509()
				a.Resolver = &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock"}
				return config(a)
			}(),
			gate:    true,
			wantErr: "resolver and x509 are mutually exclusive",
		},
		{
			name: "x509 without claimMappings",
			config: func() *apiserver.HTTPSignatureConfig {
				a := validX509()
				a.X509.ClaimMappings = nil
				return config(a)
			}(),
			gate:    true,
			wantErr: "claimMappings is required",
		},
		{
			// The subjectKeyIdentifier is what a presented certificate's
			// authorityKeyIdentifier names, so an anchor without one can never be
			// selected and any certificate it issued would be refused as having an
			// unknown issuer.
			name: "trust anchor without a subjectKeyIdentifier",
			config: func() *apiserver.HTTPSignatureConfig {
				a := validX509()
				a.X509.CertificateAuthority = leafPEM(t)
				return config(a)
			}(),
			gate:    true,
			wantErr: "has no subjectKeyIdentifier extension",
		},
		{
			// Two certificates for one authority key. A presented certificate names
			// its issuer by key identifier, so both authenticators would be selected
			// by the same certificate.
			name: "two authenticators sharing an authority key",
			config: func() *apiserver.HTTPSignatureConfig {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				first, second := validX509(), validX509()
				first.Name = "first"
				first.X509.CertificateAuthority = caPEMForKey(t, key, "shared-key-ca", 1)
				second.Name = "second"
				second.X509.CertificateAuthority = caPEMForKey(t, key, "shared-key-ca-reissued", 2)
				return config(first, second)
			}(),
			gate:    true,
			wantErr: "same subjectKeyIdentifier as one used by authenticator",
		},
		{
			// One authenticator holding both, which is what a certificate authority
			// that reissued without rotating its key looks like mid-rollover. One
			// trust decision, so not a conflict.
			name: "one authenticator holding two certificates for one authority key",
			config: func() *apiserver.HTTPSignatureConfig {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				a := validX509()
				a.X509.CertificateAuthority = caPEMForKey(t, key, "rolling-ca", 1) + caPEMForKey(t, key, "rolling-ca-reissued", 2)
				return config(a)
			}(),
			gate: true,
		},
		{
			name: "x509 without trust anchors",
			config: func() *apiserver.HTTPSignatureConfig {
				a := validX509()
				a.X509 = &apiserver.HTTPSignatureX509{}
				return config(a)
			}(),
			gate:    true,
			wantErr: "trust anchors are required",
		},
		// There is no case here for a resolver field on an x509 authenticator, or
		// for x509's claimMappings on a resolver. nonceHandling, keyIDPrefixes,
		// relayedHeaders and cache live in resolver; certificateValidationRules and
		// claimMappings live in x509. Neither can be written in the other's place,
		// so there is nothing left for validation to catch and nothing to assert.
		// What used to be six rejections is now six compile errors.
		{
			// Accepted on either backend. Both produce an identity the cluster has
			// not written down, and the expressions read a user rather than a
			// certificate, so one rule set covers both.
			name: "resolver with userValidationRules",
			config: config(apiserver.HTTPSignatureAuthenticator{
				Resolver:            &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock"},
				UserValidationRules: []apiserver.UserValidationRule{{Expression: `!user.username.startsWith("system:")`}},
			}),
			gate: true,
		},
		{
			// Compiled with the code the authenticator runs, so an expression that
			// validates here cannot fail to compile there.
			name: "resolver with an uncompilable userValidationRule",
			config: config(apiserver.HTTPSignatureAuthenticator{
				Resolver:            &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock"},
				UserValidationRules: []apiserver.UserValidationRule{{Expression: "user.noSuchField"}},
			}),
			gate:    true,
			wantErr: "userValidationRules[0].expression",
		},
		{
			// An x509 authenticator alongside resolvers is the case the whole
			// authenticator list exists for, and neither claims the other's keyids.
			name: "x509 alongside a catch-all resolver",
			config: config(
				validX509(),
				apiserver.HTTPSignatureAuthenticator{Name: "resolver", Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock"}},
			),
			gate: true,
		},
		{
			name: "zero maxAge",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock"}, MaxAge: &metav1.Duration{}},
			),
			gate:    true,
			wantErr: "must be positive",
		},
		{
			// One value per server, so it is set once rather than per authenticator.
			name: "negative maxClockSkew",
			config: &apiserver.HTTPSignatureConfig{
				MaxClockSkew:   &metav1.Duration{Duration: -time.Second},
				Authenticators: []apiserver.HTTPSignatureAuthenticator{{Name: "a", Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock"}}},
			},
			gate:    true,
			wantErr: "must not be negative",
		},
		{
			name: "maxClockSkew",
			config: &apiserver.HTTPSignatureConfig{
				MaxClockSkew:   &metav1.Duration{Duration: 5 * time.Second},
				Authenticators: []apiserver.HTTPSignatureAuthenticator{{Name: "a", Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock"}}},
			},
			gate: true,
		},
		{
			name: "reserved relayed header",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", RelayedHeaders: []string{"Authorization"}}},
			),
			gate:    true,
			wantErr: "route around that path",
		},
		{
			name: "reserved impersonation prefix",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", RelayedHeaders: []string{"Impersonate-Extra-Scopes"}}},
			),
			gate:    true,
			wantErr: "route around that path",
		},
		{
			name: "duplicate relayed header differing only in case",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", RelayedHeaders: []string{"X-Token", "x-token"}}},
			),
			gate:    true,
			wantErr: "Duplicate value",
		},
		{
			name: "invalid relayed header name",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", RelayedHeaders: []string{"X Token"}}},
			),
			gate:    true,
			wantErr: "not a valid HTTP header field name",
		},
		{
			name: "valid relayed header",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", RelayedHeaders: []string{"X-Session-Token"}}},
			),
			gate: true,
		},
		{
			name: "zero cache maxKeys",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", Cache: &apiserver.HTTPSignatureResolverCache{MaxKeys: int32Ptr(0)}}},
			),
			gate:    true,
			wantErr: "must be positive",
		},
		{
			name: "negative cache maxAge",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", Cache: &apiserver.HTTPSignatureResolverCache{MaxAge: &metav1.Duration{Duration: -time.Second}}}},
			),
			gate:    true,
			wantErr: "must not be negative",
		},
		{
			name: "zero cache maxAge disables caching and is allowed",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", Cache: &apiserver.HTTPSignatureResolverCache{MaxAge: &metav1.Duration{}}}},
			),
			gate: true,
		},
		{
			name: "nonceHandling Consume",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", NonceHandling: apiserver.NonceHandlingConsume}},
			),
			gate: true,
		},
		{
			name: "nonceHandling Ignore",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", NonceHandling: apiserver.NonceHandlingIgnore}},
			),
			gate: true,
		},
		{
			// A typo would otherwise fall through to the safe default, leaving replay
			// protection on for an operator who meant to turn it off and sending them
			// to the resolver to find out why.
			name: "nonceHandling typo",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", NonceHandling: "ignore"}},
			),
			gate:    true,
			wantErr: "Unsupported value",
		},
		{
			name: "nonceHandling nonsense",
			config: config(
				apiserver.HTTPSignatureAuthenticator{Resolver: &apiserver.HTTPSignatureResolver{Endpoint: "unix:///a.sock", NonceHandling: "Disabled"}},
			),
			gate:    true,
			wantErr: "Unsupported value",
		},
		{
			name:    "too many resolvers",
			config:  manyResolvers(maxHTTPSignatureAuthenticators + 1),
			gate:    true,
			wantErr: "Too many",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateHTTPSignature(authenticationcel.NewDefaultCompiler(), tc.config, field.NewPath("httpSignature"), tc.gate)
			got := errs.ToAggregate()
			switch {
			case tc.wantErr == "" && got != nil:
				t.Fatalf("unexpected error: %v", got)
			case tc.wantErr != "" && got == nil:
				t.Fatalf("expected an error containing %q, got none", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(got.Error(), tc.wantErr):
				t.Fatalf("expected an error containing %q, got: %v", tc.wantErr, got)
			}
		})
	}
}

func manyResolvers(n int) *apiserver.HTTPSignatureConfig {
	out := make([]apiserver.HTTPSignatureAuthenticator, 0, n)
	for i := 0; i < n; i++ {
		id := strconv.Itoa(i)
		out = append(out, apiserver.HTTPSignatureAuthenticator{
			Name: "resolver-" + id,
			Resolver: &apiserver.HTTPSignatureResolver{
				Endpoint:      "unix:///resolver-" + id + ".sock",
				KeyIDPrefixes: []string{"prefix-" + id},
			},
		})
	}
	return &apiserver.HTTPSignatureConfig{Authenticators: out}
}
