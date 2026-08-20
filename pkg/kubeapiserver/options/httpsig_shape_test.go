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

package options

import (
	"strings"
	"testing"
	"time"

	"k8s.io/apiserver/pkg/apis/apiserver"
)

// TestHTTPSignatureYAMLShape decodes the httpSignature section and checks where each
// field landed, using the loader kube-apiserver runs at startup.
//
// This exists because of how the sub-struct move was found to be broken. The Go tests
// were updated alongside the types and compiled clean; the integration suite builds
// its server configuration as YAML text, so it went on writing endpoint at the
// authenticator level, and nothing caught it until twenty-five tests failed at server
// start fourteen minutes into a run. A field's place in the document has no
// compile-time coverage, so it gets a test that reads like the document an operator
// writes and fails in a second.
func TestHTTPSignatureYAMLShape(t *testing.T) {
	config, err := loadAuthenticationConfigFromData([]byte(`
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
httpSignature:
  authority: api.example.com
  scheme: https
  maxClockSkew: 5s
  authenticators:
  - name: corp-resolver
    maxAge: 1m
    userValidationRules:
    - expression: '!user.username.startsWith("system:")'
      message: no system identities
    resolver:
      endpoint: unix:///var/run/httpsig/resolver.sock
      keyIDPrefixes: [corp]
      relayedHeaders: [X-Session-Token]
      nonceHandling: Ignore
      cache:
        maxKeys: 512
        maxAge: 3m
        negativeMaxAge: 15s
  - name: workload-certificates
    maxAge: 2m
    x509:
      certificateAuthority: |
        -----BEGIN CERTIFICATE-----
        the decoder does not parse this
        -----END CERTIFICATE-----
      certificateValidationRules:
      - expression: cert.notAfter - cert.notBefore <= duration('24h')
      claimMappings:
        username:
          expression: cert.subject.commonName
      cache:
        maxEntries: 256
        ttl: 30s
`))
	if err != nil {
		t.Fatalf("the reference shape does not decode: %v", err)
	}
	h := config.HTTPSignature
	if h == nil {
		t.Fatal("httpSignature decoded as absent")
	}

	// Section-level fields: this server's description of itself.
	if h.Authority != "api.example.com" || h.Scheme != "https" {
		t.Errorf("authority/scheme = %q/%q", h.Authority, h.Scheme)
	}
	if h.MaxClockSkew == nil || h.MaxClockSkew.Duration != 5*time.Second {
		t.Errorf("maxClockSkew = %v, want 5s on the section", h.MaxClockSkew)
	}
	if len(h.Authenticators) != 2 {
		t.Fatalf("got %d authenticators, want 2", len(h.Authenticators))
	}
	res, x := h.Authenticators[0], h.Authenticators[1]

	// Resolver-only fields belong to the resolver.
	if res.Resolver == nil {
		t.Fatal("resolver decoded as absent")
	}
	if got := res.Resolver.Endpoint; got != "unix:///var/run/httpsig/resolver.sock" {
		t.Errorf("resolver.endpoint = %q", got)
	}
	if got := res.Resolver.KeyIDPrefixes; len(got) != 1 || got[0] != "corp" {
		t.Errorf("resolver.keyIDPrefixes = %v", got)
	}
	if got := res.Resolver.RelayedHeaders; len(got) != 1 || got[0] != "X-Session-Token" {
		t.Errorf("resolver.relayedHeaders = %v", got)
	}
	if res.Resolver.NonceHandling != apiserver.NonceHandlingIgnore {
		t.Errorf("resolver.nonceHandling = %q", res.Resolver.NonceHandling)
	}
	if c := res.Resolver.Cache; c == nil || c.MaxKeys == nil || *c.MaxKeys != 512 ||
		c.MaxAge == nil || c.MaxAge.Duration != 3*time.Minute ||
		c.NegativeMaxAge == nil || c.NegativeMaxAge.Duration != 15*time.Second {
		t.Errorf("resolver.cache did not decode: %+v", c)
	}
	if res.X509 != nil {
		t.Error("a resolver authenticator decoded an x509 block")
	}

	// Fields that apply to both stay on the authenticator.
	if res.MaxAge == nil || res.MaxAge.Duration != time.Minute {
		t.Errorf("maxAge = %v, want 1m on the authenticator", res.MaxAge)
	}
	if len(res.UserValidationRules) != 1 {
		t.Errorf("userValidationRules did not decode on a resolver authenticator: %v", res.UserValidationRules)
	}

	// x509-only fields belong to x509.
	if x.X509 == nil {
		t.Fatal("x509 decoded as absent")
	}
	if !strings.Contains(x.X509.CertificateAuthority, "BEGIN CERTIFICATE") {
		t.Error("x509.certificateAuthority did not decode")
	}
	if len(x.X509.CertificateValidationRules) != 1 {
		t.Errorf("x509.certificateValidationRules = %v", x.X509.CertificateValidationRules)
	}
	if m := x.X509.ClaimMappings; m == nil || m.Username.Expression != "cert.subject.commonName" {
		t.Error("x509.claimMappings did not decode")
	}
	if c := x.X509.Cache; c == nil || c.MaxEntries == nil || *c.MaxEntries != 256 ||
		c.TTL == nil || c.TTL.Duration != 30*time.Second {
		t.Errorf("x509.cache did not decode: %+v", c)
	}
	if x.Resolver != nil {
		t.Error("an x509 authenticator decoded a resolver block")
	}
}

// TestHTTPSignatureRejectsTheOldShape is the other half: a field left where it used
// to sit is an error rather than a silent zero.
//
// That is what strict decoding buys, and it is why moving these fields needs no
// conversion for configurations written against the previous shape. An operator is
// told at startup, and the message names the field, so what to move is not a guess.
func TestHTTPSignatureRejectsTheOldShape(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
		body  string
	}{
		{"endpoint on the authenticator", "endpoint",
			"    endpoint: unix:///a.sock\n"},
		{"keyIDPrefixes on the authenticator", "keyIDPrefixes",
			"    resolver:\n      endpoint: unix:///a.sock\n    keyIDPrefixes: [corp]\n"},
		{"relayedHeaders on the authenticator", "relayedHeaders",
			"    resolver:\n      endpoint: unix:///a.sock\n    relayedHeaders: [X-Token]\n"},
		{"nonceHandling on the authenticator", "nonceHandling",
			"    resolver:\n      endpoint: unix:///a.sock\n    nonceHandling: Ignore\n"},
		{"cache on the authenticator", "cache",
			"    resolver:\n      endpoint: unix:///a.sock\n    cache: {maxKeys: 8}\n"},
		{"claimMappings on the authenticator", "claimMappings",
			"    x509:\n      certificateAuthority: x\n    claimMappings:\n      username:\n        expression: 'a'\n"},
		{"certificateValidationRules on the authenticator", "certificateValidationRules",
			"    x509:\n      certificateAuthority: x\n    certificateValidationRules:\n    - expression: 'true'\n"},
		{"certificateCache inside x509", "certificateCache",
			"    x509:\n      certificateAuthority: x\n      certificateCache: {ttl: 1m}\n"},
		{"tolerance on the authenticator", "tolerance",
			"    resolver:\n      endpoint: unix:///a.sock\n    tolerance: 5s\n"},
		{"maxClockSkew on the authenticator", "maxClockSkew",
			"    resolver:\n      endpoint: unix:///a.sock\n    maxClockSkew: 5s\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadAuthenticationConfigFromData([]byte(`
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: a
` + tc.body))
			if err == nil {
				t.Fatalf("%q was accepted where it no longer belongs; strict decoding is what tells an operator", tc.field)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("the error should name %q so an operator knows what to move, got: %v", tc.field, err)
			}
		})
	}
}
