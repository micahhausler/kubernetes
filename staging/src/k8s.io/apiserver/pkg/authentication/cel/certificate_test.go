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

package cel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/google/cel-go/common/types"
)

// testCertificate builds a self-signed certificate exercising every field the
// CEL type exposes, so a field that is declared but not populated shows up as a
// compile success with a wrong answer rather than passing unnoticed.
func testCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	uri, err := url.Parse("spiffe://cluster.local/ns/default/sa/builder")
	if err != nil {
		t.Fatalf("parsing URI: %v", err)
	}
	notBefore := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1234567890),
		Subject: pkix.Name{
			CommonName:         "builder",
			Organization:       []string{"system:nodes", "extra-org"},
			OrganizationalUnit: []string{"platform"},
		},
		NotBefore:      notBefore,
		NotAfter:       notBefore.Add(12 * time.Hour),
		DNSNames:       []string{"builder.example.com"},
		URIs:           []*url.URL{uri},
		EmailAddresses: []string{"builder@example.com"},
		IPAddresses:    []net.IP{net.ParseIP("10.0.0.1")},
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		// A usage Go does not name, which is the form a purpose-minted usage
		// takes.
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 57683, 1}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return cert
}

// testThumbprint computes the digest the authenticator passes in. It is the same
// value transporthttpsig.CertificateKeyID builds, without the prefix; this package
// deliberately does not depend on that one, so the test states it directly.
func testThumbprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// TestCertificateExpressions checks that the declared type and the runtime value
// agree, which is the thing that cannot be checked by compilation alone: an
// expression compiles against the DeclType and evaluates against the value, so a
// field present in one and absent from the other only fails here.
func TestCertificateExpressions(t *testing.T) {
	cert := testCertificate(t)
	compiler := NewDefaultCompiler()
	value := CertificateValue(cert, testThumbprint(cert))

	for _, tc := range []struct {
		name string
		expr string
		want any
	}{
		// A nested object field read through a native nested map. This is the
		// assumption the whole type shape rests on.
		{"nested subject", `cert.subject.commonName`, "builder"},
		{"nested issuer", `cert.issuer.commonName`, "builder"},
		{"nested list macro", `cert.subject.organization.exists(o, o == 'system:nodes')`, true},
		{"nested list size", `cert.subject.organization.size()`, int64(2)},
		{"organizational unit", `cert.subject.organizationalUnit.exists(o, o == 'platform')`, true},

		{"serial is decimal", `cert.serialNumber`, "1234567890"},

		// Timestamp arithmetic is how a rule bounds a certificate's lifetime.
		// Without it there would have to be a dedicated maxCertificateLifetime
		// field.
		{"lifetime under bound", `cert.notAfter - cert.notBefore <= duration('24h')`, true},
		{"lifetime over bound", `cert.notAfter - cert.notBefore <= duration('1h')`, false},
		{"timestamp comparison", `cert.notBefore < cert.notAfter`, true},

		{"dns SANs", `cert.dnsSANs`, []string{"builder.example.com"}},
		{"uri SANs", `cert.uriSANs[0]`, "spiffe://cluster.local/ns/default/sa/builder"},
		{"uri SAN prefix", `cert.uriSANs.exists(u, u.startsWith('spiffe://cluster.local/ns/default/'))`, true},
		{"email SANs", `cert.emailSANs[0]`, "builder@example.com"},
		{"ip SANs", `cert.ipSANs[0]`, "10.0.0.1"},

		// The thumbprint is the caller's, so what is asserted here is that it
		// arrives intact rather than that this package computes it.
		{"thumbprint is hex", `cert.sha256Thumbprint.matches('^[0-9a-f]{64}$')`, true},
		{"thumbprint is the caller's", `cert.sha256Thumbprint == '` + testThumbprint(cert) + `'`, true},

		// Named and unnamed usages both surface, which is what lets a
		// deployment require a purpose-minted usage as a rule.
		{"named ext key usage", `cert.extendedKeyUsages.exists(u, u == 'clientAuth')`, true},
		{"oid ext key usage", `cert.extendedKeyUsages.exists(u, u == '1.3.6.1.4.1.57683.1')`, true},

		// SAN types are separate lists, so a rule for a DNS name cannot be
		// satisfied by a URI with the same text.
		{"SAN types do not cross", `cert.dnsSANs.exists(d, d.startsWith('spiffe://'))`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := compiler.CompileCertificateExpression(&CertificateMappingExpression{Expression: tc.expr})
			if err != nil {
				t.Fatalf("compiling %q: %v", tc.expr, err)
			}
			out, _, err := result.Program.ContextEval(context.Background(), &varNameActivation{name: certVarName, value: value})
			if err != nil {
				t.Fatalf("evaluating %q: %v", tc.expr, err)
			}
			got, err := out.ConvertToNative(reflect.TypeOf(tc.want))
			if err != nil {
				t.Fatalf("converting result of %q: %v", tc.expr, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%q = %#v, want %#v", tc.expr, got, tc.want)
			}
		})
	}
}

// TestMultiValuedNameAttributesAreUnordered records that the order of a
// multi-valued distinguished name attribute does not survive DER encoding. A
// multi-valued attribute is encoded as an ASN.1 SET, whose members are
// canonically ordered by their encoding, so the order a certificate authority
// passed in is not the order a verifier reads out.
//
// This is recorded rather than worked around. Sorting the list here would hide
// the fact and disagree with every other tool that prints a subject. The
// consequence for a rule is that indexing positionally into organization or
// organizationalUnit is a latent bug whose behavior depends on the bytes of the
// other values, and exists() is the correct idiom. The API documentation says so.
func TestMultiValuedNameAttributesAreUnordered(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	// Chosen so that the input order and the canonical order differ, which is
	// what makes the reordering observable at all.
	in := []string{"zzz", "aaa"}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cn", Organization: in},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}

	if reflect.DeepEqual(cert.Subject.Organization, in) {
		t.Skip("DER encoding preserved the input order; the ordering hazard this test records may no longer apply")
	}
	// The set of values is preserved even though the order is not, which is why
	// exists() is sound and indexing is not.
	want := []string{"aaa", "zzz"}
	if !reflect.DeepEqual(cert.Subject.Organization, want) {
		t.Errorf("organization = %v, want %v (canonical SET order)", cert.Subject.Organization, want)
	}
}

// TestCertificateEnvironmentHasNoClock is the invariant that makes a
// certificate's validation and mapping result cacheable. If an expression could
// read the current time, the same certificate could map to two different
// identities and the cache would be serving a stale answer rather than a
// memoized one.
func TestCertificateEnvironmentHasNoClock(t *testing.T) {
	compiler := NewDefaultCompiler()
	for _, expr := range []string{
		`now < cert.notAfter`,
		`request.time < cert.notAfter`,
		`timeSinceEpoch() > 0`,
	} {
		if _, err := compiler.CompileCertificateExpression(&CertificateValidationCondition{Expression: expr}); err == nil {
			t.Errorf("expression %q compiled, but the certificate environment must expose no clock: "+
				"a time-dependent expression would make the validation cache serve stale identities", expr)
		}
	}
}

// TestCertificateEnvironmentIsIsolated checks that the certificate environment
// does not leak the other authenticators' variables, and that theirs do not leak
// the certificate. One environment per variable is what enforces this.
func TestCertificateEnvironmentIsIsolated(t *testing.T) {
	compiler := NewDefaultCompiler()

	if _, err := compiler.CompileCertificateExpression(&CertificateValidationCondition{Expression: `has(claims.sub)`}); err == nil {
		t.Error("a certificate expression referenced claims, which is not in its environment")
	}
	if _, err := compiler.CompileCertificateExpression(&CertificateValidationCondition{Expression: `user.username == 'x'`}); err == nil {
		t.Error("a certificate expression referenced user, which is not in its environment")
	}
	if _, err := compiler.CompileClaimsExpression(&ClaimMappingExpression{Expression: `cert.subject.commonName`}); err == nil {
		t.Error("a claims expression referenced cert, which is not in its environment")
	}
	if _, err := compiler.CompileUserExpression(&UserValidationCondition{Expression: `cert.subject.commonName == 'x'`}); err == nil {
		t.Error("a user expression referenced cert, which is not in its environment")
	}
}

// TestCertificateMapperEvaluates covers the mapper seam rather than the type: a
// single expression through EvalCertificateMapping and a list through
// EvalCertificateMappings.
func TestCertificateMapperEvaluates(t *testing.T) {
	cert := testCertificate(t)
	compiler := NewDefaultCompiler()
	value := CertificateValue(cert, testThumbprint(cert))

	single, err := compiler.CompileCertificateExpression(&CertificateMappingExpression{Expression: `'pod:' + cert.uriSANs[0]`})
	if err != nil {
		t.Fatalf("compiling: %v", err)
	}
	got, err := NewCertificateMapper([]CompilationResult{single}).EvalCertificateMapping(context.Background(), value)
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	if want := "pod:spiffe://cluster.local/ns/default/sa/builder"; got.EvalResult.Value() != want {
		t.Errorf("got %v, want %v", got.EvalResult.Value(), want)
	}

	rules := make([]CompilationResult, 0, 2)
	for _, expr := range []string{`cert.subject.commonName == 'builder'`, `cert.dnsSANs.size() == 1`} {
		r, err := compiler.CompileCertificateExpression(&CertificateValidationCondition{Expression: expr})
		if err != nil {
			t.Fatalf("compiling %q: %v", expr, err)
		}
		rules = append(rules, r)
	}
	results, err := NewCertificateMapper(rules).EvalCertificateMappings(context.Background(), value)
	if err != nil {
		t.Fatalf("evaluating rules: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for i, r := range results {
		if r.EvalResult != types.True {
			t.Errorf("rule %d evaluated to %v, want true", i, r.EvalResult)
		}
	}
}
