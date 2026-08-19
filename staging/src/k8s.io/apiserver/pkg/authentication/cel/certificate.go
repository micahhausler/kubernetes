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
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/traits"

	apiservercel "k8s.io/apiserver/pkg/cel"
)

// This file declares the kubernetes.Certificate CEL type and builds the value an
// expression evaluates against. Both live here, and both are generated from one
// table of fields, so a field cannot be declared without being populated. The
// alternative, a declaration in one place and a value in another, is the shape
// the SubjectAccessReview types take, and it needs a comment on each half asking
// the next person to remember the other.
//
// Nothing here reads a clock or a request. That is what makes a certificate's
// validation and mapping result a pure function of the certificate, and
// therefore cacheable. Adding a request-scoped variable to this environment
// would silently invalidate that.

// certificateTypeName is the CEL type name of the certificate variable's value.
const certificateTypeName = "kubernetes.Certificate"

// certificateNameTypeName is the CEL type name of a certificate's subject and
// issuer distinguished names.
const certificateNameTypeName = "kubernetes.CertificateName"

// certField is one field of kubernetes.Certificate: its name, its declared
// type, and how its value is read from a certificate. Declaring the three
// together is what keeps the type and the value in agreement.
type certField struct {
	name     string
	declType *apiservercel.DeclType
	value    func(certificate) any
}

// certificate is what a field is read from: the parsed certificate, plus the
// thumbprint its caller already computed.
//
// The thumbprint is passed in rather than computed here because it is the
// identifier the signature's keyid carries, and that identifier is defined once,
// by the wire format. A second implementation of "lowercase hex SHA-256 of the
// DER" would agree with the first only for as long as someone kept checking.
type certificate struct {
	cert       *x509.Certificate
	thumbprint string
}

// nameField is one field of kubernetes.CertificateName.
type nameField struct {
	name     string
	declType *apiservercel.DeclType
	value    func(pkix.Name) any
}

func declField(name string, declType *apiservercel.DeclType) *apiservercel.DeclField {
	// Nothing is required: a certificate may legitimately omit any of these, and
	// an expression that cares says so itself.
	return apiservercel.NewDeclField(name, declType, false, nil, nil)
}

func declFields(fields ...*apiservercel.DeclField) map[string]*apiservercel.DeclField {
	out := make(map[string]*apiservercel.DeclField, len(fields))
	for _, f := range fields {
		out[f.Name] = f
	}
	return out
}

var stringListType = apiservercel.NewListType(apiservercel.StringType, -1)

// nameFields are the attributes exposed from a distinguished name.
//
// Only the attributes that carry identity in practice are exposed. Country,
// locality, province, street, and postal code are omitted: no Kubernetes
// convention puts identity in them, and an unused field is still a field that
// has to keep working.
//
// The order of organization and organizationalUnit is not meaningful. A
// multi-valued name attribute is encoded as an ASN.1 SET, whose members are
// canonically ordered by their encoding, so the order the issuer supplied is not
// the order read back. A rule must test membership with exists() rather than
// index a position.
var nameFields = []nameField{
	{"commonName", apiservercel.StringType, func(n pkix.Name) any { return n.CommonName }},
	{"organization", stringListType, func(n pkix.Name) any { return n.Organization }},
	{"organizationalUnit", stringListType, func(n pkix.Name) any { return n.OrganizationalUnit }},
}

// certificateNameType is the declared type of a subject or issuer.
var certificateNameType = func() *apiservercel.DeclType {
	fields := make([]*apiservercel.DeclField, 0, len(nameFields))
	for _, f := range nameFields {
		fields = append(fields, declField(f.name, f.declType))
	}
	return apiservercel.NewObjectType(certificateNameTypeName, declFields(fields...))
}()

// certificateFields are the attributes exposed from a certificate.
//
// The subject alternative names are separated by type rather than flattened into
// one list. A rule that means "this DNS name" must not also match a URI that
// happens to have the same text, and a flattened list cannot express the
// difference.
//
// notBefore and notAfter are exposed as timestamps rather than as a precomputed
// lifetime, because subtracting them is the general form. That is how a rule
// bounds a certificate's lifetime, which is the only lever a verifier has over
// the withdrawal window:
//
//	cert.notAfter - cert.notBefore <= duration('24h')
//
// extendedKeyUsages is exposed for the same reason. The verifier does not check
// extended key usage itself, because no registered usage fits this purpose, so a
// deployment that has minted one states the requirement as a rule.
var certificateFields = []certField{
	{"subject", certificateNameType, func(c certificate) any { return nameValue(c.cert.Subject) }},
	{"issuer", certificateNameType, func(c certificate) any { return nameValue(c.cert.Issuer) }},

	// Decimal, which is what Go renders. Note that openssl prints a serial in
	// hex, so a value copied from openssl output will not compare equal.
	{"serialNumber", apiservercel.StringType, func(c certificate) any {
		if c.cert.SerialNumber == nil {
			return ""
		}
		return c.cert.SerialNumber.String()
	}},

	{"notBefore", apiservercel.TimestampType, func(c certificate) any { return c.cert.NotBefore }},
	{"notAfter", apiservercel.TimestampType, func(c certificate) any { return c.cert.NotAfter }},

	{"dnsSANs", stringListType, func(c certificate) any { return c.cert.DNSNames }},
	{"uriSANs", stringListType, func(c certificate) any { return uriSANs(c.cert) }},
	{"emailSANs", stringListType, func(c certificate) any { return c.cert.EmailAddresses }},
	{"ipSANs", stringListType, func(c certificate) any { return ipSANs(c.cert) }},

	// The same value the signature's keyid carries, supplied by the caller rather
	// than recomputed, so a rule can pin one exact certificate without depending
	// on any attribute its issuer controls.
	{"sha256Thumbprint", apiservercel.StringType, func(c certificate) any { return c.thumbprint }},

	{"extendedKeyUsages", stringListType, func(c certificate) any { return extKeyUsages(c.cert) }},
}

// CertificateType is the declared type of the cert variable. Registering this
// one type is enough: the nested name type is reachable through its fields.
var CertificateType = func() *apiservercel.DeclType {
	fields := make([]*apiservercel.DeclField, 0, len(certificateFields))
	for _, f := range certificateFields {
		fields = append(fields, declField(f.name, f.declType))
	}
	return apiservercel.NewObjectType(certificateTypeName, declFields(fields...))
}()

// CertificateValue returns the value an expression evaluates against.
//
// The thumbprint is the caller's, because the caller has already computed it in
// order to check it against the signature's keyid.
//
// It is built eagerly rather than lazily, unlike the claims value the JWT
// authenticator builds. Every field here is a slice copy or a string, so there is
// nothing worth deferring, and a lazy map is not safe for concurrent use.
func CertificateValue(cert *x509.Certificate, thumbprint string) traits.Mapper {
	c := certificate{cert: cert, thumbprint: thumbprint}
	fields := make(map[string]any, len(certificateFields))
	for _, f := range certificateFields {
		fields[f.name] = f.value(c)
	}
	// The field names are identifiers chosen here, so unlike a token's claim
	// names they never need CEL escaping.
	return types.DefaultTypeAdapter.NativeToValue(fields).(traits.Mapper)
}

func nameValue(name pkix.Name) map[string]any {
	fields := make(map[string]any, len(nameFields))
	for _, f := range nameFields {
		fields[f.name] = f.value(name)
	}
	return fields
}

// uriSANs renders the URI subject alternative names.
//
// Workload identity schemes put their identifier here, so this is usually the
// field a mapping reads. It is the one field with an external constraint on its
// shape: without it, this authenticator would need a Kubernetes-specific subject
// convention that nothing else issues.
func uriSANs(cert *x509.Certificate) []string {
	out := make([]string, 0, len(cert.URIs))
	for _, u := range cert.URIs {
		out = append(out, u.String())
	}
	return out
}

func ipSANs(cert *x509.Certificate) []string {
	out := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// extKeyUsageNames are the conventional names of the usages Go recognizes. The
// names match the openssl and RFC 5280 spelling, so a value read from a
// certificate's own documentation is the value to write in a rule.
var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "any",
	x509.ExtKeyUsageServerAuth:                     "serverAuth",
	x509.ExtKeyUsageClientAuth:                     "clientAuth",
	x509.ExtKeyUsageCodeSigning:                    "codeSigning",
	x509.ExtKeyUsageEmailProtection:                "emailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:                      "ipsecUser",
	x509.ExtKeyUsageTimeStamping:                   "timeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "ocspSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "microsoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "netscapeServerGatedCrypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "microsoftCommercialCodeSigning",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "microsoftKernelCodeSigning",
}

// extKeyUsages renders the extended key usages, named where Go recognizes them
// and as a dotted object identifier where it does not. A usage minted for this
// purpose will be in the second form.
func extKeyUsages(cert *x509.Certificate) []string {
	out := make([]string, 0, len(cert.ExtKeyUsage)+len(cert.UnknownExtKeyUsage))
	for _, u := range cert.ExtKeyUsage {
		if name, ok := extKeyUsageNames[u]; ok {
			out = append(out, name)
			continue
		}
		// Unreachable unless Go adds a usage. Rendering the numeric value keeps
		// a rule diagnosable rather than silently dropping the usage.
		out = append(out, fmt.Sprintf("unknown-%d", u))
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		out = append(out, oid.String())
	}
	return out
}
