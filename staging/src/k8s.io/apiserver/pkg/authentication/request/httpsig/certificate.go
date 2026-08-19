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
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/micahhausler/httpsig"

	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	certutil "k8s.io/client-go/util/cert"

	transporthttpsig "k8s.io/client-go/transport/httpsig"
)

// This file resolves a signature's key and identity from an X.509 certificate the
// request carries, instead of from configuration.
//
// # What the server stops holding
//
// A configured key list holds a public key and an identity per client, and
// withdrawing one means editing a file. Here the server holds a certificate
// authority bundle and nothing per client. That is the point, and it sets the
// limits: there is no per-client state to delete, so a certificate's lifetime is
// the withdrawal window, subject to the validation cache's own bound.
//
// # Order of work, and why
//
// The verifier's rule elsewhere is to check the signature before doing anything a
// caller could use to make the server work. That rule appears to invert here,
// because the verification key has to come from the certificate before there is
// anything to verify with. It does not actually invert, because the two halves of
// reading a certificate can be separated:
//
//  1. Recompute the leaf's digest and compare it to the keyid. One hash, and it
//     rejects a mismatched assertion before anything else.
//  2. Parse the leaf and take its public key. One parse, size bounded.
//  3. Verify the signature. This proves the caller holds the leaf's private key.
//     It grants nothing: the certificate is still untrusted.
//  4. Only now build the chain and evaluate the expressions.
//
// So the expensive half is still behind proof of possession. What an
// unauthenticated caller can cause is one hash and one parse of at most
// MaxCertificateHeaderBytes.

const (
	// defaultCacheMaxEntries bounds remembered validations when configuration
	// does not.
	defaultCacheMaxEntries = 1024

	// defaultCacheTTL bounds how long a validation is trusted when configuration
	// does not.
	defaultCacheTTL = 5 * time.Minute
)

// certificateResolver resolves a signature against a certificate the request
// carries, validated against configured trust anchors.
type certificateResolver struct {
	resolverName string
	policy       httpsig.Policy

	// roots are the trust anchors, and the source of intermediates. Nothing in
	// the chain comes from the request: the leaf is the only certificate read
	// from it, which is what bounds the chain build to a fixed pool.
	roots *x509.CertPool

	mapper authenticationcel.CertificateCELMapper

	// cache holds validated certificates, keyed by the digest this server
	// computed over the presented bytes, never by the keyid the client claimed.
	cache    *cache.LRUExpireCache
	cacheTTL time.Duration
}

var _ resolver = &certificateResolver{}

// validated is a certificate that chained to the trust anchors and satisfied the
// configured rules: its verification key and the identity it maps to.
//
// Both halves are cached together because both are pure functions of the
// certificate. The expression environment declares no clock and no request, so no
// rule or mapping can produce a different answer for the same certificate at a
// different time, which is what makes this a memo rather than stale state.
type validated struct {
	verifier httpsig.Verifier
	info     *user.DefaultInfo
}

// identity returns a copy, because the cached value outlives the request that
// produced it. Nothing in the chain today writes to a user.Info, and the
// authenticated group adder builds a fresh one rather than appending to this. But
// it carries the Extra map over by reference, so a shared map would be reachable
// by anything downstream that ever decided to annotate it, and the failure that
// would produce is one request's attributes appearing on another's identity.
func (v *validated) identity() *user.DefaultInfo {
	info := &user.DefaultInfo{Name: v.info.Name, UID: v.info.UID}
	if v.info.Groups != nil {
		info.Groups = make([]string, len(v.info.Groups))
		copy(info.Groups, v.info.Groups)
	}
	if v.info.Extra != nil {
		info.Extra = make(map[string][]string, len(v.info.Extra))
		for k, values := range v.info.Extra {
			copied := make([]string, len(values))
			copy(copied, values)
			info.Extra[k] = copied
		}
	}
	return info
}

func newCertificateResolver(c apiserver.HTTPSignatureAuthenticator, policy httpsig.Policy, compiler authenticationcel.Compiler) (*certificateResolver, error) {
	if c.KeyDerivation != nil {
		return nil, fmt.Errorf("keyDerivation applies to hmac-sha256 only, and a certificate carries its own key")
	}
	if c.ClaimMappings == nil {
		return nil, fmt.Errorf("claimMappings is required with x509, because the identity comes from the certificate rather than from this file")
	}

	roots, err := certutil.NewPoolFromBytes([]byte(c.X509.CertificateAuthority))
	if err != nil {
		return nil, fmt.Errorf("x509.certificateAuthority: %w", err)
	}

	mapper, err := CompileCertificateAuthenticator(compiler, c)
	if err != nil {
		return nil, err
	}

	maxEntries := defaultCacheMaxEntries
	ttl := defaultCacheTTL
	if cc := c.X509.CertificateCache; cc != nil {
		if cc.MaxEntries != nil {
			maxEntries = int(*cc.MaxEntries)
		}
		if cc.TTL != nil {
			ttl = cc.TTL.Duration
		}
	}

	return &certificateResolver{
		resolverName: c.Name,
		policy:       policy,
		roots:        roots,
		mapper:       mapper,
		cache:        cache.NewLRUExpireCache(maxEntries),
		cacheTTL:     ttl,
	}, nil
}

func (r *certificateResolver) name() string { return r.resolverName }

// handles claims every signature whose keyid is in the certificate form.
//
// Several certificate resolvers may claim the same signature, each with its own
// trust anchors, and the first whose anchors validate the certificate wins.
// Configuration validation refuses two whose anchors overlap, so that ordering
// does not decide an identity.
func (r *certificateResolver) handles(keyID string) bool {
	return strings.HasPrefix(keyID, transporthttpsig.CertificateKeyIDPrefix)
}

func (r *certificateResolver) resolve(req *http.Request, sig *httpsig.Signature) (*resolution, error) {
	der, err := transporthttpsig.ParseCertificateHeader(req.Header.Values(transporthttpsig.CertificateHeader))
	if err != nil {
		return nil, err
	}

	// The keyid is covered by the signature and the digest is computed here, so
	// this comparison is what binds the certificate to the signature. It is also
	// the cheapest possible rejection: one hash, before any parse.
	claimed := sig.KeyID()
	computed := transporthttpsig.CertificateKeyID(der)
	if claimed != computed {
		return nil, fmt.Errorf("the signature's keyid names a different certificate than the one the request carries: keyid says %s, the %s header digests to %s",
			claimed, transporthttpsig.CertificateHeader, computed)
	}
	// The digest is already in hand, so the expression environment is handed it
	// rather than hashing the certificate a second time.
	thumbprint := strings.TrimPrefix(computed, transporthttpsig.CertificateKeyIDPrefix)

	// A hit answers with the key and the identity together, so a client's second
	// request repeats neither the chain build nor the expressions.
	if entry, ok := r.cache.Get(claimed); ok {
		recordCacheLookup(r.resolverName, true)
		v := entry.(*validated)
		// The verifier still runs: a hit supplies the key and the identity, and
		// never the conclusion that the caller holds the key. Anyone who has
		// merely observed a certificate would otherwise authenticate as its
		// subject.
		return r.resolutionFor(v.verifier, func(context.Context) (*authenticator.Response, error) {
			return &authenticator.Response{User: v.identity()}, nil
		}), nil
	}
	recordCacheLookup(r.resolverName, false)

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing the certificate the request carries: %w", err)
	}
	if err := checkUsableForSigning(leaf); err != nil {
		return nil, err
	}
	// The algorithm is a fixed function of the key type, so there is nothing for
	// an algorithm confusion attack to confuse. Verify also rejects a signature
	// whose alg parameter disagrees with this. This call is also the bound on how
	// much work the key may cost to verify against, which is why it comes before
	// the verifier is built rather than after.
	alg, err := transporthttpsig.CertificateAlgorithm(leaf.PublicKey)
	if err != nil {
		return nil, err
	}
	verifier, err := httpsig.NewVerifier(alg, leaf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("building a %s verifier from the certificate: %w", alg, err)
	}

	// Everything from here is deferred: it runs only once the signature has
	// verified against this key, which proves the caller holds it.
	return r.resolutionFor(verifier, func(ctx context.Context) (*authenticator.Response, error) {
		return r.admit(ctx, leaf, verifier, claimed, thumbprint)
	}), nil
}

// checkUsableForSigning rejects a certificate whose own extensions say it is not
// for signing messages.
//
// This is not the extended key usage question, which has no answer that fits (see
// the API documentation). The key usage extension does have one: digitalSignature
// is what "this key may produce signatures" is spelled as, it is set on essentially
// everything signing-capable, and honoring it costs no population of certificates
// that would otherwise work.
//
// The certificate authority check closes a confusing case rather than a dangerous
// one. Presenting a trust anchor's own certificate as the leaf still requires its
// private key, and whoever holds that can mint any identity they like, so nothing
// is gained by it. But the chain would build trivially and the anchor's subject
// would map to a user, which is a surprising thing for a configuration to do
// silently.
func checkUsableForSigning(leaf *x509.Certificate) error {
	// Absent is not a refusal: the extension is optional, and a certificate
	// without it makes no claim either way.
	if leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("the certificate the request carries does not have the digitalSignature key usage, "+
			"so its own extensions say the key may not sign messages (%s)", certificateIdentifier(leaf))
	}
	if leaf.IsCA {
		return fmt.Errorf("the certificate the request carries is a certificate authority, not a leaf issued to a client (%s)",
			certificateIdentifier(leaf))
	}
	return nil
}

func (r *certificateResolver) resolutionFor(v httpsig.Verifier, identify func(context.Context) (*authenticator.Response, error)) *resolution {
	return &resolution{
		verifier: v,
		policy:   r.policy,
		identify: identify,
	}
}

// admit turns a certificate whose key the caller has proved possession of into an
// identity: chain validation, then the rules, then the mappings, then the rules
// over the result.
func (r *certificateResolver) admit(ctx context.Context, leaf *x509.Certificate, verifier httpsig.Verifier, cacheKey, thumbprint string) (*authenticator.Response, error) {
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots: r.roots,
		// Intermediates deliberately absent: they come from the configured
		// bundle, so a caller cannot extend the chain with certificates of their
		// own choosing.
		//
		// KeyUsages is ExtKeyUsageAny rather than the ExtKeyUsageClientAuth this
		// package's mTLS sibling requires, and rather than Go's default, which is
		// ExtKeyUsageServerAuth and would reject nearly everything. No registered
		// usage means "may sign detached HTTP messages": requiring client
		// authentication would silently enlist every certificate issued for
		// connection authentication, and requiring a new usage would mean
		// reissuing for everyone. The trust anchor bundle is the opt-in instead,
		// and a deployment that has minted a usage requires it with a rule.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("the certificate the request carries does not chain to this authenticator's trust anchors (%s): %w",
			certificateIdentifier(leaf), err)
	}

	certValue := authenticationcel.CertificateValue(leaf, thumbprint)

	// Rules run before mappings, so a mapping expression never reads a
	// certificate no rule has vetted. The JWT authenticator maps first and pays
	// for it with a special case; this order needs no special case.
	if r.mapper.CertificateValidationRules != nil {
		if err := evaluateCertificateRules(ctx, r.mapper.CertificateValidationRules, certValue); err != nil {
			return nil, err
		}
	}

	info, err := r.mapIdentity(ctx, certValue)
	if err != nil {
		return nil, err
	}
	// Before the operator's own rules, so an identity naming something another
	// component's decision depends on is refused whether or not a rule was written
	// against it. A mapping can derive from the certificate's subject, which puts
	// the choice in the hands of whoever requests a certificate.
	if err := checkReservedIdentity(info); err != nil {
		return nil, err
	}

	// What an assertion claims is a claim, not a conclusion. This is the
	// cluster's say over it, and it is the only thing standing between a
	// certificate authority and any identity it cares to mint.
	if r.mapper.UserValidationRules != nil {
		if err := evaluateUserRules(ctx, r.mapper.UserValidationRules, info); err != nil {
			return nil, err
		}
	}

	entry := &validated{verifier: verifier, info: info}
	r.cache.Add(cacheKey, entry, r.entryTTL(leaf, chains))
	return &authenticator.Response{User: entry.identity()}, nil
}

// entryTTL is how long this validation may be trusted: the configured bound, or
// the remaining life of the shortest-lived certificate that vouched for it,
// whichever is smaller.
//
// The chain bound is not decoration. A TTL longer than a trust anchor's remaining
// life would keep admitting requests after the anchor expired, which is the one
// case where the cache would be granting something the uncached path would refuse.
func (r *certificateResolver) entryTTL(leaf *x509.Certificate, chains [][]*x509.Certificate) time.Duration {
	ttl := r.cacheTTL
	clamp := func(notAfter time.Time) {
		if remaining := time.Until(notAfter); remaining < ttl {
			ttl = remaining
		}
	}
	clamp(leaf.NotAfter)
	// Any chain being still valid is enough to admit, so the bound is the
	// longest-lived chain, not the shortest.
	best := time.Duration(0)
	for _, chain := range chains {
		chainTTL := r.cacheTTL
		for _, cert := range chain {
			if remaining := time.Until(cert.NotAfter); remaining < chainTTL {
				chainTTL = remaining
			}
		}
		if chainTTL > best {
			best = chainTTL
		}
	}
	if best < ttl {
		ttl = best
	}
	if ttl < 0 {
		ttl = 0
	}
	return ttl
}

// certificateIdentifier names a certificate in an error without echoing it. It
// matches what the mTLS authenticator reports, so the two are greppable together.
func certificateIdentifier(cert *x509.Certificate) string {
	serial := "<none>"
	if cert.SerialNumber != nil {
		serial = cert.SerialNumber.String()
	}
	return fmt.Sprintf("subject=%q issuer=%q serial=%s", cert.Subject, cert.Issuer, serial)
}
