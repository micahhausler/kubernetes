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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/micahhausler/httpsig"
	"github.com/micahhausler/httpsig/keyscope"

	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	transporthttpsig "k8s.io/client-go/transport/httpsig"
	"k8s.io/klog/v2"
)

// key is one configured verification key and the identity it authenticates.
type key struct {
	// verifier is set for keys that verify the same way on every request. For a
	// derived key it is nil and a verifier is built per request, because the
	// derived key depends on the created timestamp the signature carries and
	// on the scope the keyid claims.
	verifier httpsig.Verifier
	// scoped is set for a derived key: material bound to its position on the
	// ladder, which derives a verifier per signature.
	scoped *keyscope.Key
	info   *user.DefaultInfo
}

// keyResolver resolves a signature against a list of keys stated in
// configuration, each with the identity it authenticates as.
type keyResolver struct {
	resolverName string
	keys         map[string]*key
	policy       httpsig.Policy
}

var _ resolver = &keyResolver{}

func newKeyResolver(c apiserver.HTTPSignatureAuthenticator, policy httpsig.Policy) (*keyResolver, error) {
	if c.ClaimMappings != nil {
		return nil, fmt.Errorf("claimMappings derives an identity from a certificate, and keys states one per key")
	}
	if len(c.CertificateValidationRules) > 0 {
		return nil, fmt.Errorf("certificateValidationRules requires x509")
	}
	if len(c.UserValidationRules) > 0 {
		return nil, fmt.Errorf("userValidationRules constrains an identity an assertion claimed, and keys states its identities in this file")
	}

	r := &keyResolver{
		resolverName: c.Name,
		keys:         make(map[string]*key, len(c.Keys)),
		policy:       policy,
	}
	for i, k := range c.Keys {
		built, err := buildKey(k, c.KeyDerivation)
		if err != nil {
			return nil, fmt.Errorf("keys[%d]: %w", i, err)
		}
		if _, dup := r.keys[k.KeyID]; dup {
			return nil, fmt.Errorf("keys[%d]: duplicate keyID %q", i, k.KeyID)
		}
		built.info = &user.DefaultInfo{
			Name:   k.User.Username,
			UID:    k.User.UID,
			Groups: k.User.Groups,
		}
		r.keys[k.KeyID] = built
	}
	return r, nil
}

func (r *keyResolver) name() string { return r.resolverName }

// handles reports whether this resolver holds the key a keyid names.
//
// A derived key's keyid carries its claimed scope after the name, joined by
// slashes, so the lookup falls back to the segment before the first slash; the
// claimed scope itself is checked by the key, not here.
func (r *keyResolver) handles(keyID string) bool {
	_, found := r.lookup(keyID)
	return found
}

func (r *keyResolver) lookup(keyID string) (*key, bool) {
	if k, ok := r.keys[keyID]; ok {
		return k, true
	}
	if name, _, found := strings.Cut(keyID, "/"); found {
		k, ok := r.keys[name]
		return k, ok
	}
	return nil, false
}

func (r *keyResolver) resolve(_ *http.Request, sig *httpsig.Signature) (*resolution, error) {
	// KeyID is an unverified claim until Verify succeeds. It is used only to
	// select a key, never to grant anything.
	k, ok := r.lookup(sig.KeyID())
	if !ok {
		return nil, fmt.Errorf("unknown keyID")
	}
	verifier, err := k.verifierFor(sig)
	if err != nil {
		return nil, err
	}
	return &resolution{
		verifier: verifier,
		policy:   r.policy,
		// The identity was decided when this file was written, so there is
		// nothing to defer and nothing that can fail here.
		identify: func(context.Context) (*authenticator.Response, error) {
			return &authenticator.Response{User: k.info}, nil
		},
	}, nil
}

// verifierFor returns the verifier for one signature. A static key holds one; a
// derived key builds one per request, checking the scope the keyid claims
// against its own configuration first, so a request signed under the wrong
// scope, whatever dimensions the ladder scopes by, is rejected with an error
// naming the disagreeing step rather than a bare signature mismatch. The verifier never derives with its
// own clock: it uses the created timestamp the signature carries, which is
// covered by the signature and bounded by the maximum age policy.
func (k *key) verifierFor(sig *httpsig.Signature) (httpsig.Verifier, error) {
	if k.scoped == nil {
		return k.verifier, nil
	}
	created := sig.Created()
	if created.IsZero() {
		return nil, fmt.Errorf("the signature carries no created parameter, and this key's verification key is derived from it")
	}
	return k.scoped.Verifier(sig.KeyID(), created)
}

// ValidateKey reports whether one configured key is usable. It is exported so
// configuration validation can reject unusable key material, ladder documents,
// and stages without repeating the rules, which live here and in the signing
// library.
func ValidateKey(k apiserver.HTTPSignatureKey, ladder *apiserver.HTTPSignatureKeyDerivation) error {
	_, err := buildKey(k, ladder)
	return err
}

// buildKey loads one configured key: parses its material, loads its ladder, and
// validates its stage. Everything that can fail does so here, at server start,
// rather than on a request.
func buildKey(k apiserver.HTTPSignatureKey, ladder *apiserver.HTTPSignatureKeyDerivation) (*key, error) {
	alg := httpsig.Algorithm(k.Algorithm)
	if k.Algorithm == "" {
		return nil, fmt.Errorf("algorithm is required")
	}
	if k.KeyID == "" {
		return nil, fmt.Errorf("keyID is required")
	}
	// A keyid in the certificate form would be claimed by a certificate resolver
	// as well as by this one, which would make identity depend on the order the
	// two appear in.
	if strings.HasPrefix(k.KeyID, transporthttpsig.CertificateKeyIDPrefix) {
		return nil, fmt.Errorf("keyID must not begin with %q, which is reserved for signatures whose key is asserted by a certificate",
			transporthttpsig.CertificateKeyIDPrefix)
	}

	if alg != httpsig.HMACSHA256 {
		if k.SecretFile != "" {
			return nil, fmt.Errorf("algorithm %s uses a public key, not secretFile", alg)
		}
		if ladder != nil && k.Stage != nil {
			return nil, fmt.Errorf("stage names a position on a derivation ladder, which applies to hmac-sha256 only; an asymmetric key is not derived")
		}
		if k.Stage != nil {
			return nil, fmt.Errorf("stage applies to hmac-sha256 only")
		}
		if k.PublicKey == "" {
			return nil, fmt.Errorf("algorithm %s requires publicKey", alg)
		}
		pub, err := parsePublicKey(k.PublicKey)
		if err != nil {
			return nil, err
		}
		verifier, err := httpsig.NewVerifier(alg, pub)
		if err != nil {
			return nil, err
		}
		return &key{verifier: verifier}, nil
	}

	if k.PublicKey != "" {
		return nil, fmt.Errorf("algorithm %s uses a shared secret, not publicKey", alg)
	}
	if k.SecretFile == "" {
		return nil, fmt.Errorf("algorithm %s requires secretFile", alg)
	}
	if k.Stage != nil && ladder == nil {
		return nil, fmt.Errorf("stage names a position on a ladder, so it requires keyDerivation")
	}
	raw, err := os.ReadFile(k.SecretFile)
	if err != nil {
		return nil, fmt.Errorf("reading secretFile: %w", err)
	}
	var material []byte
	if k.Stage != nil && k.Stage.From != "" {
		// An intermediate rung is raw hash output. The newline trim applied to
		// a plain secret would corrupt a rung that ends in a newline byte, so a
		// rung-holding secretFile holds base64. A root secret is a printable
		// string even when a stage carries scope values, so it stays plain.
		material, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("secretFile must hold base64 when stage.from is set, because a derived rung is raw bytes: %w", err)
		}
	} else {
		// A trailing newline is what an editor or `echo` leaves behind, and a
		// secret that differs by one byte fails with no clue why.
		material = bytes.TrimRight(raw, "\r\n")
	}

	if ladder == nil {
		verifier, err := httpsig.NewVerifier(alg, material)
		if err != nil {
			return nil, err
		}
		return &key{verifier: verifier}, nil
	}

	derivation, digest, err := transporthttpsig.DerivationFrom(ladder)
	if err != nil {
		return nil, err
	}
	// The digest is the drift check: the client logs the same value for its
	// copy, and a mismatch otherwise surfaces as a bare signature failure.
	klog.V(2).InfoS("Loaded key derivation ladder", "keyID", k.KeyID, "sha256", digest)
	var stage *transporthttpsig.Stage
	if k.Stage != nil {
		stage = &transporthttpsig.Stage{From: k.Stage.From, Scope: k.Stage.Scope}
	}
	// Binding the material to its position validates the stage, so a scope typo
	// fails at server start rather than on a request.
	scoped, err := keyscope.New(derivation, transporthttpsig.KeyscopeStage(k.KeyID, stage), material)
	if err != nil {
		return nil, err
	}
	return &key{scoped: scoped}, nil
}

// parsePublicKey reads a PEM-encoded public key. Both the SubjectPublicKeyInfo
// and PKCS#1 encodings are accepted, which covers what openssl emits.
func parsePublicKey(data string) (any, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, fmt.Errorf("publicKey holds no PEM block")
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing publicKey: %w", err)
		}
		switch pub.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			return pub, nil
		default:
			return nil, fmt.Errorf("publicKey holds an unsupported key type %T", pub)
		}
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("publicKey holds an unsupported PEM block %q", block.Type)
	}
}
