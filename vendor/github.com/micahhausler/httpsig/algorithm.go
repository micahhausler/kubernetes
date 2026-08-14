// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package httpsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"math/big"
)

// An Algorithm is an entry in the IANA "HTTP Signature Algorithms" registry.
type Algorithm string

// Algorithms defined by [RFC 9421 Section 3.3]. JSON Web Signature
// algorithms are not supported.
//
// [RFC 9421 Section 3.3]: https://datatracker.ietf.org/doc/html/rfc9421#section-3.3
const (
	RSAPSSSHA512    Algorithm = "rsa-pss-sha512"
	RSAV15SHA256    Algorithm = "rsa-v1_5-sha256"
	HMACSHA256      Algorithm = "hmac-sha256"
	ECDSAP256SHA256 Algorithm = "ecdsa-p256-sha256"
	ECDSAP384SHA384 Algorithm = "ecdsa-p384-sha384"
	Ed25519         Algorithm = "ed25519"
)

// A Signer signs a signature base, implementing the HTTP_SIGN primitive of
// [RFC 9421 Section 3.3].
//
// [RFC 9421 Section 3.3]: https://datatracker.ietf.org/doc/html/rfc9421#section-3.3
type Signer interface {
	Algorithm() Algorithm
	Sign(base []byte) ([]byte, error)
}

// A Verifier checks a signature over a signature base, implementing the
// HTTP_VERIFY primitive of [RFC 9421 Section 3.3].
//
// [RFC 9421 Section 3.3]: https://datatracker.ietf.org/doc/html/rfc9421#section-3.3
type Verifier interface {
	Algorithm() Algorithm
	Verify(base, signature []byte) error
}

// NewSigner returns a Signer for the given algorithm and private key. The
// key must match the algorithm: *rsa.PrivateKey for RSAPSSSHA512 and
// RSAV15SHA256, []byte for HMACSHA256, *ecdsa.PrivateKey on the matching
// curve for ECDSAP256SHA256 and ECDSAP384SHA384, and ed25519.PrivateKey for
// Ed25519.
func NewSigner(alg Algorithm, key crypto.PrivateKey) (Signer, error) {
	switch alg {
	case RSAPSSSHA512, RSAV15SHA256:
		k, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, keyError(alg, key)
		}
		return &rsaSigner{alg: alg, key: k}, nil
	case HMACSHA256:
		k, ok := key.([]byte)
		if !ok {
			return nil, keyError(alg, key)
		}
		return &hmacKey{key: k}, nil
	case ECDSAP256SHA256, ECDSAP384SHA384:
		k, ok := key.(*ecdsa.PrivateKey)
		if !ok || k.Curve != ecdsaCurve(alg) {
			return nil, keyError(alg, key)
		}
		return &ecdsaSigner{alg: alg, key: k}, nil
	case Ed25519:
		k, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, keyError(alg, key)
		}
		return &ed25519Signer{key: k}, nil
	}
	return nil, fmt.Errorf("httpsig: unsupported algorithm %q", alg)
}

// NewVerifier returns a Verifier for the given algorithm and public key. The
// key must match the algorithm: *rsa.PublicKey for RSAPSSSHA512 and
// RSAV15SHA256, []byte for HMACSHA256, *ecdsa.PublicKey on the matching
// curve for ECDSAP256SHA256 and ECDSAP384SHA384, and ed25519.PublicKey for
// Ed25519.
func NewVerifier(alg Algorithm, key crypto.PublicKey) (Verifier, error) {
	switch alg {
	case RSAPSSSHA512, RSAV15SHA256:
		k, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, keyError(alg, key)
		}
		return &rsaVerifier{alg: alg, key: k}, nil
	case HMACSHA256:
		k, ok := key.([]byte)
		if !ok {
			return nil, keyError(alg, key)
		}
		return &hmacKey{key: k}, nil
	case ECDSAP256SHA256, ECDSAP384SHA384:
		k, ok := key.(*ecdsa.PublicKey)
		if !ok || k.Curve != ecdsaCurve(alg) {
			return nil, keyError(alg, key)
		}
		return &ecdsaVerifier{alg: alg, key: k}, nil
	case Ed25519:
		k, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, keyError(alg, key)
		}
		return &ed25519Verifier{key: k}, nil
	}
	return nil, fmt.Errorf("httpsig: unsupported algorithm %q", alg)
}

func keyError(alg Algorithm, key any) error {
	return fmt.Errorf("httpsig: wrong key type %T for algorithm %q", key, alg)
}

func ecdsaCurve(alg Algorithm) elliptic.Curve {
	if alg == ECDSAP384SHA384 {
		return elliptic.P384()
	}
	return elliptic.P256()
}

func rsaHash(alg Algorithm) (crypto.Hash, func([]byte) []byte) {
	if alg == RSAPSSSHA512 {
		return crypto.SHA512, func(b []byte) []byte {
			d := sha512.Sum512(b)
			return d[:]
		}
	}
	return crypto.SHA256, func(b []byte) []byte {
		d := sha256.Sum256(b)
		return d[:]
	}
}

// pssOptions uses a salt length equal to the SHA-512 digest length (64
// bytes), per [RFC 9421 Section 3.3.1].
//
// [RFC 9421 Section 3.3.1]: https://datatracker.ietf.org/doc/html/rfc9421#section-3.3.1
var pssOptions = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA512}

type rsaSigner struct {
	alg Algorithm
	key *rsa.PrivateKey
}

func (s *rsaSigner) Algorithm() Algorithm { return s.alg }

func (s *rsaSigner) Sign(base []byte) ([]byte, error) {
	h, digest := rsaHash(s.alg)
	if s.alg == RSAPSSSHA512 {
		return rsa.SignPSS(rand.Reader, s.key, h, digest(base), pssOptions)
	}
	return rsa.SignPKCS1v15(rand.Reader, s.key, h, digest(base))
}

type rsaVerifier struct {
	alg Algorithm
	key *rsa.PublicKey
}

func (v *rsaVerifier) Algorithm() Algorithm { return v.alg }

func (v *rsaVerifier) Verify(base, signature []byte) error {
	h, digest := rsaHash(v.alg)
	var err error
	if v.alg == RSAPSSSHA512 {
		err = rsa.VerifyPSS(v.key, h, digest(base), signature, pssOptions)
	} else {
		err = rsa.VerifyPKCS1v15(v.key, h, digest(base), signature)
	}
	if err != nil {
		return ErrSignatureMismatch
	}
	return nil
}

type hmacKey struct {
	key []byte
}

func (k *hmacKey) Algorithm() Algorithm { return HMACSHA256 }

func (k *hmacKey) Sign(base []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, k.key)
	mac.Write(base)
	return mac.Sum(nil), nil
}

func (k *hmacKey) Verify(base, signature []byte) error {
	want, _ := k.Sign(base)
	// Constant-time comparison.
	if !hmac.Equal(want, signature) {
		return ErrSignatureMismatch
	}
	return nil
}

func ecdsaHash(alg Algorithm) hash.Hash {
	if alg == ECDSAP384SHA384 {
		return sha512.New384()
	}
	return sha256.New()
}

type ecdsaSigner struct {
	alg Algorithm
	key *ecdsa.PrivateKey
}

func (s *ecdsaSigner) Algorithm() Algorithm { return s.alg }

// Sign encodes the signature as r and s zero-padded to the curve size and
// concatenated, per RFC 9421 Sections [3.3.4] and [3.3.5].
//
// [3.3.4]: https://datatracker.ietf.org/doc/html/rfc9421#section-3.3.4
// [3.3.5]: https://datatracker.ietf.org/doc/html/rfc9421#section-3.3.5
func (s *ecdsaSigner) Sign(base []byte) ([]byte, error) {
	h := ecdsaHash(s.alg)
	h.Write(base)
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, h.Sum(nil))
	if err != nil {
		return nil, err
	}
	size := (s.key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	ss.FillBytes(sig[size:])
	return sig, nil
}

type ecdsaVerifier struct {
	alg Algorithm
	key *ecdsa.PublicKey
}

func (v *ecdsaVerifier) Algorithm() Algorithm { return v.alg }

func (v *ecdsaVerifier) Verify(base, signature []byte) error {
	size := (v.key.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*size {
		return ErrSignatureMismatch
	}
	h := ecdsaHash(v.alg)
	h.Write(base)
	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])
	if !ecdsa.Verify(v.key, h.Sum(nil), r, s) {
		return ErrSignatureMismatch
	}
	return nil
}

type ed25519Signer struct {
	key ed25519.PrivateKey
}

func (s *ed25519Signer) Algorithm() Algorithm { return Ed25519 }

func (s *ed25519Signer) Sign(base []byte) ([]byte, error) {
	return ed25519.Sign(s.key, base), nil
}

type ed25519Verifier struct {
	key ed25519.PublicKey
}

func (v *ed25519Verifier) Algorithm() Algorithm { return Ed25519 }

func (v *ed25519Verifier) Verify(base, signature []byte) error {
	if !ed25519.Verify(v.key, base, signature) {
		return ErrSignatureMismatch
	}
	return nil
}
