// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

// Package contentdigest computes and verifies the Content-Digest field of
// [RFC 9530]. Only sha-256 and sha-512 are supported; the registry's
// deprecated and insecure entries are deliberately absent.
//
// Callers of [github.com/micahhausler/httpsig/client] and
// [github.com/micahhausler/httpsig/server] do not need this package: the
// transport and the middleware compute and verify the field from the
// configured mode. It is for callers who sign and verify with the low-level
// [github.com/micahhausler/httpsig] API and cover the content-digest
// component themselves.
//
// A signer computes the field before signing, so that the signature covers
// it:
//
//	value, err := contentdigest.Value(contentdigest.SHA256, body)
//	if err != nil {
//		// ...
//	}
//	req.Header.Set("Content-Digest", value)
//	// then httpsig.Sign with a "content-digest" component
//
// A verifier checks the field against the body. This is a separate step from
// signature verification and neither one implies the other: covering
// content-digest binds the field value to the signature, but only [Verify]
// binds that value to the body. A verifier that requires the component and
// skips this check accepts any body the sender chooses.
//
//	if err := contentdigest.Verify(r.Header.Values("Content-Digest"), body, contentdigest.Supported()); err != nil {
//		// ...
//	}
//
// [RFC 9530]: https://datatracker.ietf.org/doc/html/rfc9530
package contentdigest

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/micahhausler/sfv"
)

// Digest algorithms this module computes and verifies, from the IANA "Hash
// Algorithms for HTTP Digest Fields" registry. The deprecated and insecure
// registry entries are deliberately absent.
const (
	SHA256 = "sha-256"
	SHA512 = "sha-512"
)

// Supported returns the algorithms this package implements, in registry
// name form. It is the widest accepted set [Verify] can be given.
func Supported() []string {
	return []string{SHA256, SHA512}
}

// ErrNoAcceptedDigest reports a Content-Digest field with no entry in the
// verifier's accepted algorithm set.
var ErrNoAcceptedDigest = errors.New("httpsig/contentdigest: no Content-Digest entry uses an accepted algorithm")

// ErrDigestMismatch reports a Content-Digest entry that does not match the
// message body.
var ErrDigestMismatch = errors.New("httpsig/contentdigest: Content-Digest does not match the body")

func digest(alg string, body []byte) ([]byte, bool) {
	switch alg {
	case SHA256:
		d := sha256.Sum256(body)
		return d[:], true
	case SHA512:
		d := sha512.Sum512(body)
		return d[:], true
	}
	return nil, false
}

// Value computes a Content-Digest field value for the body, such as
// `sha-256=:...:`. A nil body is digested as the empty body, which is a
// meaningful value: it states that there is no content.
func Value(alg string, body []byte) (string, error) {
	d, ok := digest(alg, body)
	if !ok {
		return "", fmt.Errorf("httpsig/contentdigest: unsupported digest algorithm %q", alg)
	}
	b, err := sfv.Dictionary{{Key: alg, Value: sfv.Item{Value: sfv.Bytes(d)}}}.MarshalText()
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Verify checks the Content-Digest field values against the body. Every
// entry with a supported algorithm must match the body, and at least one
// matching entry must use an algorithm in accepted. Entries with unsupported
// algorithms are ignored, but cannot satisfy the requirement on their own:
// a field carrying only unknown algorithms is rejected.
//
// The accepted set must not be empty. It is the verifier's own
// configuration, so an empty set is reported as a caller error rather than
// as a rejected message; pass [Supported] to accept everything implemented.
func Verify(values []string, body []byte, accepted []string) error {
	if len(accepted) == 0 {
		return errors.New("httpsig/contentdigest: no accepted digest algorithms given")
	}
	dict, err := sfv.ParseDictionary(values...)
	if err != nil {
		return fmt.Errorf("httpsig/contentdigest: Content-Digest is not a dictionary: %w", err)
	}
	if len(dict) == 0 {
		return errors.New("httpsig/contentdigest: Content-Digest is empty")
	}
	sawAccepted := false
	for _, m := range dict {
		item, ok := m.Value.(sfv.Item)
		if !ok {
			return fmt.Errorf("httpsig/contentdigest: Content-Digest entry %q is not an item", m.Key)
		}
		want, supported := digest(m.Key, body)
		if !supported {
			continue
		}
		got, ok := item.Value.(sfv.Bytes)
		if !ok {
			return fmt.Errorf("httpsig/contentdigest: Content-Digest entry %q is not a byte sequence", m.Key)
		}
		if !equalDigests([]byte(got), want) {
			return fmt.Errorf("%w: %s", ErrDigestMismatch, m.Key)
		}
		for _, a := range accepted {
			if m.Key == a {
				sawAccepted = true
			}
		}
	}
	if !sawAccepted {
		return ErrNoAcceptedDigest
	}
	return nil
}

// equalDigests compares digests without early exit. Digests are not secrets,
// but the comparison is on an attacker-reachable path and constant time
// costs nothing here.
func equalDigests(got, want []byte) bool {
	if len(got) != len(want) {
		return false
	}
	var v byte
	for i := range got {
		v |= got[i] ^ want[i]
	}
	return v == 0
}
