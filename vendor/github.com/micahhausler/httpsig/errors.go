// Copyright 2026 Micah Hausler
// SPDX-License-Identifier: Apache-2.0

package httpsig

import (
	"errors"
	"fmt"
)

// A SyntaxError reports a message whose signature fields or covered
// components cannot be parsed or canonicalized. It indicates a malformed
// message rather than an invalid signature; servers usually map it to a
// 400-class response.
type SyntaxError struct {
	msg string
}

func (e *SyntaxError) Error() string { return "httpsig: " + e.msg }

func syntaxErrorf(format string, args ...any) *SyntaxError {
	return &SyntaxError{msg: fmt.Sprintf(format, args...)}
}

// Verification failures reported by [Signature.Verify]. Each is wrapped in a
// [VerificationError]; test with [errors.Is].
var (
	// ErrSignatureMismatch reports that the signature does not verify
	// against the signature base and key.
	ErrSignatureMismatch = errors.New("httpsig: signature does not match")

	// ErrAlgorithmMismatch reports that the signature's alg parameter
	// disagrees with the verifier's algorithm.
	ErrAlgorithmMismatch = errors.New("httpsig: alg parameter does not match verifier algorithm")

	// ErrExpired reports a signature past its expires parameter or older
	// than the policy's MaxAge.
	ErrExpired = errors.New("httpsig: signature expired")

	// ErrCreatedInFuture reports a created parameter later than the
	// verification time.
	ErrCreatedInFuture = errors.New("httpsig: signature created in the future")

	// ErrMissingCreated reports a policy that requires the created
	// parameter when the signature has none.
	ErrMissingCreated = errors.New("httpsig: signature has no created parameter")

	// ErrMissingComponent reports a component required by policy that is
	// not covered by the signature.
	ErrMissingComponent = errors.New("httpsig: required component not covered")
)

// A VerificationError reports a signature that parsed correctly but is not
// valid for the message, key, or policy. Servers usually map it to a
// 401-class response.
type VerificationError struct {
	// Err is one of the sentinel verification errors, optionally wrapped
	// with detail.
	Err error

	// SignatureBase is the reconstructed signature base the message was
	// verified against. It is intended for debugging.
	SignatureBase []byte
}

func (e *VerificationError) Error() string { return e.Err.Error() }

func (e *VerificationError) Unwrap() error { return e.Err }
