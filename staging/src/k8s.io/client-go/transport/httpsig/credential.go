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
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/micahhausler/httpsig"

	"github.com/micahhausler/httpsig/keyscope"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/yaml"
)

// SigningCredentialAPIVersion is the only version of the credential file this
// build reads. The file is versioned because it is written by something outside
// Kubernetes, so its shape is a contract with whatever produces it.
const SigningCredentialAPIVersion = "httpsig.authentication.k8s.io/v1alpha1"

// SigningCredentialKind identifies the credential document.
const SigningCredentialKind = "SigningCredential"

// A SigningCredential is the part of a signing identity that changes: the key
// itself, the name the server knows it by, the values of any headers the
// signature covers, and when it stops being usable. Everything that does not
// change, such as the algorithm and which headers are covered, stays in the
// kubeconfig.
//
// This is the contract with whatever produces the credential: a credential
// helper, a sidecar, a key broker, or a wrapper around some provider's SDK. It
// writes this document and rewrites it on rotation. It is also the shape an exec
// plugin would print on stdout, which is the delivery mode this design is meant
// to grow into: the schema is defined once so the two cannot disagree.
type SigningCredential struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`

	// Material is the credential itself, inlined. It is a separate type because
	// this document is not the only way a credential arrives: an exec credential
	// plugin hands the same fields over through the client authentication API,
	// and the two paths have to build a signer identically.
	Material `json:",inline"`
}

// Material is a signing credential, independent of how it reached this client.
// Exactly one of Secret, SecretBase64, or PrivateKey is set.
type Material struct {
	// KeyID is the name the server knows this key by. It lives here rather
	// than in the kubeconfig because for some credential schemes it rotates
	// together with the secret.
	KeyID string `json:"keyID"`

	// Secret is a shared secret, for hmac-sha256: either a root secret or, with
	// Stage, the material of an intermediate rung.
	Secret string `json:"secret,omitempty"`

	// SecretBase64 is the same material, base64 encoded, for bytes that are not
	// printable. A derived rung is raw hash output, so this is its only safe
	// encoding.
	SecretBase64 string `json:"secretBase64,omitempty"`

	// PrivateKey is a PEM-encoded private key, for the asymmetric algorithms.
	PrivateKey string `json:"privateKey,omitempty"`

	// Stage is this credential's position on the derivation ladder the client
	// is configured with. It travels here, with the material it describes,
	// because the bytes of a derived rung cannot say what was folded into them.
	// Setting it requires the client to be configured with a ladder.
	// +optional
	Stage *Stage `json:"stage,omitempty"`

	// SignedHeaders holds values for the headers the client declares as
	// covered, keyed by header name. A name that is not declared is an error: a
	// value that is never covered would be sent unsigned.
	SignedHeaders map[string]string `json:"signedHeaders,omitempty"`

	// ExpirationTimestamp is when this credential stops being usable. The
	// meaning is the same in every delivery mode: do not sign with it after
	// this time. What differs is the recovery action, which is to re-read the
	// file here and to re-invoke the plugin under exec delivery.
	//
	// Unset means the credential does not expire on its own, which is
	// appropriate for a long-lived asymmetric key and wrong for a session
	// credential.
	ExpirationTimestamp *metav1.Time `json:"expirationTimestamp,omitempty"`
}

// A Credential is a loaded, ready to use signing identity. It is treated as
// immutable: a source that rotates returns a new one.
type Credential struct {
	// KeyID is the name the server knows the key by.
	KeyID string

	// Signer signs a signature base. It is an interface, so the key it uses
	// need not be in memory and need not be exportable.
	Signer httpsig.Signer

	// SignedHeaders holds values for the headers the configuration covers,
	// keyed by header name.
	SignedHeaders map[string]string

	// Certificate is the DER encoding of the leaf certificate that vouches for
	// the signer's key, for a credential whose identity is asserted by a
	// certificate rather than named by a configured key. Empty otherwise.
	//
	// When set, the round tripper carries it in the Signature-Certificate header
	// and KeyID names its digest. It is not part of SignedHeaders because its
	// header name is not configurable, and a value that could be configured
	// could be configured wrongly.
	Certificate []byte

	// NotAfter is when this credential stops being usable, or the zero time if
	// it does not expire on its own. The caller fails closed rather than
	// signing with an expired credential and letting the server reject it.
	NotAfter time.Time
}

// A CredentialSource produces the current signing credential. Implementations
// must be safe for concurrent use, and are expected to be cheap when nothing has
// changed, because they are asked on every request. Being asked on every request
// is what lets a client outlive its credentials.
//
// This is the seam that keeps key handling out of the round tripper. What travels
// through it is a signer, never key material, so a key held in a TPM, a platform
// keystore, or a smart card satisfies it: the holder answers signing requests and
// the round tripper cannot tell the difference. Two file-backed implementations
// are built in; an implementation may live outside this package and outside
// Kubernetes, and is installed with NewRoundTripperWithSource.
//
// The signing time is a parameter rather than something an implementation reads
// from the clock. A derived key can be scoped to a date, and it has to be scoped
// to the same date the signature carries in its created parameter. An
// implementation that does not derive ignores it.
type CredentialSource interface {
	Credential(at time.Time) (*Credential, error)
}

// fileWatcher re-reads a file when it changes. Change is detected by
// modification time and size, which is what a credential helper rewriting a
// file, or an atomically swapped directory of files, will move.
type fileWatcher struct {
	path string

	mu      sync.Mutex
	modTime time.Time
	size    int64
	loaded  bool
	// data is the bytes of the last read, retained so that contents can answer
	// with them when nothing has changed. A caller reading a pair of files needs
	// the unchanged half's bytes when the other half moves, and re-reading it
	// would be a second read of a file this watcher has already read.
	data []byte
}

// contents returns the file's current bytes and whether they differ from the
// last read.
func (w *fileWatcher) contents() (data []byte, changed bool, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	info, err := os.Stat(w.path)
	if err != nil {
		return nil, false, fmt.Errorf("httpsig: %w", err)
	}
	if w.loaded && info.ModTime().Equal(w.modTime) && info.Size() == w.size {
		return w.data, false, nil
	}
	data, err = os.ReadFile(w.path)
	if err != nil {
		return nil, false, fmt.Errorf("httpsig: %w", err)
	}
	w.modTime, w.size, w.loaded, w.data = info.ModTime(), info.Size(), true, data
	return data, true, nil
}

// keyFileSource signs with a private key read from a file, under a key ID fixed
// by configuration. The file is re-read when it changes, so a rotated key is
// picked up by a long-running client without a restart.
type keyFileSource struct {
	watcher   *fileWatcher
	keyID     string
	algorithm httpsig.Algorithm

	mu     sync.Mutex
	cached *Credential
}

func (s *keyFileSource) Credential(time.Time) (*Credential, error) {
	data, changed, err := s.watcher.contents()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !changed && s.cached != nil {
		return s.cached, nil
	}
	key, err := parsePrivateKey(s.watcher.path, data)
	if err != nil {
		return nil, err
	}
	signer, err := httpsig.NewSigner(s.algorithm, key)
	if err != nil {
		return nil, fmt.Errorf("httpsig: %s key from %s: %w", s.algorithm, s.watcher.path, err)
	}
	s.cached = &Credential{KeyID: s.keyID, Signer: signer}
	return s.cached, nil
}

// credentialFileSource signs with a credential document that something else
// maintains. Everything that rotates comes from the file.
type credentialFileSource struct {
	watcher   *fileWatcher
	algorithm httpsig.Algorithm
	// declaredHeaders are the header names the kubeconfig covers. A value for
	// anything else is rejected rather than ignored.
	declaredHeaders map[string]bool
	// ladder, when set, scopes the secret to a purpose instead of using it as
	// the signing key.
	ladder *keyscope.Derivation

	mu    sync.Mutex
	bound *BoundCredential
}

func (s *credentialFileSource) Credential(at time.Time) (*Credential, error) {
	data, changed, err := s.watcher.contents()
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if changed || s.bound == nil {
		material, err := decodeCredential(data, s.watcher.path)
		if err != nil {
			return nil, err
		}
		bound, err := NewBoundCredential(material, s.watcher.path, s.algorithm, s.ladder, s.declaredHeaders)
		if err != nil {
			return nil, err
		}
		s.bound = bound
	}
	return s.bound.At(at)
}

// staticSource signs with material the caller supplied directly. It rotates
// nothing: the credential was validated when the client was built, and the only
// thing that can change afterwards is whether it has expired.
type staticSource struct {
	bound *BoundCredential
}

func (s *staticSource) Credential(at time.Time) (*Credential, error) {
	return s.bound.At(at)
}

// BoundCredential is credential material prepared for signing: a signer, or,
// when the material sits on a derivation ladder, the key bound to its position
// on it. Every delivery mode holds one, and asks it for a credential per request.
//
// It is exported because an implementation of CredentialSource living outside
// this package needs the same behavior, and reproducing it would put a second
// copy of the expiry and derivation rules somewhere nobody looks.
type BoundCredential struct {
	cred *Credential
	// scoped is the credential's key bound to its position on the ladder. It is
	// retained because the signing key and the key ID both depend on the signing
	// time and so cannot be built once; the library memoizes the one most recent
	// derivation, whose cardinality is one whatever the wire supplies.
	scoped *keyscope.Key
	origin string
}

// NewBoundCredential validates material against the client's signing
// configuration and prepares it for use.
func NewBoundCredential(material Material, origin string, algorithm httpsig.Algorithm, ladder *keyscope.Derivation, declaredHeaders map[string]bool) (*BoundCredential, error) {
	cred, scoped, err := buildCredential(material, origin, algorithm, ladder, declaredHeaders)
	if err != nil {
		return nil, err
	}
	return &BoundCredential{cred: cred, scoped: scoped, origin: origin}, nil
}

// At returns the credential to sign a request created at the given time.
func (b *BoundCredential) At(at time.Time) (*Credential, error) {
	if b.scoped != nil {
		// The signing key and the key ID both depend on the signing time: the
		// key because a date step folds it in, the key ID because it carries the
		// claimed scope, date included, for the verifier to check. Stale material
		// fails here with a scope error naming the date step, not with a bare
		// signature mismatch at the server.
		signer, err := b.scoped.Signer(at)
		if err != nil {
			return nil, fmt.Errorf("httpsig: deriving a signing key for the credential from %s: %w", b.origin, err)
		}
		keyID, err := b.scoped.KeyID(at)
		if err != nil {
			return nil, fmt.Errorf("httpsig: building the scoped key ID for the credential from %s: %w", b.origin, err)
		}
		next := *b.cred
		next.Signer, next.KeyID = signer, keyID
		if err := next.checkNotAfter(at, b.origin); err != nil {
			return nil, err
		}
		return &next, nil
	}
	if err := b.cred.checkNotAfter(at, b.origin); err != nil {
		return nil, err
	}
	return b.cred, nil
}

// checkNotAfter fails closed on an expired credential. Whatever maintains the
// credential has already had its chance to refresh by this point, so signing
// with an expired one only moves the rejection to the server.
func (c *Credential) checkNotAfter(at time.Time, origin string) error {
	if !c.NotAfter.IsZero() && at.After(c.NotAfter) {
		return fmt.Errorf("httpsig: credential from %s expired at %s and has not been refreshed",
			origin, c.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// decodeCredential parses a signing credential document and checks its envelope.
// The origin is named only in errors: a file path, or a command.
func decodeCredential(data []byte, origin string) (Material, error) {
	var doc SigningCredential
	// Strict, so a typo'd field is an error rather than a credential that is
	// silently missing the thing the typo was meant to set.
	if err := yaml.UnmarshalStrict(data, &doc); err != nil {
		return Material{}, fmt.Errorf("httpsig: parsing credential from %s: %w", origin, err)
	}
	if doc.APIVersion != SigningCredentialAPIVersion {
		return Material{}, fmt.Errorf("httpsig: credential from %s has apiVersion %q, want %q",
			origin, doc.APIVersion, SigningCredentialAPIVersion)
	}
	if doc.Kind != SigningCredentialKind {
		return Material{}, fmt.Errorf("httpsig: credential from %s has kind %q, want %q",
			origin, doc.Kind, SigningCredentialKind)
	}
	return doc.Material, nil
}

// buildCredential turns credential material into something the round tripper can
// sign with: a signer, or a key bound to its position on a derivation ladder.
//
// Every delivery mode ends here, whether the material came from a document on
// disk or from an exec plugin through the client authentication API, so the rules
// about what a credential must carry cannot drift between them.
func buildCredential(doc Material, origin string, algorithm httpsig.Algorithm, ladder *keyscope.Derivation, declaredHeaders map[string]bool) (*Credential, *keyscope.Key, error) {
	if doc.KeyID == "" {
		return nil, nil, fmt.Errorf("httpsig: credential from %s sets no keyID", origin)
	}

	cred := &Credential{KeyID: doc.KeyID, SignedHeaders: map[string]string{}}
	var scoped *keyscope.Key
	switch {
	case algorithm == httpsig.HMACSHA256:
		if (doc.Secret == "") == (doc.SecretBase64 == "") {
			return nil, nil, fmt.Errorf("httpsig: credential from %s needs exactly one of secret or secretBase64 for %s", origin, algorithm)
		}
		if doc.PrivateKey != "" {
			return nil, nil, fmt.Errorf("httpsig: credential from %s sets privateKey, which %s does not use", origin, algorithm)
		}
		secret := []byte(doc.Secret)
		if doc.SecretBase64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(doc.SecretBase64)
			if err != nil {
				return nil, nil, fmt.Errorf("httpsig: credential from %s: secretBase64 is not base64: %w", origin, err)
			}
			secret = decoded
		}
		if doc.Stage != nil && ladder == nil {
			return nil, nil, fmt.Errorf("httpsig: credential from %s carries a derivation stage but the client is configured with no ladder", origin)
		}
		if ladder != nil {
			// Binding the material to its position validates the stage, so a
			// scope typo fails here rather than on the first request.
			key, err := keyscope.New(*ladder, KeyscopeStage(doc.KeyID, doc.Stage), secret)
			if err != nil {
				return nil, nil, fmt.Errorf("httpsig: credential from %s: %w", origin, err)
			}
			scoped = key
		} else {
			// Without derivation the secret is the signing key, which is what
			// derivation exists to avoid.
			signer, err := httpsig.NewSigner(algorithm, secret)
			if err != nil {
				return nil, nil, fmt.Errorf("httpsig: credential from %s: %w", origin, err)
			}
			cred.Signer = signer
		}
	default:
		if doc.PrivateKey == "" {
			return nil, nil, fmt.Errorf("httpsig: credential from %s sets no privateKey, which %s requires", origin, algorithm)
		}
		if doc.Secret != "" || doc.SecretBase64 != "" {
			return nil, nil, fmt.Errorf("httpsig: credential from %s sets a secret, which %s does not use", origin, algorithm)
		}
		if doc.Stage != nil {
			return nil, nil, fmt.Errorf("httpsig: credential from %s carries a derivation stage, which applies to hmac-sha256 only", origin)
		}
		key, err := parsePrivateKey(origin, []byte(doc.PrivateKey))
		if err != nil {
			return nil, nil, err
		}
		signer, err := httpsig.NewSigner(algorithm, key)
		if err != nil {
			return nil, nil, fmt.Errorf("httpsig: credential from %s: %w", origin, err)
		}
		cred.Signer = signer
	}

	for name := range doc.SignedHeaders {
		if !declaredHeaders[canonicalHeaderName(name)] {
			return nil, nil, fmt.Errorf("httpsig: credential from %s sets header %q, which is not declared as signed, so its value would travel uncovered",
				origin, name)
		}
	}
	for name := range declaredHeaders {
		if _, ok := lookupHeader(doc.SignedHeaders, name); !ok {
			return nil, nil, fmt.Errorf("httpsig: credential from %s sets no value for signed header %q", origin, name)
		}
	}
	for name, value := range doc.SignedHeaders {
		cred.SignedHeaders[name] = value
	}
	if doc.ExpirationTimestamp != nil {
		cred.NotAfter = doc.ExpirationTimestamp.Time
	}
	return cred, scoped, nil
}

// lookupHeader finds a header value case insensitively.
func lookupHeader(headers map[string]string, name string) (string, bool) {
	for k, v := range headers {
		if canonicalHeaderName(k) == canonicalHeaderName(name) {
			return v, true
		}
	}
	return "", false
}

// trimSecret removes the trailing newline an editor or a shell redirect leaves
// on a secret, which otherwise fails with no clue why.
func trimSecret(b []byte) []byte { return bytes.TrimRight(b, "\r\n") }

// Redaction.
//
// Material holds key material as plain strings, so a %v of anything containing
// one prints the secret. The redaction lives on the types that hold the material
// rather than on each type that might print one: rest.Config prints itself and is
// only one caller, and a type whose safety depends on every container remembering
// to sanitize it will eventually meet a container that forgot.
//
// The receivers are values, matching rest.TLSClientConfig, so the methods apply
// to both a Material and a *Material. Both verbs are covered because they take
// different paths through fmt: %v and %s reach String, %#v reaches GoString.

var (
	_ fmt.Stringer   = Material{}
	_ fmt.GoStringer = Material{}
	_ fmt.Stringer   = SigningCredential{}
	_ fmt.GoStringer = SigningCredential{}
	_ fmt.Stringer   = Credential{}
	_ fmt.GoStringer = Credential{}
	_ fmt.Stringer   = BoundCredential{}
	_ fmt.GoStringer = BoundCredential{}
)

// redacted is the placeholder rest.Config uses, kept identical so a reader who
// greps logs for it finds every kind of credential this client can hold.
const redacted = "--- REDACTED ---"

// GoString implements fmt.GoStringer and sanitizes the key material in a
// Material to prevent accidental leaking via logs.
func (m Material) GoString() string { return m.String() }

// String implements fmt.Stringer and sanitizes the key material in a Material.
// What survives is what identifies a credential without being able to sign with
// it: the key ID, which secret fields are set, the ladder position, the names of
// the covered headers, and the expiry.
func (m Material) String() string {
	fields := []string{fmt.Sprintf("KeyID: %q", m.KeyID)}
	// Name the fields that are set without printing them, so a credential with
	// the wrong encoding is still diagnosable from a log.
	for _, f := range []struct {
		name  string
		value string
	}{
		{"Secret", m.Secret},
		{"SecretBase64", m.SecretBase64},
		{"PrivateKey", m.PrivateKey},
	} {
		if f.value != "" {
			fields = append(fields, fmt.Sprintf("%s: %s", f.name, redacted))
		}
	}
	if m.Stage != nil {
		// A stage is a step name and scope values such as a cluster name or a
		// date. None of it is secret, and it is the first thing to check when a
		// derived key is rejected.
		fields = append(fields, fmt.Sprintf("Stage: %s", m.Stage))
	}
	if len(m.SignedHeaders) > 0 {
		fields = append(fields, fmt.Sprintf("SignedHeaders: %s", redactedHeaders(m.SignedHeaders)))
	}
	if m.ExpirationTimestamp != nil {
		fields = append(fields, fmt.Sprintf("ExpirationTimestamp: %s", m.ExpirationTimestamp.UTC().Format(time.RFC3339)))
	}
	return fmt.Sprintf("httpsig.Material{%s}", strings.Join(fields, ", "))
}

// GoString implements fmt.GoStringer and sanitizes the key material in a
// SigningCredential to prevent accidental leaking via logs.
func (c SigningCredential) GoString() string { return c.String() }

// String implements fmt.Stringer and sanitizes the key material in a
// SigningCredential. It is stated rather than inherited from the embedded
// Material so that the envelope, which is what a wrong-apiVersion error is
// about, does not disappear from the output.
func (c SigningCredential) String() string {
	return fmt.Sprintf("httpsig.SigningCredential{APIVersion: %q, Kind: %q, Material: %s}",
		c.APIVersion, c.Kind, c.Material)
}

// GoString implements fmt.GoStringer and sanitizes a Credential to prevent
// accidental leaking via logs.
func (c Credential) GoString() string { return c.String() }

// String implements fmt.Stringer and sanitizes a Credential. The Signer is an
// interface, so printing the struct prints whatever the implementation holds,
// which for a shared secret is the secret itself as a byte slice.
func (c Credential) String() string {
	signer := "<nil>"
	if c.Signer != nil {
		signer = fmt.Sprintf("%T", c.Signer)
	}
	notAfter := "<never>"
	if !c.NotAfter.IsZero() {
		notAfter = c.NotAfter.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("httpsig.Credential{KeyID: %q, Signer: %s, SignedHeaders: %s, NotAfter: %s}",
		c.KeyID, signer, redactedHeaders(c.SignedHeaders), notAfter)
}

// GoString implements fmt.GoStringer and sanitizes a BoundCredential to prevent
// accidental leaking via logs.
func (b BoundCredential) GoString() string { return b.String() }

// String implements fmt.Stringer and sanitizes a BoundCredential. The scoped key
// is reported as present rather than printed: it holds the material every rung
// was folded from, and the library type has no redaction of its own.
func (b BoundCredential) String() string {
	cred := "<nil>"
	if b.cred != nil {
		cred = b.cred.String()
	}
	derived := "<none>"
	if b.scoped != nil {
		derived = "<scoped key present>"
	}
	return fmt.Sprintf("httpsig.BoundCredential{Origin: %q, Credential: %s, Derivation: %s}",
		b.origin, cred, derived)
}

// redactedHeaders prints the names of covered headers and redacts their values.
// A covered header carries something like a session token, which is the reason
// the client refuses to send one it does not cover; the names come from
// configuration and are safe.
func redactedHeaders(headers map[string]string) string {
	if len(headers) == 0 {
		return "[]"
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for i, name := range names {
		names[i] = fmt.Sprintf("%s: %s", name, redacted)
	}
	return fmt.Sprintf("[%s]", strings.Join(names, ", "))
}
