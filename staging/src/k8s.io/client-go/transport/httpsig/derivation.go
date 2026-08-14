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
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/micahhausler/httpsig/keyscope"
)

// A Stage is one party's position on a key derivation ladder, as it appears in a
// SigningCredential or a server key entry. It travels with the key material it
// describes, because the bytes of derived material cannot say what was folded
// into them.
//
// The key's public name is deliberately not part of it. The credential already
// carries a key ID, and a second place to write the name is a second place for
// the two to disagree.
type Stage struct {
	// From names the ladder step whose output the key material is. Empty means
	// the material is the root secret and the whole ladder is folded at signing
	// time.
	// +optional
	From string `json:"from,omitempty"`

	// Scope holds values for the ladder's scope steps, and assertions for the
	// date steps at or before From. A value for a step at or before From is an
	// assertion about what is already folded into the material; a value for a
	// scope step after From is an input still to be folded. It must cover
	// exactly those; a missing value and an unexpected one are both errors.
	// +optional
	Scope map[string]string `json:"scope,omitempty"`
}

// KeyscopeStage converts a serialized stage and a key name into the signing
// library's form, which keeps the name and the position together. It is exported
// because a verifier configures its keys the same way a client does, and the two
// sides must convert identically.
func KeyscopeStage(name string, stage *Stage) keyscope.Stage {
	out := keyscope.Stage{Name: name}
	if stage != nil {
		out.From = stage.From
		out.Scope = stage.Scope
	}
	return out
}

// DerivationFrom converts a key derivation ladder from any of the Kubernetes API
// types that declare one into the signing library's form, and returns the digest
// two parties compare.
//
// The argument is any type whose JSON encoding matches the ladder schema: the
// kubeconfig's, the exec credential protocol's, or the API server
// configuration's. All of them declare the same field names, so one conversion
// serves them all rather than each API group growing its own. Passing the
// encoding through the library's unmarshaler is deliberate: it validates the
// kind, the hash, unique step names, one input source per step, date formats
// from its closed set, and the separator bans that keep a step value from
// splitting a key ID. Nothing here reimplements any of that.
//
// A ladder describes a derivation for a whole deployment, and step names are
// arbitrary labels chosen by whoever writes it:
//
//	kind: hmac-ladder
//	hash: sha-256
//	secretPrefix: "EXAMPLE1"
//	steps:
//	- {name: day,        date: YYYYMMDD}
//	- {name: cell,       scope: true}
//	- {name: purpose,    scope: true}
//	- {name: terminator, literal: example1_request}
//
// Nothing treats a name, a prefix, or a literal as meaningful, so a deployment
// scopes by whatever dimensions it has. The shape is the one AWS Signature
// Version 4 uses for its signing keys, so a ladder can describe that derivation
// exactly and material vended by existing infrastructure derives correctly. That
// is interoperability with a published scheme, not support for one provider.
//
// The caller must not pass a nil ladder.
func DerivationFrom(ladder any) (keyscope.Derivation, string, error) {
	data, err := json.Marshal(ladder)
	if err != nil {
		return keyscope.Derivation{}, "", fmt.Errorf("httpsig: encoding key derivation: %w", err)
	}
	var d keyscope.Derivation
	if err := json.Unmarshal(data, &d); err != nil {
		return keyscope.Derivation{}, "", fmt.Errorf("httpsig: key derivation: %w", err)
	}
	return d, CanonicalDigest(d), nil
}

// CanonicalDigest fingerprints a ladder so the parties that derive through it can
// tell whether they agree. Both sides log theirs when they load it, because a
// ladder that disagrees otherwise fails as a bare signature mismatch with
// nothing in the error to say why.
//
// The digest covers the parsed ladder rather than whatever bytes it was written
// as, so a ladder stated in a kubeconfig and the same ladder in an API server's
// configuration produce the same value. Digesting the source bytes would report
// drift for a difference in indentation or field order, and a diagnostic that
// cries wolf is one nobody reads. It follows that the digest is not a checksum
// of any file, and two parties can only compare digests with each other.
func CanonicalDigest(d keyscope.Derivation) string {
	// Deterministic by construction: the library's type marshals its fields in
	// declaration order and holds no maps.
	data, err := json.Marshal(d)
	if err != nil {
		// Unreachable: the type is a struct of strings, bools, and a slice.
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}
