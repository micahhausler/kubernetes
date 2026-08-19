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

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// knownAlgorithms are the algorithm names this resolver accepts as the outer map
// key, from the IANA "HTTP Signature Algorithms" registry. The set is closed here
// rather than passed through, so a typo in a file fails at load with a list of what
// was meant instead of at request time as a signature that does not verify.
var knownAlgorithms = map[string]bool{
	"ed25519":           true,
	"ecdsa-p256-sha256": true,
	"ecdsa-p384-sha384": true,
	"rsa-pss-sha512":    true,
	"rsa-v1_5-sha256":   true,
	hmacAlgorithm:       true,
}

const hmacAlgorithm = "hmac-sha256"

// A File is a resolver key file.
//
// Keys are nested by algorithm and then by key ID. Nesting rather than a flat list
// with an algorithm field means a key cannot be written without one, and the
// algorithm this resolver states is the value the API server builds its verifier
// from: the signature's own alg parameter is checked against it, which is what
// closes algorithm confusion. A file that could omit it would be a file that could
// leave that check unarmed.
type File struct {
	// KeyDerivation is the HMAC ladder this file's staged keys sit on, returned in
	// Metadata. Every party that derives states the same ladder, so this and each
	// client's copy have to agree. Required if any key sets stage.
	//
	// It is not a secret and it is not specific to one party.
	KeyDerivation *KeyDerivation `json:"keyDerivation,omitempty"`

	// MaxSignatureAge narrows how old a signature verified by any key in this file
	// may be. The API server applies the smaller of this and its own configured
	// maximum, so it can only tighten the window. Unset states no opinion.
	MaxSignatureAge *metav1.Duration `json:"maxSignatureAge,omitempty"`

	// RefreshHint is how often the API server should call Metadata again. That call
	// is also its health check for this resolver, so this sets how quickly an
	// unhealthy resolver is noticed. Unset lets the API server choose.
	RefreshHint *metav1.Duration `json:"refreshHint,omitempty"`

	// Keys is algorithm, then key ID, then the key.
	Keys map[string]map[string]Key `json:"keys"`
}

// A Key is one key and the identity it authenticates.
//
// Exactly one of PublicKey, Secret, or SecretBase64 carries the material, and which
// one is valid is determined by the algorithm it sits under.
type Key struct {
	// PublicKey is a PEM-encoded public key, for the asymmetric algorithms.
	//
	// PEM here and DER on the wire is deliberate. This file is written and read by
	// people, and PEM is what openssl and ssh-keygen produce. The protocol takes
	// PKIX DER, because a PEM block type is a second statement of the key kind and a
	// second thing to disagree with the algorithm. The conversion belongs on this
	// side of that boundary.
	PublicKey string `json:"publicKey,omitempty"`

	// Secret is a shared secret for hmac-sha256, as a UTF-8 string.
	Secret string `json:"secret,omitempty"`

	// SecretBase64 is a shared secret as base64, for bytes that are not printable.
	// A derived rung is raw hash output, so it is the only safe encoding for one.
	SecretBase64 string `json:"secretBase64,omitempty"`

	// Stage is this material's position on the ladder, set when the material is a
	// rung rather than a whole secret. It travels with the material because the
	// bytes of a rung cannot say what was folded into them.
	Stage *Stage `json:"stage,omitempty"`

	// User is the identity a request signed by this key authenticates as.
	User User `json:"user"`

	// RequiredHeaders makes this key resolve only when the API server relays these
	// header values, matched exactly and case-insensitively by name.
	//
	// This is how a resolver decides identity from something other than the key ID,
	// such as a session token. The API server relays only the headers its own
	// configuration names, and refuses a request carrying one the signature does not
	// cover, so a value that gets here was covered by the signature. Covered is not
	// verified: at the time of the lookup the signature has not been checked, so
	// treat this as narrowing which key is offered and never as proof of anything.
	RequiredHeaders map[string]string `json:"requiredHeaders,omitempty"`

	// CacheTTL is how long the API server may reuse this answer, as a duration string
	// such as "5m". Omitting it, or writing "0s", means do not cache, which is the
	// right answer for a key whose identity depends on a RequiredHeaders value that
	// rotates. A bare 0 is not valid: this is a duration, and durations are strings.
	//
	// Omission meaning no caching is deliberate rather than convenient. A key file
	// that forgets this field costs a lookup per request, which is slow and correct;
	// the alternative default would be a revocation window nobody chose.
	//
	// A cached key stays usable after this resolver stops vending it, so this is the
	// revocation window. The API server caps it by its own configured maximum.
	CacheTTL *metav1.Duration `json:"cacheTTL,omitempty"`

	// MaxSignatureAge narrows the accepted signature age for this one key, on top of
	// the file-wide value. Unset states no opinion.
	MaxSignatureAge *metav1.Duration `json:"maxSignatureAge,omitempty"`
}

// A Stage is a position on a key derivation ladder.
type Stage struct {
	// From names the ladder step whose output the material is. Empty means the
	// material is the root secret and the API server folds the whole ladder.
	From string `json:"from,omitempty"`

	// Scope holds values for the ladder's scope steps and assertions for the date
	// steps at or before From, keyed by step name. It must cover exactly those.
	Scope map[string]string `json:"scope,omitempty"`
}

// A User is an identity.
type User struct {
	Username string              `json:"username"`
	UID      string              `json:"uid,omitempty"`
	Groups   []string            `json:"groups,omitempty"`
	Extra    map[string][]string `json:"extra,omitempty"`
}

// KeyDerivation is an HMAC ladder. The field names match the ones a client states
// in its kubeconfig, so one document describes both sides.
type KeyDerivation struct {
	Kind         string              `json:"kind"`
	Hash         string              `json:"hash,omitempty"`
	SecretPrefix string              `json:"secretPrefix,omitempty"`
	Steps        []KeyDerivationStep `json:"steps"`
}

// KeyDerivationStep is one rung. Exactly one of Literal, Scope, or Date supplies the
// step's input.
type KeyDerivationStep struct {
	Name    string `json:"name"`
	Literal string `json:"literal,omitempty"`
	Scope   bool   `json:"scope,omitempty"`
	Date    string `json:"date,omitempty"`
}

// A loadedKey is a Key with its material decoded, so a malformed key fails at load
// rather than on the request that first needs it.
type loadedKey struct {
	algorithm string
	keyID     string

	// publicKeyDER is set for the asymmetric algorithms, already in the encoding the
	// protocol takes.
	publicKeyDER []byte
	// secret is set for hmac-sha256, whether a whole secret or a rung.
	secret []byte

	stage           *Stage
	user            User
	requiredHeaders map[string]string
	cacheTTL        metav1.Duration
	maxSignatureAge metav1.Duration
}

// A keySet is a loaded key file, ready to answer with.
type keySet struct {
	derivation      *KeyDerivation
	maxSignatureAge metav1.Duration
	refreshHint     metav1.Duration

	// byKeyID is keyed on the key ID as written. A derived key's key ID on the wire
	// carries its claimed scope after the name, and resolving that is this
	// resolver's job, so lookup falls back to the name.
	byKeyID map[string][]*loadedKey
}

// loadKeys reads and validates a key file.
//
// Everything that can be wrong is checked here rather than per request. A key file
// is written by a person and read by a machine on the authentication path; the
// person should hear about a mistake when they make it.
func loadKeys(path string) (*keySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file File
	// Strict, because a misspelled field would otherwise be a key that silently is not
	// what it says: a stray publicKeyy would leave the key with no material and the
	// error would arrive as a shape complaint rather than a typo.
	//
	// One class it cannot catch. encoding/json matches field names
	// case-insensitively, so publickey and PUBLICKEY both bind to publicKey and no
	// strictness setting changes that. A misspelling that differs only in case is
	// accepted, and this is the only warning of it.
	if err := yaml.UnmarshalStrict(data, &file); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	set := &keySet{
		derivation: file.KeyDerivation,
		byKeyID:    map[string][]*loadedKey{},
	}
	if file.MaxSignatureAge != nil {
		set.maxSignatureAge = *file.MaxSignatureAge
	}
	if file.RefreshHint != nil {
		set.refreshHint = *file.RefreshHint
	}

	if len(file.Keys) == 0 {
		return nil, fmt.Errorf("%s holds no keys, so this resolver would answer not-found for everything", path)
	}

	// Sorted so an error names the same key every run, and so the log of what was
	// loaded is stable and diffable across reloads.
	for _, algorithm := range sortedKeys(file.Keys) {
		if !knownAlgorithms[algorithm] {
			return nil, fmt.Errorf("%s: unknown algorithm %q (want one of %s)", path, algorithm, strings.Join(sortedSet(knownAlgorithms), ", "))
		}
		for _, keyID := range sortedKeys(file.Keys[algorithm]) {
			key := file.Keys[algorithm][keyID]
			loaded, err := loadKey(algorithm, keyID, key, file.KeyDerivation)
			if err != nil {
				return nil, fmt.Errorf("%s: keys.%s.%s: %w", path, algorithm, keyID, err)
			}
			set.byKeyID[keyID] = append(set.byKeyID[keyID], loaded)
		}
	}
	return set, nil
}

func loadKey(algorithm, keyID string, key Key, ladder *KeyDerivation) (*loadedKey, error) {
	if keyID == "" {
		return nil, fmt.Errorf("empty key ID")
	}
	if err := validateUser(key.User); err != nil {
		return nil, err
	}

	out := &loadedKey{
		algorithm:       algorithm,
		keyID:           keyID,
		stage:           key.Stage,
		user:            key.User,
		requiredHeaders: lowercaseKeys(key.RequiredHeaders),
	}
	if key.CacheTTL != nil {
		out.cacheTTL = *key.CacheTTL
	}
	if key.MaxSignatureAge != nil {
		out.maxSignatureAge = *key.MaxSignatureAge
	}

	forms := 0
	for _, set := range []bool{key.PublicKey != "", key.Secret != "", key.SecretBase64 != ""} {
		if set {
			forms++
		}
	}
	if forms != 1 {
		return nil, fmt.Errorf("set exactly one of publicKey, secret, or secretBase64, not %d", forms)
	}

	if algorithm == hmacAlgorithm {
		if key.PublicKey != "" {
			return nil, fmt.Errorf("%s verifies with a shared secret, so use secret or secretBase64 rather than publicKey", algorithm)
		}
		switch {
		case key.Secret != "":
			out.secret = []byte(key.Secret)
		default:
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key.SecretBase64))
			if err != nil {
				return nil, fmt.Errorf("decoding secretBase64: %w", err)
			}
			out.secret = decoded
		}
		if key.Stage != nil && ladder == nil {
			return nil, fmt.Errorf("stage names a position on a ladder, so it requires a top-level keyDerivation")
		}
		if key.Stage != nil && key.Secret != "" && key.Stage.From != "" {
			// A rung is raw hash output. Read as a UTF-8 string it would be mangled,
			// and the failure would arrive as a signature that does not verify.
			return nil, fmt.Errorf("a rung is raw bytes, so use secretBase64 rather than secret when stage.from is set")
		}
		return out, nil
	}

	if key.PublicKey == "" {
		return nil, fmt.Errorf("%s verifies with a public key, so use publicKey rather than a secret", algorithm)
	}
	if key.Stage != nil {
		return nil, fmt.Errorf("stage applies to %s only; an asymmetric key is not derived", hmacAlgorithm)
	}
	der, err := publicKeyDER(key.PublicKey)
	if err != nil {
		return nil, err
	}
	out.publicKeyDER = der
	return out, nil
}

// validateUser rejects an identity the API server would refuse anyway.
//
// It is checked twice on purpose, and the two checks are not the same check. The API
// server must reject a "system:" name because this resolver is across a trust
// boundary from it and whoever holds this socket could otherwise mint an identity the
// cluster's authorization rules are written around. Rejecting it here as well is a
// courtesy: it fails at the file, naming the key, rather than as a 401 whose reason
// is in a server log.
func validateUser(u User) error {
	if u.Username == "" {
		return fmt.Errorf("user.username is required")
	}
	if strings.HasPrefix(u.Username, "system:") {
		return fmt.Errorf("user.username %q begins with system:, which is reserved for identities Kubernetes issues; the API server rejects it regardless of what this file says", u.Username)
	}
	for _, group := range u.Groups {
		if group == "" {
			return fmt.Errorf("user.groups holds an empty name")
		}
		if strings.HasPrefix(group, "system:") {
			return fmt.Errorf("user.groups holds %q, which begins with system:, reserved for groups Kubernetes issues", group)
		}
	}
	return nil
}

// publicKeyDER converts a PEM public key to the PKIX DER the protocol takes, and
// checks it is a key type the API server can verify with.
//
// Both PEM block types openssl emits are accepted. The parse is not just a format
// conversion: a key that cannot be parsed here would otherwise reach the API server
// as bytes it rejects per request.
func publicKeyDER(pemText string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("publicKey holds no PEM block")
	}
	var pub any
	switch block.Type {
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing publicKey: %w", err)
		}
		pub = parsed
	case "RSA PUBLIC KEY":
		parsed, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing publicKey: %w", err)
		}
		pub = parsed
	default:
		return nil, fmt.Errorf("publicKey holds an unsupported PEM block %q", block.Type)
	}
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
	default:
		return nil, fmt.Errorf("publicKey holds an unsupported key type %T", pub)
	}
	// Re-marshaled rather than passing block.Bytes through, so a PKCS#1 key becomes
	// PKIX and every answer leaves here in one encoding.
	return x509.MarshalPKIXPublicKey(pub)
}

func lowercaseKeys(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[strings.ToLower(k)] = v
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedSet(m map[string]bool) []string {
	return sortedKeys(m)
}
