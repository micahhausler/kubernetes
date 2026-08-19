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
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/micahhausler/httpsig/keyscope"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	externalhttpsig "k8s.io/externalhttpsig/apis/v1alpha1"
	"k8s.io/klog/v2"
)

// resolver serves the three RPCs from a key file.
type resolver struct {
	externalhttpsig.UnimplementedExternalHTTPSignatureServiceServer

	path string

	mu   sync.Mutex
	keys *keySet
	// stamp is what the loaded file looked like on disk, for noticing a change.
	stamp fileStamp

	nonces *nonceStore
}

// fileStamp is the cheap change check: modification time and size. It is not a hash,
// because a hash means reading the file on every request to decide whether to read
// the file.
//
// It can miss a change made within the filesystem's timestamp granularity that also
// preserves the size. For a demo that is the right trade; a resolver holding real
// keys should be told to reload rather than guess.
type fileStamp struct {
	modTime time.Time
	size    int64
}

func stampOf(path string) (fileStamp, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{modTime: info.ModTime(), size: info.Size()}, nil
}

func newResolver(path string, maxNonces int) (*resolver, error) {
	r := &resolver{path: path, nonces: newNonceStore(maxNonces)}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// reload reads the key file unconditionally.
func (r *resolver) reload() error {
	stamp, err := stampOf(r.path)
	if err != nil {
		return err
	}
	keys, err := loadKeys(r.path)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys, r.stamp = keys, stamp
	klog.InfoS("Loaded key file", "path", r.path, "keyIDs", len(keys.byKeyID), "ladder", keys.derivation != nil)
	return nil
}

// current returns the loaded key set, reloading first if the file changed.
//
// Checked per request rather than on a timer, so editing the file has an effect an
// operator can watch: the delay they then see is the API server's cache duration,
// which is the revocation window and is a number this file sets. A timer here would
// add a second, invisible delay on top of it.
//
// A reload that fails keeps the keys already loaded. A key file being briefly
// unreadable or half-written should not log out every client.
func (r *resolver) current() *keySet {
	stamp, err := stampOf(r.path)
	if err != nil {
		klog.ErrorS(err, "Checking the key file; serving the keys already loaded", "path", r.path)
		return r.loaded()
	}
	r.mu.Lock()
	unchanged := stamp == r.stamp
	r.mu.Unlock()
	if unchanged {
		return r.loaded()
	}
	if err := r.reload(); err != nil {
		klog.ErrorS(err, "Reloading the key file; serving the keys already loaded", "path", r.path)
	}
	return r.loaded()
}

func (r *resolver) loaded() *keySet {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.keys
}

func (r *resolver) Metadata(_ context.Context, _ *externalhttpsig.MetadataRequest) (*externalhttpsig.MetadataResponse, error) {
	keys := r.current()
	resp := &externalhttpsig.MetadataResponse{
		MaxSignatureAgeSeconds: int64(keys.maxSignatureAge.Duration.Seconds()),
		RefreshHintSeconds:     int64(keys.refreshHint.Duration.Seconds()),
	}
	if keys.derivation != nil {
		resp.KeyDerivation = protoLadder(keys.derivation)
	}
	return resp, nil
}

func (r *resolver) ResolveKey(_ context.Context, req *externalhttpsig.ResolveKeyRequest) (*externalhttpsig.ResolveKeyResponse, error) {
	keys := r.current()

	candidates, name := keys.lookup(req.GetKeyId())
	if len(candidates) == 0 {
		// Not-found is a status rather than an answer with fields. A response that
		// described the absence of a key would be a shape where one mishandled field
		// authenticates a request that should have been rejected.
		return nil, status.Errorf(codes.NotFound, "no key named %q", name)
	}

	// The algorithm in the request is a claim and is used only to choose among keys
	// sharing a name. The algorithm in the response is this resolver's own, and it is
	// what the API server builds its verifier from.
	var chosen *loadedKey
	var rejected []string
	for _, key := range candidates {
		if req.GetAlgorithm() != "" && key.algorithm != req.GetAlgorithm() {
			rejected = append(rejected, fmt.Sprintf("%s: algorithm is %s", key.keyID, key.algorithm))
			continue
		}
		if err := key.headersMatch(req.GetRelayedHeaders()); err != nil {
			rejected = append(rejected, fmt.Sprintf("%s: %v", key.keyID, err))
			continue
		}
		chosen = key
		break
	}
	if chosen == nil {
		// Logged with the reason and answered without it. The caller learns that no
		// key matched, which it already knew it was asking about; which of this
		// resolver's keys nearly matched, and why, is this operator's business.
		klog.V(2).InfoS("No key matched", "keyID", req.GetKeyId(), "claimedAlgorithm", req.GetAlgorithm(), "rejected", rejected)
		return nil, status.Errorf(codes.NotFound, "no key named %q matched this request", name)
	}

	resp := &externalhttpsig.ResolveKeyResponse{
		Algorithm:              chosen.algorithm,
		User:                   protoUser(chosen.user),
		CacheTtlSeconds:        int64(chosen.cacheTTL.Duration.Seconds()),
		MaxSignatureAgeSeconds: int64(chosen.maxSignatureAge.Duration.Seconds()),
	}
	switch {
	case chosen.publicKeyDER != nil:
		resp.Material = &externalhttpsig.ResolveKeyResponse_PublicKey{PublicKey: chosen.publicKeyDER}
	case chosen.stage != nil:
		resp.Material = &externalhttpsig.ResolveKeyResponse_DerivedKey{
			DerivedKey: &externalhttpsig.DerivedKey{
				Key:   chosen.secret,
				From:  chosen.stage.From,
				Scope: chosen.stage.Scope,
			},
		}
	default:
		resp.Material = &externalhttpsig.ResolveKeyResponse_Secret{Secret: chosen.secret}
	}

	// V(2) rather than V(4). This fires once per key per cache period, not once per
	// request, so the volume is low and it is the single most useful line in this
	// log: it says which key answered, as whom, and for how long the answer stands.
	klog.V(2).InfoS("Resolved key", "keyID", req.GetKeyId(), "algorithm", chosen.algorithm,
		"username", chosen.user.Username, "cacheTTL", chosen.cacheTTL.Duration)
	return resp, nil
}

func (r *resolver) ConsumeNonce(_ context.Context, req *externalhttpsig.ConsumeNonceRequest) (*externalhttpsig.ConsumeNonceResponse, error) {
	if req.GetKeyId() == "" || req.GetNonce() == "" {
		return nil, status.Error(codes.InvalidArgument, "keyID and nonce are both required")
	}
	expires := req.GetExpiresAt().AsTime()
	if req.GetExpiresAt() == nil || expires.IsZero() {
		// Without it there is no bound on how long to remember the nonce, and a store
		// that never forgets is a store that eventually stops accepting.
		return nil, status.Error(codes.InvalidArgument, "expiresAt is required: it is when this nonce may be forgotten")
	}

	accepted, reason := r.nonces.consume(req.GetKeyId(), req.GetNonce(), expires)
	if !accepted {
		klog.V(2).InfoS("Rejected nonce", "keyID", req.GetKeyId(), "reason", reason)
	}
	return &externalhttpsig.ConsumeNonceResponse{Accepted: accepted, Reason: reason}, nil
}

// lookup returns the keys that could serve a key ID, and the name it resolved to.
//
// The whole key ID first, then the name before its first slash. A derived key's key ID
// carries its claimed scope after the name, and decomposing it is this resolver's job
// because this resolver is the party that holds the ladder: the API server hands the
// key ID over whole and does not parse it.
//
// With a ladder configured the library's own parser does the split, which validates
// the segment count and the literal steps. Without one, a plain cut is all the
// structure there is to use.
func (s *keySet) lookup(keyID string) ([]*loadedKey, string) {
	if keys, ok := s.byKeyID[keyID]; ok {
		return keys, keyID
	}
	name := keyID
	if s.derivation != nil {
		if claim, err := keyscope.ParseKeyID(libraryLadder(s.derivation), keyID); err == nil {
			name = claim.Name()
		} else {
			klog.V(4).InfoS("Key ID does not parse against this resolver's ladder; falling back to the name before the first slash",
				"keyID", keyID, "err", err)
			name, _, _ = strings.Cut(keyID, "/")
		}
	} else {
		name, _, _ = strings.Cut(keyID, "/")
	}
	return s.byKeyID[name], name
}

// headersMatch reports whether the relayed values satisfy this key's requirements.
func (k *loadedKey) headersMatch(relayed map[string]string) error {
	for name, want := range k.requiredHeaders {
		got, present := relayed[name]
		if !present {
			return fmt.Errorf("requires the relayed header %s, which was not sent", name)
		}
		if got != want {
			// The expected value is not in the error. This string reaches the API
			// server's log, and a mismatch that printed the expected value would put a
			// session token there.
			return fmt.Errorf("the relayed header %s does not have the required value", name)
		}
	}
	return nil
}

// nonceStore records nonces per key, atomically, until they expire.
type nonceStore struct {
	// max bounds the total records. Nonce values are chosen by whoever holds a key,
	// so the count is not bounded by anything this process controls.
	max int

	mu      sync.Mutex
	perKey  map[string]map[string]time.Time
	records int
}

func newNonceStore(max int) *nonceStore {
	return &nonceStore{max: max, perKey: map[string]map[string]time.Time{}}
}

// consume records a nonce and reports whether it was new.
//
// The check and the record happen under one lock, which is the whole point of this
// being an RPC rather than a per-API-server cache: two concurrent calls for the same
// key and nonce cannot both be accepted.
func (s *nonceStore) consume(keyID, nonce string, expires time.Time) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	bucket := s.perKey[keyID]
	if bucket != nil {
		if _, seen := bucket[nonce]; seen {
			return false, "this nonce has already been used for this key"
		}
	}

	if s.records >= s.max {
		s.sweep(now)
	}
	if s.records >= s.max {
		// Rejecting rather than evicting. Evicting the oldest record would let the
		// request it belonged to be replayed, which is the one outcome this store
		// exists to prevent, so a full store refuses instead. It fails closed, and
		// under load that is visible as rejected requests rather than as silent
		// replay.
		return false, fmt.Sprintf("this resolver is holding its limit of %d unexpired nonces and cannot record another", s.max)
	}

	if bucket == nil {
		bucket = map[string]time.Time{}
		s.perKey[keyID] = bucket
	}
	bucket[nonce] = expires
	s.records++
	return true, ""
}

// sweep drops records whose signatures can no longer be accepted. Called on pressure
// rather than on a timer, so an idle resolver does no work and a busy one pays for
// the space it is using.
func (s *nonceStore) sweep(now time.Time) {
	for keyID, bucket := range s.perKey {
		for nonce, expires := range bucket {
			if now.After(expires) {
				delete(bucket, nonce)
				s.records--
			}
		}
		if len(bucket) == 0 {
			delete(s.perKey, keyID)
		}
	}
}

func (s *nonceStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records
}

func protoUser(u User) *externalhttpsig.UserInfo {
	out := &externalhttpsig.UserInfo{Username: u.Username, Uid: u.UID, Groups: u.Groups}
	if len(u.Extra) > 0 {
		out.Extra = make(map[string]*externalhttpsig.ExtraValue, len(u.Extra))
		for k, v := range u.Extra {
			out.Extra[k] = &externalhttpsig.ExtraValue{Items: v}
		}
	}
	return out
}

func protoLadder(l *KeyDerivation) *externalhttpsig.KeyDerivation {
	out := &externalhttpsig.KeyDerivation{Kind: l.Kind, Hash: l.Hash, SecretPrefix: l.SecretPrefix}
	for _, step := range l.Steps {
		out.Steps = append(out.Steps, &externalhttpsig.KeyDerivationStep{
			Name: step.Name, Literal: step.Literal, Scope: step.Scope, Date: step.Date,
		})
	}
	return out
}

// libraryLadder converts the file's ladder into the signing library's form, for
// parsing a key ID. It is field by field for the same reason the API server's
// conversion is: a JSON round trip would depend on two independent sets of field
// tags agreeing, and a mismatch would drop a derivation input silently.
func libraryLadder(l *KeyDerivation) keyscope.Derivation {
	out := keyscope.Derivation{Kind: l.Kind, Hash: l.Hash, SecretPrefix: l.SecretPrefix}
	for _, step := range l.Steps {
		out.Steps = append(out.Steps, keyscope.Step{
			Name: step.Name, Literal: step.Literal, Scope: step.Scope, Date: step.Date,
		})
	}
	return out
}
