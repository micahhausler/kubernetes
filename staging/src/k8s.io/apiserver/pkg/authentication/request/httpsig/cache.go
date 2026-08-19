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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"golang.org/x/sync/singleflight"

	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/request/httpsig/metrics"
)

const (
	// defaultMaxKeys bounds each cache. It is the bound the static key list's
	// nonce buckets used before nonces moved to a resolver, kept because it sizes
	// the same thing: how many distinct peers one API server serves at once.
	defaultMaxKeys = 1024

	// defaultCacheMaxAge caps how long a resolved key is reused when
	// configuration does not. It matches the default maximum signature age, so by
	// default a key is re-resolved on roughly the same cadence as the window a
	// signature is accepted in.
	defaultCacheMaxAge = DefaultMaxAge

	// defaultNegativeMaxAge is how long an unserved keyid is remembered when
	// configuration does not.
	//
	// Chosen rather than derived, and the tension it sits between is worth
	// stating: long enough that a peer retrying a keyid no resolver serves does
	// not turn into a lookup per request, short enough that a key just created is
	// usable before an operator concludes it did not work.
	defaultNegativeMaxAge = 10 * time.Second
)

// keyCache turns a resolver's answers into verifiers and remembers them.
//
// Every property here exists because the cache key is chosen by the peer. A
// keyid, an algorithm, and a relayed header value are all wire input, so the
// number of distinct entries this cache could be asked to hold is not bounded by
// anything in the cluster. Bounded size, a bounded negative entry lifetime, and
// collapsing concurrent duplicates are the three things that follow from that.
//
// This is the same cardinality argument that keeps nonce records at the resolver
// and that keeps the signing library's derived-key memo at one entry. What is
// deliberately not copied is the token authenticator's cache, which is unbounded
// and striped for lock contention rather than for size.
type keyCache struct {
	resolver KeyResolver

	// keys holds verifiers built from answers. Eviction costs one lookup and
	// never an authentication failure, which is what makes a bound safe here.
	keys *cache.LRUExpireCache

	// absent holds keyids the resolver said it does not serve. It is separate
	// from keys so that a flood of unknown keyids cannot evict working keys.
	absent *cache.LRUExpireCache

	// inflight collapses concurrent lookups for one cache key, so a burst of
	// requests bearing the same unknown keyid costs one call rather than one per
	// request.
	inflight singleflight.Group

	maxAge         time.Duration
	negativeMaxAge time.Duration
}

func newKeyCache(resolver KeyResolver, c *apiserver.HTTPSignatureCache) *keyCache {
	maxKeys := defaultMaxKeys
	maxAge := defaultCacheMaxAge
	negativeMaxAge := defaultNegativeMaxAge
	if c != nil {
		if c.MaxKeys != nil {
			maxKeys = int(*c.MaxKeys)
		}
		if c.MaxAge != nil {
			maxAge = c.MaxAge.Duration
		}
		if c.NegativeMaxAge != nil {
			negativeMaxAge = c.NegativeMaxAge.Duration
		}
	}
	return &keyCache{
		resolver:       resolver,
		keys:           cache.NewLRUExpireCache(maxKeys),
		absent:         cache.NewLRUExpireCache(maxKeys),
		maxAge:         maxAge,
		negativeMaxAge: negativeMaxAge,
	}
}

// get returns the verifier for a request's keyid, from cache when it can.
func (c *keyCache) get(ctx context.Context, req ResolveRequest) (*verifierKey, error) {
	name := c.resolver.Name()
	entryKey := cacheKey(req)

	if _, absent := c.absent.Get(entryKey); absent {
		metrics.RecordKeyCacheLookup(name, metrics.CacheResultNegativeHit)
		return nil, ErrKeyNotFound
	}
	if cached, ok := c.keys.Get(entryKey); ok {
		metrics.RecordKeyCacheLookup(name, metrics.CacheResultHit)
		return cached.(*verifierKey), nil
	}
	metrics.RecordKeyCacheLookup(name, metrics.CacheResultMiss)

	// The shared result is the compiled verifier, so concurrent callers for one
	// keyid also share the parsing and derivation work, not just the call.
	result, err, _ := c.inflight.Do(entryKey, func() (any, error) {
		return c.resolveAndStore(ctx, entryKey, req)
	})
	if err != nil {
		return nil, err
	}
	return result.(*verifierKey), nil
}

func (c *keyCache) resolveAndStore(ctx context.Context, entryKey string, req ResolveRequest) (*verifierKey, error) {
	name := c.resolver.Name()
	resolved, err := c.resolver.ResolveKey(ctx, req)
	switch {
	case errors.Is(err, ErrKeyNotFound):
		// Remembered, because a peer that sends one unknown keyid usually sends it
		// again. A resolver failure is deliberately not remembered: it may resolve
		// on the next attempt, and caching it would extend an outage past its end.
		c.absent.Add(entryKey, struct{}{}, c.negativeMaxAge)
		return nil, err
	case err != nil:
		return nil, err
	}

	key, err := compile(name, req.KeyID, resolved)
	if err != nil {
		// A malformed answer is the resolver's fault and will keep being wrong
		// until it is fixed, but it is not the same fact as "no such key" and is
		// not recorded as one: doing so would make a resolver bug present itself
		// as a missing key and send the next resolver an unnecessary lookup.
		return nil, err
	}

	ttl := c.maxAge
	if resolved.CacheFor <= 0 {
		// The resolver said not to cache. That is the correct answer when its
		// answer depended on a relayed value that rotates, so it is honored rather
		// than replaced with a floor.
		return key, nil
	}
	if resolved.CacheFor < ttl {
		ttl = resolved.CacheFor
	}
	c.keys.Add(entryKey, key, ttl)
	return key, nil
}

// cacheKey identifies one resolvable question.
//
// It covers the relayed header values, not just the keyid. Keying on the keyid
// alone would serve a cached answer for a rotated session token, which is the
// case relayed headers exist for, so the rotation would be silently ignored.
//
// Values are hashed rather than concatenated because a relayed value can be a
// secret and this string is held in memory for the life of the entry, and because
// concatenating peer-chosen strings makes two distinct questions collide when one
// contains the separator.
func cacheKey(req ResolveRequest) string {
	if len(req.RelayedHeaders) == 0 {
		return req.KeyID + "\x00" + req.Algorithm
	}
	names := make([]string, 0, len(req.RelayedHeaders))
	for name := range req.RelayedHeaders {
		names = append(names, name)
	}
	sort.Strings(names)

	h := sha256.New()
	writeLengthPrefixed(h, req.KeyID)
	writeLengthPrefixed(h, req.Algorithm)
	for _, name := range names {
		writeLengthPrefixed(h, name)
		writeLengthPrefixed(h, req.RelayedHeaders[name])
	}
	return base64.RawStdEncoding.EncodeToString(h.Sum(nil))
}

// writeLengthPrefixed feeds a string to a hash so that no two different field
// sequences produce the same digest input.
func writeLengthPrefixed(h io.Writer, s string) {
	fmt.Fprintf(h, "%d:%s", len(s), s)
}
