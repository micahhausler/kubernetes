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
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/micahhausler/httpsig/keyscope"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apiserver/pkg/authentication/request/httpsig/metrics"
	"k8s.io/apiserver/pkg/authentication/user"
	externalhttpsig "k8s.io/externalhttpsig/apis/v1alpha1"
	"k8s.io/klog/v2"
	kmsutil "k8s.io/kms/pkg/util"
)

const (
	// callTimeout bounds one resolver call. A key lookup sits on the
	// authentication path of a request the client is waiting on, so this is
	// deliberately short: a resolver that is slow should present as a failed
	// request rather than as an API server that hangs.
	callTimeout = 5 * time.Second

	// defaultMetadataRefresh is how often Metadata is polled when the resolver
	// states no hint of its own. The same call is the health probe, so this also
	// sets how quickly an unhealthy resolver is noticed.
	defaultMetadataRefresh = 30 * time.Second

	// metadataFailureRetry is how soon Metadata is retried after a failure,
	// regardless of the refresh hint. Keys already cached keep working, so the
	// resolver is degraded rather than down and a short retry is what shortens
	// that state.
	metadataFailureRetry = 10 * time.Second
)

// remote is a KeyResolver backed by a resolver process on a local socket.
//
// The connection carries no TLS and the peer is not authenticated. Access to the
// socket is the whole trust boundary, which is the same model the KMS provider and
// the external JWT signer use, and it is why the endpoint's permissions decide who
// can vend an identity to this cluster.
type remote struct {
	name        string
	client      externalhttpsig.ExternalHTTPSignatureServiceClient
	apiServerID string

	// meta holds the resolver's last successful Metadata answer and the error from
	// the last attempt. It is swapped rather than locked because it is read on the
	// authentication path of every uncached key.
	meta atomic.Pointer[resolverMetadata]
}

// resolverMetadata is what a resolver states about itself, plus the outcome of the
// most recent attempt to ask.
type resolverMetadata struct {
	// derivation is the ladder symmetric material is derived through, and ok says
	// whether the resolver stated one at all.
	derivation keyscope.Derivation
	hasLadder  bool

	// maxAge is the resolver's narrowing of signature age, or zero for none.
	maxAge time.Duration

	// refresh is how often the resolver asked to be polled, or zero to use this
	// server's own interval.
	refresh time.Duration

	// err is the last attempt's error, or nil. A non-nil err with a ladder already
	// loaded is a degraded resolver: cached keys still verify, new ones do not
	// resolve, and the health check reports it.
	err error
}

var _ KeyResolver = &remote{}

// newRemote dials a resolver and fetches its metadata once, so a resolver that is
// absent, unusable, or states a malformed ladder fails where it is configured
// rather than on a request. The connection and the metadata refresh live for as
// long as lifecycle; dialTimeout bounds only the first metadata call.
func newRemote(lifecycle context.Context, endpoint, apiServerID string, dialTimeout time.Duration) (*remote, error) {
	// Endpoint parsing is the KMS provider's, which already accepts unix:// paths
	// and Linux abstract sockets. A second parser would be a second set of
	// accepted forms.
	addr, err := kmsutil.ParseEndpoint(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint: %w", err)
	}

	metrics.RegisterMetrics()

	r := &remote{name: endpoint, apiServerID: apiServerID}

	conn, err := grpc.NewClient(
		// The target is unused: the dialer below closes over addr and fixes the
		// network to unix, which is also how a leading @ reaches Go's abstract
		// socket handling.
		"passthrough:///"+addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithAuthority("localhost"),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", addr)
		}),
		grpc.WithChainUnaryInterceptor(metrics.OutboundRequestInterceptor(endpoint)),
	)
	if err != nil {
		return nil, fmt.Errorf("dialing resolver at %q: %w", endpoint, err)
	}
	r.client = externalhttpsig.NewExternalHTTPSignatureServiceClient(conn)

	go func() {
		<-lifecycle.Done()
		_ = conn.Close()
	}()

	dialCtx, cancel := context.WithTimeout(lifecycle, dialTimeout)
	defer cancel()
	if err := r.refreshMetadata(dialCtx); err != nil {
		return nil, fmt.Errorf("fetching metadata from resolver at %q: %w", endpoint, err)
	}
	go r.pollMetadata(lifecycle)

	return r, nil
}

func (r *remote) Name() string { return r.name }

// Check reports the outcome of the last Metadata attempt, for the API server's
// health endpoints.
func (r *remote) Check() error {
	meta := r.meta.Load()
	if meta == nil {
		return fmt.Errorf("resolver %s has not answered a metadata request", r.name)
	}
	return meta.err
}

// pollMetadata keeps the resolver's metadata current and doubles as its health
// probe.
//
// A failure is not fatal and does not clear what was already loaded. Keys already
// cached keep verifying, which is the correct behavior: a resolver being briefly
// unreachable should not log out every client whose key is still valid.
func (r *remote) pollMetadata(ctx context.Context) {
	timer := time.NewTimer(r.refreshInterval())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			klog.V(2).InfoS("HTTP signature key resolver metadata poll shutting down", "resolver", r.name)
			return
		case <-timer.C:
		}

		attempt, cancel := context.WithTimeout(ctx, callTimeout)
		err := r.refreshMetadata(attempt)
		cancel()
		if err != nil {
			klog.ErrorS(err, "Refreshing HTTP signature key resolver metadata; cached keys continue to verify", "resolver", r.name)
			timer.Reset(metadataFailureRetry)
			continue
		}
		timer.Reset(r.refreshInterval())
	}
}

func (r *remote) refreshInterval() time.Duration {
	if meta := r.meta.Load(); meta != nil && meta.refresh > 0 {
		return meta.refresh
	}
	return defaultMetadataRefresh
}

func (r *remote) refreshMetadata(ctx context.Context) error {
	resp, err := r.client.Metadata(ctx, &externalhttpsig.MetadataRequest{})
	if err != nil {
		r.recordMetadataError(err)
		return err
	}

	meta := &resolverMetadata{
		maxAge:  secondsToDuration(resp.GetMaxSignatureAgeSeconds()),
		refresh: secondsToDuration(resp.GetRefreshHintSeconds()),
	}
	if ladder := resp.GetKeyDerivation(); ladder != nil {
		derivation, digest, err := derivationFrom(ladder)
		if err != nil {
			// A malformed ladder is rejected rather than ignored. Ignoring it would
			// leave every derived key failing as a bare signature mismatch.
			wrapped := fmt.Errorf("resolver %s states a malformed key derivation ladder: %w", r.name, err)
			r.recordMetadataError(wrapped)
			return wrapped
		}
		meta.derivation = derivation
		meta.hasLadder = true

		// Logged and published so an operator can compare it against the digest a
		// client logs for its own copy of the ladder. Without that comparison a
		// disagreement is only visible as a signature that does not verify.
		klog.V(2).InfoS("Loaded key derivation ladder from HTTP signature key resolver", "resolver", r.name, "sha256", digest)
		metrics.RecordKeyDerivation(r.name, digest)
	}

	r.meta.Store(meta)
	metrics.RecordMetadataSuccess(r.name)
	return nil
}

// recordMetadataError marks the resolver unhealthy while keeping whatever metadata
// was already loaded, so a transient failure degrades rather than breaks.
func (r *remote) recordMetadataError(err error) {
	previous := r.meta.Load()
	if previous == nil {
		r.meta.Store(&resolverMetadata{err: err})
		return
	}
	updated := *previous
	updated.err = err
	r.meta.Store(&updated)
}

// ResolveKey asks the resolver about one key ID.
func (r *remote) ResolveKey(ctx context.Context, req ResolveRequest) (*ResolvedKey, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	resp, err := r.client.ResolveKey(ctx, &externalhttpsig.ResolveKeyRequest{
		KeyId:          req.KeyID,
		Algorithm:      req.Algorithm,
		Created:        timestamppb.New(req.Created),
		RelayedHeaders: req.RelayedHeaders,
		Uid:            string(uuid.NewUUID()),
		ApiServerId:    r.apiServerID,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("resolving keyID with resolver %s: %w", r.name, err)
	}

	out := &ResolvedKey{
		Algorithm: resp.GetAlgorithm(),
		MaxAge:    secondsToDuration(resp.GetMaxSignatureAgeSeconds()),
		CacheFor:  secondsToDuration(resp.GetCacheTtlSeconds()),
	}
	if u := resp.GetUser(); u != nil {
		out.User = user.DefaultInfo{
			Name:   u.GetUsername(),
			UID:    u.GetUid(),
			Groups: u.GetGroups(),
			Extra:  extraFrom(u.GetExtra()),
		}
	}

	switch material := resp.GetMaterial().(type) {
	case *externalhttpsig.ResolveKeyResponse_PublicKey:
		out.PublicKey = material.PublicKey
	case *externalhttpsig.ResolveKeyResponse_Secret:
		out.Secret = material.Secret
	case *externalhttpsig.ResolveKeyResponse_DerivedKey:
		meta := r.meta.Load()
		if meta == nil || !meta.hasLadder {
			// The rung cannot be folded without the ladder it is a rung of, and the
			// ladder is stated in Metadata. Reported as the mismatch it is rather
			// than as a key that fails to verify.
			return nil, fmt.Errorf("resolver %s returned a derived key but states no key derivation ladder in its metadata", r.name)
		}
		out.Derived = &DerivedKey{
			Key:        material.DerivedKey.GetKey(),
			From:       material.DerivedKey.GetFrom(),
			Scope:      material.DerivedKey.GetScope(),
			Derivation: meta.derivation,
		}
	default:
		return nil, fmt.Errorf("resolver %s returned no key material", r.name)
	}
	return out, nil
}

// ConsumeNonce records a nonce with the resolver.
//
// Any failure returns an error, and the caller rejects the request. There is no
// path here that accepts a request whose nonce could not be recorded.
func (r *remote) ConsumeNonce(ctx context.Context, req NonceRequest) error {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()

	resp, err := r.client.ConsumeNonce(ctx, &externalhttpsig.ConsumeNonceRequest{
		KeyId:       req.KeyID,
		Nonce:       req.Nonce,
		Created:     timestamppb.New(req.Created),
		ExpiresAt:   timestamppb.New(req.ExpiresAt),
		Uid:         string(uuid.NewUUID()),
		ApiServerId: r.apiServerID,
	})
	if err != nil {
		return fmt.Errorf("recording signature nonce with resolver %s: %w", r.name, err)
	}
	if !resp.GetAccepted() {
		if reason := resp.GetReason(); reason != "" {
			return fmt.Errorf("%w: %s", ErrNonceReplayed, reason)
		}
		return ErrNonceReplayed
	}
	return nil
}

// secondsToDuration reads one of the protocol's second-valued fields. Zero and
// negative both mean the resolver stated no opinion, so both become zero here
// rather than a negative duration that would compare as the tightest possible
// bound.
func secondsToDuration(seconds int64) time.Duration {
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func extraFrom(in map[string]*externalhttpsig.ExtraValue) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = v.GetItems()
	}
	return out
}
