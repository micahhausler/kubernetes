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
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/micahhausler/httpsig"
)

// device models a signing key that cannot be exported: a goroutine holds the key
// and answers signing requests over channels. Nothing outside it can reach the
// key bytes, which is the property a TPM, a platform keystore, or a smart card
// has and a file does not.
//
// It exists to test a claim the design makes, that key material never crosses the
// credential source interface, by writing an implementation for which crossing is
// impossible. If a future change plumbs key bytes instead of a signer, this stops
// compiling.
type device struct {
	requests  chan []byte
	responses chan []byte
	pub       ed25519.PublicKey
	stop      chan struct{}
	mu        sync.Mutex
	signCount int
}

func newDevice(t *testing.T) *device {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := &device{
		requests:  make(chan []byte),
		responses: make(chan []byte),
		pub:       pub,
		stop:      make(chan struct{}),
	}
	go func() {
		// priv is captured here and nowhere else. It is not a field, so no
		// caller can read it even by reflection on the device.
		for {
			select {
			case base := <-d.requests:
				d.responses <- ed25519.Sign(priv, base)
			case <-d.stop:
				return
			}
		}
	}()
	t.Cleanup(func() { close(d.stop) })
	return d
}

// Algorithm and Sign make the device an httpsig.Signer without ever handing out
// the key.
func (d *device) Algorithm() httpsig.Algorithm { return httpsig.Ed25519 }

func (d *device) Sign(base []byte) ([]byte, error) {
	d.mu.Lock()
	d.signCount++
	d.mu.Unlock()
	d.requests <- base
	return <-d.responses, nil
}

func (d *device) signs() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.signCount
}

// deviceSource is a CredentialSource backed by the device. It records the signing
// times it was asked about, because the round tripper's contract is that the time
// it passes here is the same one it records as created.
type deviceSource struct {
	device   *device
	keyID    string
	headers  map[string]string
	notAfter time.Time

	mu    sync.Mutex
	asked []time.Time
}

func (s *deviceSource) Credential(at time.Time) (*Credential, error) {
	s.mu.Lock()
	s.asked = append(s.asked, at)
	s.mu.Unlock()
	return &Credential{
		KeyID:         s.keyID,
		Signer:        s.device,
		SignedHeaders: s.headers,
		NotAfter:      s.notAfter,
	}, nil
}

func (s *deviceSource) askedTimes() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.asked...)
}

// TestRoundTripperWithSource is the evidence for D7: a credential source outside
// this package, holding a key it cannot export, signs Kubernetes API requests.
func TestRoundTripperWithSource(t *testing.T) {
	d := newDevice(t)
	source := &deviceSource{
		device:  d,
		keyID:   "device-key",
		headers: map[string]string{"X-Attestation": "from the device"},
	}
	c := &capture{}
	rt, err := NewRoundTripperWithSource(source, []string{"X-Attestation"}, 30*time.Second, c)
	if err != nil {
		t.Fatalf("NewRoundTripperWithSource: %v", err)
	}

	req, err := http.NewRequest("POST", "https://api.example.com/api/v1/pods", strings.NewReader(`{"kind":"Pod"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if d.signs() != 1 {
		t.Errorf("the device signed %d times, want 1", d.signs())
	}

	sigs, err := httpsig.ParseSignatures(c.req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != 1 {
		t.Fatalf("got %d signatures, want 1", len(sigs))
	}
	verifier, err := httpsig.NewVerifier(httpsig.Ed25519, d.pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := sigs[0].Verify(verifier, httpsig.Policy{
		RequiredComponents: FloorComponents,
		MaxAge:             time.Minute,
	}); err != nil {
		t.Fatalf("a device-signed request does not verify: %v", err)
	}
	if got := sigs[0].KeyID(); got != "device-key" {
		t.Errorf("keyID: got %q, want device-key", got)
	}
	if got := c.req.Header.Get("X-Attestation"); got != "from the device" {
		t.Errorf("the source's header value did not reach the request: %q", got)
	}
	// The configured extra header and the body digest must be covered, or the
	// source's own material travels unsigned.
	var covered []string
	for _, comp := range sigs[0].Components() {
		covered = append(covered, comp.Name)
	}
	joined := strings.Join(covered, " ")
	for _, want := range []string{"x-attestation", "content-digest", "content-type"} {
		if !strings.Contains(joined, want) {
			t.Errorf("covered components %v do not include %q", covered, want)
		}
	}

	// The signing time passed to the source must be the one the signature
	// records. A derived key scoped to a period depends on the two agreeing.
	asked := source.askedTimes()
	if len(asked) != 1 {
		t.Fatalf("the source was asked %d times for one request", len(asked))
	}
	if !asked[0].Truncate(time.Second).Equal(sigs[0].Created()) {
		t.Errorf("the source was asked about %v but the signature says created %v",
			asked[0].Truncate(time.Second), sigs[0].Created())
	}
}

// TestSourceAskedPerRequest is why the interface is a function rather than a
// value: a long-lived client outlives its credentials, so the source must get the
// chance to rotate on every request.
func TestSourceAskedPerRequest(t *testing.T) {
	d := newDevice(t)
	source := &deviceSource{device: d, keyID: "device-key"}
	c := &capture{}
	rt, err := NewRoundTripperWithSource(source, nil, 0, c)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		req, err := http.NewRequest("GET", "https://api.example.com/api/v1/pods", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rt.RoundTrip(req); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(source.askedTimes()); got != 5 {
		t.Errorf("the source was asked %d times for 5 requests", got)
	}
}

// TestSourceCredentialExpiry checks the round tripper enforces NotAfter even for
// a source it knows nothing about, rather than signing and letting the server
// reject it.
func TestSourceCredentialExpiry(t *testing.T) {
	d := newDevice(t)
	source := &deviceSource{
		device:   d,
		keyID:    "device-key",
		notAfter: time.Now().Add(-time.Minute),
	}
	c := &capture{}
	rt, err := NewRoundTripperWithSource(source, nil, 0, c)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", "https://api.example.com/api/v1/pods", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("want an error for an expired credential")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error %q does not say the credential expired", err)
	}
	if c.req != nil {
		t.Error("a request was sent with an expired credential")
	}
	if d.signs() != 0 {
		t.Error("the device was asked to sign with an expired credential")
	}
}

// errFromSource is what a source returns when its backing device is unavailable.
var errFromSource = errors.New("the device is busy")

// brokenSource returns credentials that violate the interface's contract, so the
// round tripper's handling of a third-party implementation can be checked.
type brokenSource struct {
	cred *Credential
	err  error
}

func (s *brokenSource) Credential(time.Time) (*Credential, error) { return s.cred, s.err }

func TestRoundTripperWithSourceErrors(t *testing.T) {
	if _, err := NewRoundTripperWithSource(nil, nil, 0, nil); err == nil ||
		!strings.Contains(err.Error(), "credential source is required") {
		t.Errorf("want a nil source error, got %v", err)
	}
	d := newDevice(t)
	if _, err := NewRoundTripperWithSource(&deviceSource{device: d}, []string{"Impersonate-User"}, 0, nil); err == nil ||
		!strings.Contains(err.Error(), "reserved") {
		t.Errorf("want a reserved header error, got %v", err)
	}

	for _, tc := range []struct {
		name   string
		source CredentialSource
		want   string
	}{{
		name:   "source fails",
		source: &brokenSource{err: errFromSource},
		want:   "the device is busy",
	}, {
		name:   "source returns no signer",
		source: &brokenSource{cred: &Credential{KeyID: "k"}},
		want:   "no signer",
	}, {
		name:   "source has no value for a covered header",
		source: &brokenSource{cred: &Credential{KeyID: "k", Signer: newDevice(t)}},
		want:   "no value for signed header",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			c := &capture{}
			headers := []string(nil)
			if tc.want == "no value for signed header" {
				headers = []string{"X-Needed"}
			}
			rt, err := NewRoundTripperWithSource(tc.source, headers, 0, c)
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest("GET", "https://api.example.com/api/v1/pods", nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = rt.RoundTrip(req)
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			if c.req != nil {
				t.Error("a request was sent despite the credential being unusable")
			}
		})
	}
}
