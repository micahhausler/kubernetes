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
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/micahhausler/httpsig"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This file holds the client's side of certificate-asserted signing.
//
// Nothing about the signing path changes. An X.509 keypair is the keypair this
// client already signs with. What changes is that the key ID and the identity stop
// coming from configuration: the key ID is derived from the certificate, and the
// identity is whatever the server maps the certificate to.
//
// The loading is tls.X509KeyPair's, not this package's. It already splits the PEM,
// accepts the PKCS#8, PKCS#1, and SEC1 key encodings, skips blocks it has no use
// for, and checks that the key belongs to the leaf. That last check is the one
// that matters here and is the one a hand-rolled loader would most likely omit.

// certificateCredential builds a credential from a certificate and its private
// key, each as PEM. For a credential bundle, where one document holds both, the
// same bytes are passed as both arguments.
//
// The algorithm is derived from the key and the key ID from the certificate.
// Both have exactly one correct value, and a configured second copy of a value
// with one correct answer is a place for the two to disagree.
func certificateCredential(origin string, certPEM, keyPEM []byte) (*Credential, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		// A mismatched pair is not a corrupt file, it is what reading two
		// separately-written files between the two writes of a rotation looks
		// like. Naming that is the difference between an operator checking the
		// rotation and an operator checking the key.
		if strings.Contains(err.Error(), "private key does not match public key") {
			return nil, fmt.Errorf("httpsig: the private key and the certificate from %s are not a pair, "+
				"which is what reading them mid-rotation looks like; they will be re-read when they next change", origin)
		}
		return nil, fmt.Errorf("httpsig: loading the certificate and key from %s: %w", origin, err)
	}
	leaf := pair.Leaf
	alg, err := CertificateAlgorithm(leaf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("httpsig: %s: %w", origin, err)
	}
	signer, err := httpsig.NewSigner(alg, pair.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("httpsig: %s key from %s: %w", alg, origin, err)
	}
	return &Credential{
		KeyID:  CertificateKeyID(leaf.Raw),
		Signer: signer,
		// The leaf's own expiry is the credential's expiry, so this client
		// refuses to sign with an expired certificate rather than signing and
		// letting the server reject it. Nothing has to be configured to get
		// that, and nothing can configure it away.
		NotAfter: leaf.NotAfter,
		// Only the leaf. The verifier builds the chain from its own configured
		// intermediates, so the rest would be bytes nothing reads.
		Certificate: leaf.Raw,
	}, nil
}

// NewCertificateCredential builds a credential from a certificate and its private
// key that arrived some way other than from a file, which today means from an exec
// plugin's response.
//
// It is exported for the same reason NewBoundCredential is: every delivery mode has
// to build a credential identically, and a second copy of these rules somewhere
// else would drift from this one.
func NewCertificateCredential(origin string, certPEM, keyPEM []byte, expiry *metav1.Time) (*BoundCredential, error) {
	cred, err := certificateCredential(origin, certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	// Two expiries with different meanings arrive here. The certificate says when
	// signing has to stop. The plugin's status says when to ask the plugin again.
	// A signing attempt has to respect whichever comes first, so the earlier wins:
	// taking the plugin's alone would sign with an expired certificate, and taking
	// the certificate's alone would keep signing with material the plugin has
	// declared stale.
	if expiry != nil && (cred.NotAfter.IsZero() || expiry.Time.Before(cred.NotAfter)) {
		cred.NotAfter = expiry.Time
	}
	return &BoundCredential{cred: cred, origin: origin}, nil
}

// certificateFileSource signs with a certificate and private key held on disk,
// re-read when either file changes.
type certificateFileSource struct {
	// certWatcher holds the certificate. keyWatcher holds the private key, or is
	// nil for a credential bundle, where one document holds both.
	certWatcher *fileWatcher
	keyWatcher  *fileWatcher

	mu     sync.Mutex
	cached *Credential
}

func (s *certificateFileSource) Credential(at time.Time) (*Credential, error) {
	certPEM, changed, err := s.certWatcher.contents()
	if err != nil {
		return nil, err
	}
	keyPEM := certPEM
	if s.keyWatcher != nil {
		// Both files are checked every time, because either may have moved and a
		// stale read of one against a fresh read of the other is the mismatch
		// case certificateCredential reports.
		var keyChanged bool
		keyPEM, keyChanged, err = s.keyWatcher.contents()
		if err != nil {
			return nil, err
		}
		changed = changed || keyChanged
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if changed || s.cached == nil {
		cred, err := certificateCredential(s.certWatcher.path, certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
		s.cached = cred
	}
	return s.cached, s.cached.checkNotAfter(at, s.certWatcher.path)
}
