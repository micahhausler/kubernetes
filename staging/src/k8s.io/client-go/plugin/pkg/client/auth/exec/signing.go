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

package exec

import (
	"fmt"
	"time"

	"github.com/micahhausler/httpsig"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/apis/clientauthentication"
	transporthttpsig "k8s.io/client-go/transport/httpsig"
)

// This file holds the exec plugin's side of HTTP message signature credentials:
// what the plugin is told to produce, and how what it returns becomes something
// the signing round tripper can use.
//
// The division is the same one the kubeconfig draws. What does not change about a
// signing identity, the algorithm and the derivation and the covered headers,
// comes from the client's configuration. What rotates, the key and the values of
// the headers it comes with, comes from the plugin.

// declaredSignedHeaders indexes the covered header names for lookup. A credential
// that sets a header outside this set, or omits one inside it, is rejected.
func declaredSignedHeaders(signing *transporthttpsig.Config) map[string]bool {
	if signing == nil {
		return nil
	}
	declared := make(map[string]bool, len(signing.SignedHeaders))
	for _, h := range signing.SignedHeaders {
		declared[transporthttpsig.CanonicalHeaderName(h.Name)] = true
	}
	return declared
}

// alg reports the signing algorithm the client is configured for.
func alg(signing *transporthttpsig.Config) httpsig.Algorithm {
	return httpsig.Algorithm(signing.Algorithm)
}

// signatureRequest builds what the plugin is told about the signature it has to
// produce material for.
func signatureRequest(signing *transporthttpsig.Config) *clientauthentication.HTTPSignatureRequest {
	req := &clientauthentication.HTTPSignatureRequest{Algorithm: signing.Algorithm}
	for _, h := range signing.SignedHeaders {
		req.SignedHeaders = append(req.SignedHeaders, clientauthentication.HTTPSignatureHeader{Name: h.Name})
	}
	if d := signing.KeyDerivation; d != nil {
		ladder := &clientauthentication.HTTPSignatureKeyDerivation{
			Kind:         d.Kind,
			Hash:         d.Hash,
			SecretPrefix: d.SecretPrefix,
		}
		for _, step := range d.Steps {
			ladder.Steps = append(ladder.Steps, clientauthentication.HTTPSignatureKeyDerivationStep{
				Name:    step.Name,
				Literal: step.Literal,
				Scope:   step.Scope,
				Date:    step.Date,
			})
		}
		req.KeyDerivation = ladder
	}
	return req
}

// signatureMaterial converts what the plugin returned into the form every
// delivery mode shares, so the rules about what a credential must carry are
// applied by one implementation rather than restated here.
//
// The expiry comes from the status rather than from the signature block. A plugin
// already says when its credential stops being usable, and a second place to say
// it is a second place for the two to disagree.
func signatureMaterial(sig *clientauthentication.HTTPSignatureCredential, expiry *metav1.Time) transporthttpsig.Material {
	material := transporthttpsig.Material{
		KeyID:               sig.KeyID,
		Secret:              sig.Secret,
		SecretBase64:        sig.SecretBase64,
		PrivateKey:          sig.PrivateKey,
		SignedHeaders:       sig.SignedHeaders,
		ExpirationTimestamp: expiry,
	}
	if sig.Stage != nil {
		material.Stage = &transporthttpsig.Stage{From: sig.Stage.From, Scope: sig.Stage.Scope}
	}
	return material
}

// signingSource hands the round tripper the credential currently in force,
// running the plugin again when it has expired.
//
// The round tripper asks on every request, which is what makes a long-lived
// client work: a controller outlives its credentials, and the plugin's refresh
// happens underneath this call rather than on a schedule this package keeps.
type signingSource struct {
	a *Authenticator
}

func (s *signingSource) Credential(at time.Time) (*transporthttpsig.Credential, error) {
	creds, err := s.a.getCreds()
	if err != nil {
		return nil, fmt.Errorf("getting credentials: %w", err)
	}
	if creds.signing == nil {
		return nil, fmt.Errorf("exec plugin %s returned no signing key material", s.a.cmd)
	}
	return creds.signing.At(at)
}
