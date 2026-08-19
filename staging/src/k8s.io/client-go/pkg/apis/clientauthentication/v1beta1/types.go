/*
Copyright 2018 The Kubernetes Authors.

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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ExecCredential is used by exec-based plugins to communicate credentials to
// HTTP transports.
type ExecCredential struct {
	metav1.TypeMeta `json:""`

	// Spec holds information passed to the plugin by the transport.
	Spec ExecCredentialSpec `json:"spec,omitempty"`

	// Status is filled in by the plugin and holds the credentials that the transport
	// should use to contact the API.
	// +optional
	Status *ExecCredentialStatus `json:"status,omitempty"`
}

// ExecCredentialSpec holds request and runtime specific information provided by
// the transport.
type ExecCredentialSpec struct {
	// Cluster contains information to allow an exec plugin to communicate with the
	// kubernetes cluster being authenticated to. Note that Cluster is non-nil only
	// when provideClusterInfo is set to true in the exec provider config (i.e.,
	// ExecConfig.ProvideClusterInfo).
	// +optional
	Cluster *Cluster `json:"cluster,omitempty"`

	// Interactive declares whether stdin has been passed to this exec plugin.
	Interactive bool `json:"interactive"`

	// HTTPSignature is the client's signing configuration, set when the client
	// is configured to authenticate by signing requests rather than by sending
	// a credential. A plugin that does not understand it must not return an
	// HTTPSignature credential.
	// +optional
	HTTPSignature *HTTPSignatureRequest `json:"httpSignature,omitempty"`
}

// ExecCredentialStatus holds credentials for the transport to use.
//
// Token and ClientKeyData are sensitive fields. This data should only be
// transmitted in-memory between client and exec plugin process. Exec plugin
// itself should at least be protected via file permissions.
type ExecCredentialStatus struct {
	// ExpirationTimestamp indicates a time when the provided credentials expire.
	// +optional
	ExpirationTimestamp *metav1.Time `json:"expirationTimestamp,omitempty"`
	// Token is a bearer token used by the client for request authentication.
	Token string `json:"token,omitempty" datapolicy:"token"`
	// PEM-encoded client TLS certificates (including intermediates, if any).
	ClientCertificateData string `json:"clientCertificateData,omitempty"`
	// PEM-encoded private key for the above certificate.
	ClientKeyData string `json:"clientKeyData,omitempty" datapolicy:"security-key"`

	// HTTPSignature is key material for signing each request, returned instead
	// of a token or a client certificate. A status may carry a signature or a
	// credential that transits, never both.
	// +optional
	HTTPSignature *HTTPSignatureCredential `json:"httpSignature,omitempty"`
}

// Cluster contains information to allow an exec plugin to communicate
// with the kubernetes cluster being authenticated to.
//
// To ensure that this struct contains everything someone would need to communicate
// with a kubernetes cluster (just like they would via a kubeconfig), the fields
// should shadow "k8s.io/client-go/tools/clientcmd/api/v1".Cluster, with the exception
// of CertificateAuthority, since CA data will always be passed to the plugin as bytes.
type Cluster struct {
	// Server is the address of the kubernetes cluster (https://hostname:port).
	Server string `json:"server"`
	// TLSServerName is passed to the server for SNI and is used in the client to
	// check server certificates against. If ServerName is empty, the hostname
	// used to contact the server is used.
	// +optional
	TLSServerName string `json:"tls-server-name,omitempty"`
	// InsecureSkipTLSVerify skips the validity check for the server's certificate.
	// This will make your HTTPS connections insecure.
	// +optional
	InsecureSkipTLSVerify bool `json:"insecure-skip-tls-verify,omitempty"`
	// CAData contains PEM-encoded certificate authority certificates.
	// If empty, system roots should be used.
	// +listType=atomic
	// +optional
	CertificateAuthorityData []byte `json:"certificate-authority-data,omitempty"`
	// ProxyURL is the URL to the proxy to be used for all requests to this
	// cluster.
	// +optional
	ProxyURL string `json:"proxy-url,omitempty"`
	// DisableCompression allows client to opt-out of response compression for all requests to the server. This is useful
	// to speed up requests (specifically lists) when client-server network bandwidth is ample, by saving time on
	// compression (server-side) and decompression (client-side): https://github.com/kubernetes/kubernetes/issues/112296.
	// +optional
	DisableCompression bool `json:"disable-compression,omitempty"`
	// Config holds additional config data that is specific to the exec
	// plugin with regards to the cluster being authenticated to.
	//
	// This data is sourced from the clientcmd Cluster object's
	// extensions[client.authentication.k8s.io/exec] field:
	//
	// clusters:
	// - name: my-cluster
	//   cluster:
	//     ...
	//     extensions:
	//     - name: client.authentication.k8s.io/exec  # reserved extension name for per cluster exec config
	//       extension:
	//         audience: 06e3fbd18de8  # arbitrary config
	//
	// In some environments, the user config may be exactly the same across many clusters
	// (i.e. call this exec plugin) minus some details that are specific to each cluster
	// such as the audience.  This field allows the per cluster config to be directly
	// specified with the cluster info.  Using this field to store secret data is not
	// recommended as one of the prime benefits of exec plugins is that no secrets need
	// to be stored directly in the kubeconfig.
	// +optional
	Config runtime.RawExtension `json:"config,omitempty"`
}

// HTTPSignatureRequest tells a plugin what a signing credential has to satisfy.
// It is the part of the client's signing configuration a plugin needs in order
// to produce a usable credential, and nothing in it is secret.
//
// Without it a plugin has to guess the covered header set, and a credential that
// omits a value for a header the client covers is rejected before any request is
// sent.
type HTTPSignatureRequest struct {
	// Algorithm is the signing algorithm the client is configured for, named as
	// in the IANA "HTTP Signature Algorithms" registry. It tells the plugin
	// which kind of key material to return.
	Algorithm string `json:"algorithm"`

	// KeyDerivation is the ladder the client derives through, when it derives.
	// A plugin returning an intermediate rung derives through this same ladder;
	// a plugin returning the root secret can ignore it.
	// +optional
	KeyDerivation *HTTPSignatureKeyDerivation `json:"keyDerivation,omitempty"`

	// SignedHeaders are the names of headers the client covers with the
	// signature. The plugin has to return a value for every one of them.
	// +optional
	// +listType=atomic
	SignedHeaders []HTTPSignatureHeader `json:"signedHeaders,omitempty"`
}

// HTTPSignatureHeader names a header covered by the signature.
type HTTPSignatureHeader struct {
	// Name is the header name.
	Name string `json:"name"`
}

// HTTPSignatureCredential is key material for signing requests, returned by a
// plugin instead of a token or a client certificate. The signature covers each
// request, so this material is used locally and never sent to the server.
//
// Secret, SecretBase64, and PrivateKey are sensitive. A shared secret means the
// server holds a copy that can produce signatures indistinguishable from this
// client's; asymmetric keys have no such property.
type HTTPSignatureCredential struct {
	// KeyID is the name the server knows this key by. For a derived key it is
	// the name alone, without the scope segments the signature adds.
	KeyID string `json:"keyID"`

	// Secret is a shared secret for hmac-sha256, as a UTF-8 string. Exactly one
	// of Secret, SecretBase64, or PrivateKey is set.
	// +optional
	Secret string `json:"secret,omitempty" datapolicy:"secret-key"`

	// SecretBase64 is a shared secret as base64. An intermediate rung of a
	// derivation ladder is raw hash output rather than text, so it travels this
	// way.
	// +optional
	SecretBase64 string `json:"secretBase64,omitempty" datapolicy:"secret-key"`

	// PrivateKey is a PEM-encoded private key, for the asymmetric algorithms.
	// +optional
	PrivateKey string `json:"privateKey,omitempty" datapolicy:"security-key"`

	// Stage is this material's position on the derivation ladder. Absent means
	// the material is the root secret and the whole ladder is folded at signing
	// time. Set means it is an intermediate rung, which bounds what the holder
	// can sign for.
	// +optional
	Stage *HTTPSignatureStage `json:"stage,omitempty"`

	// SignedHeaders are values for the headers the client covers, keyed by
	// header name. This is what lets a rotating session token stay out of the
	// kubeconfig and rotate without one.
	// +optional
	SignedHeaders map[string]string `json:"signedHeaders,omitempty" datapolicy:"token"`
}

// HTTPSignatureStage is a position on a derivation ladder.
type HTTPSignatureStage struct {
	// From names the ladder step whose output the material is. Empty means the
	// material is the root secret.
	// +optional
	From string `json:"from,omitempty"`

	// Scope holds values for the ladder's scope steps, and assertions for the
	// date steps at or before From. It has to cover exactly those; a missing
	// key and an unexpected key are both errors.
	// +optional
	Scope map[string]string `json:"scope,omitempty"`
}

// HTTPSignatureKeyDerivation is a key derivation ladder: a chain of HMAC steps
// that turns a root secret into a signing key scoped to a purpose and, with a
// date step, to a day. A ladder is not a secret and not specific to one party.
//
// The transport passes the ladder from its configuration to the plugin, because
// a plugin that hands back an intermediate rung has to derive that rung, and it
// cannot do so without knowing the chain.
type HTTPSignatureKeyDerivation struct {
	// Kind discriminates the derivation form. Only "hmac-ladder" is defined.
	Kind string `json:"kind"`

	// Hash is the HMAC hash used to derive: "sha-256" or "sha-512". The
	// signature algorithm is always hmac-sha256; this governs derivation only.
	// +optional
	Hash string `json:"hash,omitempty"`

	// SecretPrefix is prepended to the root secret before the first step. It
	// applies only when the material is the root secret, never to an
	// intermediate rung.
	// +optional
	SecretPrefix string `json:"secretPrefix,omitempty"`

	// Steps are the rungs, applied in order. Each step's input is fed to HMAC
	// keyed by the previous step's output, and the last output is the signing
	// key.
	// +listType=atomic
	Steps []HTTPSignatureKeyDerivationStep `json:"steps"`
}

// HTTPSignatureKeyDerivationStep is one rung of a ladder. Exactly one of
// Literal, Scope, or Date supplies the step's input.
//
// Step names are arbitrary labels chosen by whoever writes the ladder. Nothing
// in the implementation treats a name, a prefix, or a literal as meaningful.
type HTTPSignatureKeyDerivationStep struct {
	// Name identifies the step. Names are unique within a ladder and key the
	// scope map each party supplies. A name may not contain "/", because step
	// values are joined by slashes into the key ID a signature carries.
	Name string `json:"name"`

	// Literal is a fixed input value, the same for every party.
	// +optional
	Literal string `json:"literal,omitempty"`

	// Scope marks the input as a deployment-scoped value, such as a cell or a
	// purpose name, supplied by each party's stage.
	// +optional
	Scope bool `json:"scope,omitempty"`

	// Date names a date format from a closed set: "YYYYMMDD" or "YYYY-MM-DD".
	// The input is the signature's created timestamp rendered in UTC, so the
	// signer and the verifier render the same value without consulting their
	// own clocks.
	// +optional
	Date string `json:"date,omitempty"`
}
