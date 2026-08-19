/*
Copyright 2014 The Kubernetes Authors.

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

package api

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
)

// Where possible, json tags match the cli argument names.
// Top level config objects and all values required for proper functioning are not "omitempty".  Any truly optional piece of config is allowed to be omitted.

// Config holds the information needed to build connect to remote kubernetes clusters as a given user
// IMPORTANT if you add fields to this struct, please update IsConfigEmpty()
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type Config struct {
	// Legacy field from pkg/api/types.go TypeMeta.
	// TODO(jlowdermilk): remove this after eliminating downstream dependencies.
	// +k8s:conversion-gen=false
	// +optional
	Kind string `json:"kind,omitempty"`
	// Legacy field from pkg/api/types.go TypeMeta.
	// TODO(jlowdermilk): remove this after eliminating downstream dependencies.
	// +k8s:conversion-gen=false
	// +optional
	APIVersion string `json:"apiVersion,omitempty"`
	// Preferences holds general information to be use for cli interactions
	// Deprecated: this field is deprecated in v1.34. It is not used by any of the Kubernetes components.
	Preferences Preferences `json:"preferences,omitzero"`
	// Clusters is a map of referencable names to cluster configs
	Clusters map[string]*Cluster `json:"clusters"`
	// AuthInfos is a map of referencable names to user configs
	AuthInfos map[string]*AuthInfo `json:"users"`
	// Contexts is a map of referencable names to context configs
	Contexts map[string]*Context `json:"contexts"`
	// CurrentContext is the name of the context that you would like to use by default
	CurrentContext string `json:"current-context"`
	// Extensions holds additional information. This is useful for extenders so that reads and writes don't clobber unknown fields
	// +optional
	Extensions map[string]runtime.Object `json:"extensions,omitempty"`
}

// IMPORTANT if you add fields to this struct, please update IsConfigEmpty()
// Deprecated: this structure is deprecated in v1.34. It is not used by any of the Kubernetes components.
type Preferences struct {
	// +optional
	Colors bool `json:"colors,omitempty"`
	// Extensions holds additional information. This is useful for extenders so that reads and writes don't clobber unknown fields
	// +optional
	Extensions map[string]runtime.Object `json:"extensions,omitempty"`
}

// Cluster contains information about how to communicate with a kubernetes cluster
type Cluster struct {
	// LocationOfOrigin indicates where this object came from.  It is used for round tripping config post-merge, but never serialized.
	// +k8s:conversion-gen=false
	LocationOfOrigin string `json:"-"`
	// Server is the address of the kubernetes cluster (https://hostname:port).
	Server string `json:"server"`
	// TLSServerName is used to check server certificate. If TLSServerName is empty, the hostname used to contact the server is used.
	// +optional
	TLSServerName string `json:"tls-server-name,omitempty"`
	// InsecureSkipTLSVerify skips the validity check for the server's certificate. This will make your HTTPS connections insecure.
	// +optional
	InsecureSkipTLSVerify bool `json:"insecure-skip-tls-verify,omitempty"`
	// CertificateAuthority is the path to a cert file for the certificate authority.
	// +optional
	CertificateAuthority string `json:"certificate-authority,omitempty"`
	// CertificateAuthorityData contains PEM-encoded certificate authority certificates. Overrides CertificateAuthority
	// +optional
	CertificateAuthorityData []byte `json:"certificate-authority-data,omitempty"`
	// ProxyURL is the URL to the proxy to be used for all requests made by this
	// client. URLs with "http", "https", and "socks5" schemes are supported.  If
	// this configuration is not provided or the empty string, the client
	// attempts to construct a proxy configuration from http_proxy and
	// https_proxy environment variables. If these environment variables are not
	// set, the client does not attempt to proxy requests.
	//
	// socks5 proxying does not currently support spdy streaming endpoints (exec,
	// attach, port forward).
	// +optional
	ProxyURL string `json:"proxy-url,omitempty"`
	// DisableCompression allows client to opt-out of response compression for all requests to the server. This is useful
	// to speed up requests (specifically lists) when client-server network bandwidth is ample, by saving time on
	// compression (server-side) and decompression (client-side): https://github.com/kubernetes/kubernetes/issues/112296.
	// +optional
	DisableCompression bool `json:"disable-compression,omitempty"`
	// Extensions holds additional information. This is useful for extenders so that reads and writes don't clobber unknown fields
	// +optional
	Extensions map[string]runtime.Object `json:"extensions,omitempty"`
}

// AuthInfo contains information that describes identity information.  This is use to tell the kubernetes cluster who you are.
type AuthInfo struct {
	// LocationOfOrigin indicates where this object came from.  It is used for round tripping config post-merge, but never serialized.
	// +k8s:conversion-gen=false
	LocationOfOrigin string `json:"-"`
	// ClientCertificate is the path to a client cert file for TLS.
	// +optional
	ClientCertificate string `json:"client-certificate,omitempty"`
	// ClientCertificateData contains PEM-encoded data from a client cert file for TLS. Overrides ClientCertificate
	// +optional
	ClientCertificateData []byte `json:"client-certificate-data,omitempty"`
	// ClientKey is the path to a client key file for TLS.
	// +optional
	ClientKey string `json:"client-key,omitempty"`
	// ClientKeyData contains PEM-encoded data from a client key file for TLS. Overrides ClientKey
	// +optional
	ClientKeyData []byte `json:"client-key-data,omitempty" datapolicy:"security-key"`
	// Token is the bearer token for authentication to the kubernetes cluster.
	// +optional
	Token string `json:"token,omitempty" datapolicy:"token"`
	// TokenFile is a pointer to a file that contains a bearer token (as described above).  If both Token and TokenFile are present,
	// the TokenFile will be periodically read and the last successfully read value takes precedence over Token.
	// +optional
	TokenFile string `json:"tokenFile,omitempty"`
	// Impersonate is the username to act-as.
	// +optional
	Impersonate string `json:"act-as,omitempty"`
	// ImpersonateUID is the uid to impersonate.
	// +optional
	ImpersonateUID string `json:"act-as-uid,omitempty"`
	// ImpersonateGroups is the groups to impersonate.
	// +optional
	ImpersonateGroups []string `json:"act-as-groups,omitempty"`
	// ImpersonateUserExtra contains additional information for impersonated user.
	// +optional
	ImpersonateUserExtra map[string][]string `json:"act-as-user-extra,omitempty"`
	// Username is the username for basic authentication to the kubernetes cluster.
	// +optional
	Username string `json:"username,omitempty"`
	// Password is the password for basic authentication to the kubernetes cluster.
	// +optional
	Password string `json:"password,omitempty" datapolicy:"password"`
	// AuthProvider specifies a custom authentication plugin for the kubernetes cluster.
	// +optional
	AuthProvider *AuthProviderConfig `json:"auth-provider,omitempty"`
	// Exec specifies a custom exec-based authentication plugin for the kubernetes cluster.
	// +optional
	Exec *ExecConfig `json:"exec,omitempty"`
	// HTTPSignature specifies that requests are authenticated by signing each one
	// with an HTTP message signature (RFC 9421).
	// +optional
	HTTPSignature *HTTPSignatureConfig `json:"httpSignature,omitempty"`
	// Extensions holds additional information. This is useful for extenders so that reads and writes don't clobber unknown fields
	// +optional
	Extensions map[string]runtime.Object `json:"extensions,omitempty"`
}

// Context is a tuple of references to a cluster (how do I communicate with a kubernetes cluster), a user (how do I identify myself), and a namespace (what subset of resources do I want to work with)
type Context struct {
	// LocationOfOrigin indicates where this object came from.  It is used for round tripping config post-merge, but never serialized.
	// +k8s:conversion-gen=false
	LocationOfOrigin string `json:"-"`
	// Cluster is the name of the cluster for this context
	Cluster string `json:"cluster"`
	// AuthInfo is the name of the authInfo for this context
	AuthInfo string `json:"user"`
	// Namespace is the default namespace to use on unspecified requests
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// Extensions holds additional information. This is useful for extenders so that reads and writes don't clobber unknown fields
	// +optional
	Extensions map[string]runtime.Object `json:"extensions,omitempty"`
}

// AuthProviderConfig holds the configuration for a specified auth provider.
type AuthProviderConfig struct {
	Name string `json:"name"`
	// +optional
	Config map[string]string `json:"config,omitempty"`
}

var _ fmt.Stringer = new(AuthProviderConfig)
var _ fmt.GoStringer = new(AuthProviderConfig)

// GoString implements fmt.GoStringer and sanitizes sensitive fields of
// AuthProviderConfig to prevent accidental leaking via logs.
func (c AuthProviderConfig) GoString() string {
	return c.String()
}

// String implements fmt.Stringer and sanitizes sensitive fields of
// AuthProviderConfig to prevent accidental leaking via logs.
func (c AuthProviderConfig) String() string {
	cfg := "<nil>"
	if c.Config != nil {
		cfg = "--- REDACTED ---"
	}
	return fmt.Sprintf("api.AuthProviderConfig{Name: %q, Config: map[string]string{%s}}", c.Name, cfg)
}

// ExecConfig specifies a command to provide client credentials. The command is exec'd
// and outputs structured stdout holding credentials.
//
// See the client.authentication.k8s.io API group for specifications of the exact input
// and output format
type ExecConfig struct {
	// Command to execute.
	Command string `json:"command"`
	// Arguments to pass to the command when executing it.
	// +optional
	Args []string `json:"args"`
	// Env defines additional environment variables to expose to the process. These
	// are unioned with the host's environment, as well as variables client-go uses
	// to pass argument to the plugin.
	// +optional
	Env []ExecEnvVar `json:"env"`

	// Preferred input version of the ExecInfo. The returned ExecCredentials MUST use
	// the same encoding version as the input.
	APIVersion string `json:"apiVersion,omitempty"`

	// This text is shown to the user when the executable doesn't seem to be
	// present. For example, `brew install foo-cli` might be a good InstallHint for
	// foo-cli on Mac OS systems.
	InstallHint string `json:"installHint,omitempty"`

	// ProvideClusterInfo determines whether or not to provide cluster information,
	// which could potentially contain very large CA data, to this exec plugin as a
	// part of the KUBERNETES_EXEC_INFO environment variable. By default, it is set
	// to false. Package k8s.io/client-go/tools/auth/exec provides helper methods for
	// reading this environment variable.
	ProvideClusterInfo bool `json:"provideClusterInfo"`

	// Config holds additional config data that is specific to the exec
	// plugin with regards to the cluster being authenticated to.
	//
	// This data is sourced from the clientcmd Cluster object's extensions[exec] field:
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
	// +k8s:conversion-gen=false
	Config runtime.Object `json:"-"`

	// InteractiveMode determines this plugin's relationship with standard input. Valid
	// values are "Never" (this exec plugin never uses standard input), "IfAvailable" (this
	// exec plugin wants to use standard input if it is available), or "Always" (this exec
	// plugin requires standard input to function). See ExecInteractiveMode values for more
	// details.
	//
	// If APIVersion is client.authentication.k8s.io/v1alpha1 or
	// client.authentication.k8s.io/v1beta1, then this field is optional and defaults
	// to "IfAvailable" when unset. Otherwise, this field is required.
	// +optional
	InteractiveMode ExecInteractiveMode `json:"interactiveMode,omitempty"`

	// StdinUnavailable indicates whether the exec authenticator can pass standard
	// input through to this exec plugin. For example, a higher level entity might be using
	// standard input for something else and therefore it would not be safe for the exec
	// plugin to use standard input. This is kept here in order to keep all of the exec configuration
	// together, but it is never serialized.
	// +k8s:conversion-gen=false
	StdinUnavailable bool `json:"-"`

	// StdinUnavailableMessage is an optional message to be displayed when the exec authenticator
	// cannot successfully run this exec plugin because it needs to use standard input and
	// StdinUnavailable is true. For example, a process that is already using standard input to
	// read user instructions might set this to "used by my-program to read user instructions".
	// +k8s:conversion-gen=false
	StdinUnavailableMessage string `json:"-"`

	// PluginPolicy is the policy governing whether or not the configured
	// `Command` may run.
	// +k8s:conversion-gen=false
	PluginPolicy PluginPolicy `json:"-"`
}

// AllowlistEntry is an entry in the allowlist. For each allowlist item, at
// least one field must be nonempty. A struct with all empty fields is
// considered a misconfiguration error. Each field is a criterion for
// execution. If multiple fields are specified, then the criteria of all
// specified fields must be met. That is, the result of an individual entry is
// the logical AND of all checks corresponding to the specified fields within
// the entry.
type AllowlistEntry struct {
	// Command matching is performed by first resolving the absolute path of both
	// the plugin and the name in the allowlist entry using `exec.LookPath`. It
	// will be called on both, and the resulting strings must be equal. If
	// either call to `exec.LookPath` results in an error, the `Command` check
	// will be considered a failure.
	Command string `json:"-"`
}

// PluginPolicy describes the policy type and allowlist (if any) for client-go
// credential plugins.
type PluginPolicy struct {
	// PolicyType specifies the policy governing which, if any, client-go
	// credential plugins may be executed. It MUST be one of { "", "AllowAll", "DenyAll", "Allowlist" }.
	// If the policy is "", then it falls back to "AllowAll" (this is required
	// to maintain backward compatibility). If the policy is DenyAll, no
	// credential plugins may run. If the policy is Allowlist, only those
	// plugins meeting the criteria specified in the `credentialPluginAllowlist`
	// field may run. If the policy is not `Allowlist` but one is provided, it
	// is considered a configuration error.
	PolicyType PolicyType `json:"-"`

	// Allowlist is a slice of allowlist entries. If any of them is a match,
	// then the executable in question may execute. That is, the result is the
	// logical OR of all entries in the allowlist. This list MUST be nil
	// whenever the policy is not "Allowlist".
	Allowlist []AllowlistEntry `json:"-"`
}

type PolicyType string

const (
	PluginPolicyAllowAll  PolicyType = "AllowAll"
	PluginPolicyDenyAll   PolicyType = "DenyAll"
	PluginPolicyAllowlist PolicyType = "Allowlist"
)

var _ fmt.Stringer = new(ExecConfig)
var _ fmt.GoStringer = new(ExecConfig)

// GoString implements fmt.GoStringer and sanitizes sensitive fields of
// ExecConfig to prevent accidental leaking via logs.
func (c ExecConfig) GoString() string {
	return c.String()
}

// String implements fmt.Stringer and sanitizes sensitive fields of ExecConfig
// to prevent accidental leaking via logs.
func (c ExecConfig) String() string {
	var args []string
	if len(c.Args) > 0 {
		args = []string{"--- REDACTED ---"}
	}
	env := "[]ExecEnvVar(nil)"
	if len(c.Env) > 0 {
		env = "[]ExecEnvVar{--- REDACTED ---}"
	}
	config := "runtime.Object(nil)"
	if c.Config != nil {
		config = "runtime.Object(--- REDACTED ---)"
	}
	return fmt.Sprintf("api.ExecConfig{Command: %q, Args: %#v, Env: %s, APIVersion: %q, ProvideClusterInfo: %t, Config: %s, StdinUnavailable: %t}", c.Command, args, env, c.APIVersion, c.ProvideClusterInfo, config, c.StdinUnavailable)
}

// ExecEnvVar is used for setting environment variables when executing an exec-based
// credential plugin.
type ExecEnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ExecInteractiveMode is a string that describes an exec plugin's relationship with standard input.
type ExecInteractiveMode string

const (
	// NeverExecInteractiveMode declares that this exec plugin never needs to use standard
	// input, and therefore the exec plugin will be run regardless of whether standard input is
	// available for user input.
	NeverExecInteractiveMode ExecInteractiveMode = "Never"
	// IfAvailableExecInteractiveMode declares that this exec plugin would like to use standard input
	// if it is available, but can still operate if standard input is not available. Therefore, the
	// exec plugin will be run regardless of whether stdin is available for user input. If standard
	// input is available for user input, then it will be provided to this exec plugin.
	IfAvailableExecInteractiveMode ExecInteractiveMode = "IfAvailable"
	// AlwaysExecInteractiveMode declares that this exec plugin requires standard input in order to
	// run, and therefore the exec plugin will only be run if standard input is available for user
	// input. If standard input is not available for user input, then the exec plugin will not be run
	// and an error will be returned by the exec plugin runner.
	AlwaysExecInteractiveMode ExecInteractiveMode = "Always"
)

// HTTPSignatureConfig configures signing every request with an HTTP message
// signature (RFC 9421). The signature covers the request itself, so no
// credential is sent and a captured request cannot be replayed as a different
// one.
//
// This holds what does not change about a signing identity. What does change,
// the key and any header values it comes with, is loaded from the file named
// here and re-read when that file changes, so a client that outlives its
// credentials keeps working.
//
// What a signature covers is not configurable. Kubernetes fixes the covered
// component set, because the server requires that set independently of what a
// signature declares it covers, and a client that covers less produces
// signatures the server rejects. SignedHeaders adds to the covered set; nothing
// removes from it.
type HTTPSignatureConfig struct {
	// APIVersion is the version of this configuration payload. Only
	// "client.authentication.k8s.io/v1alpha1" is understood. The field is
	// required, so that the payload shape can change while the httpSignature
	// field name stays fixed.
	APIVersion string `json:"apiVersion"`

	// Algorithm is the signing algorithm, named as in the IANA "HTTP Signature
	// Algorithms" registry: ed25519, ecdsa-p256-sha256, ecdsa-p384-sha384,
	// rsa-pss-sha512, rsa-v1_5-sha256, or hmac-sha256. Required, and never
	// inferred from the key, so that a key cannot be used under an algorithm
	// its holder did not intend.
	//
	// It must be empty with CertFile or CredentialBundleFile. A certificate's
	// key type determines the algorithm on both sides, so there is no other
	// algorithm the verifier would accept and nothing for a stated one to
	// disagree with.
	// +optional
	Algorithm string `json:"algorithm,omitempty"`

	// KeyFile is the path to a PEM-encoded private key, for a key that is
	// simply present on disk. Exactly one of KeyFile or CredentialFile is
	// required. The file is re-read when it changes.
	// +optional
	KeyFile string `json:"keyFile,omitempty"`

	// CertFile is the path to a PEM-encoded X.509 certificate whose key is in
	// KeyFile. Setting it makes the certificate the assertion of who the client
	// is: the server validates it against its own trust anchors and derives the
	// identity from it, rather than looking the key ID up in its configuration.
	//
	// This is mutual TLS with the handshake replaced by a message signature, so
	// the certificate, its issuance, and its subject conventions are the ones
	// already in use. Unlike mutual TLS, the authentication is in the message and
	// survives a TLS-terminating hop.
	//
	// KeyID and Algorithm must not be set with it. The key ID is the
	// certificate's digest and the algorithm follows from its key type, so
	// stating either would be a second copy of a value with one correct answer.
	//
	// Both files are re-read when either changes, and a key that does not match
	// the certificate is rejected rather than used, because that is what reading
	// two separately written files mid-rotation produces. Prefer
	// CredentialBundleFile where it is available, which cannot produce that case.
	// +optional
	CertFile string `json:"certFile,omitempty"`

	// CredentialBundleFile is the path to one PEM document whose first block is
	// a private key and whose remaining blocks are the issued certificate chain,
	// leaf first. This is what a pod certificate projected volume writes.
	//
	// It carries the same assertion as CertFile with KeyFile, and it is the
	// better form wherever it is available: one read returns a consistent key and
	// certificate, where two files can be read between the two writes of a
	// rotation.
	// +optional
	CredentialBundleFile string `json:"credentialBundleFile,omitempty"`

	// KeyID is the name the server knows the key by. Required with KeyFile, and
	// invalid with CredentialFile, where the key ID rotates with the key, and
	// with a certificate, where it is the certificate's digest.
	// +optional
	KeyID string `json:"keyID,omitempty"`

	// CredentialFile is the path to a signing credential document maintained by
	// something outside Kubernetes: a credential helper, a sidecar, or a
	// wrapper around some provider's SDK. It carries the key, the key ID, the
	// values of any signed headers, and an optional expiry, and is re-read when
	// it changes.
	//
	// This is the form to use for anything that rotates, and the only form that
	// can carry a shared secret or a session token. A shared secret in a file
	// the client reads is still a secret the server holds a copy of, which
	// means the server can produce signatures indistinguishable from this
	// client's; asymmetric keys have no such property.
	// +optional
	CredentialFile string `json:"credentialFile,omitempty"`

	// KeyDerivation is a key derivation ladder, stated identically here and in
	// the server's configuration. When set, the signing key is derived from the
	// credential's secret through the ladder rather than being the secret
	// itself, so the secret is scoped to a purpose and, with a date step, to a
	// day. The credential may carry an intermediate rung of the ladder instead
	// of the root secret; its stage says which.
	//
	// Valid only with the hmac-sha256 algorithm.
	// +optional
	KeyDerivation *HTTPSignatureKeyDerivation `json:"keyDerivation,omitempty"`

	// SignedHeaders are the names of headers set on every request and covered
	// by the signature. Use them to carry material the server needs in order to
	// resolve the key, such as a session token, so the signature binds that
	// material to the request.
	//
	// Only names appear here. The values come from the credential file, which
	// is what keeps a rotating token out of the kubeconfig and lets it rotate
	// without one.
	// +optional
	SignedHeaders []HTTPSignatureHeader `json:"signedHeaders,omitempty"`

	// TTL sets the signature expires parameter to the signing time plus this
	// duration, as a Go duration string such as "30s". Empty omits expires;
	// the created parameter is always set and the server bounds signature age
	// regardless. A TTL shorter than the server's bound narrows the replay
	// window further.
	// +optional
	TTL string `json:"ttl,omitempty"`
}

// HTTPSignatureHeader names a header that is set on each request and covered by
// the signature. The value comes from the credential file.
type HTTPSignatureHeader struct {
	// Name is the header name.
	Name string `json:"name"`
}

// HTTPSignatureKeyDerivation is a key derivation ladder: a chain of HMAC steps
// that turns a root secret into a signing key scoped to a purpose and, with a
// date step, to a day. A ladder is not a secret and not specific to one party.
//
// Every party that derives states the same ladder, so this and the server's
// copy have to agree. Both log a digest of theirs when they load it, because a
// disagreement otherwise fails as a bare signature mismatch with nothing in the
// error to say why.
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
	// own clocks. The set is deliberately not a Go layout or a strftime
	// string: a ladder is read by implementations in any language, and a
	// format token has to mean the same thing to all of them.
	// +optional
	Date string `json:"date,omitempty"`
}

// NewConfig is a convenience function that returns a new Config object with non-nil maps
func NewConfig() *Config {
	return &Config{
		Clusters:   make(map[string]*Cluster),
		AuthInfos:  make(map[string]*AuthInfo),
		Contexts:   make(map[string]*Context),
		Extensions: make(map[string]runtime.Object),
	}
}

// NewContext is a convenience function that returns a new Context
// object with non-nil maps
func NewContext() *Context {
	return &Context{Extensions: make(map[string]runtime.Object)}
}

// NewCluster is a convenience function that returns a new Cluster
// object with non-nil maps
func NewCluster() *Cluster {
	return &Cluster{Extensions: make(map[string]runtime.Object)}
}

// NewAuthInfo is a convenience function that returns a new AuthInfo
// object with non-nil maps
func NewAuthInfo() *AuthInfo {
	return &AuthInfo{
		Extensions:           make(map[string]runtime.Object),
		ImpersonateUserExtra: make(map[string][]string),
	}
}

// NewPreferences is a convenience function that returns a new
// Preferences object with non-nil maps
// Deprecated: this method is deprecated in v1.34. It is not used by any of the Kubernetes components.
func NewPreferences() *Preferences {
	return &Preferences{Extensions: make(map[string]runtime.Object)}
}
