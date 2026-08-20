/*
Copyright 2017 The Kubernetes Authors.

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

package apiserver

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	tracingapi "k8s.io/component-base/tracing/api/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AdmissionConfiguration provides versioned configuration for admission controllers.
type AdmissionConfiguration struct {
	metav1.TypeMeta

	// Plugins allows specifying a configuration per admission control plugin.
	// +optional
	Plugins []AdmissionPluginConfiguration
}

// AdmissionPluginConfiguration provides the configuration for a single plug-in.
type AdmissionPluginConfiguration struct {
	// Name is the name of the admission controller.
	// It must match the registered admission plugin name.
	Name string

	// Path is the path to a configuration file that contains the plugin's
	// configuration
	// +optional
	Path string

	// Configuration is an embedded configuration object to be used as the plugin's
	// configuration. If present, it will be used instead of the path to the configuration file.
	// +optional
	Configuration *runtime.Unknown
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// EgressSelectorConfiguration provides versioned configuration for egress selector clients.
type EgressSelectorConfiguration struct {
	metav1.TypeMeta

	// EgressSelections contains a list of egress selection client configurations
	EgressSelections []EgressSelection
}

// EgressSelection provides the configuration for a single egress selection client.
type EgressSelection struct {
	// Name is the name of the egress selection.
	// Currently supported values are "controlplane", "etcd" and "cluster"
	Name string

	// Connection is the exact information used to configure the egress selection
	Connection Connection
}

// Connection provides the configuration for a single egress selection client.
type Connection struct {
	// Protocol is the protocol used to connect from client to the konnectivity server.
	ProxyProtocol ProtocolType

	// Transport defines the transport configurations we use to dial to the konnectivity server.
	// This is required if ProxyProtocol is HTTPConnect or GRPC.
	// +optional
	Transport *Transport
}

// ProtocolType is a set of valid values for Connection.ProtocolType
type ProtocolType string

// Valid types for ProtocolType for konnectivity server
const (
	// Use HTTPConnect to connect to konnectivity server
	ProtocolHTTPConnect ProtocolType = "HTTPConnect"
	// Use grpc to connect to konnectivity server
	ProtocolGRPC ProtocolType = "GRPC"
	// Connect directly (skip konnectivity server)
	ProtocolDirect ProtocolType = "Direct"
)

// Transport defines the transport configurations we use to dial to the konnectivity server
type Transport struct {
	// TCP is the TCP configuration for communicating with the konnectivity server via TCP
	// ProxyProtocol of GRPC is not supported with TCP transport at the moment
	// Requires at least one of TCP or UDS to be set
	// +optional
	TCP *TCPTransport

	// UDS is the UDS configuration for communicating with the konnectivity server via UDS
	// Requires at least one of TCP or UDS to be set
	// +optional
	UDS *UDSTransport
}

// TCPTransport provides the information to connect to konnectivity server via TCP
type TCPTransport struct {
	// URL is the location of the konnectivity server to connect to.
	// As an example it might be "https://127.0.0.1:8131"
	URL string

	// TLSConfig is the config needed to use TLS when connecting to konnectivity server
	// +optional
	TLSConfig *TLSConfig
}

// UDSTransport provides the information to connect to konnectivity server via UDS
type UDSTransport struct {
	// UDSName is the name of the unix domain socket to connect to konnectivity server
	// This does not use a unix:// prefix. (Eg: /etc/srv/kubernetes/konnectivity-server/konnectivity-server.socket)
	UDSName string
}

// TLSConfig provides the authentication information to connect to konnectivity server
// Only used with TCPTransport
type TLSConfig struct {
	// caBundle is the file location of the CA to be used to determine trust with the konnectivity server.
	// Must be absent/empty if TCPTransport.URL is prefixed with http://
	// If absent while TCPTransport.URL is prefixed with https://, default to system trust roots.
	// +optional
	CABundle string

	// clientKey is the file location of the client key to authenticate with the konnectivity server
	// Must be absent/empty if TCPTransport.URL is prefixed with http://
	// Must be configured if TCPTransport.URL is prefixed with https://
	// +optional
	ClientKey string

	// clientCert is the file location of the client certificate to authenticate with the konnectivity server
	// Must be absent/empty if TCPTransport.URL is prefixed with http://
	// Must be configured if TCPTransport.URL is prefixed with https://
	// +optional
	ClientCert string

	// tlsServerName is used to check server certificate. If tlsServerName is empty, the hostname used to contact the server is used.
	// +optional
	TLSServerName string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TracingConfiguration provides versioned configuration for tracing clients.
type TracingConfiguration struct {
	metav1.TypeMeta

	// Embed the component config tracing configuration struct
	tracingapi.TracingConfiguration
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuthenticationConfiguration provides versioned configuration for authentication.
type AuthenticationConfiguration struct {
	metav1.TypeMeta

	JWT []JWTAuthenticator

	// If present --anonymous-auth must not be set
	Anonymous *AnonymousAuthConfig

	// HTTPSignature authenticates requests by HTTP message signature (RFC 9421)
	// rather than by a credential the client sends.
	HTTPSignature *HTTPSignatureConfig
}

// AnonymousAuthConfig provides the configuration for the anonymous authenticator.
type AnonymousAuthConfig struct {
	Enabled bool

	// If set, anonymous auth is only allowed if the request meets one of the
	// conditions.
	Conditions []AnonymousAuthCondition
}

// AnonymousAuthCondition describes the condition under which anonymous auth
// should be enabled.
type AnonymousAuthCondition struct {
	// Path for which anonymous auth is enabled.
	Path string
}

// JWTAuthenticator provides the configuration for a single JWT authenticator.
type JWTAuthenticator struct {
	Issuer               Issuer
	ClaimValidationRules []ClaimValidationRule
	ClaimMappings        ClaimMappings
	UserValidationRules  []UserValidationRule
}

// Issuer provides the configuration for an external provider's specific settings.
type Issuer struct {
	// url points to the issuer URL in a format https://url or https://url/path.
	// This must match the "iss" claim in the presented JWT, and the issuer returned from discovery.
	// Same value as the --oidc-issuer-url flag.
	// Discovery information is fetched from "{url}/.well-known/openid-configuration" unless overridden by discoveryURL.
	// Required to be unique across all JWT authenticators.
	// Note that egress selection configuration is not used for this network connection.
	// +required
	URL string
	// discoveryURL, if specified, overrides the URL used to fetch discovery
	// information instead of using "{url}/.well-known/openid-configuration".
	// The exact value specified is used, so "/.well-known/openid-configuration"
	// must be included in discoveryURL if needed.
	//
	// The "issuer" field in the fetched discovery information must match the "issuer.url" field
	// in the AuthenticationConfiguration and will be used to validate the "iss" claim in the presented JWT.
	// This is for scenarios where the well-known and jwks endpoints are hosted at a different
	// location than the issuer (such as locally in the cluster).
	//
	// Example:
	// A discovery url that is exposed using kubernetes service 'oidc' in namespace 'oidc-namespace'
	// and discovery information is available at '/.well-known/openid-configuration'.
	// discoveryURL: "https://oidc.oidc-namespace/.well-known/openid-configuration"
	// certificateAuthority is used to verify the TLS connection and the hostname on the leaf certificate
	// must be set to 'oidc.oidc-namespace'.
	//
	// curl https://oidc.oidc-namespace/.well-known/openid-configuration (.discoveryURL field)
	// {
	//     issuer: "https://oidc.example.com" (.url field)
	// }
	//
	// discoveryURL must be different from url.
	// Required to be unique across all JWT authenticators.
	// Note that egress selection configuration is not used for this network connection.
	// +optional
	DiscoveryURL         string
	CertificateAuthority string
	Audiences            []string
	AudienceMatchPolicy  AudienceMatchPolicyType
	EgressSelectorType   EgressSelectorType
}

// AudienceMatchPolicyType is a set of valid values for Issuer.AudienceMatchPolicy
type AudienceMatchPolicyType string

// Valid types for AudienceMatchPolicyType
const (
	AudienceMatchPolicyMatchAny AudienceMatchPolicyType = "MatchAny"
)

type EgressSelectorType string

const (
	EgressSelectorControlPlane EgressSelectorType = "controlplane"

	EgressSelectorCluster EgressSelectorType = "cluster"
)

// ClaimValidationRule provides the configuration for a single claim validation rule.
type ClaimValidationRule struct {
	Claim         string
	RequiredValue string

	Expression string
	Message    string
}

// ClaimMappings provides the configuration for claim mapping
type ClaimMappings struct {
	Username PrefixedClaimOrExpression
	Groups   PrefixedClaimOrExpression
	UID      ClaimOrExpression
	Extra    []ExtraMapping
}

// PrefixedClaimOrExpression provides the configuration for a single prefixed claim or expression.
type PrefixedClaimOrExpression struct {
	Claim  string
	Prefix *string

	Expression string
}

// ClaimOrExpression provides the configuration for a single claim or expression.
type ClaimOrExpression struct {
	Claim      string
	Expression string
}

// ExtraMapping provides the configuration for a single extra mapping.
type ExtraMapping struct {
	Key             string
	ValueExpression string
}

// UserValidationRule provides the configuration for a single user validation rule.
type UserValidationRule struct {
	Expression string
	Message    string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AuthorizationConfiguration struct {
	metav1.TypeMeta

	// Authorizers is an ordered list of authorizers to
	// authorize requests against.
	// This is similar to the --authorization-modes kube-apiserver flag
	// Must be at least one.
	Authorizers []AuthorizerConfiguration `json:"authorizers"`
}

const (
	TypeWebhook                                          AuthorizerType = "Webhook"
	FailurePolicyNoOpinion                               string         = "NoOpinion"
	FailurePolicyDeny                                    string         = "Deny"
	AuthorizationWebhookConnectionInfoTypeKubeConfigFile string         = "KubeConfigFile"
	AuthorizationWebhookConnectionInfoTypeInCluster      string         = "InClusterConfig"
)

type AuthorizerType string

type AuthorizerConfiguration struct {
	// Type refers to the type of the authorizer
	// "Webhook" is supported in the generic API server
	// Other API servers may support additional authorizer
	// types like Node, RBAC, ABAC, etc.
	Type AuthorizerType

	// Name used to describe the webhook
	// This is explicitly used in monitoring machinery for metrics
	// Note: Names must be DNS1123 labels like `myauthorizername` or
	//		 subdomains like `myauthorizer.example.domain`
	// Required, with no default
	Name string

	// Webhook defines the configuration for a Webhook authorizer
	// Must be defined when Type=Webhook
	Webhook *WebhookConfiguration
}

type WebhookConfiguration struct {
	// The duration to cache 'authorized' responses from the webhook
	// authorizer.
	// Same as setting `--authorization-webhook-cache-authorized-ttl` flag
	// Default: 5m0s
	AuthorizedTTL metav1.Duration
	// CacheAuthorizedRequests specifies whether authorized requests should be cached.
	// If set to true, the TTL for cached decisions can be configured via the
	// AuthorizedTTL field.
	// Default: true
	CacheAuthorizedRequests bool
	// The duration to cache 'unauthorized' responses from the webhook
	// authorizer.
	// Same as setting `--authorization-webhook-cache-unauthorized-ttl` flag
	// Default: 30s
	UnauthorizedTTL metav1.Duration
	// CacheUnauthorizedRequests specifies whether unauthorized requests should be cached.
	// If set to true, the TTL for cached decisions can be configured via the
	// UnauthorizedTTL field.
	// Default: true
	CacheUnauthorizedRequests bool
	// Timeout for the webhook request
	// Maximum allowed value is 30s.
	// Required, no default value.
	Timeout metav1.Duration
	// The API version of the authorization.k8s.io SubjectAccessReview to
	// send to and expect from the webhook.
	// Same as setting `--authorization-webhook-version` flag
	// Valid values: v1beta1, v1
	// Required, no default value
	SubjectAccessReviewVersion string
	// MatchConditionSubjectAccessReviewVersion specifies the SubjectAccessReview
	// version the CEL expressions are evaluated against
	// Valid values: v1
	// Required, no default value
	MatchConditionSubjectAccessReviewVersion string
	// Controls the authorization decision when a webhook request fails to
	// complete or returns a malformed response or errors evaluating
	// matchConditions.
	// Valid values:
	//   - NoOpinion: continue to subsequent authorizers to see if one of
	//     them allows the request
	//   - Deny: reject the request without consulting subsequent authorizers
	// Required, with no default.
	FailurePolicy string

	// ConnectionInfo defines how we talk to the webhook
	ConnectionInfo WebhookConnectionInfo

	// matchConditions is a list of conditions that must be met for a request to be sent to this
	// webhook. An empty list of matchConditions matches all requests.
	// There are a maximum of 64 match conditions allowed.
	//
	// The exact matching logic is (in order):
	//   1. If at least one matchCondition evaluates to FALSE, then the webhook is skipped.
	//   2. If ALL matchConditions evaluate to TRUE, then the webhook is called.
	//   3. If at least one matchCondition evaluates to an error (but none are FALSE):
	//      - If failurePolicy=Deny, then the webhook rejects the request
	//      - If failurePolicy=NoOpinion, then the error is ignored and the webhook is skipped
	MatchConditions []WebhookMatchCondition
}

type WebhookConnectionInfo struct {
	// Controls how the webhook should communicate with the server.
	// Valid values:
	// - KubeConfigFile: use the file specified in kubeConfigFile to locate the
	//   server.
	// - InClusterConfig: use the in-cluster configuration to call the
	//   SubjectAccessReview API hosted by kube-apiserver. This mode is not
	//   allowed for kube-apiserver.
	Type string

	// Path to KubeConfigFile for connection info
	// Required, if connectionInfo.Type is KubeConfig
	KubeConfigFile *string
}

type WebhookMatchCondition struct {
	// expression represents the expression which will be evaluated by CEL. Must evaluate to bool.
	// CEL expressions have access to the contents of the SubjectAccessReview in v1 version.
	// If version specified by subjectAccessReviewVersion in the request variable is v1beta1,
	// the contents would be converted to the v1 version before evaluating the CEL expression.
	//
	// - 'resourceAttributes' describes information for a resource access request and is unset for non-resource requests. e.g. has(request.resourceAttributes) && request.resourceAttributes.namespace == 'default'
	// - 'nonResourceAttributes' describes information for a non-resource access request and is unset for resource requests. e.g. has(request.nonResourceAttributes) && request.nonResourceAttributes.path == '/healthz'.
	// - 'user' is the user to test for. e.g. request.user == 'alice'
	// - 'groups' is the groups to test for. e.g. ('group1' in request.groups)
	// - 'extra' corresponds to the user.Info.GetExtra() method from the authenticator.
	// - 'uid' is the information about the requesting user. e.g. request.uid == '1'
	//
	// Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/
	Expression string
}

// HTTPSignatureConfig provides the configuration for authenticating requests by
// HTTP message signature (RFC 9421).
//
// What sits here rather than on each authenticator is this server's description of
// itself as clients experience it; what sits on an authenticator is trust policy
// for one backend. Authority and Scheme are additionally consumed before any
// authenticator has been selected, when the request's signatures are parsed, so
// they could not be per-authenticator without parsing every signature once per
// authenticator.
type HTTPSignatureConfig struct {
	// Authority and Scheme are the external values clients sign, for a server
	// behind a TLS-terminating proxy or load balancer. Unset means they are
	// derived from the connection, which is correct only when clients reach
	// this server directly. The Forwarded and X-Forwarded-* fields are
	// unsigned input and are never consulted.
	Authority string
	Scheme    string

	// MaxClockSkew is added to every time comparison, to allow for the signer's
	// clock differing from this server's. Unset means none.
	//
	// A verifier cannot measure a client's clock, so this is a risk budget whose
	// justification is this server's own time synchronisation. That is one fact
	// with one answer, which is why it is not per authenticator.
	MaxClockSkew *metav1.Duration

	// Authenticators are attempted in the order given. Which ones handle a
	// signature is decided before any work is done for it: a keyid in the
	// certificate form selects the single authenticator holding the trust anchor
	// the presented certificate's authorityKeyIdentifier names, and any other keyid
	// selects the resolver authenticators whose key ID prefixes admit it.
	Authenticators []HTTPSignatureAuthenticator
}

// HTTPSignatureAuthenticator is one way of resolving a signature's keyid to a
// verification key and an identity. Exactly one of Resolver or X509 is set.
//
// Neither states an identity in configuration. Resolver names a process, which
// answers for a key ID with the key that verifies signatures bearing it and the
// identity it authenticates as, and which records the nonces those signatures
// carry. X509 takes both key and identity from a certificate the request
// carries, which the configured trust anchors have to validate.
//
// Either way the identity is a claim rather than a conclusion: this server refuses
// the three names it asserts itself, and UserValidationRules is where a cluster
// states what else an authenticator may not claim.
//
// A field that means something to only one of the two lives in that one's
// struct. Only what applies to both is stated here.
type HTTPSignatureAuthenticator struct {
	// Name identifies this authenticator in errors and metrics. Required to be
	// unique. It never appears on the wire.
	Name string

	// Resolver takes the verification key and the identity from a process this
	// server calls over a Unix domain socket.
	Resolver *HTTPSignatureResolver

	// X509 takes the verification key and the identity from a certificate the
	// request carries in the Signature-Certificate header, validated against this
	// authenticator's trust anchors.
	X509 *HTTPSignatureX509

	// MaxAge bounds how old a signature may be, measured from its created
	// parameter. Unset means five minutes.
	//
	// With Resolver and the default nonce handling, replay is closed by the
	// resolver recording nonces rather than by this, and what this bounds is how
	// stale a request may be, and so how long a resolver has to remember a nonce.
	//
	// With X509, or with NonceHandling Ignore, nothing records nonces and this
	// plus MaxClockSkew is the entire replay window: a captured request can be
	// replayed within it against every API server without limit.
	MaxAge *metav1.Duration

	// UserValidationRules are applied to the identity before authentication
	// completes, whichever backend produced it, and all must pass. They are the
	// cluster's say over what an authenticator may claim, which matters because
	// neither backend states an identity in configuration.
	//
	// There is no default rule. An authenticator with none stated may assert any
	// name outside the three the server reserves for itself.
	UserValidationRules []UserValidationRule
}

// HTTPSignatureResolver resolves a signature's verification key and identity
// through a process this server calls over a Unix domain socket.
//
// The resolver answers what configuration cannot: which key verifies signatures
// bearing a key ID, who that key authenticates as, and whether a nonce has
// already been used for that key. The last of those closes replay across every
// API server in the cluster, which no certificate can do.
type HTTPSignatureResolver struct {
	// Endpoint is the resolver's Unix domain socket, as unix:///path/to/socket,
	// or unix://@name for a Linux abstract socket.
	//
	// The connection carries no TLS and this server does not authenticate the
	// resolver. Access to the socket is the whole trust boundary.
	Endpoint string

	// KeyIDPrefixes narrows which key IDs this resolver is asked about, matched
	// against the segment before a key ID's first "/". Unset means every key ID.
	//
	// Resolvers are consulted in order, so a key ID no resolver serves costs one
	// call per resolver whose prefixes admit it, driven by a caller who has
	// authenticated nothing.
	KeyIDPrefixes []string

	// RelayedHeaders names request headers whose values are sent to this resolver
	// with a key lookup. Nothing else about the request is sent.
	//
	// A named header present but not covered by the signature rejects the request
	// before any lookup. Covered is not verified: at lookup time the value is
	// still a claim. Headers with their own configuration path elsewhere may not
	// be named.
	RelayedHeaders []string

	// NonceHandling says whether this server asks the resolver to record the nonce
	// each accepted signature carries. The zero value means Consume, so replay
	// protection is on unless it is turned off in so many words.
	//
	// Ignore makes the replay window MaxAge plus MaxClockSkew, during which a
	// captured request can be replayed against every API server without limit.
	NonceHandling NonceHandling

	// Cache bounds what this server remembers of this resolver's answers.
	Cache *HTTPSignatureResolverCache
}

// HTTPSignatureX509 resolves a signature's key and identity from an X.509
// certificate the request carries, rather than from configuration.
//
// This is mutual TLS with the handshake replaced by a message signature. The
// same certificate authority, the same issuance, and the same subject
// conventions apply; only the point of authentication moves into the message,
// which is what lets it survive a TLS-terminating hop.
//
// The certificate is bound to the signature by the keyid, which has to be
// "x509-sha256:" followed by the hex SHA-256 digest of the leaf's DER encoding.
// A signature's parameters are always part of its signature base, so a keyid
// that names the certificate binds the certificate without any header coverage
// rule. The header is covered as well, but that is belt and braces.
type HTTPSignatureX509 struct {
	// CertificateAuthority contains PEM-encoded certificate authority
	// certificates that a presented certificate must chain to. A certificate
	// authority is public trust material, so it is stated inline rather than
	// referenced by path.
	//
	// Point this at a certificate authority issued for this purpose. Pointing
	// it at the cluster's client certificate authority would give every
	// certificate already issued for connection authentication the ability to
	// sign detached messages, which its issuer never agreed to and nobody opted
	// in to.
	CertificateAuthority string

	// CertificateValidationRules constrain which certificates this
	// authenticator accepts, beyond chaining to its trust anchors. They run
	// before ClaimMappings, so a mapping expression never sees a certificate no
	// rule has vetted.
	CertificateValidationRules []CertificateValidationRule

	// ClaimMappings derives the user attributes from the certificate. Required,
	// because the identity comes from the certificate rather than from
	// configuration.
	ClaimMappings *HTTPSignatureClaimMappings

	// Cache holds the results of successful certificate validation, so a client's
	// second request does not repeat the chain build and the CEL evaluation its
	// first one paid for.
	Cache *HTTPSignatureX509Cache
}

// HTTPSignatureX509Cache bounds the memoization of certificate validation. Only
// successful validations are cached. A negative cache would be keyed on bytes a
// peer chooses, which is unbounded cardinality for anyone who can send a
// request, and it would buy nothing: an untrusted certificate is rejected by one
// chain build.
//
// Caching the mapped identity, rather than only the key, is sound because the
// mapping is a pure function of the certificate. The CEL environment declares no
// clock and no request-scoped variable, so no expression can produce a different
// answer for the same certificate at a different time.
type HTTPSignatureX509Cache struct {
	// MaxEntries caps how many validated certificates are remembered. Unset
	// means 1024. Eviction costs the evicted client one revalidation.
	MaxEntries *int32

	// TTL bounds how long a validation is trusted, and is therefore the window
	// in which withdrawing a certificate has no effect. Unset means five
	// minutes.
	//
	// The effective lifetime of an entry is the smallest of this, the time
	// remaining on the leaf, and the time remaining on every certificate in the
	// validated chain. Without the chain bound, a TTL longer than a trust
	// anchor's remaining life would keep admitting past the anchor's expiry.
	TTL *metav1.Duration
}

// CertificateValidationRule is one CEL rule a presented certificate must
// satisfy. Rules are logically ANDed.
type CertificateValidationRule struct {
	// Expression is evaluated by CEL and must return true for the certificate
	// to be accepted.
	//
	// Expressions have access to the certificate as the CEL variable 'cert', a
	// kubernetes.Certificate. Nothing else is in scope: there is no clock and no
	// request, which is what makes the result cacheable per certificate.
	Expression string

	// Message customizes the error returned when Expression returns false.
	Message string
}

// HTTPSignatureClaimMappings maps a certificate's attributes onto the user
// attributes a request authenticates as.
//
// Mappings are expressions and never field references. A certificate is not a
// map of names to values the way a token's claim set is, so there is no
// equivalent of the JWT authenticator's claim form. The name is kept for the
// analogy with that authenticator, which is what a reader will look for.
//
// No prefix is applied to any mapped value. An administrator owns avoiding
// collision with the names other authenticators issue, and an expression can
// prepend a literal where a prefix is wanted.
type HTTPSignatureClaimMappings struct {
	// Username is the mapped user name. Required. The expression must produce a
	// non-empty string.
	Username HTTPSignatureClaimExpression

	// Groups are the mapped groups. The expression must produce a string or a
	// list of strings; "", [], and null are treated as no groups.
	Groups HTTPSignatureClaimExpression

	// UID is the mapped user UID. The expression must produce a string.
	UID HTTPSignatureClaimExpression

	// Extra are mapped extra attributes.
	Extra []ExtraMapping
}

// HTTPSignatureClaimExpression is one CEL expression over the certificate. It is
// a struct rather than a bare string so that the field reads the same as the JWT
// authenticator's equivalent.
type HTTPSignatureClaimExpression struct {
	// Expression is evaluated by CEL against the 'cert' variable.
	Expression string
}

// HTTPSignatureResolverCache bounds what this server remembers of a resolver's
// answers. A key ID is chosen by the peer, so neither cache may grow with the
// number of distinct ones.
type HTTPSignatureResolverCache struct {
	// MaxKeys caps the entries in each of the two caches kept per resolver: keys
	// it resolved, and key IDs it said it does not serve. Unset means 1024. The
	// two are separate so a flood of unknown key IDs cannot evict working keys.
	MaxKeys *int32

	// MaxAge caps how long a resolved key is reused, capping the duration the
	// resolver states with each answer. Unset means five minutes. A cached key
	// outlives its revocation, so this is the revocation window.
	MaxAge *metav1.Duration

	// NegativeMaxAge is how long this server remembers that a resolver does not
	// serve a key ID. Unset means ten seconds. A resolver cannot state this
	// itself, because not-found is a status rather than an answer with fields.
	NegativeMaxAge *metav1.Duration
}

// NonceHandling says what this server does with the nonce a signature carries.
//
// There is no per-API-server option, and its absence is a decision rather than an
// omission. A nonce remembered in one process is not replay protection: with several
// API servers and no shared state, a captured request can be replayed once against
// each one that has not seen it. Offering that would be offering a guarantee that
// does not hold, so the choice is between one shared record and none.
type NonceHandling string

const (
	// NonceHandlingConsume asks the resolver to record every accepted signature's
	// nonce, and rejects the request if it cannot. This is the default, and it is
	// what closes replay across more than one API server.
	NonceHandlingConsume NonceHandling = "Consume"

	// NonceHandlingIgnore skips the call. The nonce is still required on the
	// signature and still covered by it; nothing tracks whether it has been seen.
	//
	// This exists because the alternative was worse. Without it, a deployment whose
	// resolver has no nonce store has to implement ConsumeNonce as a stub that
	// always accepts, which is a resolver that lies about the RPC's contract, costs
	// a round trip per request, and leaves nothing in this file to say that replay
	// protection is off. Stating it here is legible; hiding it in a resolver is not.
	NonceHandlingIgnore NonceHandling = "Ignore"
)
