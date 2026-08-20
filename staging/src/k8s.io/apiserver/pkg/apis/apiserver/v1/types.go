/*
Copyright 2019 The Kubernetes Authors.

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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	tracingapi "k8s.io/component-base/tracing/api/v1"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AdmissionConfiguration provides versioned configuration for admission controllers.
type AdmissionConfiguration struct {
	metav1.TypeMeta `json:""`

	// Plugins allows specifying a configuration per admission control plugin.
	// +optional
	Plugins []AdmissionPluginConfiguration `json:"plugins"`
}

// AdmissionPluginConfiguration provides the configuration for a single plug-in.
type AdmissionPluginConfiguration struct {
	// Name is the name of the admission controller.
	// It must match the registered admission plugin name.
	Name string `json:"name"`

	// Path is the path to a configuration file that contains the plugin's
	// configuration
	// +optional
	Path string `json:"path"`

	// Configuration is an embedded configuration object to be used as the plugin's
	// configuration. If present, it will be used instead of the path to the configuration file.
	// +optional
	Configuration *runtime.Unknown `json:"configuration"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AuthenticationConfiguration provides versioned configuration for authentication.
type AuthenticationConfiguration struct {
	metav1.TypeMeta `json:""`

	// jwt is a list of authenticator to authenticate Kubernetes users using
	// JWT compliant tokens. The authenticator will attempt to parse a raw ID token,
	// verify it's been signed by the configured issuer. The public key to verify the
	// signature is discovered from the issuer's public endpoint using OIDC discovery.
	// For an incoming token, each JWT authenticator will be attempted in
	// the order in which it is specified in this list.  Note however that
	// other authenticators may run before or after the JWT authenticators.
	// The specific position of JWT authenticators in relation to other
	// authenticators is neither defined nor stable across releases.  Since
	// each JWT authenticator must have a unique issuer URL, at most one
	// JWT authenticator will attempt to cryptographically validate the token.
	//
	// The minimum valid JWT payload must contain the following claims:
	// {
	//		"iss": "https://issuer.example.com",
	//		"aud": ["audience"],
	//		"exp": 1234567890,
	//		"<username claim>": "username"
	// }
	JWT []JWTAuthenticator `json:"jwt"`

	// If present --anonymous-auth must not be set
	Anonymous *AnonymousAuthConfig `json:"anonymous,omitempty"`

	// httpSignature authenticates requests by HTTP message signature
	// (RFC 9421) rather than by a credential the client sends.
	//
	// Each entry names a resolver that answers, for a key ID, which key verifies
	// signatures bearing it and whose identity it is. Entries are consulted in
	// the order given.
	//
	// Requires the HTTPSignatureAuthentication feature gate.
	// +featureGate=HTTPSignatureAuthentication
	// +optional
	HTTPSignature *HTTPSignatureConfig `json:"httpSignature,omitempty"`
}

// AnonymousAuthConfig provides the configuration for the anonymous authenticator.
type AnonymousAuthConfig struct {
	Enabled bool `json:"enabled"`

	// If set, anonymous auth is only allowed if the request meets one of the
	// conditions.
	Conditions []AnonymousAuthCondition `json:"conditions,omitempty"`
}

// AnonymousAuthCondition describes the condition under which anonymous auth
// should be enabled.
type AnonymousAuthCondition struct {
	// Path for which anonymous auth is enabled.
	Path string `json:"path"`
}

// JWTAuthenticator provides the configuration for a single JWT authenticator.
type JWTAuthenticator struct {
	// issuer contains the basic OIDC provider connection options.
	// +required
	Issuer Issuer `json:"issuer"`

	// claimValidationRules are rules that are applied to validate token claims to authenticate users.
	// +optional
	ClaimValidationRules []ClaimValidationRule `json:"claimValidationRules,omitempty"`

	// claimMappings points claims of a token to be treated as user attributes.
	// +required
	ClaimMappings ClaimMappings `json:"claimMappings"`

	// userValidationRules are rules that are applied to final user before completing authentication.
	// These allow invariants to be applied to incoming identities such as preventing the
	// use of the system: prefix that is commonly used by Kubernetes components.
	// The validation rules are logically ANDed together and must all return true for the validation to pass.
	// +optional
	UserValidationRules []UserValidationRule `json:"userValidationRules,omitempty"`
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
	URL string `json:"url"`

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
	DiscoveryURL *string `json:"discoveryURL,omitempty"`

	// certificateAuthority contains PEM-encoded certificate authority certificates
	// used to validate the connection when fetching discovery information.
	// If unset, the system verifier is used.
	// Same value as the content of the file referenced by the --oidc-ca-file flag.
	// +optional
	CertificateAuthority string `json:"certificateAuthority,omitempty"`

	// audiences is the set of acceptable audiences the JWT must be issued to.
	// At least one of the entries must match the "aud" claim in presented JWTs.
	// Same value as the --oidc-client-id flag (though this field supports an array).
	// Required to be non-empty.
	// +required
	Audiences []string `json:"audiences"`

	// audienceMatchPolicy defines how the "audiences" field is used to match the "aud" claim in the presented JWT.
	// Allowed values are:
	// 1. "MatchAny" when multiple audiences are specified and
	// 2. empty (or unset) or "MatchAny" when a single audience is specified.
	//
	// - MatchAny: the "aud" claim in the presented JWT must match at least one of the entries in the "audiences" field.
	// For example, if "audiences" is ["foo", "bar"], the "aud" claim in the presented JWT must contain either "foo" or "bar" (and may contain both).
	//
	// - "": The match policy can be empty (or unset) when a single audience is specified in the "audiences" field. The "aud" claim in the presented JWT must contain the single audience (and may contain others).
	//
	// For more nuanced audience validation, use claimValidationRules.
	//   example: claimValidationRule[].expression: 'sets.equivalent(claims.aud, ["bar", "foo", "baz"])' to require an exact match.
	// +optional
	AudienceMatchPolicy AudienceMatchPolicyType `json:"audienceMatchPolicy,omitempty"`

	// egressSelectorType is an indicator of which egress selection should be used for sending all traffic related
	// to this issuer (discovery, JWKS, distributed claims, etc).  If unspecified, no custom dialer is used.
	// When specified, the valid choices are "controlplane" and "cluster".  These correspond to the associated
	// values in the --egress-selector-config-file.
	//
	// - controlplane: for traffic intended to go to the control plane.
	//
	// - cluster: for traffic intended to go to the system being managed by Kubernetes.
	//
	// +optional
	EgressSelectorType EgressSelectorType `json:"egressSelectorType,omitempty"`
}

// AudienceMatchPolicyType is a set of valid values for issuer.audienceMatchPolicy
type AudienceMatchPolicyType string

// Valid types for AudienceMatchPolicyType
const (
	// MatchAny means the "aud" claim in the presented JWT must match at least one of the entries in the "audiences" field.
	AudienceMatchPolicyMatchAny AudienceMatchPolicyType = "MatchAny"
)

// EgressSelectorType is an indicator of which egress selection should be used for sending traffic.
type EgressSelectorType string

const (
	// EgressSelectorControlPlane is the EgressSelectorType for traffic intended to go to the control plane.
	EgressSelectorControlPlane EgressSelectorType = "controlplane"

	// EgressSelectorCluster is the EgressSelectorType for traffic intended to go to the system being managed by Kubernetes.
	EgressSelectorCluster EgressSelectorType = "cluster"
)

// ClaimValidationRule provides the configuration for a single claim validation rule.
type ClaimValidationRule struct {
	// claim is the name of a required claim.
	// Same as --oidc-required-claim flag.
	// Only string claim keys are supported.
	// Mutually exclusive with expression and message.
	// +optional
	Claim string `json:"claim,omitempty"`
	// requiredValue is the value of a required claim.
	// Same as --oidc-required-claim flag.
	// Only string claim values are supported.
	// If claim is set and requiredValue is not set, the claim must be present with a value set to the empty string.
	// Mutually exclusive with expression and message.
	// +optional
	RequiredValue string `json:"requiredValue,omitempty"`

	// expression represents the expression which will be evaluated by CEL.
	// Must produce a boolean.
	//
	// CEL expressions have access to the contents of the token claims, organized into CEL variable:
	// - 'claims' is a map of claim names to claim values.
	//   For example, a variable named 'sub' can be accessed as 'claims.sub'.
	//   Nested claims can be accessed using dot notation, e.g. 'claims.foo.bar'.
	// Must return true for the validation to pass.
	//
	// Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/
	//
	// Mutually exclusive with claim and requiredValue.
	// +optional
	Expression string `json:"expression,omitempty"`
	// message customizes the returned error message when expression returns false.
	// message is a literal string.
	// Mutually exclusive with claim and requiredValue.
	// +optional
	Message string `json:"message,omitempty"`
}

// ClaimMappings provides the configuration for claim mapping
type ClaimMappings struct {
	// username represents an option for the username attribute.
	// The claim's value must be a singular string.
	// Same as the --oidc-username-claim and --oidc-username-prefix flags.
	// If username.expression is set, the expression must produce a string value.
	// If username.expression uses 'claims.email', then 'claims.email_verified' must be used in
	// username.expression or extra[*].valueExpression or claimValidationRules[*].expression.
	// An example claim validation rule expression that matches the validation automatically
	// applied when username.claim is set to 'email' is 'claims.?email_verified.orValue(true) == true'. By explicitly comparing
	// the value to true, we let type-checking see the result will be a boolean, and to make sure a non-boolean email_verified
	// claim will be caught at runtime.
	//
	// In the flag based approach, the --oidc-username-claim and --oidc-username-prefix are optional. If --oidc-username-claim is not set,
	// the default value is "sub". For the authentication config, there is no defaulting for claim or prefix. The claim and prefix must be set explicitly.
	// For claim, if --oidc-username-claim was not set with legacy flag approach, configure username.claim="sub" in the authentication config.
	// For prefix:
	//     (1) --oidc-username-prefix="-", no prefix was added to the username. For the same behavior using authentication config,
	//         set username.prefix=""
	//     (2) --oidc-username-prefix="" and  --oidc-username-claim != "email", prefix was "<value of --oidc-issuer-url>#". For the same
	//         behavior using authentication config, set username.prefix="<value of issuer.url>#"
	//     (3) --oidc-username-prefix="<value>". For the same behavior using authentication config, set username.prefix="<value>"
	// +required
	Username PrefixedClaimOrExpression `json:"username"`
	// groups represents an option for the groups attribute.
	// The claim's value must be a string or string array claim.
	// If groups.claim is set, the prefix must be specified (and can be the empty string).
	// If groups.expression is set, the expression must produce a string or string array value.
	//  "", [], and null values are treated as the group mapping not being present.
	// +optional
	Groups PrefixedClaimOrExpression `json:"groups,omitempty"`

	// uid represents an option for the uid attribute.
	// Claim must be a singular string claim.
	// If uid.expression is set, the expression must produce a string value.
	// +optional
	UID ClaimOrExpression `json:"uid"`

	// extra represents an option for the extra attribute.
	// expression must produce a string or string array value.
	// If the value is empty, the extra mapping will not be present.
	//
	// hard-coded extra key/value
	// - key: "foo"
	//   valueExpression: "'bar'"
	// This will result in an extra attribute - foo: ["bar"]
	//
	// hard-coded key, value copying claim value
	// - key: "foo"
	//   valueExpression: "claims.some_claim"
	// This will result in an extra attribute - foo: [value of some_claim]
	//
	// hard-coded key, value derived from claim value
	// - key: "admin"
	//   valueExpression: '(has(claims.is_admin) && claims.is_admin) ? "true":""'
	// This will result in:
	//  - if is_admin claim is present and true, extra attribute - admin: ["true"]
	//  - if is_admin claim is present and false or is_admin claim is not present, no extra attribute will be added
	//
	// +optional
	Extra []ExtraMapping `json:"extra,omitempty"`
}

// PrefixedClaimOrExpression provides the configuration for a single prefixed claim or expression.
type PrefixedClaimOrExpression struct {
	// claim is the JWT claim to use.
	// Mutually exclusive with expression.
	// +optional
	Claim string `json:"claim,omitempty"`
	// prefix is prepended to claim's value to prevent clashes with existing names.
	// prefix needs to be set if claim is set and can be the empty string.
	// Mutually exclusive with expression.
	// +optional
	Prefix *string `json:"prefix,omitempty"`

	// expression represents the expression which will be evaluated by CEL.
	//
	// CEL expressions have access to the contents of the token claims, organized into CEL variable:
	// - 'claims' is a map of claim names to claim values.
	//   For example, a variable named 'sub' can be accessed as 'claims.sub'.
	//   Nested claims can be accessed using dot notation, e.g. 'claims.foo.bar'.
	//
	// Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/
	//
	// Mutually exclusive with claim and prefix.
	// +optional
	Expression string `json:"expression,omitempty"`
}

// ClaimOrExpression provides the configuration for a single claim or expression.
type ClaimOrExpression struct {
	// claim is the JWT claim to use.
	// Either claim or expression must be set.
	// Mutually exclusive with expression.
	// +optional
	Claim string `json:"claim,omitempty"`

	// expression represents the expression which will be evaluated by CEL.
	//
	// CEL expressions have access to the contents of the token claims, organized into CEL variable:
	// - 'claims' is a map of claim names to claim values.
	//   For example, a variable named 'sub' can be accessed as 'claims.sub'.
	//   Nested claims can be accessed using dot notation, e.g. 'claims.foo.bar'.
	//
	// Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/
	//
	// Mutually exclusive with claim.
	// +optional
	Expression string `json:"expression,omitempty"`
}

// ExtraMapping provides the configuration for a single extra mapping.
type ExtraMapping struct {
	// key is a string to use as the extra attribute key.
	// key must be a domain-prefix path (e.g. example.org/foo). All characters before the first "/" must be a valid
	// subdomain as defined by RFC 1123. All characters trailing the first "/" must
	// be valid HTTP Path characters as defined by RFC 3986.
	// key must be lowercase.
	// Required to be unique.
	// +required
	Key string `json:"key"`

	// valueExpression is a CEL expression to extract extra attribute value.
	// valueExpression must produce a string or string array value.
	// "", [], and null values are treated as the extra mapping not being present.
	// Empty string values contained within a string array are filtered out.
	//
	// CEL expressions have access to the contents of the token claims, organized into CEL variable:
	// - 'claims' is a map of claim names to claim values.
	//   For example, a variable named 'sub' can be accessed as 'claims.sub'.
	//   Nested claims can be accessed using dot notation, e.g. 'claims.foo.bar'.
	//
	// Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/
	//
	// +required
	ValueExpression string `json:"valueExpression"`
}

// UserValidationRule provides the configuration for a single user info validation rule.
type UserValidationRule struct {
	// expression represents the expression which will be evaluated by CEL.
	// Must return true for the validation to pass.
	//
	// CEL expressions have access to the contents of UserInfo, organized into CEL variable:
	// - 'user' - authentication.k8s.io/v1, Kind=UserInfo object
	//    Refer to https://github.com/kubernetes/api/blob/release-1.28/authentication/v1/types.go#L105-L122 for the definition.
	//    API documentation: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.28/#userinfo-v1-authentication-k8s-io
	//
	// Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/
	//
	// +required
	Expression string `json:"expression"`

	// message customizes the returned error message when rule returns false.
	// message is a literal string.
	// +optional
	Message string `json:"message,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

type AuthorizationConfiguration struct {
	metav1.TypeMeta `json:""`

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
	Type string `json:"type"`

	// Name used to describe the webhook
	// This is explicitly used in monitoring machinery for metrics
	// Note: Names must be DNS1123 labels like `myauthorizername` or
	//		 subdomains like `myauthorizer.example.domain`
	// Required, with no default
	Name string `json:"name"`

	// Webhook defines the configuration for a Webhook authorizer
	// Must be defined when Type=Webhook
	// Must not be defined when Type!=Webhook
	Webhook *WebhookConfiguration `json:"webhook,omitempty"`
}

type WebhookConfiguration struct {
	// The duration to cache 'authorized' responses from the webhook
	// authorizer.
	// Same as setting `--authorization-webhook-cache-authorized-ttl` flag
	// Default: 5m0s
	AuthorizedTTL metav1.Duration `json:"authorizedTTL"`
	// CacheAuthorizedRequests specifies whether authorized requests should be cached.
	// If set to true, the TTL for cached decisions can be configured via the
	// AuthorizedTTL field.
	// Default: true
	// +optional
	CacheAuthorizedRequests *bool `json:"cacheAuthorizedRequests,omitempty"`
	// The duration to cache 'unauthorized' responses from the webhook
	// authorizer.
	// Same as setting `--authorization-webhook-cache-unauthorized-ttl` flag
	// Default: 30s
	UnauthorizedTTL metav1.Duration `json:"unauthorizedTTL"`
	// CacheUnauthorizedRequests specifies whether unauthorized requests should be cached.
	// If set to true, the TTL for cached decisions can be configured via the
	// UnauthorizedTTL field.
	// Default: true
	// +optional
	CacheUnauthorizedRequests *bool `json:"cacheUnauthorizedRequests,omitempty"`
	// Timeout for the webhook request
	// Maximum allowed value is 30s.
	// Required, no default value.
	Timeout metav1.Duration `json:"timeout"`
	// The API version of the authorization.k8s.io SubjectAccessReview to
	// send to and expect from the webhook.
	// Same as setting `--authorization-webhook-version` flag
	// Valid values: v1beta1, v1
	// Required, no default value
	SubjectAccessReviewVersion string `json:"subjectAccessReviewVersion"`
	// MatchConditionSubjectAccessReviewVersion specifies the SubjectAccessReview
	// version the CEL expressions are evaluated against
	// Valid values: v1
	// Required, no default value
	MatchConditionSubjectAccessReviewVersion string `json:"matchConditionSubjectAccessReviewVersion"`
	// Controls the authorization decision when a webhook request fails to
	// complete or returns a malformed response or errors evaluating
	// matchConditions.
	// Valid values:
	//   - NoOpinion: continue to subsequent authorizers to see if one of
	//     them allows the request
	//   - Deny: reject the request without consulting subsequent authorizers
	// Required, with no default.
	FailurePolicy string `json:"failurePolicy"`

	// ConnectionInfo defines how we talk to the webhook
	ConnectionInfo WebhookConnectionInfo `json:"connectionInfo"`

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
	MatchConditions []WebhookMatchCondition `json:"matchConditions"`
}

type WebhookConnectionInfo struct {
	// Controls how the webhook should communicate with the server.
	// Valid values:
	// - KubeConfigFile: use the file specified in kubeConfigFile to locate the
	//   server.
	// - InClusterConfig: use the in-cluster configuration to call the
	//   SubjectAccessReview API hosted by kube-apiserver. This mode is not
	//   allowed for kube-apiserver.
	Type string `json:"type"`

	// Path to KubeConfigFile for connection info
	// Required, if connectionInfo.Type is KubeConfig
	KubeConfigFile *string `json:"kubeConfigFile"`
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
	Expression string `json:"expression"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// TracingConfiguration provides versioned configuration for tracing clients.
type TracingConfiguration struct {
	metav1.TypeMeta `json:""`

	// Embed the component config tracing configuration struct
	tracingapi.TracingConfiguration `json:""`
}

// HTTPSignatureConfig provides the configuration for authenticating requests by
// HTTP message signature (RFC 9421). A client signs each request over its
// method, authority, path, query, body digest, and selected headers, so no
// credential is sent and a captured request cannot be replayed as a different
// one.
//
// What a signature must cover is not configurable. This server requires a fixed
// component set, because a signature declares its own covered components: a
// verifier that accepted whatever a signature claimed to cover would accept one
// covering nothing.
type HTTPSignatureConfig struct {
	// authority is the external authority clients sign, for a server behind a
	// TLS-terminating proxy or load balancer that rewrites the Host header.
	// Unset means the authority is taken from the connection, which is correct
	// only when clients reach this server directly.
	//
	// The Forwarded and X-Forwarded-* fields are unsigned input and are never
	// consulted. State the deployment fact here instead.
	// +optional
	Authority string `json:"authority,omitempty"`

	// scheme is the external scheme clients sign, for the same case as
	// authority. Unset means the scheme is taken from the connection.
	// +optional
	Scheme string `json:"scheme,omitempty"`

	// maxClockSkew is added to every time comparison, to allow for the signer's
	// clock differing from this server's. It widens the window in which a
	// signature is accepted by the same amount. Unset means none, which requires
	// signers to agree with this server's clock to the second.
	//
	// Size it against what it widens. On a resolver, replay is closed by the nonce
	// record and this only lengthens how long the resolver is asked to remember one:
	// nonceHandling defaults to recording, so that holds unless a deployment turns it
	// off in so many words. On an x509 authenticator, or on a resolver that has, there
	// is no record and maxAge plus this value is the entire window in which a captured
	// request can be replayed against every API server.
	//
	// This is a statement about this server's own time synchronisation, not about
	// any one signer: a verifier cannot measure a client's clock, so what is being
	// set is a risk budget, and the budget's justification is the same whichever
	// authenticator answers. Stating it per authenticator would be a place for two
	// of them to disagree about a fact with one answer.
	// +optional
	MaxClockSkew *metav1.Duration `json:"maxClockSkew,omitempty"`

	// authenticators resolve a signature's keyid to a verification key and an
	// identity. They are attempted in the order given.
	//
	// The fields above are not repeated per authenticator. authority and scheme
	// describe how clients reach this one server; maxClockSkew describes this
	// server's clock. What belongs on an authenticator is trust policy for one
	// backend, and what belongs here is this server's description of itself as
	// clients experience it.
	// +required
	// +listType=atomic
	Authenticators []HTTPSignatureAuthenticator `json:"authenticators"`
}

// HTTPSignatureAuthenticator is one way of resolving a signature's keyid to a
// verification key and an identity. Exactly one of resolver or x509 is required.
//
// Neither states an identity in this file. resolver names a process, which
// answers for a key ID with the key that verifies signatures bearing it and the
// identity it authenticates as, and which records the nonces those signatures
// carry. x509 takes both key and identity from a certificate the request
// carries, which this authenticator's trust anchors have to validate.
//
// The difference is what the server depends on at request time. With resolver it
// depends on a process being reachable, and gets revocation and cross-server
// replay protection from it. With x509 it depends on nothing beyond a
// certificate authority bundle, and gets neither: a certificate's lifetime is
// the withdrawal window, and nothing records nonces.
//
// Either way the identity is a claim rather than a conclusion. This server refuses
// the three names it asserts itself, and userValidationRules is where a cluster
// states what else an authenticator may not claim.
//
// A field that means something to only one of the two lives inside that one's
// struct. Only what applies to both is stated here, so there is no way to write
// a field down and have it silently ignored.
type HTTPSignatureAuthenticator struct {
	// name identifies this authenticator in errors and in metrics. It never
	// appears on the wire, and it is not what a signature's keyid names.
	// Required to be unique across authenticators.
	// +required
	Name string `json:"name"`

	// resolver takes the verification key and the identity from a process this
	// server calls.
	//
	// Mutually exclusive with x509.
	// +optional
	Resolver *HTTPSignatureResolver `json:"resolver,omitempty"`

	// x509 takes the verification key and the identity from a certificate the
	// request carries.
	//
	// Mutually exclusive with resolver.
	// +optional
	X509 *HTTPSignatureX509 `json:"x509,omitempty"`

	// maxAge bounds how old a signature may be, measured from its created
	// parameter. Signatures without created are rejected. Unset means 5m.
	//
	// With resolver and the default nonce handling, replay is closed by the
	// resolver recording nonces rather than by this value. What this bounds is how
	// stale a request may be, and therefore how long the resolver has to remember
	// a nonce: it is told an expiry of created plus this value plus maxClockSkew,
	// and may forget the nonce after that. A resolver may narrow it, for itself or
	// for one key; nothing widens it.
	//
	// With x509, or with nonceHandling Ignore, nothing records nonces and this
	// plus maxClockSkew is the entire replay window. That difference in role is why
	// this sits here rather than in either backend: one field, one meaning, and a
	// consequence that depends on what is resolving.
	// +optional
	MaxAge *metav1.Duration `json:"maxAge,omitempty"`

	// userValidationRules are rules applied to the identity before authentication
	// completes, whichever backend produced it. The rules are logically ANDed and
	// must all return true.
	//
	// These allow invariants to be applied to incoming identities, such as
	// preventing use of the system: prefix that Kubernetes components use. Neither
	// backend states an identity in this file, so what either produces is a claim
	// rather than a conclusion, and this is the cluster's say over it.
	//
	// There is no default rule. An authenticator with none stated may assert any
	// name outside the three the server reserves for itself, including
	// system:masters.
	// +optional
	// +listType=atomic
	UserValidationRules []UserValidationRule `json:"userValidationRules,omitempty"`
}

// HTTPSignatureResolver resolves a signature's verification key and identity
// through a process this server calls over a Unix domain socket.
//
// The resolver answers what this file cannot: which key verifies signatures
// bearing a key ID, who that key authenticates as, and whether a nonce has
// already been used for that key. The last of those is what closes replay across
// every API server in the cluster, and no certificate can do it.
type HTTPSignatureResolver struct {
	// endpoint is the resolver's Unix domain socket, as unix:///path/to/socket,
	// or unix://@name for a Linux abstract socket.
	//
	// The connection carries no TLS and this server does not authenticate the
	// resolver. Access to the socket is the whole trust boundary, so its
	// permissions decide who can vend an identity to this cluster. An abstract
	// socket has no permissions at all and is bounded only by the network
	// namespace.
	// +required
	Endpoint string `json:"endpoint"`

	// keyIDPrefixes narrows which key IDs this resolver is asked about. A key ID
	// matches when the segment before its first "/" equals one of these entries.
	// Unset means this resolver is asked about every key ID.
	//
	// Resolvers are consulted in the order their authenticators appear, and one
	// that does not serve a key ID is asked before the next is tried. So a key ID
	// that no resolver serves costs one call per resolver whose prefixes admit it,
	// driven by a caller who has authenticated nothing. Stating prefixes reduces
	// that to one call, or to none.
	//
	// There is deliberately no equivalent under x509. A certificate keyid is a
	// digest of the certificate, so it carries no operator-chosen namespace to
	// match on, and selecting an x509 authenticator costs no call.
	// +optional
	// +listType=atomic
	KeyIDPrefixes []string `json:"keyIDPrefixes,omitempty"`

	// relayedHeaders names request headers whose values are sent to this resolver
	// with a key lookup, such as a rotating session token that says which key to
	// vend. Nothing else about the request is sent: not the method, not the path,
	// not the body.
	//
	// A named header present on a request but not covered by its signature causes
	// the request to be rejected before any lookup, so an intermediary cannot
	// inject one. Covered is not the same as verified: verification needs the key
	// the lookup returns, so at lookup time the value is still only a claim.
	//
	// A header with its own configuration path elsewhere may not be named here.
	// Authorization, the signature fields, Content-Digest, and the impersonation
	// headers are rejected, because relaying is not a way to route around those
	// paths.
	// +optional
	// +listType=atomic
	RelayedHeaders []string `json:"relayedHeaders,omitempty"`

	// nonceHandling says whether this server asks the resolver to record the nonce
	// each accepted signature carries. Unset means Consume.
	//
	// Set it to Ignore only with the replay window understood: it becomes maxAge
	// plus maxClockSkew, during which a captured request can be replayed against
	// every API server, without limit. Nothing else detects that.
	// +optional
	NonceHandling NonceHandling `json:"nonceHandling,omitempty"`

	// cache bounds what this server remembers of this resolver's answers. Unset
	// means the default each field states.
	// +optional
	Cache *HTTPSignatureResolverCache `json:"cache,omitempty"`
}

// HTTPSignatureX509 resolves a signature's verification key and identity from an
// X.509 certificate the request carries in the Signature-Certificate header.
//
// This is mutual TLS with the handshake replaced by a message signature. The
// same certificate authority, the same issuance, the same certificate tooling,
// and the same subject conventions apply. Only the point of authentication moves
// into the message, which is what lets it survive a TLS-terminating hop, and
// what makes distribution and rotation the certificate machinery's problem
// rather than this file's.
//
// The certificate is bound to the signature by the keyid, which must be
// "x509-sha256:" followed by the lowercase hex SHA-256 digest of the leaf
// certificate's DER encoding. A signature's parameters are always part of its
// signature base, so a keyid naming the certificate binds the certificate
// without relying on any header coverage rule. The header is covered as well,
// which is belt and braces rather than the mechanism.
//
// Only the leaf is read from the request. Intermediates come from
// certificateAuthority, so the work an unauthenticated caller can cause is one
// parse and one chain build against a fixed pool, whatever the number of
// authenticators configured: the leaf's authorityKeyIdentifier names the trust
// anchor that issued it, and that selects one of them.
//
// A presented certificate must carry that extension. RFC 5280 requires a conforming
// issuer to set it, and without it there is nothing to select an authenticator by.
//
// The signature algorithm is not configurable and is determined by the leaf's
// key type: ed25519 for an Ed25519 key, ecdsa-p256-sha256 for P-256,
// ecdsa-p384-sha384 for P-384, and rsa-pss-sha512 for RSA. One algorithm per key
// type leaves nothing for an algorithm confusion attack to confuse, and it keeps
// rsa-v1_5-sha256 unreachable.
type HTTPSignatureX509 struct {
	// certificateAuthority contains PEM-encoded certificate authority
	// certificates that a presented certificate must chain to. A certificate
	// authority is public trust material, so it is stated inline rather than
	// referenced by path.
	//
	// Two authenticators may not share any certificate here, which means a shared
	// organizational root cannot be used to give two of them different mappings. Put
	// the intermediate in each bundle and leave the root out: an entry here is a trust
	// anchor whether or not something above it signed it, so an intermediate alone is
	// a complete bundle. That is the better configuration anyway, for the reason
	// above, and the restriction is not arbitrary: a certificate the shared root
	// issued directly would name it as its issuer and so select both authenticators.
	//
	// This bundle must contain the certificate that directly issued a presented
	// certificate, not only the root above it. Intermediates are never read from the
	// request, so a two-tier authority means putting both the root and the
	// intermediate here. That was already required to build a chain; it now also
	// decides which authenticator is asked, so a missing intermediate is reported as
	// an unknown issuer rather than as a chain failure.
	//
	// Every certificate here must carry a subjectKeyIdentifier, which RFC 5280
	// requires of a conforming certificate authority certificate. That is the value a
	// presented certificate's authorityKeyIdentifier names, so it is what selects
	// this authenticator. Two authenticators may not hold the same identifier, nor
	// two certificates for the same public key: a certificate would then select both
	// and which identity it received would depend on the order they appear here.
	//
	// Point this at a certificate authority issued for this purpose. Pointing
	// it at the cluster's client certificate authority would give every
	// certificate already issued for connection authentication the ability to
	// sign detached messages that survive a proxy, which its issuer never
	// agreed to and which nobody opted in to.
	//
	// Extended key usage is not checked, so this bundle being dedicated is a
	// requirement rather than a recommendation. No registered usage means "may
	// sign detached HTTP messages": requiring client authentication would make
	// every certificate issued for connection authentication a signing credential,
	// and requiring a distinct usage would mean new issuance for everyone. Both
	// choices enlist the wrong population, so the bundle is what says who is
	// enlisted.
	//
	// A worked example of getting this wrong: an operator puts their organization's
	// general-purpose internal certificate authority here, because that is the
	// authority they have. Every internal TLS server certificate that authority ever
	// issued is now an API server identity, and if claimMappings derives from the
	// subject then whoever can request a certificate chooses what that identity is.
	//
	// The key usage extension is checked, where present: a certificate without
	// digitalSignature is refused, because that is the extension that answers
	// whether the key may sign at all. A certificate authority certificate is
	// refused as a leaf.
	// +required
	CertificateAuthority string `json:"certificateAuthority"`

	// certificateValidationRules constrain which certificates this authenticator
	// accepts, beyond chaining to its trust anchors. The rules are logically
	// ANDed and must all return true.
	//
	// They run before claimMappings, so a mapping expression never sees a
	// certificate no rule has vetted. This is deliberately the opposite order
	// from the JWT authenticator, which maps first and compensates for it.
	// +optional
	// +listType=atomic
	CertificateValidationRules []CertificateValidationRule `json:"certificateValidationRules,omitempty"`

	// claimMappings derives the user attributes from the certificate.
	//
	// Required, because the identity comes from the certificate rather than from
	// this file. This is where the cluster decides what a certificate is allowed
	// to mean, which matters because the identity is now an assertion rather than
	// something an administrator wrote down.
	// +required
	ClaimMappings *HTTPSignatureClaimMappings `json:"claimMappings,omitempty"`

	// cache holds the results of successful certificate validation, so a client's
	// second request does not repeat the chain build and the expression
	// evaluation its first one paid for.
	// +optional
	Cache *HTTPSignatureX509Cache `json:"cache,omitempty"`
}

// HTTPSignatureX509Cache bounds the memoization of certificate validation.
//
// Only successful validations are cached. A negative cache would be keyed on
// bytes a peer chooses, which is unbounded cardinality for anyone who can send a
// request, and it would buy nothing: an untrusted certificate is rejected by one
// chain build. Because entries are created only on success, occupying one
// requires a certificate the configured authority actually issued.
//
// Caching the mapped identity, rather than only the verification key, is sound
// because the mapping is a pure function of the certificate. The expression
// environment declares no clock and no request, so no expression can produce a
// different answer for the same certificate at a different time.
type HTTPSignatureX509Cache struct {
	// maxEntries caps how many validated certificates are remembered. Unset
	// means 1024. Eviction costs the evicted client one revalidation and
	// nothing else.
	// +optional
	MaxEntries *int32 `json:"maxEntries,omitempty"`

	// ttl bounds how long a validation is trusted, and is therefore the window
	// in which withdrawing a certificate has no effect. Unset means 5m.
	//
	// The effective lifetime of an entry is the smallest of this, the time
	// remaining on the leaf, and the time remaining on every certificate in the
	// validated chain. Without the chain bound, a ttl longer than a trust
	// anchor's remaining life would keep admitting requests past the anchor's
	// expiry.
	// +optional
	TTL *metav1.Duration `json:"ttl,omitempty"`
}

// CertificateValidationRule provides the configuration for a single certificate
// validation rule.
type CertificateValidationRule struct {
	// expression represents the expression which will be evaluated by CEL.
	// Must produce a boolean, and must return true for the validation to pass.
	//
	// CEL expressions have access to the presented certificate, organized into
	// CEL variable:
	// - 'cert' - a kubernetes.Certificate object describing the leaf, with
	//   fields: subject and issuer (each with commonName, organization, and
	//   organizationalUnit), serialNumber, notBefore, notAfter, dnsSANs,
	//   uriSANs, emailSANs, ipSANs, sha256Thumbprint, and extendedKeyUsages.
	//
	// Nothing else is in scope. There is no clock and no request, which is what
	// makes a certificate's validation result cacheable.
	//
	// Test a multi-valued attribute with exists() and never by position. A
	// multi-valued name attribute is encoded as an ASN.1 SET, whose members are
	// canonically ordered by their encoding, so the order the issuer supplied is
	// not the order read back:
	//   cert.subject.organization.exists(o, o == 'system:nodes')
	//
	// A certificate's lifetime is expressed by subtracting its validity bounds.
	// There is no dedicated field for it, because this is the general form:
	//   cert.notAfter - cert.notBefore <= duration('24h')
	//
	// Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/
	// +required
	Expression string `json:"expression"`

	// message customizes the returned error message when expression returns
	// false. message is a literal string.
	// +optional
	Message string `json:"message,omitempty"`
}

// HTTPSignatureClaimMappings maps a certificate's attributes onto the user
// attributes a request authenticates as.
//
// Mappings are expressions and never field references. A certificate is not a
// map of names to values the way a token's claim set is, so there is no
// equivalent of the JWT authenticator's claim form. The field name is kept for
// the analogy with that authenticator, which is what a reader will look for.
//
// No prefix is applied to any mapped value. An administrator owns avoiding
// collision with the names other authenticators issue, and an expression can
// prepend a literal where a prefix is wanted.
//
// Three names are refused outright, because the server asserts them itself and an
// authenticator claiming one would be stating a falsehood: the groups
// system:authenticated and system:unauthenticated, which the server adds according
// to whether authentication succeeded, and the username system:anonymous, which the
// anonymous authenticator asserts about a request that carried no credential.
//
// Everything else, including system:masters, is left to userValidationRules.
// Mapping a node's certificate to system:node:<name> is a legitimate use, which is
// why there is no ban here.
type HTTPSignatureClaimMappings struct {
	// username is the mapped user name. The expression must produce a non-empty
	// string.
	// +required
	Username HTTPSignatureClaimExpression `json:"username"`

	// groups are the mapped groups. The expression must produce a string or a
	// list of strings. "", [], and null are treated as the mapping not being
	// present. The authenticated group is added by the server and does not need
	// to be produced here.
	// +optional
	Groups HTTPSignatureClaimExpression `json:"groups,omitempty"`

	// uid is the mapped user UID. The expression must produce a string.
	// +optional
	UID HTTPSignatureClaimExpression `json:"uid,omitempty"`

	// extra are mapped extra attributes. Each expression must produce a string
	// or a list of strings; "", [], and null are treated as the mapping not
	// being present.
	// +optional
	// +listType=atomic
	Extra []ExtraMapping `json:"extra,omitempty"`
}

// HTTPSignatureClaimExpression is one CEL expression over the presented
// certificate.
//
// It is a struct holding one field rather than a bare string so that this reads
// the same as the JWT authenticator's equivalent, where the field is one of
// several alternatives.
type HTTPSignatureClaimExpression struct {
	// expression represents the expression which will be evaluated by CEL
	// against the 'cert' variable. See CertificateValidationRule.expression for
	// what is in scope.
	//
	// Documentation on CEL: https://kubernetes.io/docs/reference/using-api/cel/
	// +optional
	Expression string `json:"expression,omitempty"`
}

// HTTPSignatureResolverCache bounds what this server remembers of a resolver's
// answers.
//
// A key ID is chosen by the peer, so the number of distinct ones this server is
// asked about is not bounded by anything in the cluster. Neither cache may be
// allowed to grow with it.
type HTTPSignatureResolverCache struct {
	// maxKeys caps the entries in each of the two caches kept per resolver: keys
	// it resolved, and key IDs it said it does not serve. Unset means 1024.
	//
	// The two are separate so that a flood of unknown key IDs cannot evict
	// working keys. Eviction from either costs one lookup and never an
	// authentication failure, which is why a bound is safe to impose here.
	// +optional
	MaxKeys *int32 `json:"maxKeys,omitempty"`

	// maxAge caps how long a resolved key is reused. A resolver states its own
	// duration with each answer and this caps it; the shorter applies. Unset
	// means 5m.
	//
	// A cached key stays usable after the resolver stops vending it, so this is
	// the revocation window.
	// +optional
	MaxAge *metav1.Duration `json:"maxAge,omitempty"`

	// negativeMaxAge is how long this server remembers that a resolver does not
	// serve a key ID. Unset means 10s.
	//
	// A resolver cannot state this itself, because not-found is a status rather
	// than an answer with fields. Longer spares the resolver repeated lookups for
	// the same unknown key ID; shorter shortens the wait before a key that has
	// just been created works.
	// +optional
	NegativeMaxAge *metav1.Duration `json:"negativeMaxAge,omitempty"`
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
