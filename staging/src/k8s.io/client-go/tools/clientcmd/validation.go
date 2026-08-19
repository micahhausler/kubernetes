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

package clientcmd

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/validation"
	authexec "k8s.io/client-go/plugin/pkg/client/auth/exec"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	transporthttpsig "k8s.io/client-go/transport/httpsig"
)

var (
	ErrNoContext   = errors.New("no context chosen")
	ErrEmptyConfig = NewEmptyConfigError("no configuration has been provided, try setting KUBERNETES_MASTER environment variable")
	// message is for consistency with old behavior
	ErrEmptyCluster = errors.New("cluster has no server defined")
)

// NewEmptyConfigError returns an error wrapping the given message which IsEmptyConfig() will recognize as an empty config error
func NewEmptyConfigError(message string) error {
	return &errEmptyConfig{message}
}

type errEmptyConfig struct {
	message string
}

func (e *errEmptyConfig) Error() string {
	return e.message
}

type errContextNotFound struct {
	ContextName string
}

func (e *errContextNotFound) Error() string {
	return fmt.Sprintf("context was not found for specified context: %v", e.ContextName)
}

// IsContextNotFound returns a boolean indicating whether the error is known to
// report that a context was not found
func IsContextNotFound(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(*errContextNotFound); ok || err == ErrNoContext {
		return true
	}
	return strings.Contains(err.Error(), "context was not found for specified context")
}

// IsEmptyConfig returns true if the provided error indicates the provided configuration
// is empty.
func IsEmptyConfig(err error) bool {
	switch t := err.(type) {
	case errConfigurationInvalid:
		if len(t) != 1 {
			return false
		}
		_, ok := t[0].(*errEmptyConfig)
		return ok
	}
	_, ok := err.(*errEmptyConfig)
	return ok
}

// errConfigurationInvalid is a set of errors indicating the configuration is invalid.
type errConfigurationInvalid []error

// errConfigurationInvalid implements error and Aggregate
var _ error = errConfigurationInvalid{}
var _ utilerrors.Aggregate = errConfigurationInvalid{}

func newErrConfigurationInvalid(errs []error) error {
	switch len(errs) {
	case 0:
		return nil
	default:
		return errConfigurationInvalid(errs)
	}
}

// Error implements the error interface
func (e errConfigurationInvalid) Error() string {
	return fmt.Sprintf("invalid configuration: %v", utilerrors.NewAggregate(e).Error())
}

// Errors implements the utilerrors.Aggregate interface
func (e errConfigurationInvalid) Errors() []error {
	return e
}

// Is implements the utilerrors.Aggregate interface
func (e errConfigurationInvalid) Is(target error) bool {
	return e.visit(func(err error) bool {
		return errors.Is(err, target)
	})
}

func (e errConfigurationInvalid) visit(f func(err error) bool) bool {
	for _, err := range e {
		switch err := err.(type) {
		case errConfigurationInvalid:
			if match := err.visit(f); match {
				return match
			}
		case utilerrors.Aggregate:
			for _, nestedErr := range err.Errors() {
				if match := f(nestedErr); match {
					return match
				}
			}
		default:
			if match := f(err); match {
				return match
			}
		}
	}

	return false
}

// IsConfigurationInvalid returns true if the provided error indicates the configuration is invalid.
func IsConfigurationInvalid(err error) bool {
	switch err.(type) {
	case *errContextNotFound, errConfigurationInvalid:
		return true
	}
	return IsContextNotFound(err)
}

// Validate checks for errors in the Config.  It does not return early so that it can find as many errors as possible.
func Validate(config clientcmdapi.Config) error {
	validationErrors := make([]error, 0)

	if clientcmdapi.IsConfigEmpty(&config) {
		return newErrConfigurationInvalid([]error{ErrEmptyConfig})
	}

	if len(config.CurrentContext) != 0 {
		if _, exists := config.Contexts[config.CurrentContext]; !exists {
			validationErrors = append(validationErrors, &errContextNotFound{config.CurrentContext})
		}
	}

	for contextName, context := range config.Contexts {
		validationErrors = append(validationErrors, validateContext(contextName, *context, config)...)
	}

	for authInfoName, authInfo := range config.AuthInfos {
		validationErrors = append(validationErrors, validateAuthInfo(authInfoName, *authInfo)...)
	}

	for clusterName, clusterInfo := range config.Clusters {
		validationErrors = append(validationErrors, validateClusterInfo(clusterName, *clusterInfo)...)
	}

	return newErrConfigurationInvalid(validationErrors)
}

// ConfirmUsable looks a particular context and determines if that particular part of the config is useable.  There might still be errors in the config,
// but no errors in the sections requested or referenced.  It does not return early so that it can find as many errors as possible.
func ConfirmUsable(config clientcmdapi.Config, passedContextName string) error {
	validationErrors := make([]error, 0)

	if clientcmdapi.IsConfigEmpty(&config) {
		return newErrConfigurationInvalid([]error{ErrEmptyConfig})
	}

	var contextName string
	if len(passedContextName) != 0 {
		contextName = passedContextName
	} else {
		contextName = config.CurrentContext
	}

	if len(contextName) == 0 {
		return ErrNoContext
	}

	context, exists := config.Contexts[contextName]
	if !exists {
		validationErrors = append(validationErrors, &errContextNotFound{contextName})
	}

	if exists {
		validationErrors = append(validationErrors, validateContext(contextName, *context, config)...)

		// Default to empty users and clusters and let the validation function report an error.
		authInfo := config.AuthInfos[context.AuthInfo]
		if authInfo == nil {
			authInfo = &clientcmdapi.AuthInfo{}
		}
		validationErrors = append(validationErrors, validateAuthInfo(context.AuthInfo, *authInfo)...)

		cluster := config.Clusters[context.Cluster]
		if cluster == nil {
			cluster = &clientcmdapi.Cluster{}
		}
		validationErrors = append(validationErrors, validateClusterInfo(context.Cluster, *cluster)...)
	}

	return newErrConfigurationInvalid(validationErrors)
}

// validateClusterInfo looks for conflicts and errors in the cluster info
func validateClusterInfo(clusterName string, clusterInfo clientcmdapi.Cluster) []error {
	validationErrors := make([]error, 0)

	emptyCluster := clientcmdapi.NewCluster()
	if reflect.DeepEqual(*emptyCluster, clusterInfo) {
		return []error{ErrEmptyCluster}
	}

	if len(clusterInfo.Server) == 0 {
		if len(clusterName) == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("default cluster has no server defined"))
		} else {
			validationErrors = append(validationErrors, fmt.Errorf("no server found for cluster %q", clusterName))
		}
	}
	if proxyURL := clusterInfo.ProxyURL; proxyURL != "" {
		if _, err := parseProxyURL(proxyURL); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("invalid 'proxy-url' %q for cluster %q: %w", proxyURL, clusterName, err))
		}
	}
	// Make sure CA data and CA file aren't both specified
	if len(clusterInfo.CertificateAuthority) != 0 && len(clusterInfo.CertificateAuthorityData) != 0 {
		validationErrors = append(validationErrors, fmt.Errorf("certificate-authority-data and certificate-authority are both specified for %v. certificate-authority-data will override.", clusterName))
	}
	if len(clusterInfo.CertificateAuthority) != 0 {
		clientCertCA, err := os.Open(clusterInfo.CertificateAuthority)
		if err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("unable to read certificate-authority %v for %v due to %w", clusterInfo.CertificateAuthority, clusterName, err))
		} else {
			defer clientCertCA.Close()
		}
	}

	return validationErrors
}

// validateAuthInfo looks for conflicts and errors in the auth info
func validateAuthInfo(authInfoName string, authInfo clientcmdapi.AuthInfo) []error {
	validationErrors := make([]error, 0)

	usingAuthPath := false
	methods := make([]string, 0, 3)
	if len(authInfo.Token) != 0 {
		methods = append(methods, "token")
	}
	if len(authInfo.Username) != 0 || len(authInfo.Password) != 0 {
		methods = append(methods, "basicAuth")
	}
	if authInfo.HTTPSignature != nil {
		methods = append(methods, "httpSignature")
		// A client certificate is a credential that transits, and a signature is
		// one that does not. Presenting both leaves the server to authenticate
		// whichever its authenticator chain reaches first, so the resulting
		// identity would depend on server ordering rather than on this file.
		//
		// This is stated here rather than by adding clientCert to the methods
		// list above, because that list has never included client certificates
		// and widening it would newly reject configurations that combine a
		// certificate with a token. Under httpSignature the certificate and key
		// belong under httpSignature.certFile and httpSignature.keyFile, where
		// they are signing material rather than TLS material.
		if len(authInfo.ClientCertificate) != 0 || len(authInfo.ClientCertificateData) != 0 {
			validationErrors = append(validationErrors, fmt.Errorf(
				"client-cert cannot be provided in combination with httpSignature for %v; "+
					"to sign with that certificate set httpSignature.certFile and httpSignature.keyFile instead", authInfoName))
		}
	}

	if len(authInfo.ClientCertificate) != 0 || len(authInfo.ClientCertificateData) != 0 {
		// Make sure cert data and file aren't both specified
		if len(authInfo.ClientCertificate) != 0 && len(authInfo.ClientCertificateData) != 0 {
			validationErrors = append(validationErrors, fmt.Errorf("client-cert-data and client-cert are both specified for %v. client-cert-data will override.", authInfoName))
		}
		// Make sure key data and file aren't both specified
		if len(authInfo.ClientKey) != 0 && len(authInfo.ClientKeyData) != 0 {
			validationErrors = append(validationErrors, fmt.Errorf("client-key-data and client-key are both specified for %v; client-key-data will override", authInfoName))
		}
		// Make sure a key is specified
		if len(authInfo.ClientKey) == 0 && len(authInfo.ClientKeyData) == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("client-key-data or client-key must be specified for %v to use the clientCert authentication method.", authInfoName))
		}

		if len(authInfo.ClientCertificate) != 0 {
			clientCertFile, err := os.Open(authInfo.ClientCertificate)
			if err != nil {
				validationErrors = append(validationErrors, fmt.Errorf("unable to read client-cert %v for %v due to %w", authInfo.ClientCertificate, authInfoName, err))
			} else {
				defer clientCertFile.Close()
			}
		}
		if len(authInfo.ClientKey) != 0 {
			clientKeyFile, err := os.Open(authInfo.ClientKey)
			if err != nil {
				validationErrors = append(validationErrors, fmt.Errorf("unable to read client-key %v for %v due to %w", authInfo.ClientKey, authInfoName, err))
			} else {
				defer clientKeyFile.Close()
			}
		}
	}

	if authInfo.Exec != nil {
		if authInfo.AuthProvider != nil {
			validationErrors = append(validationErrors, fmt.Errorf("authProvider cannot be provided in combination with an exec plugin for %s", authInfoName))
		}
		if len(authInfo.Exec.Command) == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("command must be specified for %v to use exec authentication plugin", authInfoName))
		}
		if len(authInfo.Exec.APIVersion) == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("apiVersion must be specified for %v to use exec authentication plugin", authInfoName))
		}
		for _, v := range authInfo.Exec.Env {
			if len(v.Name) == 0 {
				validationErrors = append(validationErrors, fmt.Errorf("env variable name must be specified for %v to use exec authentication plugin", authInfoName))
			}
		}
		switch authInfo.Exec.InteractiveMode {
		case "":
			validationErrors = append(validationErrors, fmt.Errorf("interactiveMode must be specified for %v to use exec authentication plugin", authInfoName))
		case clientcmdapi.NeverExecInteractiveMode, clientcmdapi.IfAvailableExecInteractiveMode, clientcmdapi.AlwaysExecInteractiveMode:
			// These are valid
		default:
			validationErrors = append(validationErrors, fmt.Errorf("invalid interactiveMode for %v: %q", authInfoName, authInfo.Exec.InteractiveMode))
		}

		if err := authexec.ValidatePluginPolicy(authInfo.Exec.PluginPolicy); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("allowlist misconfiguration: %w", err))
		}
	}

	if authInfo.HTTPSignature != nil {
		validationErrors = append(validationErrors, validateHTTPSignature(authInfoName, authInfo)...)
	}

	// authPath also provides information for the client to identify the server, so allow multiple auth methods in that case
	if (len(methods) > 1) && (!usingAuthPath) {
		validationErrors = append(validationErrors, fmt.Errorf("more than one authentication method found for %v; found %v, only one is allowed", authInfoName, methods))
	}

	// ImpersonateUID, ImpersonateGroups or ImpersonateUserExtra should be requested with a user
	if (len(authInfo.ImpersonateUID) > 0 || len(authInfo.ImpersonateGroups) > 0 || len(authInfo.ImpersonateUserExtra) > 0) && (len(authInfo.Impersonate) == 0) {
		validationErrors = append(validationErrors, fmt.Errorf("requesting uid, groups or user-extra for %v without impersonating a user", authInfoName))
	}
	return validationErrors
}

// validateHTTPSignature looks for conflicts and errors in an httpSignature stanza.
//
// It does not check the algorithm name, the key encoding, or the contents of the
// credential file. The signer owns the algorithm registry and the credential
// schema, and duplicating either here would give two places to keep in sync.
// Those errors surface when the client is built.
func validateHTTPSignature(authInfoName string, authInfo clientcmdapi.AuthInfo) []error {
	var validationErrors []error
	sig := authInfo.HTTPSignature

	if authInfo.AuthProvider != nil {
		validationErrors = append(validationErrors, fmt.Errorf("authProvider cannot be provided in combination with httpSignature for %v", authInfoName))
	}

	if len(sig.APIVersion) == 0 {
		validationErrors = append(validationErrors, fmt.Errorf("apiVersion must be specified for %v to use httpSignature authentication", authInfoName))
	}

	// A certificate asserts who the client is, so the key ID and the algorithm
	// both follow from it and neither may be stated. Elsewhere the algorithm is
	// required and never inferred, so that a key cannot be used under an
	// algorithm its holder did not intend; a certificate's key type leaves only
	// one algorithm the server would accept, so there is nothing to infer wrongly.
	assertsCertificate := len(sig.CertFile) != 0 || len(sig.CredentialBundleFile) != 0
	if assertsCertificate {
		if len(sig.Algorithm) != 0 {
			validationErrors = append(validationErrors, fmt.Errorf(
				"algorithm must not be specified for %v alongside certFile or credentialBundleFile, because the certificate's key type determines it", authInfoName))
		}
		if len(sig.KeyID) != 0 {
			validationErrors = append(validationErrors, fmt.Errorf(
				"keyID must not be specified for %v alongside certFile or credentialBundleFile, because it is the certificate's digest", authInfoName))
		}
		if len(sig.CertFile) != 0 && len(sig.CredentialBundleFile) != 0 {
			validationErrors = append(validationErrors, fmt.Errorf(
				"certFile and credentialBundleFile are alternatives for %v: a bundle already holds the certificate", authInfoName))
		}
		if len(sig.CredentialFile) != 0 {
			validationErrors = append(validationErrors, fmt.Errorf(
				"credentialFile cannot be combined with a certificate for %v: the certificate is the credential", authInfoName))
		}
		if len(sig.SignedHeaders) > 0 {
			validationErrors = append(validationErrors, fmt.Errorf(
				"signedHeaders requires credentialFile or exec for %v, because header values come from a credential", authInfoName))
		}
	} else if len(sig.Algorithm) == 0 {
		validationErrors = append(validationErrors, fmt.Errorf("algorithm must be specified for %v to use httpSignature authentication", authInfoName))
	}

	// httpSignature states the shape of the signature: the algorithm, the
	// derivation, the covered headers, and the lifetime. What rotates comes from
	// a credential source, and an exec plugin is one of them, so this stanza
	// appears alongside exec rather than in conflict with it.
	//
	// certFile is not a source of its own: it names the certificate that vouches
	// for the key in keyFile, so the pair is one source. credentialBundleFile is
	// one source holding both halves.
	sources := 0
	for _, set := range []bool{
		len(sig.KeyFile) != 0,
		len(sig.CredentialFile) != 0,
		len(sig.CredentialBundleFile) != 0,
		authInfo.Exec != nil,
	} {
		if set {
			sources++
		}
	}
	if sources != 1 {
		validationErrors = append(validationErrors, fmt.Errorf(
			"exactly one credential source must be specified for %v to use httpSignature authentication: "+
				"keyFile, keyFile with certFile, credentialFile, credentialBundleFile, or exec", authInfoName))
	}
	if len(sig.CertFile) != 0 {
		if len(sig.KeyFile) == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("keyFile must be specified alongside certFile for %v, because a certificate carries no private key", authInfoName))
		}
		validationErrors = append(validationErrors, validateReadableFile("certFile", sig.CertFile, authInfoName)...)
	}
	if len(sig.CredentialBundleFile) != 0 {
		if len(sig.KeyFile) != 0 {
			validationErrors = append(validationErrors, fmt.Errorf("keyFile must not be specified alongside credentialBundleFile for %v, because the bundle holds the key", authInfoName))
		}
		validationErrors = append(validationErrors, validateReadableFile("credentialBundleFile", sig.CredentialBundleFile, authInfoName)...)
	}
	// A key file carries a key and nothing else. Anything that rotates, and any
	// header value, has to come from a credential.
	rotates := len(sig.CredentialFile) != 0 || authInfo.Exec != nil
	if len(sig.KeyFile) != 0 && !assertsCertificate {
		if len(sig.KeyID) == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("keyID must be specified alongside keyFile for %v", authInfoName))
		}
		if len(sig.SignedHeaders) > 0 {
			validationErrors = append(validationErrors, fmt.Errorf("signedHeaders requires credentialFile or exec for %v, because header values come from a credential", authInfoName))
		}
		validationErrors = append(validationErrors, validateReadableFile("keyFile", sig.KeyFile, authInfoName)...)
	}
	if authInfo.Exec != nil && len(sig.KeyID) != 0 {
		validationErrors = append(validationErrors, fmt.Errorf("keyID must not be specified alongside exec for %v, because the key ID comes from the credential", authInfoName))
	}
	if len(sig.CredentialFile) != 0 {
		if len(sig.KeyID) != 0 {
			validationErrors = append(validationErrors, fmt.Errorf("keyID must not be specified alongside credentialFile for %v, because the key ID comes from the credential", authInfoName))
		}
		validationErrors = append(validationErrors, validateReadableFile("credentialFile", sig.CredentialFile, authInfoName)...)
	}
	if sig.KeyDerivation != nil {
		// The derived key comes from the credential's secret, so a derivation
		// without a credential has nothing to derive from.
		if !rotates {
			validationErrors = append(validationErrors, fmt.Errorf("keyDerivation requires credentialFile or exec for %v, because the derived key comes from a credential's secret", authInfoName))
		}
		// Convert to check it: the signing library validates the kind, the hash,
		// the step names, one input source per step, the closed set of date
		// formats, and the separator bans. Reporting that here means a bad
		// ladder is a kubeconfig error rather than a signature mismatch on the
		// first request.
		if _, _, err := transporthttpsig.DerivationFrom(sig.KeyDerivation); err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("keyDerivation is invalid for %v: %w", authInfoName, err))
		}
	}

	if len(sig.TTL) != 0 {
		ttl, err := time.ParseDuration(sig.TTL)
		if err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("invalid httpSignature ttl for %v: %w", authInfoName, err))
		} else if ttl <= 0 {
			validationErrors = append(validationErrors, fmt.Errorf("httpSignature ttl for %v must be positive", authInfoName))
		}
	}

	seen := map[string]bool{}
	for _, h := range sig.SignedHeaders {
		if len(h.Name) == 0 {
			validationErrors = append(validationErrors, fmt.Errorf("signed header name must be specified for %v", authInfoName))
			continue
		}
		name := strings.ToLower(h.Name)
		if seen[name] {
			validationErrors = append(validationErrors, fmt.Errorf("signed header %v is specified more than once for %v", h.Name, authInfoName))
		}
		seen[name] = true
		if transporthttpsig.IsReservedHeader(name) {
			validationErrors = append(validationErrors, fmt.Errorf("signed header %v for %v is reserved and has its own configuration; setting it here would bypass that path", h.Name, authInfoName))
		}
	}
	return validationErrors
}

// validateReadableFile reports a file the client will need and cannot read.
func validateReadableFile(field, path, authInfoName string) []error {
	f, err := os.Open(path)
	if err != nil {
		return []error{fmt.Errorf("unable to read httpSignature %s %v for %v due to %w", field, path, authInfoName, err)}
	}
	defer f.Close()
	return nil
}

// validateContext looks for errors in the context.  It is not transitive, so errors in the reference authInfo or cluster configs are not included in this return
func validateContext(contextName string, context clientcmdapi.Context, config clientcmdapi.Config) []error {
	validationErrors := make([]error, 0)

	if len(contextName) == 0 {
		validationErrors = append(validationErrors, fmt.Errorf("empty context name for %#v is not allowed", context))
	}

	if len(context.AuthInfo) == 0 {
		validationErrors = append(validationErrors, fmt.Errorf("user was not specified for context %q", contextName))
	} else if _, exists := config.AuthInfos[context.AuthInfo]; !exists {
		validationErrors = append(validationErrors, fmt.Errorf("user %q was not found for context %q", context.AuthInfo, contextName))
	}

	if len(context.Cluster) == 0 {
		validationErrors = append(validationErrors, fmt.Errorf("cluster was not specified for context %q", contextName))
	} else if _, exists := config.Clusters[context.Cluster]; !exists {
		validationErrors = append(validationErrors, fmt.Errorf("cluster %q was not found for context %q", context.Cluster, contextName))
	}

	if len(context.Namespace) != 0 {
		if len(validation.IsDNS1123Label(context.Namespace)) != 0 {
			validationErrors = append(validationErrors, fmt.Errorf("namespace %q for context %q does not conform to the kubernetes DNS_LABEL rules", context.Namespace, contextName))
		}
	}

	return validationErrors
}
