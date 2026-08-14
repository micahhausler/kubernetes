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

package rest

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"k8s.io/client-go/pkg/apis/clientauthentication"
	"k8s.io/client-go/plugin/pkg/client/auth/exec"
	"k8s.io/client-go/tools/metrics"
	"k8s.io/client-go/transport"
	transporthttpsig "k8s.io/client-go/transport/httpsig"
)

// HTTPClientFor returns an http.Client that will provide the authentication
// or transport level security defined by the provided Config. Will return the
// default http.DefaultClient if no special case behavior is needed.
func HTTPClientFor(config *Config) (*http.Client, error) {
	transport, err := TransportFor(config)
	if err != nil {
		return nil, err
	}
	var httpClient *http.Client
	if transport != http.DefaultTransport || config.Timeout > 0 {
		httpClient = &http.Client{
			Transport: transport,
			Timeout:   config.Timeout,
		}
	} else {
		httpClient = http.DefaultClient
	}

	return httpClient, nil
}

// TLSConfigFor returns a tls.Config that will provide the transport level security defined
// by the provided Config. Will return nil if no transport level security is requested.
func TLSConfigFor(config *Config) (*tls.Config, error) {
	cfg, err := config.TransportConfig()
	if err != nil {
		return nil, err
	}
	return transport.TLSConfigFor(cfg)
}

// TransportFor returns an http.RoundTripper that will provide the authentication
// or transport level security defined by the provided Config. Will return the
// default http.DefaultTransport if no special case behavior is needed.
func TransportFor(config *Config) (http.RoundTripper, error) {
	cfg, err := config.TransportConfig()
	if err != nil {
		return nil, err
	}
	return transport.New(cfg)
}

// HTTPWrappersForConfig wraps a round tripper with any relevant layered behavior from the
// config. Exposed to allow more clients that need HTTP-like behavior but then must hijack
// the underlying connection (like WebSocket or HTTP2 clients). Pure HTTP clients should use
// the higher level TransportFor or RESTClientFor methods.
func HTTPWrappersForConfig(config *Config, rt http.RoundTripper) (http.RoundTripper, error) {
	cfg, err := config.TransportConfig()
	if err != nil {
		return nil, err
	}
	return transport.HTTPWrappersForConfig(cfg, rt)
}

// TransportConfig converts a client config to an appropriate transport config.
func (c *Config) TransportConfig() (*transport.Config, error) {
	metrics.EnsureRegistered()
	conf := &transport.Config{
		UserAgent:          c.UserAgent,
		Transport:          c.Transport,
		WrapTransport:      c.WrapTransport,
		DisableCompression: c.DisableCompression,
		TLS: transport.TLSConfig{
			Insecure:   c.Insecure,
			ServerName: c.ServerName,
			CAFile:     c.CAFile,
			CAData:     c.CAData,
			CertFile:   c.CertFile,
			CertData:   c.CertData,
			KeyFile:    c.KeyFile,
			KeyData:    c.KeyData,
			NextProtos: c.NextProtos,
		},
		Username:        c.Username,
		Password:        c.Password,
		BearerToken:     c.BearerToken,
		BearerTokenFile: c.BearerTokenFile,
		Impersonate: transport.ImpersonationConfig{
			UserName: c.Impersonate.UserName,
			UID:      c.Impersonate.UID,
			Groups:   c.Impersonate.Groups,
			Extra:    c.Impersonate.Extra,
		},
		Proxy: c.Proxy,
	}

	if c.Dial != nil {
		conf.DialHolder = &transport.DialHolder{Dial: c.Dial}
	}

	if c.ExecProvider != nil && c.AuthProvider != nil {
		return nil, errors.New("execProvider and authProvider cannot be used in combination")
	}

	if c.ExecProvider != nil {
		var cluster *clientauthentication.Cluster
		if c.ExecProvider.ProvideClusterInfo {
			var err error
			cluster, err = ConfigToExecCluster(c)
			if err != nil {
				return nil, err
			}
		}
		// An exec plugin is a credential source, and httpSignature says what kind
		// of credential it is asked for. With signing configured the plugin
		// returns key material rather than a token, and the authenticator
		// installs the signer instead of a bearer round tripper.
		var provider *exec.Authenticator
		var err error
		if c.HTTPSignature != nil {
			provider, err = exec.GetSigningAuthenticator(c.ExecProvider, cluster, c.HTTPSignature)
		} else {
			provider, err = exec.GetAuthenticator(c.ExecProvider, cluster)
		}
		if err != nil {
			return nil, err
		}
		if err := provider.UpdateTransportConfig(conf); err != nil {
			return nil, err
		}
	}
	if c.AuthProvider != nil {
		provider, err := GetAuthProvider(c.Host, c.AuthProvider, c.AuthConfigPersister)
		if err != nil {
			return nil, err
		}
		conf.Wrap(provider.WrapTransport)
	}

	if c.HTTPSignature != nil && c.ExecProvider == nil {
		if err := c.validateHTTPSignatureExclusive(); err != nil {
			return nil, err
		}
		// Wrapping here puts the signer closest to the wire, so the
		// impersonation and user agent round trippers have already set their
		// headers when it runs and the signature can cover them.
		cfg := *c.HTTPSignature
		conf.Wrap(func(rt http.RoundTripper) http.RoundTripper {
			signing, err := transporthttpsig.NewRoundTripper(cfg, rt)
			if err != nil {
				return errorRoundTripper{err}
			}
			return signing
		})
	}
	return conf, nil
}

// validateHTTPSignatureExclusive reports a configuration that presents a
// credential alongside a signature. Both would be sent, the server would
// authenticate whichever its authenticator chain reached first, and the
// resulting identity would depend on server ordering rather than on the
// client's configuration.
//
// ExecProvider is deliberately not a conflict: an exec plugin is where signing
// key material comes from, so the two compose rather than compete. What the
// plugin may not do is return a token alongside the material, which the exec
// authenticator rejects when it reads the plugin's answer.
func (c *Config) validateHTTPSignatureExclusive() error {
	var conflicts []string
	if len(c.BearerToken) != 0 || len(c.BearerTokenFile) != 0 {
		conflicts = append(conflicts, "bearer token")
	}
	if len(c.Username) != 0 || len(c.Password) != 0 {
		conflicts = append(conflicts, "basic auth")
	}
	if c.AuthProvider != nil {
		conflicts = append(conflicts, "authProvider")
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("httpSignature cannot be used in combination with %s", strings.Join(conflicts, " or "))
	}
	return nil
}

// errorRoundTripper fails every request with the same error. Signer construction
// happens inside a transport wrapper, which cannot report an error, so the error
// is carried to the first request instead of being dropped.
type errorRoundTripper struct {
	err error
}

func (rt errorRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, rt.err
}

// Wrap adds a transport middleware function that will give the caller
// an opportunity to wrap the underlying http.RoundTripper prior to the
// first API call being made. The provided function is invoked after any
// existing transport wrappers are invoked.
func (c *Config) Wrap(fn transport.WrapperFunc) {
	c.WrapTransport = transport.Wrappers(c.WrapTransport, fn)
}
