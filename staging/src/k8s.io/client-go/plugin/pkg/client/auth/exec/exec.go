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

package exec

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	clientfeatures "k8s.io/client-go/features"
	"k8s.io/client-go/pkg/apis/clientauthentication"
	"k8s.io/client-go/pkg/apis/clientauthentication/install"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/metrics"
	"k8s.io/client-go/transport"
	httpsig "k8s.io/client-go/transport/httpsig"
	"k8s.io/client-go/util/connrotation"
	"k8s.io/client-go/util/pluginpolicy"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	"k8s.io/utils/dump"
)

const execInfoEnv = "KUBERNETES_EXEC_INFO"
const installHintVerboseHelp = `

It looks like you are trying to use a client-go credential plugin that is not installed.

To learn more about this feature, consult the documentation available at:
      https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins`

var scheme = runtime.NewScheme()
var codecs = serializer.NewCodecFactory(scheme)

func init() {
	install.Install(scheme)
}

var (
	// Since transports can be constantly re-initialized by programs like kubectl,
	// keep a cache of initialized authenticators keyed by a hash of their config.
	globalCache = newCache()
	// The list of API versions we accept.
	apiVersions = map[string]schema.GroupVersion{
		clientauthenticationv1beta1.SchemeGroupVersion.String(): clientauthenticationv1beta1.SchemeGroupVersion,
		clientauthenticationv1.SchemeGroupVersion.String():      clientauthenticationv1.SchemeGroupVersion,
	}
)

func newCache() *cache {
	return &cache{m: make(map[string]*Authenticator)}
}

func cacheKey(conf *api.ExecConfig, cluster *clientauthentication.Cluster, signing *httpsig.Config) string {
	key := struct {
		conf    *api.ExecConfig
		cluster *clientauthentication.Cluster
		signing *httpsig.Config
	}{
		conf:    conf,
		cluster: cluster,
		signing: signing,
	}
	return dump.Pretty(key)
}

type cache struct {
	mu sync.Mutex
	m  map[string]*Authenticator
}

func (c *cache) get(s string) (*Authenticator, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.m[s]
	return a, ok
}

// put inserts an authenticator into the cache. If an authenticator is already
// associated with the key, the first one is returned instead.
func (c *cache) put(s string, a *Authenticator) *Authenticator {
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, ok := c.m[s]
	if ok {
		return existing
	}
	c.m[s] = a
	return a
}

// sometimes rate limits how often a function f() is called. Specifically, Do()
// will run the provided function f() up to threshold times every interval
// duration.
type sometimes struct {
	threshold int
	interval  time.Duration

	clock clock.Clock
	mu    sync.Mutex

	count  int       // times we have called f() in this window
	window time.Time // beginning of current window of length interval
}

func (s *sometimes) Do(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.clock.Now()
	if s.window.IsZero() {
		s.window = now
	}

	// If we are no longer in our saved time window, then we get to reset our run
	// count back to 0 and start increasing towards the threshold again.
	if inWindow := now.Sub(s.window) < s.interval; !inWindow {
		s.window = now
		s.count = 0
	}

	// If we have not run the function more than threshold times in this current
	// time window, we get to run it now!
	if underThreshold := s.count < s.threshold; underThreshold {
		s.count++
		f()
	}
}

// GetAuthenticator returns an exec-based plugin for providing client credentials.
func GetAuthenticator(config *api.ExecConfig, cluster *clientauthentication.Cluster) (*Authenticator, error) {
	metrics.EnsureRegistered()
	return newAuthenticator(globalCache, term.IsTerminal, config, cluster, nil)
}

// GetSigningAuthenticator returns an exec-based plugin that provides HTTP message
// signature key material rather than a credential that transits.
//
// The signing configuration is required because it decides what the plugin is
// asked for and what its answer has to satisfy: the algorithm, the derivation
// ladder a plugin needs in order to hand back an intermediate rung, and the
// headers a credential must supply a value for. It is part of the cache key for
// the same reason, since two clients naming the same command may cover different
// headers.
func GetSigningAuthenticator(config *api.ExecConfig, cluster *clientauthentication.Cluster, signing *httpsig.Config) (*Authenticator, error) {
	metrics.EnsureRegistered()
	if signing == nil {
		return nil, fmt.Errorf("exec plugin: a signing configuration is required")
	}
	// The field a plugin answers in is an alpha addition to a GA API, so the
	// client refuses to ask for it unless the gate is on. Failing here rather
	// than when the plugin runs means the configuration is rejected while the
	// client is being built.
	if !clientfeatures.FeatureGates().Enabled(clientfeatures.ClientsAllowHTTPSignature) {
		return nil, fmt.Errorf("exec plugin: signing key material from an exec plugin requires the %s feature gate", clientfeatures.ClientsAllowHTTPSignature)
	}
	return newAuthenticator(globalCache, term.IsTerminal, config, cluster, signing)
}

func newAuthenticator(c *cache, isTerminalFunc func(int) bool, config *api.ExecConfig, cluster *clientauthentication.Cluster, signing *httpsig.Config) (*Authenticator, error) {
	key := cacheKey(config, cluster, signing)
	if a, ok := c.get(key); ok {
		return a, nil
	}

	gv, ok := apiVersions[config.APIVersion]
	if !ok {
		return nil, fmt.Errorf("exec plugin: invalid apiVersion %q", config.APIVersion)
	}

	connTracker := connrotation.NewConnectionTracker()
	defaultDialer := connrotation.NewDialerWithTracker(
		(&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		connTracker,
	)

	// Whether a credential program may run is decided in
	// k8s.io/client-go/util/pluginpolicy, because more than one kind of
	// credential program answers to the same policy.
	policyChecker, err := newPolicyChecker(config.Command, config.PluginPolicy)
	if err != nil {
		return nil, fmt.Errorf("invalid plugin policy: %w", err)
	}

	a := &Authenticator{
		// Clean is called to normalize the path to facilitate comparison with
		// the allowlist, when present
		cmd:                filepath.Clean(config.Command),
		args:               config.Args,
		group:              gv,
		cluster:            cluster,
		provideClusterInfo: config.ProvideClusterInfo,

		signing:         signing,
		declaredHeaders: declaredSignedHeaders(signing),

		policyChecker: policyChecker,

		installHint: config.InstallHint,
		sometimes: &sometimes{
			threshold: 10,
			interval:  time.Hour,
			clock:     clock.RealClock{},
		},

		stdin:           os.Stdin,
		stderr:          os.Stderr,
		interactiveFunc: func() (bool, error) { return isInteractive(isTerminalFunc, config) },
		now:             time.Now,
		environ:         os.Environ,

		connTracker: connTracker,
	}

	for _, env := range config.Env {
		a.env = append(a.env, env.Name+"="+env.Value)
	}

	// these functions are made comparable and stored in the cache so that repeated clientset
	// construction with the same rest.Config results in a single TLS cache and Authenticator
	a.getCert = &transport.GetCertHolder{GetCert: a.cert}
	a.dial = &transport.DialHolder{Dial: defaultDialer.DialContext}

	return c.put(key, a), nil
}

func isInteractive(isTerminalFunc func(int) bool, config *api.ExecConfig) (bool, error) {
	var shouldBeInteractive bool
	switch config.InteractiveMode {
	case api.NeverExecInteractiveMode:
		shouldBeInteractive = false
	case api.IfAvailableExecInteractiveMode:
		shouldBeInteractive = !config.StdinUnavailable && isTerminalFunc(int(os.Stdin.Fd()))
	case api.AlwaysExecInteractiveMode:
		if !isTerminalFunc(int(os.Stdin.Fd())) {
			return false, errors.New("standard input is not a terminal")
		}
		if config.StdinUnavailable {
			suffix := ""
			if len(config.StdinUnavailableMessage) > 0 {
				// only print extra ": <message>" if the user actually specified a message
				suffix = fmt.Sprintf(": %s", config.StdinUnavailableMessage)
			}
			return false, fmt.Errorf("standard input is unavailable%s", suffix)
		}
		shouldBeInteractive = true
	default:
		return false, fmt.Errorf("unknown interactiveMode: %q", config.InteractiveMode)
	}

	return shouldBeInteractive, nil
}

// Authenticator is a client credential provider that rotates credentials by executing a plugin.
// The plugin input and output are defined by the API group client.authentication.k8s.io.
type Authenticator struct {
	// Set by the config
	cmd                string
	args               []string
	group              schema.GroupVersion
	env                []string
	cluster            *clientauthentication.Cluster
	provideClusterInfo bool

	policyChecker *pluginpolicy.Checker

	// signing is set when the plugin provides signing key material rather than a
	// credential that transits. It holds what does not change about the signing
	// identity, which is what the plugin is told in order to produce material
	// that fits.
	signing *httpsig.Config
	// declaredHeaders is signing.SignedHeaders indexed for lookup.
	declaredHeaders map[string]bool

	// Used to avoid log spew by rate limiting install hint printing. We didn't do
	// this by interval based rate limiting alone since that way may have prevented
	// the install hint from showing up for kubectl users.
	sometimes   *sometimes
	installHint string

	// Stubbable for testing
	stdin           io.Reader
	stderr          io.Writer
	interactiveFunc func() (bool, error)
	now             func() time.Time
	environ         func() []string

	// connTracker tracks all connections opened that we need to close when rotating a client certificate
	connTracker *connrotation.ConnectionTracker

	// Cached results.
	//
	// The mutex also guards calling the plugin. Since the plugin could be
	// interactive we want to make sure it's only called once.
	mu          sync.Mutex
	cachedCreds *credentials
	exp         time.Time

	// getCert makes Authenticator.cert comparable to support TLS config caching
	getCert *transport.GetCertHolder
	// dial is used for clients which do not specify a custom dialer
	// it is comparable to support TLS config caching
	dial *transport.DialHolder
}

type credentials struct {
	token string           `datapolicy:"token"`
	cert  *tls.Certificate `datapolicy:"secret-key"`
	// signing holds key material the client signs each request with. Unlike the
	// other two it never leaves this process.
	signing *httpsig.BoundCredential `datapolicy:"secret-key"`
}

// UpdateTransportConfig updates the transport.Config to use credentials
// returned by the plugin.
func (a *Authenticator) UpdateTransportConfig(c *transport.Config) error {
	// A client configured to sign is configured to sign. The precedence rules
	// below exist so that a credential stated on the command line wins over an
	// exec plugin, which is a choice between two credentials that transit; a
	// signature is not one of those, and silently not installing the signer would
	// authenticate the request as something else with nothing said about it.
	//
	// The conflicting cases are refused rather than ranked, by
	// rest.Config.validateHTTPSignatureExclusive and by clientcmd validation, so
	// reaching here with signing configured means there is nothing to rank.
	if a.signing == nil {
		// If a bearer token is present in the request - avoid the GetCert callback when
		// setting up the transport, as that triggers the exec action if the server is
		// also configured to allow client certificates for authentication. For requests
		// like "kubectl get --token (token) pods" we should assume the intention is to
		// use the provided token for authentication. The same can be said for when the
		// user specifies basic auth or cert auth.
		if c.HasTokenAuth() || c.HasBasicAuth() || c.HasCertAuth() {
			return nil
		}
	} else if c.HasCertAuth() {
		// Not reachable through clientcmd or rest.Config, both of which refuse the
		// combination. Refused here too rather than trusted to be unreachable,
		// because the failure mode is silent authentication as the wrong identity.
		return fmt.Errorf("exec plugin is configured to sign requests, but the client also has a client certificate; " +
			"to sign with that certificate set httpSignature.certFile and httpSignature.keyFile instead")
	}

	if a.signing != nil {
		// Signing replaces the credential rather than adding to it, so the
		// bearer token round tripper below is not installed and neither is the
		// client certificate callback: this plugin returns neither.
		//
		// Wrapping here puts the signer closest to the wire, so the impersonation
		// and user agent round trippers have already set their headers when it
		// runs and the signature can cover them.
		names := make([]string, 0, len(a.signing.SignedHeaders))
		for _, h := range a.signing.SignedHeaders {
			names = append(names, h.Name)
		}
		signing := *a.signing
		c.Wrap(func(rt http.RoundTripper) http.RoundTripper {
			signer, err := httpsig.NewRoundTripperWithSource(&signingSource{a}, names, signing.TTL, rt)
			if err != nil {
				return errorRoundTripper{err}
			}
			return signer
		})
		return nil
	}

	c.Wrap(func(rt http.RoundTripper) http.RoundTripper {
		return &roundTripper{a, rt}
	})

	if c.HasCertCallback() {
		return errors.New("can't add TLS certificate callback: transport.Config.TLS.GetCert already set")
	}
	c.TLS.GetCertHolder = a.getCert // comparable for TLS config caching

	if c.DialHolder != nil {
		if c.DialHolder.Dial == nil {
			return errors.New("invalid transport.Config.DialHolder: wrapped Dial function is nil")
		}

		// if c has a custom dialer, we have to wrap it
		// TLS config caching is not supported for this config
		d := connrotation.NewDialerWithTracker(c.DialHolder.Dial, a.connTracker)
		c.DialHolder = &transport.DialHolder{Dial: d.DialContext}
	} else {
		c.DialHolder = a.dial // comparable for TLS config caching
	}

	return nil
}

var _ utilnet.RoundTripperWrapper = &roundTripper{}

type roundTripper struct {
	a    *Authenticator
	base http.RoundTripper
}

func (r *roundTripper) WrappedRoundTripper() http.RoundTripper {
	return r.base
}

func (r *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// If a user has already set credentials, use that. This makes commands like
	// "kubectl get --token (token) pods" work.
	if req.Header.Get("Authorization") != "" {
		return r.base.RoundTrip(req)
	}

	creds, err := r.a.getCreds()
	if err != nil {
		return nil, fmt.Errorf("getting credentials: %v", err)
	}
	if creds.token != "" {
		req.Header.Set("Authorization", "Bearer "+creds.token)
	}

	res, err := r.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusUnauthorized {
		if err := r.a.maybeRefreshCreds(creds); err != nil {
			klog.Errorf("refreshing credentials: %v", err)
		}
	}
	return res, nil
}

func (a *Authenticator) credsExpired() bool {
	if a.exp.IsZero() {
		return false
	}
	return a.now().After(a.exp)
}

func (a *Authenticator) cert() (*tls.Certificate, error) {
	creds, err := a.getCreds()
	if err != nil {
		return nil, err
	}
	return creds.cert, nil
}

func (a *Authenticator) getCreds() (*credentials, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cachedCreds != nil && !a.credsExpired() {
		return a.cachedCreds, nil
	}

	if err := a.refreshCredsLocked(); err != nil {
		return nil, err
	}

	return a.cachedCreds, nil
}

// maybeRefreshCreds executes the plugin to force a rotation of the
// credentials, unless they were rotated already.
func (a *Authenticator) maybeRefreshCreds(creds *credentials) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Since we're not making a new pointer to a.cachedCreds in getCreds, no
	// need to do deep comparison.
	if creds != a.cachedCreds {
		// Credentials already rotated.
		return nil
	}

	return a.refreshCredsLocked()
}

// refreshCredsLocked executes the plugin and reads the credentials from
// stdout. It must be called while holding the Authenticator's mutex.
func (a *Authenticator) refreshCredsLocked() error {
	interactive, err := a.interactiveFunc()
	if err != nil {
		return fmt.Errorf("exec plugin cannot support interactive mode: %w", err)
	}

	cred := &clientauthentication.ExecCredential{
		Spec: clientauthentication.ExecCredentialSpec{
			Interactive: interactive,
		},
	}
	if a.provideClusterInfo {
		cred.Spec.Cluster = a.cluster
	}
	if a.signing != nil {
		// A plugin cannot produce a usable credential without this: it has to
		// know which headers to supply values for, and a plugin handing back an
		// intermediate rung has to derive through the same ladder the client
		// derives through. None of it is secret, so it is not gated on
		// provideClusterInfo.
		cred.Spec.HTTPSignature = signatureRequest(a.signing)
	}

	env := append(a.environ(), a.env...)
	data, err := runtime.Encode(codecs.LegacyCodec(a.group), cred)
	if err != nil {
		return fmt.Errorf("encode ExecCredentials: %v", err)
	}
	env = append(env, fmt.Sprintf("%s=%s", execInfoEnv, data))

	stdout := &bytes.Buffer{}
	cmd := exec.Command(a.cmd, a.args...)
	cmd.Env = env
	cmd.Stderr = a.stderr
	cmd.Stdout = stdout
	if interactive {
		cmd.Stdin = a.stdin
	}

	err = a.updateCommandAndCheckAllowlistLocked(cmd)
	incrementPolicyMetric(err)
	if err != nil {
		return err
	}

	err = cmd.Run()
	incrementCallsMetric(err)
	if err != nil {
		return a.wrapCmdRunErrorLocked(err)
	}

	_, gvk, err := codecs.UniversalDecoder(a.group).Decode(stdout.Bytes(), nil, cred)
	if err != nil {
		return fmt.Errorf("decoding stdout: %v", err)
	}
	if gvk.Group != a.group.Group || gvk.Version != a.group.Version {
		return fmt.Errorf("exec plugin is configured to use API version %s, plugin returned version %s",
			a.group, schema.GroupVersion{Group: gvk.Group, Version: gvk.Version})
	}

	if cred.Status == nil {
		return fmt.Errorf("exec plugin didn't return a status field")
	}
	if cred.Status.Token == "" && cred.Status.ClientCertificateData == "" && cred.Status.ClientKeyData == "" && cred.Status.HTTPSignature == nil {
		return fmt.Errorf("exec plugin didn't return a token, a cert/key pair, or signing key material")
	}
	if (cred.Status.ClientCertificateData == "") != (cred.Status.ClientKeyData == "") {
		return fmt.Errorf("exec plugin returned only certificate or key, not both")
	}
	// A credential that transits alongside one that does not would leave the
	// server to authenticate whichever its authenticator chain reached first, so
	// the identity would depend on server ordering rather than on this
	// configuration.
	//
	// A certificate is not in that category when the client is configured to sign.
	// Then the certificate is the assertion of who the signer is, used locally to
	// derive the key ID and carried in a covered header, and it never becomes the
	// client's TLS material. So the pair serves one purpose or the other, chosen by
	// configuration, and only a token is unconditionally in conflict.
	if cred.Status.HTTPSignature != nil && cred.Status.Token != "" {
		return fmt.Errorf("exec plugin returned signing key material alongside a token, which are alternatives rather than additions")
	}
	if cred.Status.HTTPSignature != nil && cred.Status.ClientCertificateData != "" {
		return fmt.Errorf("exec plugin returned both signing key material and a certificate; a signature is made under one key, so return the certificate and its key, or the key material, not both")
	}
	if a.signing != nil && cred.Status.Token != "" {
		return fmt.Errorf("exec plugin returned a token, but this client is configured to sign requests rather than to send a credential")
	}
	if cred.Status.HTTPSignature != nil && a.signing == nil {
		return fmt.Errorf("exec plugin returned signing key material, but this client is not configured to sign requests")
	}
	signsWithCertificate := a.signing != nil && cred.Status.ClientCertificateData != ""
	if a.signing != nil && cred.Status.HTTPSignature == nil && !signsWithCertificate {
		return fmt.Errorf("exec plugin returned no signing key material and no certificate, and this client is configured to sign requests")
	}
	// The algorithm is stated in the kubeconfig for key material and derived from
	// the key type for a certificate. Which one the plugin would return is not
	// knowable before it runs, so this is the first point where both facts exist,
	// and it is therefore where they are compared.
	if signsWithCertificate && a.signing.Algorithm != "" {
		return fmt.Errorf("exec plugin returned a certificate to sign with, but the kubeconfig states algorithm %q; "+
			"a certificate's key type determines the algorithm, so leave it unset when the plugin returns one", a.signing.Algorithm)
	}
	if cred.Status.HTTPSignature != nil && a.signing.Algorithm == "" {
		return fmt.Errorf("exec plugin returned signing key material, but the kubeconfig states no algorithm; " +
			"algorithm is required unless the plugin returns a certificate, whose key type determines it")
	}
	if signsWithCertificate && len(a.declaredHeaders) > 0 {
		return fmt.Errorf("exec plugin returned a certificate to sign with, but the kubeconfig covers signed headers, whose values only a signing credential carries")
	}

	if cred.Status.ExpirationTimestamp != nil {
		a.exp = cred.Status.ExpirationTimestamp.Time
	} else {
		a.exp = time.Time{}
	}

	newCreds := &credentials{
		token: cred.Status.Token,
	}
	if sig := cred.Status.HTTPSignature; sig != nil {
		// Validating here means a plugin that returns material the client cannot
		// use fails when the plugin runs, naming what is wrong with the
		// credential, rather than as a signature the server rejects.
		bound, err := httpsig.NewBoundCredential(signatureMaterial(sig, cred.Status.ExpirationTimestamp),
			"exec plugin "+a.cmd, alg(a.signing), a.signing.KeyDerivation, a.declaredHeaders)
		if err != nil {
			return err
		}
		newCreds.signing = bound
	}
	if signsWithCertificate {
		// The certificate is signing material, so it is built into a credential
		// here and deliberately not installed below as the client's TLS
		// certificate. The same bytes would otherwise authenticate the connection
		// as well, which is the ordering ambiguity this whole flow exists to avoid.
		bound, err := httpsig.NewCertificateCredential("exec plugin "+a.cmd,
			[]byte(cred.Status.ClientCertificateData), []byte(cred.Status.ClientKeyData),
			cred.Status.ExpirationTimestamp)
		if err != nil {
			return err
		}
		newCreds.signing = bound
	}
	if cred.Status.ClientKeyData != "" && cred.Status.ClientCertificateData != "" && !signsWithCertificate {
		cert, err := tls.X509KeyPair([]byte(cred.Status.ClientCertificateData), []byte(cred.Status.ClientKeyData))
		if err != nil {
			return fmt.Errorf("failed parsing client key/certificate: %v", err)
		}

		// Leaf is initialized to be nil:
		//  https://golang.org/pkg/crypto/tls/#X509KeyPair
		// Leaf certificate is the first certificate:
		//  https://golang.org/pkg/crypto/tls/#Certificate
		// Populating leaf is useful for quickly accessing the underlying x509
		// certificate values.
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("failed parsing client leaf certificate: %v", err)
		}
		newCreds.cert = &cert
	}

	oldCreds := a.cachedCreds
	a.cachedCreds = newCreds
	// Only close all connections when TLS cert rotates. Token rotation doesn't
	// need the extra noise.
	if oldCreds != nil && !reflect.DeepEqual(oldCreds.cert, a.cachedCreds.cert) {
		// Can be nil if the exec auth plugin only returned token auth.
		if oldCreds.cert != nil && oldCreds.cert.Leaf != nil {
			metrics.ClientCertRotationAge.Observe(time.Since(oldCreds.cert.Leaf.NotBefore))
		}
		a.connTracker.CloseAll()
	}

	expiry := time.Time{}
	if a.cachedCreds.cert != nil && a.cachedCreds.cert.Leaf != nil {
		expiry = a.cachedCreds.cert.Leaf.NotAfter
	}
	expirationMetrics.set(a, expiry)
	return nil
}

// wrapCmdRunErrorLocked pulls out the code to construct a helpful error message
// for when the exec plugin's binary fails to Run().
//
// It must be called while holding the Authenticator's mutex.
func (a *Authenticator) wrapCmdRunErrorLocked(err error) error {
	switch err.(type) {
	case *exec.Error: // Binary does not exist (see exec.Error).
		builder := strings.Builder{}
		fmt.Fprintf(&builder, "exec: executable %s not found", a.cmd)

		a.sometimes.Do(func() {
			fmt.Fprint(&builder, installHintVerboseHelp)
			if a.installHint != "" {
				fmt.Fprintf(&builder, "\n\n%s", a.installHint)
			}
		})

		return errors.New(builder.String())

	case *exec.ExitError: // Binary execution failed (see exec.Cmd.Run()).
		e := err.(*exec.ExitError)
		return fmt.Errorf(
			"exec: executable %s failed with exit code %d",
			a.cmd,
			e.ProcessState.ExitCode(),
		)

	default:
		return fmt.Errorf("exec: %v", err)
	}
}

// `updateCommandAndCheckAllowlistLocked` determines whether or not the specified
// executable may run according to the credential plugin policy. If the plugin is
// allowed, `nil` is returned. If the plugin is not allowed, an error must be
// returned explaining why. When the policy is an allowlist and the command
// matches only after path resolution, cmd.Path is updated, so the program that
// was checked is the program that runs.
func (a *Authenticator) updateCommandAndCheckAllowlistLocked(cmd *exec.Cmd) error {
	return a.policyChecker.Check(cmd)
}

// newPolicyChecker converts the configured policy into a checker.
func newPolicyChecker(command string, policy api.PluginPolicy) (*pluginpolicy.Checker, error) {
	return pluginpolicy.New(command, pluginpolicy.Type(policy.PolicyType), allowlistCommands(policy))
}

// allowlistCommands flattens the allowlist to the commands it names, preserving
// nil. An unspecified allowlist under an Allowlist policy is a misconfiguration
// and is not the same as an empty one, so nil must survive the conversion.
func allowlistCommands(policy api.PluginPolicy) []string {
	if policy.Allowlist == nil {
		return nil
	}
	commands := make([]string, 0, len(policy.Allowlist))
	for _, entry := range policy.Allowlist {
		commands = append(commands, entry.Command)
	}
	return commands
}

func ValidatePluginPolicy(policy api.PluginPolicy) error {
	return pluginpolicy.Validate(pluginpolicy.Type(policy.PolicyType), allowlistCommands(policy))
}

// errorRoundTripper fails every request with the same error. The signing round
// tripper is built inside a transport wrapper, which has no way to report an
// error, so the error is carried to the first request instead of being dropped.
type errorRoundTripper struct {
	err error
}

func (rt errorRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, rt.err
}
