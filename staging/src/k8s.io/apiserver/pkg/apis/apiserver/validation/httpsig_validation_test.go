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

package validation

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/apis/apiserver"
)

func validHTTPSignatureConfig() apiserver.HTTPSignatureAuthenticator {
	return apiserver.HTTPSignatureAuthenticator{
		Endpoint: "unix:///var/run/httpsig-resolver.sock",
	}
}

func int32Ptr(i int32) *int32 { return &i }

func TestValidateHTTPSignatureAuthenticators(t *testing.T) {
	for _, tc := range []struct {
		name    string
		configs []apiserver.HTTPSignatureAuthenticator
		gate    bool
		// wantErr is a substring of the expected error, or empty for no error.
		wantErr string
	}{
		{
			name:    "valid",
			configs: []apiserver.HTTPSignatureAuthenticator{validHTTPSignatureConfig()},
			gate:    true,
		},
		{
			name:    "absent section is fine with the gate off",
			configs: nil,
			gate:    false,
		},
		{
			name:    "present section needs the gate",
			configs: []apiserver.HTTPSignatureAuthenticator{validHTTPSignatureConfig()},
			gate:    false,
			wantErr: "HTTPSignatureAuthentication feature gate is disabled",
		},
		{
			name:    "endpoint is required",
			configs: []apiserver.HTTPSignatureAuthenticator{{}},
			gate:    true,
			wantErr: "keys are not configured in this file",
		},
		{
			name:    "endpoint must be a unix socket",
			configs: []apiserver.HTTPSignatureAuthenticator{{Endpoint: "https://resolver.example.com"}},
			gate:    true,
			wantErr: "unsupported scheme",
		},
		{
			name: "abstract socket is accepted",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///@httpsig-resolver"},
			},
			gate: true,
		},
		{
			name: "duplicate endpoints",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"one"}},
				{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"two"}},
			},
			gate:    true,
			wantErr: "Duplicate value",
		},
		{
			name: "two catch-all resolvers fan out",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock"},
				{Endpoint: "unix:///b.sock"},
			},
			gate:    true,
			wantErr: "at most one entry may omit keyIDPrefixes",
		},
		{
			name: "one catch-all alongside a prefixed resolver is fine",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"corp"}},
				{Endpoint: "unix:///b.sock"},
			},
			gate: true,
		},
		{
			name: "duplicate prefix across resolvers",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"corp"}},
				{Endpoint: "unix:///b.sock", KeyIDPrefixes: []string{"corp"}},
			},
			gate:    true,
			wantErr: "Duplicate value",
		},
		{
			name: "prefix with a slash can never match",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"corp/cell-a"}},
			},
			gate:    true,
			wantErr: "can never match",
		},
		{
			name: "empty prefix",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{""}},
			},
			gate:    true,
			wantErr: "omit keyIDPrefixes",
		},
		{
			name: "disagreeing authority",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"one"}, Authority: "one.example.com"},
				{Endpoint: "unix:///b.sock", KeyIDPrefixes: []string{"two"}, Authority: "two.example.com"},
			},
			gate:    true,
			wantErr: "describes this server rather than a resolver",
		},
		{
			name: "disagreeing scheme",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"one"}, Scheme: "https"},
				{Endpoint: "unix:///b.sock", KeyIDPrefixes: []string{"two"}, Scheme: "http"},
			},
			gate:    true,
			wantErr: "describes this server rather than a resolver",
		},
		{
			name: "agreeing scheme and authority",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", KeyIDPrefixes: []string{"one"}, Scheme: "https", Authority: "api.example.com"},
				{Endpoint: "unix:///b.sock", KeyIDPrefixes: []string{"two"}, Scheme: "https", Authority: "api.example.com"},
			},
			gate: true,
		},
		{
			name: "bad scheme",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", Scheme: "ftp"},
			},
			gate:    true,
			wantErr: "must be http or https",
		},
		{
			name: "zero maxAge",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", MaxAge: &metav1.Duration{}},
			},
			gate:    true,
			wantErr: "must be positive",
		},
		{
			name: "negative tolerance",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", Tolerance: &metav1.Duration{Duration: -time.Second}},
			},
			gate:    true,
			wantErr: "must not be negative",
		},
		{
			name: "reserved relayed header",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", RelayedHeaders: []string{"Authorization"}},
			},
			gate:    true,
			wantErr: "route around that path",
		},
		{
			name: "reserved impersonation prefix",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", RelayedHeaders: []string{"Impersonate-Extra-Scopes"}},
			},
			gate:    true,
			wantErr: "route around that path",
		},
		{
			name: "duplicate relayed header differing only in case",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", RelayedHeaders: []string{"X-Token", "x-token"}},
			},
			gate:    true,
			wantErr: "Duplicate value",
		},
		{
			name: "invalid relayed header name",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", RelayedHeaders: []string{"X Token"}},
			},
			gate:    true,
			wantErr: "not a valid HTTP header field name",
		},
		{
			name: "valid relayed header",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", RelayedHeaders: []string{"X-Session-Token"}},
			},
			gate: true,
		},
		{
			name: "zero cache maxKeys",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", Cache: &apiserver.HTTPSignatureCache{MaxKeys: int32Ptr(0)}},
			},
			gate:    true,
			wantErr: "must be positive",
		},
		{
			name: "negative cache maxAge",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", Cache: &apiserver.HTTPSignatureCache{MaxAge: &metav1.Duration{Duration: -time.Second}}},
			},
			gate:    true,
			wantErr: "must not be negative",
		},
		{
			name: "zero cache maxAge disables caching and is allowed",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", Cache: &apiserver.HTTPSignatureCache{MaxAge: &metav1.Duration{}}},
			},
			gate: true,
		},
		{
			name: "nonceHandling Consume",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", NonceHandling: apiserver.NonceHandlingConsume},
			},
			gate: true,
		},
		{
			name: "nonceHandling Ignore",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", NonceHandling: apiserver.NonceHandlingIgnore},
			},
			gate: true,
		},
		{
			// A typo would otherwise fall through to the safe default, leaving replay
			// protection on for an operator who meant to turn it off and sending them
			// to the resolver to find out why.
			name: "nonceHandling typo",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", NonceHandling: "ignore"},
			},
			gate:    true,
			wantErr: "Unsupported value",
		},
		{
			name: "nonceHandling nonsense",
			configs: []apiserver.HTTPSignatureAuthenticator{
				{Endpoint: "unix:///a.sock", NonceHandling: "Disabled"},
			},
			gate:    true,
			wantErr: "Unsupported value",
		},
		{
			name:    "too many resolvers",
			configs: manyResolvers(maxHTTPSignatureResolvers + 1),
			gate:    true,
			wantErr: "Too many",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateHTTPSignatureAuthenticators(tc.configs, field.NewPath("httpSignature"), tc.gate)
			got := errs.ToAggregate()
			switch {
			case tc.wantErr == "" && got != nil:
				t.Fatalf("unexpected error: %v", got)
			case tc.wantErr != "" && got == nil:
				t.Fatalf("expected an error containing %q, got none", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(got.Error(), tc.wantErr):
				t.Fatalf("expected an error containing %q, got: %v", tc.wantErr, got)
			}
		})
	}
}

func manyResolvers(n int) []apiserver.HTTPSignatureAuthenticator {
	out := make([]apiserver.HTTPSignatureAuthenticator, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, apiserver.HTTPSignatureAuthenticator{
			Endpoint:      "unix:///resolver-" + string(rune('a'+i)) + ".sock",
			KeyIDPrefixes: []string{"prefix-" + string(rune('a'+i))},
		})
	}
	return out
}
