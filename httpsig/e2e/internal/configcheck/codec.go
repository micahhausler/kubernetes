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

package configcheck

import (
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apiserver/pkg/apis/apiserver"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
)

// authenticationConfigCodecs decodes an authentication configuration the way
// kube-apiserver does. Strict, so a field name the server would ignore is an error
// here instead: the failure this whole package exists to prevent is a configuration
// that looks right and does something else.
var authenticationConfigCodecs = sync.OnceValue(func() serializer.CodecFactory {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{apiserver.AddToScheme, apiserverv1.AddToScheme} {
		if err := add(scheme); err != nil {
			panic(fmt.Sprintf("configcheck: building the scheme: %v", err))
		}
	}
	return serializer.NewCodecFactory(scheme, serializer.EnableStrict)
})

// decodeAuthenticationConfiguration decodes one configuration file.
func decodeAuthenticationConfiguration(data []byte) (*apiserver.AuthenticationConfiguration, error) {
	decoded, err := runtime.Decode(authenticationConfigCodecs().UniversalDecoder(), data)
	if err != nil {
		return nil, err
	}
	config, ok := decoded.(*apiserver.AuthenticationConfiguration)
	if !ok {
		return nil, fmt.Errorf("decoded to %T, want an AuthenticationConfiguration", decoded)
	}
	return config, nil
}
