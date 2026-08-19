#!/usr/bin/env bash

# Copyright The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Exercises every credential end to end against the demo cluster.
#
# Each proves three separate things, and they are worth keeping apart:
#   whoami   the API server verified a signature and resolved it to an identity
#   SSAR     that identity's groups reached the authorizer
#   negative the wrong credential is rejected, so the checks above are not passing
#            for some other reason such as a client certificate or anonymous access
#
# Two ways of resolving a signature are covered. For the configured keys the server
# holds a key and an identity per client. For the certificate the server holds a
# certificate authority and nothing per client: the identity comes from the
# certificate the request carries, which is why the rogue context matters. Its
# certificate has the same subject and a signature that verifies against its own
# key, so the only thing wrong with it is who issued it.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
root="$(cd ../.. && pwd)"

# env.sh owns the cluster name, and kind names the container after it. Reading it
# from kind.yaml would be wrong now that up.sh renders that file rather than
# treating it as the source.
source ./env.sh
cluster="$HTTPSIG_CLUSTER"

kubectl="${HTTPSIG_KUBECTL:-$root/_output/bin/kubectl}"
export KUBECONFIG="$PWD/fixtures/kubeconfig"

# Signing from a client is alpha, so the client side is gated too. Without this
# the client refuses to sign rather than silently sending nothing.
export KUBE_FEATURE_ClientsAllowHTTPSignature=true

[[ -x "$kubectl" ]] || { echo "test.sh: no kubectl at $kubectl. Run ./up.sh first." >&2; exit 1; }
[[ -f "$KUBECONFIG" ]] || { echo "test.sh: no $KUBECONFIG. Run ./up.sh first." >&2; exit 1; }

failures=0

# Properties of the layout rather than of any request, checked because they are
# what the external key API is for and because a regression in them would not
# show up as a failing request.
#
# The root secret is nowhere near the node: the resolver holds a key folded
# through the date step, so even it can mint signatures only for the one day its
# rung names. A shared secret otherwise lets a verifier produce signatures
# indistinguishable from the client's.
if grep -rqs "httpsig-kind-demo-not-a-real-secret" fixtures/node/ fixtures/resolver/; then
  echo "  FAIL the root secret reached a file that is generated rather than held"
  failures=1
else
  echo "  ok   neither the node nor the resolver holds the root HMAC secret"
fi

# And the stronger property, which the static key list could not have: the
# directory the control plane mounts holds no key material at all. Before the move
# to a resolver this held a derived HMAC key and every public key.
node_files="$(find fixtures/node -type f -printf '%f\n' | sort | tr '\n' ' ')"
if [[ "$node_files" == "authentication-config.yaml " ]]; then
  echo "  ok   the control plane mounts one file, and it holds no key material"
else
  echo "  FAIL fixtures/node holds more than the authentication config: $node_files"
  failures=1
fi
if grep -rqsE "BEGIN (PUBLIC|EC|RSA|PRIVATE) KEY|secretBase64|secretFile" fixtures/node/; then
  echo "  FAIL key material appears in the directory the control plane mounts"
  failures=1
else
  echo "  ok   no key, public or private, in the API server's configuration"
fi

# The resolver is what answers for those keys, so a demo that passed with it dead
# would be proving something other than what it claims.
if ./resolver.sh status >/dev/null 2>&1; then
  echo "  ok   the resolver is running and holding the keys"
else
  echo "  FAIL the resolver is not running. Run ./up.sh, or ./resolver.sh start"
  failures=1
fi

# The same property for the assertion flow. The server is given the certificate
# authority and nothing else: no private key, and nothing naming this client.
if ls fixtures/node/ | grep -qE '\.key$|bundle'; then
  echo "  FAIL a private key is in fixtures/node/, which the API server mounts"
  failures=1
elif grep -qs "cert-demo" fixtures/node/authentication-config.yaml; then
  echo "  FAIL the API server's configuration names the certificate client; its identity"
  echo "       is supposed to come from the certificate rather than from this file"
  failures=1
else
  echo "  ok   the API server holds only the CA, and names no certificate client"
fi
check() {
  local what="$1" want="$2" got="$3"
  if [[ "$got" == "$want" ]]; then
    printf '  ok   %-34s %s\n' "$what" "$got"
  else
    printf '  FAIL %-34s want %q, got %q\n' "$what" "$want" "$got"
    failures=$((failures + 1))
  fi
}

ssar() { # context verb resource -> "true" or "false"
  "$kubectl" --context "$1" create -o jsonpath='{.status.allowed}' -f - <<EOF
apiVersion: authorization.k8s.io/v1
kind: SelfSubjectAccessReview
spec:
  resourceAttributes:
    namespace: default
    verb: $2
    resource: $3
EOF
}

for spec in "hmac:hmac-demo:httpsig-hmac" \
            "ecdsa:ecdsa-demo:httpsig-asymmetric" \
            "cert:cert-demo:httpsig-certificate" \
            "bundle:cert-demo:httpsig-certificate"; do
  IFS=: read -r context username group <<<"$spec"
  echo "== $context"

  # SelfSubjectReview: the server reports back the identity it authenticated,
  # which is the shortest path from "a signature verified" to "as whom".
  whoami="$("$kubectl" --context "$context" auth whoami -o json 2>&1)" || {
    printf '  FAIL %-34s %s\n' "auth whoami" "${whoami//$'\n'/ }"
    failures=$((failures + 1))
    continue
  }
  check "username" "$username" "$(jq -r '.status.userInfo.username' <<<"$whoami")"
  check "group from the key" "true" "$(jq --arg g "$group" 'any(.status.userInfo.groups[]; . == $g)' <<<"$whoami")"
  check "group shared by both keys" "true" "$(jq 'any(.status.userInfo.groups[]; . == "httpsig-demo")' <<<"$whoami")"

  # SelfSubjectAccessReview. Allowed because up.sh bound the shared group to
  # view; denied for create because view does not grant it. Both directions
  # matter: a "yes" to everything would mean we are talking as an admin.
  check "SSAR list pods (view allows)" "true" "$(ssar "$context" list pods)"
  check "SSAR create pods (view denies)" "false" "$(ssar "$context" create pods)"

  # The identity is the certificate's own when the certificate is the assertion, so
  # the thumbprint the server reports has to be the one this client holds. A
  # mismatch would mean the two sides digest different bytes, which the keyid
  # binding rests on.
  if [[ "$context" == cert || "$context" == bundle ]]; then
    want_uid="$(openssl x509 -in fixtures/client/cert-demo.crt -outform der | openssl dgst -sha256 -hex | awk '{print $NF}')"
    check "uid is the certificate digest" "$want_uid" "$(jq -r '.status.userInfo.uid' <<<"$whoami")"
    check "issuer arrives as an extra" "httpsig-demo-ca" \
      "$(jq -r '.status.userInfo.extra["httpsig.example.com/issuer"][0] // ""' <<<"$whoami")"
    continue
  fi

  # A wrong key of the right kind. The client signs happily and the server
  # rejects, with a 401 that deliberately does not say which part was wrong.
  tampered="$(HTTPSIG_DEMO_TAMPER=1 "$kubectl" --context "$context" auth whoami 2>&1 || true)"
  # Matching Unauthorized specifically. A looser pattern such as "error" would
  # also match the plugin failing to run, which would report a pass for a
  # request that was never signed and never sent.
  if grep -q "Unauthorized" <<<"$tampered"; then
    printf '  ok   %-34s rejected\n' "tampered key"
  else
    printf '  FAIL %-34s expected rejection, got %q\n' "tampered key" "${tampered//$'\n'/ }"
    failures=$((failures + 1))
  fi
done

# The trust boundary, over the wire. This certificate has the same subject as the
# accepted one and its signature verifies against its own key, so possession is not
# what is wrong with it. The server refuses it because nothing it holds issued it,
# which is the property that lets the server hold no per-client state at all.
echo "== rogue"
rogue="$("$kubectl" --context rogue auth whoami 2>&1 || true)"
if grep -q "Unauthorized" <<<"$rogue"; then
  printf '  ok   %-34s rejected\n' "certificate from another CA"
else
  printf '  FAIL %-34s expected rejection, got %q\n' "certificate from another CA" "${rogue//$'\n'/ }"
  failures=$((failures + 1))
fi

echo
if (( failures )); then
  echo "test.sh: $failures failed"
  echo "If whoami came back anonymous or unauthorized for both keys, check that"
  echo "  - \$kubectl is the source build, since a released one silently ignores"
  echo "    the httpSignature block in the kubeconfig, and"
  echo "  - the API server has the feature gate: docker exec $cluster-control-plane \\"
  echo "      grep -e authentication-config -e feature-gates /etc/kubernetes/manifests/kube-apiserver.yaml"
  exit 1
fi
echo "test.sh: all checks passed"
