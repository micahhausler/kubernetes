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

# Exercises both keys end to end against the demo cluster.
#
# Each key proves three separate things, and they are worth keeping apart:
#   whoami   the API server verified a signature and mapped the key to an identity
#   SSAR     that identity's groups reached the authorizer
#   tamper   a wrong key is rejected, so the checks above are not passing for
#            some other reason such as the client certificate or anonymous access
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
root="$(cd ../.. && pwd)"

kubectl="${HTTPSIG_KUBECTL:-$root/_output/bin/kubectl}"
export KUBECONFIG="$PWD/fixtures/kubeconfig"

# Signing from a client is alpha, so the client side is gated too. Without this
# the client refuses to sign rather than silently sending nothing.
export KUBE_FEATURE_ClientsAllowHTTPSignature=true

[[ -x "$kubectl" ]] || { echo "test.sh: no kubectl at $kubectl. Run ./up.sh first." >&2; exit 1; }
[[ -f "$KUBECONFIG" ]] || { echo "test.sh: no $KUBECONFIG. Run ./up.sh first." >&2; exit 1; }

failures=0

# A property of the layout rather than of a request: the API server is given a
# key folded through the date step, so the root secret is not in the directory it
# mounts. This is what the ladder buys in this configuration. A shared secret
# otherwise lets the verifier mint signatures indistinguishable from the
# client's; here it could do so only for the one day its rung names.
if grep -rqs "httpsig-kind-demo-not-a-real-secret" fixtures/node/; then
  echo "  FAIL the root secret is in fixtures/node/, which the API server mounts"
  failures=1
else
  echo "  ok   the API server never sees the root HMAC secret"
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

for spec in "hmac:hmac-demo:httpsig-hmac" "ecdsa:ecdsa-demo:httpsig-asymmetric"; do
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

echo
if (( failures )); then
  echo "test.sh: $failures failed"
  echo "If whoami came back anonymous or unauthorized for both keys, check that"
  echo "  - \$kubectl is the source build, since a released one silently ignores"
  echo "    the httpSignature block in the kubeconfig, and"
  echo "  - the API server has the feature gate: docker exec httpsig-control-plane \\"
  echo "      grep -e authentication-config -e feature-gates /etc/kubernetes/manifests/kube-apiserver.yaml"
  exit 1
fi
echo "test.sh: all checks passed"
