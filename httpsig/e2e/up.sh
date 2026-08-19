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

# Brings up the demo cluster and writes a kubeconfig with one user per key.
#
# The node image has to be a source build of this branch, because the API server
# does the verifying. Build it once with:
#
#   kind build node-image --image "$(./env.sh image)" /path/to/kubernetes
#
# and the kubectl the client side needs with:
#
#   make WHAT=cmd/kubectl
#
# The cluster and image names come from env.sh and default to the branch name, so
# two branches on one machine do not share either. See env.sh for why.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
root="$(cd ../.. && pwd)"

source ./env.sh
cluster="$HTTPSIG_CLUSTER"
image="$HTTPSIG_NODE_IMAGE"
kubectl="${HTTPSIG_KUBECTL:-$root/_output/bin/kubectl}"
kind="${HTTPSIG_KIND:-$HOME/go/bin/kind}"

die() { echo "up.sh: $*" >&2; exit 1; }

[[ -x "$kubectl" ]] || die "no kubectl at $kubectl. Build one with: make -C $root WHAT=cmd/kubectl
A released kubectl will not work: kubeconfig parsing ignores unknown fields, so it
would drop the httpSignature block and send unauthenticated requests instead."
[[ -x "$kind" ]] || die "no kind at $kind"
docker image inspect "$image" >/dev/null 2>&1 || die "no node image $image.
Build one with: $kind build node-image --image $image $root"

./gen-fixtures.sh

# The name and the image are substituted rather than passed as flags, so the file
# kind reads is complete on its own and says what it built.
rendered=fixtures/kind.yaml
sed -E "s|^name:.*|name: $cluster|; s|^(\s*)image:.*|\\1image: $image|" kind.yaml >"$rendered"
grep -q "^name: $cluster\$" "$rendered" || die "could not set the cluster name in $rendered"
grep -q "image: $image\$" "$rendered" || die "could not set the node image in $rendered"

if "$kind" get clusters 2>/dev/null | grep -qx "$cluster"; then
  echo "up.sh: cluster $cluster already exists, reusing it"
else
  "$kind" create cluster --config "$rendered"
fi

admin=fixtures/admin.kubeconfig
"$kind" get kubeconfig --name "$cluster" >"$admin"

server="$("$kubectl" --kubeconfig "$admin" config view --raw -o jsonpath='{.clusters[0].cluster.server}')"
ca="$("$kubectl" --kubeconfig "$admin" config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"
[[ -n "$server" && -n "$ca" ]] || die "could not read the cluster address out of $admin"

./write-kubeconfig.sh "$server" "$ca"

# Authorization for the groups the signatures authenticate as. Without this the
# access review still works and answers "no", which proves authentication but
# says nothing about the groups arriving. Binding to the group rather than the
# user is what makes a "yes" evidence that the group came from the key.
"$kubectl" --kubeconfig "$admin" apply -f - >/dev/null <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: httpsig-demo-view
  namespace: default
subjects:
- kind: Group
  name: httpsig-demo
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
---
# kubectl validates a manifest client side before sending it, and part of that is
# listing custom resource definitions to find out whether the kind is one. That
# read is cluster scoped and the view role does not include it, so without this
# every kubectl create by a demo user fails on validation rather than on
# anything to do with the request. Only list, because that is the only verb the
# client uses here.
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: httpsig-demo-crd-lister
rules:
- apiGroups: ["apiextensions.k8s.io"]
  resources: ["customresourcedefinitions"]
  verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: httpsig-demo-crd-lister
subjects:
- kind: Group
  name: httpsig-demo
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: httpsig-demo-crd-lister
  apiGroup: rbac.authorization.k8s.io
EOF
# The authorizer sees role bindings through an informer, so a grant is not
# effective the instant apply returns. On a cluster this young the lag is enough
# for the next command to be denied. Waiting here, by impersonating the group as
# admin, keeps the retry out of test.sh: a denial there should mean a real denial.
wait_for_grant() { # description, can-i arguments
  local what="$1"; shift
  for _ in $(seq 1 60); do
    if [[ "$("$kubectl" --kubeconfig "$admin" auth can-i "$@" \
             --as=httpsig-readiness --as-group=httpsig-demo 2>/dev/null)" == "yes" ]]; then
      return 0
    fi
    sleep 0.5
  done
  die "the $what grant never took effect"
}
wait_for_grant "view" list pods -n default
wait_for_grant "CRD list" list customresourcedefinitions.apiextensions.k8s.io
echo "up.sh: bound group httpsig-demo to view in namespace default, and it is in effect"
echo "up.sh: ready. Run ./test.sh"
echo "up.sh: tear down with: $kind delete cluster --name $cluster"
