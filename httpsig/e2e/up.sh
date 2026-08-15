#!/usr/bin/env bash
# Brings up the demo cluster and writes a kubeconfig with one user per key.
#
# The node image has to be a source build of this branch, because the API server
# does the verifying. Build it once with:
#
#   kind build node-image --image kindest/node:httpsig-dev /path/to/kubernetes
#
# and the kubectl the client side needs with:
#
#   make WHAT=cmd/kubectl
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
root="$(cd ../.. && pwd)"

cluster=httpsig
# kind.yaml owns the image name; this only reads it back so the check below can
# fail with something better than a connection refused twenty seconds in.
image="${HTTPSIG_NODE_IMAGE:-$(grep -oP '^\s*image:\s*\K\S+' kind.yaml)}"
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

if "$kind" get clusters 2>/dev/null | grep -qx "$cluster"; then
  echo "up.sh: cluster $cluster already exists, reusing it"
else
  create=(--config kind.yaml)
  [[ -n "${HTTPSIG_NODE_IMAGE:-}" ]] && create+=(--image "$HTTPSIG_NODE_IMAGE")
  "$kind" create cluster "${create[@]}"
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
  local i
  for i in $(seq 1 60); do
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
