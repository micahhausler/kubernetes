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

# Tears down the demo: the cluster and the resolver.
#
# This exists because the demo is now two things rather than one. Deleting the
# cluster and forgetting the resolver leaves a process holding a socket, and the
# next up.sh then fails on a socket that is in use rather than starting cleanly.
#
# Generated fixtures are left alone. They hold the client's keys, and a script
# named down should not be the thing that deletes them; pass --fixtures to say so
# explicitly.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

# env.sh is the one answer for which cluster this worktree owns, so tearing down can
# only ever reach the one this branch created.
source ./env.sh
cluster="$HTTPSIG_CLUSTER"
kind="${HTTPSIG_KIND:-$HOME/go/bin/kind}"

# The resolver goes first. It is the thing the API server depends on, so stopping
# it before the cluster keeps the last thing in its log from being a page of
# connection errors from a control plane that is already going away.
./resolver.sh stop || true

if [[ -x "$kind" ]] && "$kind" get clusters 2>/dev/null | grep -qx "$cluster"; then
  "$kind" delete cluster --name "$cluster"
else
  echo "down.sh: no cluster named $cluster"
fi

if [[ "${1:-}" == "--fixtures" ]]; then
  rm -rf fixtures
  echo "down.sh: removed fixtures, including the client's keys"
else
  echo "down.sh: kept fixtures. Pass --fixtures to remove the generated keys too."
fi
