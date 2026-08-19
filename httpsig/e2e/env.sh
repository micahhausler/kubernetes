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

# The names this demo takes over on the machine it runs on: the kind cluster, and
# the node image tag. Sourced by every other script here so there is one answer,
# and executable so a human can ask for the same one.
#
#   ./env.sh          both, as shell assignments
#   ./env.sh cluster  the cluster name alone
#   ./env.sh image    the node image alone
#
# Both default to a value derived from the current git branch, and both can be
# overridden:
#
#   HTTPSIG_CLUSTER=other ./up.sh
#   HTTPSIG_NODE_IMAGE=kindest/node:mine ./up.sh
#
# Deriving from the branch rather than using one fixed name is not only about two
# clusters colliding. The node image has to be a source build of the branch under
# test, because the API server is what does the verifying, so a tag shared between
# branches means whichever branch built last decides what the other one tests, and
# it passes or fails without saying so. A per-branch tag makes that a missing
# image, which up.sh reports.
#
# The cluster name is load-bearing beyond naming: it is the value both sides fold
# into the HMAC key derivation ladder. Client and server have to agree on it, so
# every script reads it from here rather than deciding for itself.
set -euo pipefail

# slug is the branch name reduced to what kind and a docker tag both accept:
# lowercase, with runs of anything else collapsed to a single dash. A detached
# HEAD has no branch name, so fall back to the checkout's directory, which for a
# git worktree is already per-branch.
httpsig_slug() {
  local name
  name="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  if [[ -z "$name" || "$name" == "HEAD" ]]; then
    name="$(basename "$(git rev-parse --show-toplevel 2>/dev/null || pwd)")"
  fi
  name="$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//')"
  # A name has to start with an alphanumeric and fit kind's length limit with the
  # "-control-plane" suffix kind appends to the node it creates.
  name="${name:0:40}"
  printf '%s' "${name:-httpsig}"
}

HTTPSIG_SLUG="${HTTPSIG_SLUG:-$(httpsig_slug)}"
HTTPSIG_CLUSTER="${HTTPSIG_CLUSTER:-$HTTPSIG_SLUG}"
HTTPSIG_NODE_IMAGE="${HTTPSIG_NODE_IMAGE:-kindest/node:$HTTPSIG_SLUG-dev}"
export HTTPSIG_SLUG HTTPSIG_CLUSTER HTTPSIG_NODE_IMAGE

# Only when run rather than sourced.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-all}" in
  cluster) echo "$HTTPSIG_CLUSTER" ;;
  image) echo "$HTTPSIG_NODE_IMAGE" ;;
  all)
    echo "HTTPSIG_CLUSTER=$HTTPSIG_CLUSTER"
    echo "HTTPSIG_NODE_IMAGE=$HTTPSIG_NODE_IMAGE"
    ;;
  *)
    echo "env.sh: unknown argument ${1}, want cluster, image, or nothing" >&2
    exit 1
    ;;
  esac
fi
