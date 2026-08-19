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

# Builds the demo tools and generates the key material, the resolver's key file,
# and the API server's authentication configuration. Idempotent, and safe to
# rerun: the resolver's HMAC key is bound to a date, so rerunning is how it gets
# refreshed.
#
# The directory layout is the trust boundary, not just filing:
#
#   fixtures/node/      bind mounted into the control plane container
#   fixtures/resolver/  the resolver's key file; mounted nowhere
#   fixtures/client/    host only, never mounted anywhere
#   fixtures/socket/    the resolver's socket, mounted read only into the node
#   fixtures/bin/       the demo tool and the resolver
#
# What is under node/ is the point of this arrangement, and it is now one file
# that names a socket. No key material is mounted into the control plane at all.
# Before the move to a resolver, node/ held a derived HMAC key and every public
# key; the API server's copy of that material is what the external key API
# removes.
#
# What is still not anywhere near the node: the client's ECDSA private key, and
# the root HMAC secret. The resolver gets a key derived from the root, bound to
# one UTC day, which is the whole point of the ladder. A shared secret normally
# means the verifier can forge signatures indistinguishable from the client's;
# here whoever holds the resolver's file can do so only for today, and only for
# this one key.
set -euo pipefail


cd "$(dirname "${BASH_SOURCE[0]}")"
node=fixtures/node
client=fixtures/client
resolver_dir=fixtures/resolver
socket_dir=fixtures/socket
bin=fixtures/bin
mkdir -p "$node" "$client" "$resolver_dir" "$socket_dir" "$bin"

# The resolver's file holds every key. It is mounted nowhere, and the mode says
# so: the only process that reads it is the resolver, running as this user.
chmod 700 "$resolver_dir"

demo="$bin/httpsig-demo"
go build -o "$demo" ./cmd/httpsig-demo
echo "built $demo"

resolver="$bin/httpsig-resolver"
go build -o "$resolver" ./cmd/httpsig-resolver
echo "built $resolver"

# env.sh owns the cluster name. It is also the value of the ladder's cluster
# scope step, so both the broker and the client have to agree on it, and reading
# it from one place is cheaper than keeping three copies in step.
source ./env.sh
cluster="$HTTPSIG_CLUSTER"

# A demo secret in a repository is not a secret. It is named as such so that no
# one is tempted to lift the pattern into anything real.
readonly hmac_secret="httpsig-kind-demo-not-a-real-secret"

# Written with printf rather than echo so there is no trailing newline. Both
# sides trim one, but a secret that differs by a byte between them fails as a
# signature mismatch with nothing to point at.
printf '%s' "$hmac_secret" >"$client/hmac.secret"
chmod 600 "$client/hmac.secret"

if [[ ! -f "$client/ecdsa-p384.key" ]]; then
  # SEC1 "EC PRIVATE KEY" PEM, which the client parses directly. PKCS#8
  # ("PRIVATE KEY") also works if you would rather use openssl genpkey.
  openssl ecparam -name secp384r1 -genkey -noout -out "$client/ecdsa-p384.key"
  chmod 600 "$client/ecdsa-p384.key"
  echo "generated $client/ecdsa-p384.key"
fi
if [[ ! -f "$client/ecdsa-p384.tamper.key" ]]; then
  # An unrelated key on the same curve, for the negative test. Generated here
  # rather than in the plugin so the plugin has no reason to hold a key
  # generator, and so the same wrong key is used every run.
  openssl ecparam -name secp384r1 -genkey -noout -out "$client/ecdsa-p384.tamper.key"
  chmod 600 "$client/ecdsa-p384.tamper.key"
  echo "generated $client/ecdsa-p384.tamper.key"
fi

# The broker's half. The tool holds the root secret, folds the ladder down to the
# date step, and reports the rung with the stage that names where it sits. The
# stage comes from the library rather than being written here, so there is only
# one statement of where the rung came from.
derived="$("$demo" derive --secret-file "$client/hmac.secret" --cluster "$cluster")"
rung="$(jq -r .rung <<<"$derived")"
rung_from="$(jq -r .from <<<"$derived")"
rung_date="$(jq -r '.scope.date' <<<"$derived")"
# Rendered from whatever scope the library reported rather than named key by key,
# so another step in the ladder needs no change here.
rung_scope="$(jq -r '.scope | to_entries[] | "        \(.key): \"\(.value)\""' <<<"$derived")"

public_key="$(openssl ec -in "$client/ecdsa-p384.key" -pubout 2>/dev/null)"

# The resolver's key file. Every key and every identity lives here, keyed by
# algorithm and then by key ID, and this file is mounted nowhere: the resolver
# reads it on the host.
#
# Scope values are quoted. A date unquoted is a valid YAML integer and the field
# is a string, so it would fail to decode.
{
  cat <<EOF
# Generated by gen-fixtures.sh. Read by httpsig-resolver on the host, and
# deliberately not mounted into the cluster.
#
# The ladder is stated here and in the client's kubeconfig, rendered from one
# definition in the demo tool. The resolver hands it to the API server in
# Metadata, so the API server holds no copy of its own. Both the resolver and the
# client log a digest of theirs; comparing those two is how a disagreement gets
# diagnosed, because it otherwise fails as a signature that does not verify.
keyDerivation:
EOF
  "$demo" ladder --indent "  "
  # SC2001: the seds below indent every line of a multi-line block, a PEM key and a
  # rendered scope map. A parameter expansion replaces the newlines but leaves the
  # first line unindented, so it is not the same operation.
  # shellcheck disable=SC2001
  cat <<EOF
# Narrows how old a signature may be, on top of whatever the API server is
# configured with. The API server takes the smaller of the two.
maxSignatureAge: 1m
keys:
  hmac-sha256:
    demo-hmac:
      # Not the root secret. A key folded through the date step, so this file is
      # useless for any day but the one its stage names. A rung is raw hash
      # output rather than text, which is why it travels as base64.
      secretBase64: $rung
      stage:
        from: $rung_from
        scope:
$(sed 's/^      /          /' <<<"$rung_scope")
      user:
        username: hmac-demo
        groups:
        - httpsig-demo
        - httpsig-hmac
      cacheTTL: 1m
  ecdsa-p384-sha384:
    demo-ecdsa-p384:
      publicKey: |
$(sed 's/^/        /' <<<"$public_key")
      user:
        username: ecdsa-demo
        groups:
        - httpsig-demo
        - httpsig-asymmetric
      cacheTTL: 1m
EOF
} >"$resolver_dir/keys.yaml"
chmod 600 "$resolver_dir/keys.yaml"
echo "wrote $resolver_dir/keys.yaml"

# The API server's configuration. One entry, naming a socket, and nothing else.
# Read what is absent here: no key, no public key, no identity, no ladder. That
# absence is the whole point of the external key API, and it is the difference a
# reader should notice against the previous version of this file.
cat >"$node/authentication-config.yaml" <<EOF
# Generated by gen-fixtures.sh. Mounted at /httpsig in the control plane node.
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
httpSignature:
  # The resolver, which runs on the host. Its socket reaches the node through a
  # read-only bind mount, so the API server can connect to it and cannot replace
  # it. Access to that socket is the whole trust boundary: nothing authenticates
  # the peer at either end.
- endpoint: unix:///httpsig-socket/resolver.sock
  # Verified against the created timestamp the signature carries, so a stale
  # request is refused. Replay is closed by the resolver recording nonces, not by
  # this; what this bounds is how long the resolver is asked to remember one.
  maxAge: 1m
EOF

echo "wrote $node/authentication-config.yaml"
echo "gen-fixtures.sh: the resolver's HMAC key is folded through $rung_from: bound to cluster"
echo "                 $cluster and to $rung_date (UTC). Rerun this after that date"
echo "                 rolls, or that key stops verifying. The resolver re-reads its"
echo "                 file on change, so it needs no restart; the API server picks the"
echo "                 change up when its key cache expires."
echo "gen-fixtures.sh: no key material is mounted into the node. $node holds one file"
echo "                 naming a socket; the keys are in $resolver_dir, mounted nowhere."
