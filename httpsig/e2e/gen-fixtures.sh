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

# Builds the demo tool and generates the key material and the API server's
# authentication configuration. Idempotent, and safe to rerun: the API server's
# key is bound to a date, so rerunning is how it gets refreshed.
#
# The directory layout is the trust boundary, not just filing:
#
#   fixtures/node/    bind mounted into the control plane container
#   fixtures/client/  host only, never mounted anywhere
#   fixtures/bin/     the demo tool
#
# Note what is not under node/. The ECDSA private key is not, because it never
# needs to be. Neither is the root HMAC secret: the server gets a key derived
# from it, bound to one UTC day, which is the whole point of the ladder. A shared
# secret normally means the verifier can forge signatures indistinguishable from
# the client's; here it can do so only for today, and only for this one key.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
node=fixtures/node
client=fixtures/client
bin=fixtures/bin
mkdir -p "$node" "$client" "$bin"

demo="$bin/httpsig-demo"
go build -o "$demo" ./cmd/httpsig-demo
echo "built $demo"

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
# Indented to sit under stage.scope, which is four levels deep now that each
# authenticator is a list item.
rung_scope="$(jq -r '.scope | to_entries[] | "          \(.key): \"\(.value)\""' <<<"$derived")"

# A rung is raw hash output rather than text, so it travels as base64. That is
# also why the server requires base64 whenever a stage is set: trimming a
# trailing newline off a plain secret would corrupt bytes that happen to end in
# one.
printf '%s' "$rung" >"$node/hmac-rung.b64"
chmod 600 "$node/hmac-rung.b64"

# The certificate authority for the assertion flow, and one leaf it issues.
#
# Its own authority, not the cluster's client CA, and that is a requirement rather
# than tidiness: pointing the server at a CA that issues for anything else would let
# every certificate that CA ever issued sign API requests, which its issuer never
# agreed to. Extended key usage is not checked by the verifier, so the bundle is the
# only thing saying who is enlisted.
#
# Under node/ only the CA certificate appears. The leaf's private key is the
# client's, so it lives under client/ and is never mounted.
if [[ ! -f "$node/demo-ca.crt" ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
    -keyout "$client/demo-ca.key" -out "$node/demo-ca.crt" -days 30 \
    -subj "/CN=httpsig-demo-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,digitalSignature" 2>/dev/null
  chmod 600 "$client/demo-ca.key"
  echo "generated $node/demo-ca.crt and $client/demo-ca.key"
fi

# issue_leaf <name> <subject> <ca-cert> <ca-key>
#
# The lifetime is short on purpose. A certificate's lifetime is the withdrawal
# window in this design, because the server holds nothing per client to delete, and
# the config states a rule refusing anything longer than a day.
issue_leaf() {
  local name="$1" subject="$2" ca_crt="$3" ca_key="$4"
  [[ -f "$client/$name.crt" ]] && return 0
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
    -keyout "$client/$name.key" -out "$client/$name.csr" -subj "$subject" 2>/dev/null
  openssl x509 -req -in "$client/$name.csr" -CA "$ca_crt" -CAkey "$ca_key" \
    -out "$client/$name.crt" -days 1 -set_serial "0x$(openssl rand -hex 8)" \
    -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n') 2>/dev/null
  rm -f "$client/$name.csr"
  chmod 600 "$client/$name.key"
  echo "generated $client/$name.crt"
}

# The organization becomes the group, which is what the config's mapping reads, so
# this subject is where the demo user's authorization comes from.
issue_leaf cert-demo "/CN=cert-demo/O=httpsig-demo/O=httpsig-certificate" \
  "$node/demo-ca.crt" "$client/demo-ca.key"

# A credential bundle: the key first, then the chain. This is the shape a
# PodCertificateProjection writes, and the reason it is one file is that two files
# can be read between the two writes of a rotation.
cat "$client/cert-demo.key" "$client/cert-demo.crt" >"$client/cert-demo.bundle.pem"
chmod 600 "$client/cert-demo.bundle.pem"

# test.sh checks that the identity's UID is the certificate's digest, computing it
# with openssl. Confirm here that openssl and the server agree on what that digest
# is, since the shell has no way to know what the server means by it.
HTTPSIG_LEAF="$PWD/$client/cert-demo.crt" \
HTTPSIG_OPENSSL_THUMBPRINT="$(openssl x509 -in "$client/cert-demo.crt" -outform der | openssl dgst -sha256 -hex | awk '{print $NF}')" \
  go test ../../httpsig/e2e/internal/configcheck/ -run TestLeafThumbprint -count=1 >/dev/null || {
  echo "gen-fixtures.sh: openssl and the server disagree about the certificate digest." >&2
  exit 1
}

# An authority the server is not given, for the negative case. A leaf from it is
# well formed and its signature verifies against its own key; the only thing wrong
# with it is that nothing the server trusts issued it.
if [[ ! -f "$client/rogue-ca.crt" ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
    -keyout "$client/rogue-ca.key" -out "$client/rogue-ca.crt" -days 30 \
    -subj "/CN=httpsig-rogue-ca" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,digitalSignature" 2>/dev/null
  chmod 600 "$client/rogue-ca.key"
fi
issue_leaf rogue "/CN=cert-demo/O=httpsig-demo/O=httpsig-certificate" \
  "$client/rogue-ca.crt" "$client/rogue-ca.key"

public_key="$(openssl ec -in "$client/ecdsa-p384.key" -pubout 2>/dev/null)"

# The API server is told the ladder, the two configured keys and the identity each
# one authenticates as, and one certificate authority it will accept assertions
# from. Note the asymmetry the field names carry: a public key is inline because it
# is not a secret, and key material is referenced by path because it is.
#
# Two ways of resolving a signature sit side by side here, and the difference is what
# the server holds. The keys authenticator holds a key and an identity per client.
# The x509 authenticator holds a CA certificate and nothing per client: the identity
# comes from the certificate the request carries. Which one handles a signature is
# decided by its keyid, which every signature covers.
#
# Scope values are quoted. A date unquoted is a valid YAML integer and the field
# is a string, so it would fail to decode.
{
  cat <<EOF
# Generated by gen-fixtures.sh. Mounted at /httpsig in the control plane node.
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: demo-keys
    # Verified against the created timestamp the signature carries, so a captured
    # request can be replayed only until it ages out of this window.
    maxAge: 1m
    # Stated identically here and in the client's kubeconfig. Both sides render it
    # from one definition in the demo tool, because a ladder that differs between
    # them fails as a signature mismatch and says nothing about why.
    keyDerivation:
EOF
  "$demo" ladder --indent "      "
  # SC2001: the sed below indents every line of a multi-line PEM block. A
  # parameter expansion replaces the newlines but leaves the first line
  # unindented, so it is not the same operation.
  # shellcheck disable=SC2001
  cat <<EOF
    keys:
    - keyID: demo-hmac
      algorithm: hmac-sha256
      # Not the root secret. A key folded through the date step, so this file is
      # useless for any day but the one its stage names.
      secretFile: /httpsig/hmac-rung.b64
      stage:
        from: $rung_from
        scope:
$rung_scope
      user:
        username: hmac-demo
        groups:
        - httpsig-demo
        - httpsig-hmac
    - keyID: demo-ecdsa-p384
      algorithm: ecdsa-p384-sha384
      publicKey: |
$(sed 's/^/        /' <<<"$public_key")
      user:
        username: ecdsa-demo
        groups:
        - httpsig-demo
        - httpsig-asymmetric
  - name: demo-certificates
    maxAge: 1m
    x509:
      # This CA and nothing else. A certificate from any other authority is well
      # formed and its signature verifies against its own key; it is refused because
      # nothing here issued it.
      certificateAuthority: |
$(sed 's/^/        /' <"$node/demo-ca.crt")
      certificateCache:
        # Short so the demo can be reasoned about. This is also the window in which
        # withdrawing a certificate has no effect, since the server holds nothing
        # per client to delete.
        ttl: 30s
    # Run before the mappings, so a mapping never reads a certificate no rule has
    # vetted. A certificate's lifetime is the withdrawal window, and this is the
    # only lever the verifier has over it.
    certificateValidationRules:
    - expression: cert.notAfter - cert.notBefore <= duration('24h')
      message: certificate lifetime must not exceed 24 hours
    # No identity for this client appears anywhere in this file. It comes from the
    # certificate, which is the point.
    claimMappings:
      username:
        expression: cert.subject.commonName
      groups:
        expression: cert.subject.organization
      uid:
        # The same value the signature's keyid carries, so the identity names one
        # exact certificate rather than anything its issuer could reuse.
        expression: cert.sha256Thumbprint
      extra:
      - key: httpsig.example.com/issuer
        valueExpression: cert.issuer.commonName
    # The mapping above derives the groups from the certificate's subject, which
    # hands the choice of group to whoever can request one. Without this rule, a
    # requester naming system:masters in their organization would receive cluster
    # administrator.
    userValidationRules:
    - expression: '!user.username.startsWith("system:") && !user.groups.exists(g, g.startsWith("system:"))'
      message: 'this authenticator may not assert an identity under the system: prefix'
EOF
} >"$node/authentication-config.yaml"

echo "wrote $node/authentication-config.yaml"

# Decode and validate it here, with the same code the API server runs at startup.
# Otherwise a configuration the server refuses surfaces as kubeadm reporting a
# connection refused twenty seconds into up.sh, from an API server that logged its
# complaint inside a container that no longer exists.
HTTPSIG_CONFIG="$PWD/$node/authentication-config.yaml" HTTPSIG_NODE_DIR="$PWD/$node" \
  go test ../../httpsig/e2e/internal/configcheck/ -count=1 >/dev/null || {
  echo "gen-fixtures.sh: the generated configuration would be refused by the API server." >&2
  echo "                 Rerun for the detail: HTTPSIG_CONFIG=$PWD/$node/authentication-config.yaml \\" >&2
  echo "                   HTTPSIG_NODE_DIR=$PWD/$node go test ../../httpsig/e2e/internal/configcheck/ -v" >&2
  exit 1
}
echo "validated $node/authentication-config.yaml against the API server's own validation"
echo "gen-fixtures.sh: the server's HMAC key is folded through $rung_from: bound to cluster"
echo "                 $cluster and to $rung_date (UTC). Rerun this and restart the API"
echo "                 server after that date rolls, or it stops verifying."
