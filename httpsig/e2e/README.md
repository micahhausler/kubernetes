# HTTP message signature authentication on kind

A two-key demo: one shared HMAC secret, one ECDSA P-384 keypair, both delivered by
the same credential plugin, both verified by the API server against keys it does not
hold, each mapping to a different identity. The check at the end is a self subject
access review.

## The shape of it

```
  fixtures/resolver/keys.yaml        every key and identity        mounted nowhere
  fixtures/client/                  the client's private keys     mounted nowhere
  fixtures/node/                    one authentication config     mounted into the node
  fixtures/socket/resolver.sock     the resolver's socket         mounted read only
```

Read the third line against the fourth. The directory the control plane mounts holds
one file, and that file names a socket. No key, no public key, no identity, no
derivation ladder. `test.sh` asserts that, because it is the property the external key
API exists for and a regression in it would not show up as a failing request.

`httpsig-resolver` holds the keys and answers the API server's lookups over the
socket. It also records the nonce of every accepted signature, which is what closes
replay across more than one API server.

### Why the resolver runs on the host

It runs beside `up.sh` rather than inside the cluster. That is not what a real
deployment looks like, where it would be a pod or a node process next to the API
server. For a demo it is clearer: the log is a file you can read, the key file is
where it was generated, and stopping it is killing a process.

The reachability is the same either way, and two facts make it work:

- **A unix socket crosses a bind mount.** `kind.yaml` mounts `fixtures/socket` into
  the node, and a kubeadm patch mounts it into the API server pod, so the API server
  connects to a socket a host process created.
- **The mount is read only, and that still permits `connect`.** Connecting to a unix
  socket is a permission check on the inode rather than a write to the filesystem. So
  the weaker mount costs nothing and means nothing in the node can unlink the socket
  and listen in the resolver's place.

The socket is mode `0600` and owned by the user who ran `up.sh`. kube-apiserver in a
kind node runs as root, and root has `CAP_DAC_OVERRIDE`, so it connects; a non-root
process that does not own the socket does not.

### Why it starts before the cluster

`up.sh` starts the resolver first, and that ordering is load-bearing. kube-apiserver
fetches each resolver's metadata while building its authenticator and refuses to start
if it cannot. Started afterwards, the API server would crash-loop through `kubeadm
init` and the cluster would never come up.

## Running it

```
./up.sh          # fixtures, resolver, cluster, kubeconfig, RBAC
./test.sh        # both keys: whoami, access review, tampered key
./down.sh        # cluster and resolver
```

`down.sh` exists because the demo is two things now. Deleting the cluster and
forgetting the resolver leaves a process holding a socket, and the next `up.sh` then
fails on a socket in use rather than starting cleanly. It keeps the generated keys
unless you pass `--fixtures`.

The resolver has its own controls:

```
./resolver.sh status     # pid, socket mode, lookups and rejected nonces so far
./resolver.sh log        # follow it
./resolver.sh stop
./resolver.sh start
```

### Things worth trying once it is up

**Watch a lookup happen.** `./resolver.sh log` in one terminal, `./test.sh` in
another. Two lookups for six requests, because the answers are cached for the
`cacheTTL` the key file sets:

```
"Resolved key" keyID="demo-hmac/20260819/<cluster>/k8s1_request" username="hmac-demo"
"Resolved key" keyID="demo-ecdsa-p384"                                username="ecdsa-demo"
```

The HMAC key ID carries its claimed scope, and the resolver is the party that
decomposes it, because the resolver is the party that holds the ladder.

**Revoke a key.** Delete the `demo-ecdsa-p384` block from
`fixtures/resolver/keys.yaml`. The resolver re-reads the file on change, and that
context stops authenticating once the API server's cached answer expires. The delay is
the `cacheTTL` the file set, which is what makes the revocation window a number you
chose rather than a property of two processes.

**Stop the resolver.** Every signed request gets 401, including for keys the API
server has cached, because the nonce can no longer be recorded and a request that
cannot be shown not to be a replay is refused. Start it again and requests recover on
their own within a few seconds, as gRPC reconnects; the API server does not need
restarting.

## What has to be built

The API server does the verifying and kubectl does the signing, so both come from
this branch. About five minutes for the node image, well under one for kubectl.

```
KUBE_GIT_VERSION=v1.37.0-alpha.0.httpsig KUBE_GIT_TREE_STATE=clean \
  kind build node-image --image "$(./env.sh image)" /path/to/kubernetes
make WHAT=cmd/kubectl
```

`KUBE_GIT_VERSION` is not optional in a fork with no release tags. Without it the
build derives an empty version and kind stops with `failed to parse source
version: could not parse "" as version`.

The image name has to be the one `up.sh` will ask for, which is why the command
above reads it from `env.sh` rather than spelling it out. If kind falls back to its
own default node image, the failure arrives indirectly: an older kubelet panics on
the unrecognized feature gate, no static pods are created, and kubeadm reports a
connection refused from an API server that never started. A component handed a
feature gate it does not recognize refuses to start rather than ignoring it, which
is why the gate is set only on the API server.

The cluster name and the image tag both default to the current git branch, so two
branches checked out on one machine can run their clusters at the same time without
either noticing. `./env.sh` prints both names, and `HTTPSIG_CLUSTER` or
`HTTPSIG_NODE_IMAGE` overrides either.

The two collisions that buys are worth telling apart. A cluster name collides loudly:
`up.sh` would find the other branch's cluster and reuse it, so you would test this
branch's kubectl against that branch's API server, and a teardown from either would
take out the other's. A node image tag collides silently, which is worse, because it
is a Docker tag and therefore global to the machine: whichever branch built last
decides what a new cluster runs, the cluster comes up, and the tests pass or fail
having exercised code you did not build.

A released kubectl will not work either, and that fails quietly rather than
loudly: kubeconfig parsing ignores unknown fields, so it drops the
`httpSignature` block and sends unauthenticated requests. If both keys come back
unauthorized, suspect the binary before the cluster.

## The pieces

| File | What it is |
| --- | --- |
| `cmd/httpsig-demo` | The demo tool: credential plugin, key broker, and the ladder |
| `cmd/httpsig-resolver` | The key resolver the API server asks. Has [its own README](cmd/httpsig-resolver/README.md) |
| `env.sh` | The cluster name and node image tag, derived from the branch, and the one source every script reads them from |
| `gen-fixtures.sh` | Builds both tools, generates the keys, derives the resolver's key, writes its key file and the API server's configuration |
| `kind.yaml` | Cluster: the feature gate, the configuration file, and the two mounts. `up.sh` renders it into `fixtures/` with the names from `env.sh` |
| `resolver.sh` | Start, stop, and inspect the resolver |
| `write-kubeconfig.sh` | The kubeconfig, one user per key |
| `up.sh` / `test.sh` / `down.sh` | Bring up, check, tear down |

`httpsig-demo` has three subcommands because they share a definition that has to
agree:

```
httpsig-demo ladder                                  the ladder both sides state
httpsig-demo derive --secret-file F --cluster C       the broker: the server's rung
httpsig-demo credential --fixtures D --cluster C      the plugin kubectl runs
```

It is Go rather than shell for two reasons. The credential output is built from
the real `ExecCredential` types, so a field name cannot drift from the API it has
to satisfy. And the derivation is the library's own, so the demo cannot disagree
with the server about what the ladder means.

## Where the key material lives

```
fixtures/resolver/  the resolver's key file, and its log. Mounted nowhere.
fixtures/client/    the client's private keys. Mounted nowhere.
fixtures/node/      one authentication configuration. Mounted into the control plane.
fixtures/socket/    the resolver's socket. Mounted read only into the control plane.
fixtures/bin/       the demo tool and the resolver
```

No key material is mounted into the control plane at all. That is the difference the
external key API makes, and it is worth comparing against what this directory used to
hold: a derived HMAC key and every public key, in the file the API server read at
startup.

Neither private key is anywhere near the node, and neither is the root HMAC secret.
The resolver gets a key folded from that root through a date step, so what *it* holds
is useless for any other day. That matters because a shared secret normally means the
verifier can mint signatures indistinguishable from the client's; here whoever holds
the resolver's file could do so only for today, and only for this one key.

`test.sh` asserts all of it: the root secret absent from both generated files, the
mounted directory holding exactly one file, and no PEM block or secret field anywhere
in it. Those are properties of the layout, and a later edit could break them without
any request failing.

The cost is that the resolver's HMAC key expires daily. Rerun `gen-fixtures.sh` after
the UTC date rolls. No restart is needed at either end: the resolver re-reads its file
when it changes, and the API server picks the change up when its cached answer
expires.

## What the demo actually demonstrates

One plugin serves both keys. It is told the algorithm in
`spec.httpSignature.algorithm` and answers with material of that kind, so the
kubeconfig never names which key it holds. The kubeconfig carries the algorithm
and the TTL, which do not rotate; the key and the key ID come from the plugin on
every request. That split is why a rotating credential needs no kubeconfig edit.

The HMAC key is derived rather than shared directly. The ladder is a date step, a
cluster scope step, and a terminator literal:

```
K8S1‖root -> date -> cluster -> terminator
                        ^
                        the server's key is folded to here
```

The client holds the root and folds the whole chain on every request, taking the
date from the signature's own `created` parameter, so the two sides agree even
across a date boundary. The server holds only the rung, which is bound to one day
and one cluster.

Both bindings were checked by breaking them, since a step that is never exercised
proves nothing:

| Change | Result |
| --- | --- |
| Server given yesterday's rung | HMAC rejected, ECDSA unaffected |
| Client folds a different cluster name | HMAC rejected, ECDSA unaffected |

No scope value ever comes from the request. A holder folds with the value in its
own stage, which is what makes the scope segments in the `keyid` an assertion the
server compares rather than an input it trusts.

`test.sh` checks three separate things per key, and the third is the one that
makes the first two mean anything:

- `auth whoami` proves a signature verified and which identity it mapped to.
- The access review proves the groups from the key reached the authorizer. It
  asserts both a yes and a no, because a yes to everything would mean we are
  talking as the admin rather than as the signer.
- A tampered key must be rejected. Without it, a passing `whoami` could be some
  other authenticator letting the request through.

## When it does not work

These exact fixtures and this plugin were run against an in-process API server
before the cluster existed, and both keys authenticated. So a failure here is
most likely in the kind plumbing rather than in the fixtures or the protocol.
The in-tree integration tests cover the protocol:

```
go test ./test/integration/apiserver/httpsig/
```

Check the resolver before the cluster, since the API server depends on it:

```
./resolver.sh status
tail fixtures/resolver/resolver.log
```

Then the API server, and note the socket is now part of what to check:

```
node="$(./env.sh cluster)-control-plane"
docker exec "$node" \
  grep -e authentication-config -e feature-gates /etc/kubernetes/manifests/kube-apiserver.yaml
docker exec "$node" ls -l /httpsig /httpsig-socket
kubectl --kubeconfig fixtures/admin.kubeconfig -n kube-system logs "kube-apiserver-$node"
```

Two failures are worth telling apart, because they look the same from a client and
have opposite causes.

**The cluster never comes up.** The API server fetches the resolver's metadata while
building its authenticator and refuses to start without it, so a missing socket is a
crash loop through `kubeadm init` rather than a cluster that authenticates nobody. If
`/httpsig-socket` is empty inside the node, the resolver was not running when the
cluster was created, or the mount is wrong. `up.sh` starts the resolver first for
exactly this reason.

**The cluster is up and every signed request gets 401.** The resolver died, or its key
file no longer holds the key being used. Nonces cannot be recorded without it, and a
request that cannot be shown not to be a replay is refused. Start it again and requests
recover within a few seconds as gRPC reconnects; the API server does not need
restarting.

## Extending it

The demo deliberately leaves out the parts that need something to talk to:
signed headers carrying a session token, and an expiring credential that kubectl
refreshes. The credential subcommand rejects a request for signed headers rather
than returning a credential the client would refuse, so adding one means adding
its value there too.

Because the ladder has a scope step, every holder states a value for it, so the
client sends a stage carrying only `cluster`. A ladder of dates and literals alone
would need no stage on the client at all. Another scope step, for a purpose or a
tenant, is the same shape of change: `gen-fixtures.sh` renders the server's stage
from whatever scope the broker reports, so it needs no edit.

The reverse arrangement is the other half worth building: the broker hands the
*client* a rung and keeps the root, which bounds what a stolen kubeconfig can
sign for. `httpsig-demo derive` is already the broker for that; what is missing is
returning the rung and its stage from the credential subcommand.

Two more, now that a resolver is in the picture. A second resolver with
`keyIDPrefixes` would show routing by key ID and prove each is asked only about its
own keys. And `relayedHeaders` with the resolver's `requiredHeaders` would show
identity chosen by a session token rather than by a key ID, which is the deployment
shape where the key ID names a key and the token names a session.
