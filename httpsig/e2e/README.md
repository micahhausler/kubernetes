# HTTP message signature authentication on kind

A two-key demo: one shared HMAC secret, one ECDSA P-384 keypair, both delivered
by the same credential plugin, both verified by the API server, each mapping to a
different identity. The check at the end is a self subject access review.

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
either noticing. It also stops a branch from testing an image another branch built,
which would otherwise pass or fail without saying so. `./env.sh` prints both names,
and `HTTPSIG_CLUSTER` or `HTTPSIG_NODE_IMAGE` overrides either.

A released kubectl will not work either, and that fails quietly rather than
loudly: kubeconfig parsing ignores unknown fields, so it drops the
`httpSignature` block and sends unauthenticated requests. If both keys come back
unauthorized, suspect the binary before the cluster.

## Running it

```
./up.sh          # fixtures, cluster, kubeconfig, RBAC
./test.sh        # both keys: whoami, access review, tampered key
kind delete cluster --name "$(./env.sh cluster)"
```

`up.sh` is safe to rerun. It reuses an existing cluster and leaves existing keys
alone, so the API server's configuration and the client's keys cannot drift.

## The pieces

| File | What it is |
| --- | --- |
| `cmd/httpsig-demo` | The demo tool: credential plugin, key broker, and the ladder |
| `env.sh` | The cluster name and node image tag, derived from the branch, and the one source every script reads them from |
| `gen-fixtures.sh` | Builds the tool, generates the keys, derives the server's key, writes the authentication configuration |
| `kind.yaml` | Cluster: the feature gate, the configuration file, and the mount. `up.sh` renders it into `fixtures/` with the names from `env.sh` |
| `write-kubeconfig.sh` | The kubeconfig, one user per key |
| `up.sh` / `test.sh` | Bring up, then check |

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
fixtures/node/     bind mounted into the control plane container
fixtures/client/   host only, never mounted anywhere
fixtures/bin/      the demo tool
```

Neither private key is under `node/`. The ECDSA key is not, because it never needs
to be. The root HMAC secret is not either, which is what the derivation ladder
buys here: the server is given a key folded from that secret through a date step,
so what it holds is useless for any other day.

That matters because a shared secret normally means the verifier can mint
signatures indistinguishable from the client's. Here it could do so only for
today, and only for this one key. `test.sh` asserts the root secret is absent from
the mounted directory, since that is a property of the layout that a later edit
could quietly break.

The cost is that the server's key expires daily. Rerun `gen-fixtures.sh` and
restart the API server after the UTC date rolls. A restart, not a file update:
see D4 in `../DECISIONS.md` for why a reload will not do it, and why that is a
defect rather than a fact of life.

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

If those pass, look at the API server:

```
docker exec httpsig-control-plane \
  grep -e authentication-config -e feature-gates /etc/kubernetes/manifests/kube-apiserver.yaml
docker exec httpsig-control-plane ls -l /httpsig
kubectl --kubeconfig fixtures/admin.kubeconfig -n kube-system logs kube-apiserver-httpsig-control-plane
```

The API server reads `secretFile` while validating its configuration, so a broken
mount is a crash loop rather than a cluster that authenticates nobody. That is the
failure to expect if `/httpsig` is empty.

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
