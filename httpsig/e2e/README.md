# HTTP message signature authentication on kind

A demo of both ways the API server resolves a signature to an identity.

Two configured keys, a shared HMAC secret and an ECDSA P-384 keypair, delivered by
the same credential plugin. For these the server holds a key and an identity per
client, stated in its configuration.

One X.509 certificate, delivered as a certificate and key pair and again as a single
credential bundle. For this the server holds a certificate authority and nothing per
client: the identity comes from the certificate the request carries. A fourth
credential, issued by an authority the server was never given, is there to show what
that trust boundary is worth.

Which way a signature is resolved is decided by its `keyid`, which every signature
covers. The check at the end is a self subject access review.

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
`httpSignature` block and sends unauthenticated requests. If every credential comes
back unauthorized, suspect the binary before the cluster.

## Running it

```
./up.sh          # fixtures, cluster, kubeconfig, RBAC
./test.sh        # every credential: whoami, access review, and the negative case
kind delete cluster --name "$(./env.sh cluster)"
```

`up.sh` is safe to rerun. It reuses an existing cluster and leaves existing keys and
certificates alone, so the API server's configuration and the client's material
cannot drift.

`gen-fixtures.sh` and `write-kubeconfig.sh` validate what they write, using the
API server's own validation and client-go's own kubeconfig loader. Both failure modes
they catch are otherwise mute: a configuration the server refuses appears as a
connection refused twenty seconds into `up.sh`, from an API server whose complaint is
inside a container that no longer exists, and a kubeconfig with a typo in the
`httpSignature` block is accepted with the block dropped, sending unauthenticated
requests instead.

## The pieces

| File | What it is |
| --- | --- |
| `cmd/httpsig-demo` | The demo tool: credential plugin, key broker, and the ladder |
| `env.sh` | The cluster name and node image tag, derived from the branch, and the one source every script reads them from |
| `gen-fixtures.sh` | Builds the tool, generates the keys and certificates, derives the server's key, writes and validates the authentication configuration |
| `kind.yaml` | Cluster: the feature gate, the configuration file, and the mount. `up.sh` renders it into `fixtures/` with the names from `env.sh` |
| `write-kubeconfig.sh` | The kubeconfig, one user per credential, validated |
| `internal/configcheck` | The validation both generators run against what they wrote, and against `../examples` |
| `up.sh` / `test.sh` | Bring up, then check |

## What the layout is claiming

The directory split is the trust boundary rather than filing, and `test.sh` asserts
it before it sends a request:

| Under `fixtures/node/`, mounted into the API server | Under `fixtures/client/`, never mounted |
| --- | --- |
| the HMAC key folded through the date step | the root HMAC secret |
| the demo certificate authority's certificate | the certificate authority's private key |
| the authentication configuration | the ECDSA private key, and the certificate and its key |

Two properties fall out of that. A shared secret normally lets the verifier mint
signatures indistinguishable from the client's; here it can do so only for the one
UTC day its rung names. And the API server's configuration names no certificate
client at all, which is what the certificate flow is for: the identity arrives with
the request.

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

One plugin serves both configured keys. The certificate contexts use no plugin: their material is named in the kubeconfig, and the key ID and algorithm come from the certificate. It is told the algorithm in
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
before the cluster existed, and every credential authenticated. So a failure here is
most likely in the kind plumbing rather than in the fixtures or the protocol.
The in-tree integration tests cover the protocol:

```
go test ./test/integration/apiserver/httpsig/
```

If those pass, look at the API server:

```
node="$(./env.sh cluster)-control-plane"
docker exec "$node" \
  grep -e authentication-config -e feature-gates /etc/kubernetes/manifests/kube-apiserver.yaml
docker exec "$node" ls -l /httpsig
kubectl --kubeconfig fixtures/admin.kubeconfig -n kube-system logs "kube-apiserver-$node"
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
