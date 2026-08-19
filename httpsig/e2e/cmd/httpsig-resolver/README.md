# httpsig-resolver

A key resolver for HTTP message signature authentication, backed by a YAML file.

kube-apiserver asks it which key verifies signatures bearing a key ID and whose
identity that is, and asks it to record the nonce each accepted signature carries.
kube-apiserver does all of the cryptography. This process holds key material and
nonce state and never sees a request.

It implements `k8s.io/externalhttpsig`. It exists to make the API's shape concrete
and to give the demo something to point at.

## What it is not

Key material sits in a file on disk, in plaintext, next to the identity it
authenticates. That is the objection the external key API exists to answer, moved one
process over.

What moving it buys is still real: the file is not kube-apiserver's configuration, so
it is not on every control plane node, editing it takes effect without restarting
anything, and reading it compromises one process rather than the API server. What it
does not buy is a key management system. A real resolver fronts one.

Nonce state is in memory in one process. That is correct for one resolver and wrong
the moment there are two, because two would each accept a replay the other had
recorded. Starting a second copy on the same socket is refused for that reason. A real
deployment needs shared storage with an atomic compare-and-set, which is what the RPC's
contract requires and which this implementation satisfies only by being alone.

**If you are writing a resolver with no nonce store, do not implement `ConsumeNonce`
as a stub that returns accepted.** Set `nonceHandling: Ignore` on the API server's
`httpSignature` entry instead. kube-apiserver then skips the call, so it costs nothing,
and the configuration says replay protection is off where an operator will see it. A
stub that always accepts hides that in your source, and it lies about an RPC whose
contract is an atomic check-and-record.

## Running it

```
httpsig-resolver --keys keys.yaml --listen /var/run/httpsig/resolver.sock
```

Point kube-apiserver at it:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
httpSignature:
- endpoint: unix:///var/run/httpsig/resolver.sock
```

The endpoint takes three slashes, including for an abstract socket
(`unix:///@resolver` for `--listen @resolver`).

| Flag | Default | |
|---|---|---|
| `--keys` | | Key file. Required. Reloaded when it changes. |
| `--listen` | | Socket path, or `@name` for a Linux abstract socket. Required. |
| `--socket-mode` | `0600` | Socket permissions. This is the trust boundary. |
| `--max-nonces` | `65536` | Unexpired nonce records to hold. |

**`--socket-mode` is a security setting, not a convenience.** On Linux, connecting to a
unix socket requires write permission on it, so whoever can write to this socket can
vend an identity to the cluster. The connection carries no TLS and nothing authenticates
the peer, which is the same model the KMS provider and the external JWT signer use.
Widen it only to reach a kube-apiserver running as a different user, and prefer `0660`
with a shared group. World-writable is refused rather than warned about.

An abstract socket has no permissions at all. It is bounded by the network namespace and
nothing else, and the startup log says so.

## The key file

Keys are nested by algorithm, then by key ID. This example is complete and is loaded by
a test in this package, so it parses as written:

```yaml
# Optional. The HMAC ladder this file's staged keys sit on, returned to kube-apiserver
# in Metadata. Every party that derives states the same ladder, so this and each
# client's copy have to agree. Both log a digest of theirs; comparing them is how a
# disagreement gets diagnosed, because it otherwise fails as a signature that does not
# verify.
keyDerivation:
  kind: hmac-ladder
  hash: sha-256
  secretPrefix: DEMO1
  steps:
  - {name: date, date: YYYYMMDD}
  - {name: cluster, scope: true}
  - {name: terminator, literal: demo1_request}

# Optional. Narrows how old a signature verified by any key here may be. kube-apiserver
# applies the smaller of this and its own maximum, so it can only tighten.
maxSignatureAge: 2m

# Optional. How often kube-apiserver should call Metadata again. That call is also its
# health check for this resolver, so this sets how quickly an unhealthy one is noticed.
refreshHint: 30s

keys:
  ed25519:
    alice-key:
      # PEM here, PKIX DER on the wire. This file is written by people and PEM is what
      # openssl produces; the protocol takes DER because a PEM block type is a second
      # statement of the key kind and a second thing to disagree with the algorithm.
      publicKey: |
        -----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEAQd1FZmzAVHm6PvsnaZzF5aBse/EvB0BfPGvioIvekps=
        -----END PUBLIC KEY-----
      user:
        username: alice
        uid: uid-alice
        groups: [signers]
        extra:
          department: [platform]
      # How long kube-apiserver may reuse this answer. A cached key outlives its
      # revocation, so this is the revocation window.
      cacheTTL: 5m

  hmac-sha256:
    AKIABOBEXAMPLE:
      secret: a-shared-secret
      user: {username: bob, groups: [signers]}
      cacheTTL: 5m

    # A rung rather than a whole secret. This bounds what a compromise of this file
    # yields: only what the rung's scope covers, and past a date step, only until that
    # date rolls.
    scoped-key:
      # base64 because a rung is raw hash output, not text.
      secretBase64: aGFzaCBvdXRwdXQgYnl0ZXM=
      stage:
        from: cluster
        scope: {date: '20260101', cluster: cluster-a}
      user: {username: scoped, groups: [signers]}
      cacheTTL: 5m

    # Identity chosen by a relayed header rather than by the key ID. kube-apiserver
    # relays only headers its own configuration names, and refuses a request carrying
    # one the signature does not cover.
    session-key:
      secret: another-shared-secret
      requiredHeaders:
        X-Session-Token: the-expected-token
      user: {username: session-user}
      # Omitted, so not cached: an identity that depends on a rotating value must not
      # be answered from cache.
```

### Rules worth knowing before you edit it

**The algorithm is the outer key**, so a key cannot be written without one. That matters
more than it looks: kube-apiserver builds its verifier from the algorithm this resolver
states and rejects a signature whose own `alg` disagrees, which is what closes algorithm
confusion. A schema that let the algorithm be omitted would be a schema that could leave
that check unarmed.

**Exactly one of `publicKey`, `secret`, or `secretBase64`**, and it has to match the
algorithm it sits under. A public key under `hmac-sha256` is refused rather than used as
a shared secret.

**`cacheTTL` is a duration string.** `5m` and `0s` are valid; a bare `0` is not.
Omitting it means do not cache, which costs a lookup per request and is the safe
default: the alternative would be a revocation window nobody chose.

**No `system:` usernames or groups.** kube-apiserver rejects them regardless, because
this resolver is across a trust boundary from it. Refusing them here as well means the
mistake is an exit code naming the key rather than a 401 whose reason is in a server log.

**Unknown fields are refused**, so a stray `publicKeyy` fails at load. One class slips
through: Go matches field names case-insensitively, so `publickey` binds to `publicKey`
and no strictness setting changes that.

## Reloading

The file is re-read when its modification time or size changes, checked on each request.
Editing it takes effect without restarting anything and without a signal.

The delay you then see is kube-apiserver's key cache, which is the `cacheTTL` this file
set. That is deliberate: the revocation window is a number stated here rather than an
invisible property of two processes. Reloading on a timer instead would add a second,
invisible delay on top of it.

A reload that fails keeps the keys already loaded. A half-written or briefly missing
file should not log out every client, so the failure is logged and the previous keys keep
serving.

## The nonce store

`ConsumeNonce` is an atomic check-and-record, which is the whole reason it is an RPC
rather than a per-API-server cache: two concurrent calls for the same key and nonce must
not both be accepted. Records are held per key, so the same nonce value under two keys is
two different facts and one client's traffic cannot reject another's.

kube-apiserver states when each nonce may be forgotten, as `created` plus the effective
maximum signature age plus its clock tolerance. Records past that are swept when the
store comes under pressure.

A full store **refuses** rather than evicting. Evicting the oldest record would permit
the replay it was preventing, so under load this fails closed and shows up as rejected
requests rather than as silent replay. If you see that rejection, `--max-nonces` is too
small for the request rate times the signature lifetime.
