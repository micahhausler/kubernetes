# HTTP message signature authentication for Kubernetes

This is a branch and a proof of concept. It applies RFC 9421, HTTP Message Signatures, to
authentication against the Kubernetes API. The client signs each request with a key it holds, and the
API server verifies the signature and maps the key to a user identity.

What that buys is proof of possession without a replayable credential. Nothing the client sends can
be captured and reused against a different request. And because the proof rides in the message
rather than in the transport, it still validates after an L7 proxy has terminated TLS, so long as
that proxy preserves the parts of the request the signature covers.

Read `DECISIONS.md` for the reasoning behind every choice, and its section 6 for the parts that are
not designed yet. A running demo on a kind cluster is in `e2e/`.

## Why

Every bearer credential Kubernetes accepts travels on the wire. A bearer token, a service account
token, an OIDC id token: the client sends the credential itself on every request, so whoever captures
one can replay it against any request until it expires. A shorter lifetime shrinks that window
without changing the kind of credential.

Client certificates are not in that category. The client signs the transport rather than sending its
key, so mTLS is already proof of possession and a complete answer for direct API server access. That
proof belongs to the connection, so it ends at the first load balancer or ingress that terminates
TLS, and the API server behind one trusts the proxy's claim about who called.

A message signature is proof of possession carried in the message. Two of the three properties below
improve on a bearer token. The third is the one a client certificate cannot give.

**Capturing a request does not yield a credential.** A proxy access log, a compromised sidecar, or a
node exfiltration produces signatures over requests that already happened. There is nothing in them
to reuse against a different request. Short bearer token lifetimes shrink the window for reuse. They
do not remove reuse.

**A signature is bound to its request.** The signature covers the method, the host, the path, the
query, a digest of the body, and a set of headers. An attacker cannot move a captured signature onto
a different verb, path, or body.

**The proof survives a TLS-terminating proxy.** The signature is part of the message, so it reaches
the API server through an intermediary that terminates TLS. Nothing in the path has to be trusted to
report who called. This holds only where the intermediary preserves what the signature covers. The
floor covers the authority, path, and query, which are what layer 7 proxies most often rewrite, so
which deployments that leaves is an open question. `DECISIONS.md` Q1 has the argument.

The honest bound on all of this: a captured request can be replayed as itself, unchanged, until it
ages out of the acceptance window. That matters most for reads, where replaying a `GET` returns the
response again. Replay protection is unimplemented, so the acceptance window is the whole of the
bound. Narrowing it further needs state shared by every API server, which is not designed.

One property belongs to the mechanism rather than to this PoC. Signing is an operation, not a value
handed over, so the key can live in a TPM, a hardware token, or a non-exportable platform key and
never be extractable at all. Nothing here delivers that. The client plumbing passes a signer rather
than a key, which is what keeps the option open.

## What a user configures

A kubeconfig user gains an `httpSignature` block, and the key comes from an ordinary exec credential
plugin. The block holds what does not change. The plugin supplies what rotates.

```yaml
users:
- name: ecdsa
  user:
    httpSignature:
      apiVersion: client.authentication.k8s.io/v1alpha1
      algorithm: ecdsa-p384-sha384
      ttl: 30s
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: my-credential-helper
      args: [credential, --cluster, my-cluster]
      interactiveMode: Never
```

The plugin is the same mechanism that already returns bearer tokens and client certificates. It
returns signing material instead, in a new `status.httpSignature` field:

```json
{
  "apiVersion": "client.authentication.k8s.io/v1",
  "kind": "ExecCredential",
  "status": {
    "httpSignature": {
      "keyID": "demo-ecdsa-p384",
      "privateKey": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
    }
  }
}
```

The client tells the plugin what to produce, in `spec.httpSignature`, so the plugin does not guess a
contract it will be held to. No key and no key ID appear in the kubeconfig. That is what lets a
credential rotate with no kubeconfig edit.

For a shared secret rather than a keypair the plugin returns `secret` instead of `privateKey`. Both
forms may also carry a derivation scope, so a broker can hand out a key narrowed to one day and one
cluster rather than the root secret. See D8.

## What an operator configures

kube-apiserver is configured by an `httpSignature` list in `AuthenticationConfiguration`, the same
file that already configures JWT and anonymous authentication, behind the
`HTTPSignatureAuthentication` alpha feature gate. Editing the file takes effect without a restart.

One entry, pointing at a resolver:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
httpSignature:
- endpoint: unix:///var/run/httpsig/resolver.sock
  # Checked against the created timestamp in the signature, so a stale request is
  # refused and the resolver knows how long to remember its nonce.
  maxAge: 1m
  # Only key IDs whose first segment matches reach this resolver. Omitting this
  # means it is asked about every key ID.
  keyIDPrefixes: [corp]
  # A value the client covers with its signature and this server passes on, for a
  # resolver that decides identity from a session token rather than from a key ID.
  relayedHeaders: [X-Session-Token]
```

No key material and no identity appears in this file. The resolver on that socket answers two
questions, and the API server does all of the cryptography itself:

- Which key verifies signatures bearing this key ID, and whose identity is it? The answer is a public
  key, a shared secret, or a rung of a key derivation ladder, plus a username, UID, and groups, plus
  how long the answer may be cached.
- Has this nonce been used for this key before? This has to be an atomic check-and-record, and it is
  why nonces left the API server: a per-process cache lets a captured request be replayed once against
  every API server that has not seen it.

A resolver with no nonce store is a real case, so `nonceHandling: Ignore` on an entry turns the second
question off and the API server stops asking it. The replay window is then the maximum signature age.
That is stated in configuration rather than faked with a resolver that always answers yes, because the
latter costs a round trip and leaves nothing an operator can audit. Unset means on, a misspelling is an
error rather than a silent default, and `apiserver_httpsig_resolver_nonce_tracking` reports which it is
per resolver.

The protocol is `k8s.io/externalhttpsig`, a small gRPC API in the shape the KMS provider and the
external JWT signer already use. A resolver holds key material and never sees a request; the API server
verifies signatures and never holds a key for longer than its cache says.

What a resolver returns is a claim, not a conclusion. The API server refuses a username or group under
the `system:` prefix, because whoever holds the resolver's socket can vend an identity to the cluster
and claiming a name Kubernetes issues would be a larger grant than vending a key.

## What is not solved

**Key distribution.** The API server knows how to ask. Deciding which party holds which key material
and how it gets there is the resolver operator's problem.

There is a resolver in `e2e/cmd/httpsig-resolver`, backed by a YAML file, which the integration tests
and the kind demo both run a real API server against. It is a demo: key material sits in plaintext next
to the identity it authenticates, and nonce state is in memory in one process. Both are the shape of the
answer rather than the answer, and its README says so.

**Bounding lookups from an unauthenticated caller.** A key lookup happens before any signature has
verified, because verifying needs the key. Length caps, an age check before the lookup, collapsing
concurrent duplicates, and a short memory of unknown key IDs all reduce the cost. Nothing caps the rate
for a caller cycling through distinct key IDs. `DECISIONS.md` Q6 works through where that limit should
live.

**Ladder agreement between a client and a resolver.** Both state the derivation ladder, and they now
have different owners: the resolver's copy comes from an identity system, the client's is authored into
a kubeconfig. Both publish a digest of theirs, so comparing them is one metric read against one log
line, but a mismatch still surfaces at the client as a signature that does not verify.

An alternative direction that would replace key lookup rather than implement it is worked through in
`DECISIONS.md` section 6: an X.509 certificate carried as a user assertion, which is mTLS with the
handshake replaced by a message signature, and for pods most of the delivery machinery already exists
in tree.

## Status

Not yet a KEP. Not proposed upstream. A fork with working client and server plumbing, an external key
resolution API, a file-backed resolver, unit tests, integration tests against a real kube-apiserver, and
a kind demo that runs the whole arrangement.

Five parts are meant to be read as proposals: the kubeconfig surface, the credential sources behind
it, the wire format and coverage rules, the verifier, and the mapping from a verified key to an
identity.
