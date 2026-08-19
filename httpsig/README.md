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

kube-apiserver reads its verification keys from `AuthenticationConfiguration`, the same file that
already configures JWT and anonymous authentication. The `httpSignature` section is new and sits
behind the `HTTPSignatureAuthentication` alpha feature gate.

The PoC's demo configuration, trimmed to one asymmetric key:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
httpSignature:
  # Checked against the created timestamp in the signature, so a captured
  # request can be replayed only until it ages out of this window.
  maxAge: 1m
  keys:
  - keyID: demo-ecdsa-p384
    algorithm: ecdsa-p384-sha384
    publicKey: |
      -----BEGIN PUBLIC KEY-----
      MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEXM4XBQ2KMgl9J+F2v3eyB5J8uEsQ+tpg
      ...
      -----END PUBLIC KEY-----
    user:
      username: ecdsa-demo
      groups:
      - httpsig-demo
```

A key entry names the algorithm, the public key, and the identity that a request signed by that key
authenticates as. A shared secret is referenced by file path instead, because a public key is not a
secret and a shared secret is.

## What is not solved

**Key lookup.** The static key list above is a stand-in so the rest can be demonstrated. It does not
scale past a handful of identities. It has no revocation short of editing a file on every control
plane node. And it puts human identities in server configuration.

Getting a credential to the client has a real answer here. Getting verification material to the
server does not. Everything unsolved sits on one side.

Two directions could replace the list, and `DECISIONS.md` section 6 works through both:

- **An X.509 certificate as a user assertion.** The client sends a certificate alongside the
  signature. The server validates it against a CA and reads the identity from the subject. This is
  mTLS with the handshake replaced by a message signature, and for pods most of the delivery
  machinery already exists in tree.
- **An external lookup API.** The verifier asks a key distribution service what key verifies a given
  key ID and who it belongs to, then checks the signature locally. Only the lookup is remote, and
  its answer is cacheable because a key is stable where a token is not.

## Status

Not yet a KEP. Not proposed upstream. A fork with working client and server plumbing, unit tests,
integration tests against a real kube-apiserver, and a kind demo.

Five parts are meant to be read as proposals: the kubeconfig surface, the credential sources behind
it, the wire format and coverage rules, the verifier, and the mapping from a verified key to an
identity.
