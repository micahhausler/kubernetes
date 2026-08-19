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

A complete, commented reference covering both ways of resolving a signature is in
[`examples/authentication-config.yaml`](examples/authentication-config.yaml). It is validated on
every test run with the same decode and validation kube-apiserver performs at startup, so it is a
file to copy from rather than a snippet to retype. The key material in it is inert: both private
keys were destroyed when they were generated.

The trimmed versions below are for reading.

The PoC's demo configuration, trimmed to one asymmetric key:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: demo-keys
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

## Identity from a certificate instead

The key list above puts an identity per client in server configuration. The alternative is for the
client to carry an X.509 certificate and for the server to hold only the authority that issued it:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
httpSignature:
  authenticators:
  - name: workload-certificates
    x509:
      # Issue an authority for this purpose. Pointing this at the cluster's
      # client CA would let every certificate already issued for connection
      # authentication sign detached messages, which its issuer never agreed to.
      certificateAuthority: |
        -----BEGIN CERTIFICATE-----
        ...
        -----END CERTIFICATE-----
    # Rules run before the mappings, so a mapping never reads a certificate no
    # rule has vetted.
    certificateValidationRules:
    - expression: cert.notAfter - cert.notBefore <= duration('24h')
      message: certificate lifetime must not exceed 24 hours
    claimMappings:
      username:
        expression: '"cert:" + cert.uriSANs[0]'
      groups:
        expression: cert.subject.organization
    # The mapping above derives groups from the certificate's subject, which hands
    # the choice of group to whoever can request one. Without this rule a requester
    # naming system:masters in their organization would receive cluster administrator.
    userValidationRules:
    - expression: '!user.username.startsWith("system:") && !user.groups.exists(g, g.startsWith("system:"))'
      message: 'this authenticator may not assert an identity under the system: prefix'
```

The client side states the certificate and its key, and nothing else:

```yaml
users:
- name: workload
  user:
    httpSignature:
      apiVersion: client.authentication.k8s.io/v1alpha1
      certFile: /var/run/secrets/workload/tls.crt
      keyFile:  /var/run/secrets/workload/tls.key
      # No algorithm and no keyID. The certificate's key type determines the
      # algorithm, and the key ID is the certificate's digest.
```

For a pod there is a one-file form, `credentialBundleFile`, which is what a
`PodCertificateProjection` writes: one read returns a consistent key and certificate, where two
files can be read between the two writes of a rotation.

This is mutual TLS with the handshake replaced by a message signature. The same authority, the same
issuance, and the same subject conventions apply; only the point of authentication moves into the
message, which is what lets it survive a TLS-terminating hop.

What binds the certificate to the signature is the `keyid`, which must be `x509-sha256:` followed by
the leaf's digest. A signature's parameters are always part of its signature base, so a `keyid`
naming the certificate is covered by every signature that carries one. The server recomputes the
digest from the bytes it received rather than trusting the claim.

## What is not solved

**Revocation, for a certificate.** The server holds nothing per client, which is the point, so there
is nothing to delete. A certificate's lifetime is the window, narrowed by the validation cache's TTL
and by whatever lifetime rule the configuration states. For pods, kube-apiserver caps issuance.

**Replay, for a certificate.** Nonces are remembered per configured key, and a certificate is not a
configured key, so `maxAge` alone bounds replay there. The nonce parameter is on the wire and is
deliberately not recorded, so enforcement can begin later without breaking existing clients. The
bound needs a design rather than a constant: a bucket keyed on the trust anchor would put every
client under one authority into one shared, peer-driven cache, which is the arrangement that turns
replay tracking into a replay enabling mechanism.

**Key lookup, in general.** The static key list does not scale past a handful of identities and has
no revocation short of editing a file on every control plane node. A certificate answers that for
clients that can be issued one. For those that cannot, the remaining direction is an external lookup
API: the verifier asks a key distribution service what key verifies a given key ID and who it
belongs to, then checks the signature locally. Only the lookup is remote, and its answer is
cacheable because a key is stable where a token is not. Key resolution is an interface, so that is a
third implementation rather than a rewrite. `DECISIONS.md` section 6 works through it.

## Status

Not yet a KEP. Not proposed upstream. A fork with working client and server plumbing, unit tests,
integration tests against a real kube-apiserver, and a kind demo.

Five parts are meant to be read as proposals: the kubeconfig surface, the credential sources behind
it, the wire format and coverage rules, the verifier, and the mapping from a verified key to an
identity.
