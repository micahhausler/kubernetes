# HTTP Message Signatures in Kubernetes: PoC decisions and assumptions

Status: working document for a proof of concept on a fork. Not a KEP.

This records the reasoning behind decisions made as well as open questions.

## What this PoC is, and what it is not

It is a porcelain and plumbing layer for the client and the server: the kubeconfig surface, the
credential sources behind it, the signing round tripper, the wire format and coverage rules, the
verifier, and the mapping from a verified key to an identity. Those are the parts
meant to be read as proposals.

Key lookup was the gap this document opened with, and it is now built twice. The static key list is
gone, and identity no longer comes from server configuration by either route.

An `httpSignature` authenticator either names a resolver on a Unix socket, which answers for a key ID
with the key that verifies signatures bearing it and the identity it authenticates, and which records
the nonces those signatures carry (D11); or it names a certificate authority, and takes the key and
the identity from a certificate the request carries (D15). Which one answers a signature is decided by
its keyid. D12 covers the seam they share and what it deleted.

Key *distribution* remains out of scope, and that distinction is worth holding. Getting verification
material to the verifier is answered: it asks. Deciding which party holds which key material, and how
it gets there, is the resolver operator's problem and this document does not have a view on it.

A resolver implementation is in `e2e/cmd/httpsig-resolver`, backed by a YAML file. It is a demo rather
than a key management system, and its own README says where that line is. It is what the integration
tests point a real API server at over a real socket.

The kind demo in `e2e/` runs against it end to end, and it is where the arrangement is easiest to see:
the directory the control plane mounts holds one file naming a socket, and no key material at all.

## 1. What this adds

A client signs each request over a set of covered components: the method, the hostname, the path,
the query, a digest of the body, and selected headers. The server verifies the signature, resolves
the signing key to a user identity (authentication), and admits the request. The credential itself
is never sent in cleartext over the wire.

This implementation uses two new libraries:

- `github.com/micahhausler/sfv` v0.2.0 for RFC 9651 structured fields
- `github.com/micahhausler/httpsig` v0.3.2 for RFC 9421 wire format, signing and
  verification, RFC 9530 content digests, and the key derivation in D8

## 2. Motivation

The property to lead with is not non-replayability. A signature scheme with a `created` timestamp
and an acceptance window still admits replay inside that window, and detecting a replay would take
state shared by all API servers. Replay protection is unimplemented. See D5.

The properties that do hold. The first two are what a signature has over a bearer token, which
transits on every request. The third is what it has over a client certificate, which signs the
transport rather than the message:

1. **The credential never transits.** Capturing a request yields a request, not a reusable
   credential. A proxy access log, a compromised sidecar, or a node exfiltration produces signatures
   over requests that already happened. Short-lived bearer tokens shorten the window of reuse; they
   do not remove reuse.

   This property matters more now than it did when short-lived tokens were designed. A short
   lifetime is an assumption about attacker speed: the credential expires before anyone can find a
   use for it and chain that use into a larger one. The assumption was made about human attackers,
   who have to read what they captured, decide what to try, and try it. An agent driven by a
   language model reuses a captured token iteratively at machine speed and can chain several
   separate weaknesses inside a window of minutes. The bound, stated exactly: the window still
   limits what an attacker reaches, so short lifetimes have not stopped working. What has changed is
   the return on each further reduction. Going from an hour to five minutes buys less than that
   change used to buy.

2. **Request integrity binding.** A captured signature cannot be repurposed to a different verb,
   path, query, or body. A successful in-window replay therefore reproduces the identical request
   and nothing else. What that is worth to an attacker varies by request, and for a read it is worth
   the response: replaying a captured `GET` on a Secret discloses the Secret.

3. **Authentication that survives a TLS-terminating intermediary.** This is the property mTLS cannot
   provide. A client certificate authenticates the TLS connection, so it dies at the first load
   balancer, ingress, or terminating proxy. A message signature is carried in the message, so it
   reaches the API server through intermediaries that terminate TLS.

One further property belongs to the mechanism rather than to the PoC: the signing key never has to
be extractable. Signing is an operation the client performs, not a value it hands over, so the key
can live in a TPM, a secure enclave, a hardware token, or a non-exportable platform key and be used
without leaving it. The signature is then proof of possession. The holder of the key has to take
part in every request, so exfiltrating request logs, process memory, or configuration files yields
nothing that can be replayed from another machine.  The PoC does none of this. It reads private keys
and shared secrets from files, or takes them from an exec plugin, see D3. This is written down
because the KEP argues about the mechanism, not about how the PoC loads keys.

Non-replayability is then stated as what it is: `created` plus a maximum age bound the replay
window, and nothing narrows it further. See D5.

Property 3 is the strongest leg and it is in tension with the covered component set. See Q1.

## 3. Alternatives considered

| Alternative | Why it does not cover this | Why it is still relevant |
| --- | --- | --- |
| Bearer token with short TTL | The credential transits on every request and is replayable by anyone who captures it, for the remainder of its lifetime. Shortening the TTL shrinks the window and raises the issuance rate; it does not change the kind of credential. The window is also worth more to an attacker than it once was: an automated agent can use a captured token at machine speed, so minutes are enough to chain several weaknesses. See motivation 1. | It is the incumbent and the baseline any new mode is measured against. |
| Client certificates (mTLS) | Authenticates the connection, not the message, so it terminates at the first TLS-terminating hop. Kubernetes has no revocation path for client certs, and certificate distribution does not federate to an external identity provider. | For direct API server access with an operator-controlled CA, mTLS is a complete answer and this proposal does not displace it. |
| Exec credential plugin | The protocol carries no request data to the plugin (`ExecCredentialSpec` has cluster info and an interactive flag, nothing about method, path, or body) and the response can express only a token or a client certificate. A plugin can hold signing key material, but what it returns to client-go is a static credential. | The exec plugin is the sanctioned extension path and is where key material acquisition belongs. See D3. |
| Auth provider plugin framework (`rest.RegisterAuthProviderPlugin`) | Frozen. The gcp and azure providers were replaced by error-returning stubs pointing at exec plugins. Its `WrapTransport` interface is the shape a signer needs, which is the point: the mechanism that could express this was deliberately retired in favor of a per-credential model. | Explains why a new first-class mechanism is required rather than a plugin. |
| DPoP / proof-of-possession bound tokens (RFC 9449) | Binds a token to a key, so the token still transits and the binding proof is a second credential. Solves token theft, not token transit. Nothing in Kubernetes issues DPoP-bound tokens today. | If SIG Auth has an existing PoP thread, this proposal should join it or explain why not. |
| Authenticating proxy (front proxy) doing verification out of tree | Works today and is how an out-of-tree prototype demonstrates this. Requires operating a proxy, and the proxy re-originates the request with `X-Remote-User`, so the API server trusts the proxy rather than the client. | This is the fallback if in-tree verification is rejected. In-tree support is what makes the mode usable without extra infrastructure. |
| Session token pattern: encrypted key material carried in a signed request header, decrypted by the server | Inverts motivation 1. The credential transits on every request, protected by a server-held wrapping key. Also makes the API server a credential issuer with a root key and a rotation story. | Architecturally interesting for a stateless deployment with no key lookup, and demonstrated in that prototype. Recorded here as rejected for in-tree use, not overlooked. See D4. |

## 4. Decisions

### D1: kubeconfig gets a first-class `AuthInfo` field

`AuthInfo` gains an `httpSignature` field in both the internal (`clientcmd/api`) and serialized
(`clientcmd/api/v1`) types.

Rationale: this is the shape the KEP proposes. Building the PoC on the shape under discussion is
what makes the PoC evidence rather than a demo.

**Objection recorded:** a field can never be removed from `AuthInfo`. There is no kubeconfig v2.
Building the PoC on the first-class field means the field set is chosen before it is proven, and the
KEP inherits whatever the PoC shipped, because that is what reviewers have running in front of them.
The `Extensions` escape hatch would have cost zero API type changes and forced the field set to be
discovered empirically.

Mitigations adopted in place of using `Extensions`:

- The struct carries only knobs with a demonstrated use in the PoC. Nothing speculative.
- The inner payload follows `ExecConfig` rather than `AuthProviderConfig`: `AuthProviderConfig` is
  an untyped `map[string]string` that accreted gcp, azure, and oidc and took years to remove.
  `ExecConfig` carries its own `apiVersion`, which kept the payload shape revisable while the field
  name stayed stable. The only permanent commitment is the name `httpSignature`.

### D2: three coverage classes; the server owns the requirement

Coverage is split into a fixed floor, a fixed set of headers covered when present, and
user-specified extras.

| Class | Contents | Client | Server |
| --- | --- | --- | --- |
| Floor | `@method`, `@authority`, `@path`, `@query`, content digest when a body is present | always signed | required by policy |
| Protected headers | `Impersonate-User`, `Impersonate-Uid`, `Impersonate-Group`, `Impersonate-Extra-*`, `Audit-ID`, `Accept`, `Content-Type`, `User-Agent` | covered when present on the outgoing request | if present on the received request, must be covered |
| User extras | headers named in the kubeconfig `signedHeaders` list | injected and always covered | covered by construction; the key lookup may read them |

`created` is a signature parameter rather than a covered component, so it is not in the floor. The
verifier requires it all the same: a signature it cannot age is rejected, because the acceptance
window is the only bound on replay.

`@query` is in the floor because Kubernetes API semantics live in the query string: `dryRun`,
`watch`, `fieldSelector`, `resourceVersion`. A signature that leaves the query uncovered permits a
bystander to turn a dry run into a real write.

`Content-Type` is in the protected set because the content digest binds the body bytes but not their
interpretation. The API server parses the same bytes as JSON, YAML, or protobuf depending on this
header.

Users may add covered headers. Users may not remove floor components. The security floor is not
negotiable from the client side, and a client-configurable coverage list would also break
interoperability with a server whose policy is fixed.

Two verifier obligations follow, and both are invariants rather than implementation details:

- **The verifier requires the floor independently of what the signature claims to cover.** RFC 9421
  signatures are self-describing: the covered component list is in `Signature-Input`, chosen by the
  signer. A verifier that checks only "the signature is valid for the components it declares"
  accepts a signature covering nothing, because an attacker signs a component list of their choosing
  with their own key. The floor is verifier policy. The client profile is a convenience so that the
  client produces something the verifier will accept.

- **A protected header present on the request must appear in the covered set.** Coverage protects
  against removal for free: dropping a covered header makes the signature base unreconstructable and
  verification fails. Addition is not protected by RFC mechanics. An intermediary that appends
  `Impersonate-User` to a signed request that carried no impersonation header produces a request
  whose signature still verifies. The presence check is the only defense against header addition.

`Authorization` is deliberately not in the protected set. When a request carries both a bearer token
and a signature, the union authenticates it with whichever authenticator it reaches first, and the
authentication filter then deletes the `Authorization` header. So an injected `Authorization` header
has no effect on a request the signature authenticated. Adding it to the protected set would
mean signing over a credential that should not have been sent.

### D3: credentials come from something that maintains them, not from the environment

The kubeconfig holds what does not change about a signing identity: the algorithm, which headers the
signature covers, the key derivation scope, and the signature lifetime. What changes comes from a
credential source, described in D7.

An exec plugin is the source to prefer, and D10 is its own decision. Two file-backed sources exist in
client-go alongside it, and the client re-reads both when the file changes:

- `keyFile` with `keyID`, for a private key that is simply present on disk, so key rotation does not
  need a restart.
- `credentialFile`, for anything else. It names a document carrying the key, the key ID, the values
  of any covered headers, and an optional expiry.

The rest of this section is about what a credential must carry, which is the same whichever source
delivers it. The document the file forms read is versioned, because something outside Kubernetes
writes it:

```yaml
apiVersion: httpsig.authentication.k8s.io/v1alpha1
kind: SigningCredential
keyID: signer-1
secret: <shared secret, for hmac-sha256>       # exactly one of secret,
secretBase64: <base64 bytes, for a derived rung> # secretBase64, or privateKey
privateKey: <PEM, for the asymmetric algorithms>
stage:                                         # position on a derivation ladder,
  from: purpose                                # see D8
  scope: {day: "20260830", cell: cell-1, purpose: api}
signedHeaders:
  X-Session-Token: <value>
expirationTimestamp: 2026-08-13T23:00:00Z
```

The decoder rejects unknown fields. A typo'd field name would otherwise produce a credential
silently missing whatever the field was meant to set.

`signedHeaders` in the kubeconfig lists only header names; the values come from the credential. This
is what keeps a rotating session token out of the kubeconfig, and it lets that token rotate without
rewriting one. A value the credential supplies for a header the kubeconfig does not cover is an
error rather than an unsigned header on the wire.

`expirationTimestamp` means the same thing in every delivery mode: do not sign with this credential
after this time. What differs is the recovery action, which here is to re-read the file. An expired
credential fails at the client rather than producing a rejection at the server.

#### Four delivery modes, one credential

The credential reaches the client one of four ways, and all four end at one
builder, so the rules about what a credential must carry cannot drift between
them:

- `exec`, the ordinary credential plugin, returning signing key material instead of a token. This is
  the form to prefer, and it is the subject of D10. A credential producer already knows how to hold
  a long-term secret and mint scoped material from it; running it as a subprocess keeps that
  material out of the kubeconfig and out of this process's configuration.
- `credentialFile`, a document something else maintains. The right fallback where a subprocess per
  refresh is unwelcome, and what a projected volume or a sidecar already produces. **This is the
  signing analogue of `tokenFile`**, and it earns its place for the same reason that field does: a
  projected volume or a sidecar rewrites a credential in place, and nothing has to fork a process to
  pick it up.  Kubernetes already re-reads `tokenFile` on this exact pattern, so the case is a
  deployed one rather than an imagined one.
- `keyFile`, a private key on disk with a fixed key ID, for the simple case, matching `client-key`
  in a kubeconfig.
- a `Credential` stated directly in `rest.Config`, for a caller that already holds the material.
  This is the analogue of `rest.Config.BearerToken` against `BearerTokenFile`, and it exists because
  reading a file was never supposed to be the mechanism, only one source. A caller with a key in
  memory should not have to write it to disk for this package to read back. Nothing rotates it, so
  it is validated when the client is built and an already expired one is a configuration error
  rather than a runtime one; a caller whose material rotates supplies a `CredentialSource` instead.

Deliberately not in the kubeconfig: the inline form. A kubeconfig can already carry a bearer token
and a private key inline, so precedent would allow it, but D3's whole argument is that a signing
credential should not live in a file that gets copied around and committed. The inline form is a
Go-level affordance for programs, and `exec` is the answer for kubeconfigs.

Only the file forms carry that envelope. An exec plugin returns the same fields inside its
`ExecCredential` status instead, which is why they are a separate type. One implementation validates
the material and builds a signer from it, and every delivery path calls it. A second copy of the rule
that a covered header must have a value is a second place for the rule to be wrong.

#### Redaction lives on the type that holds the material

`Material`, `SigningCredential`, `Credential`, and `BoundCredential` each implement `String` and
`GoString`, so `rest.Config` needs no special case for signing: it prints the credential and the
credential redacts itself. Both methods are needed because `fmt` reaches them by different paths, and
a type implementing only one leaks through the other. Covered header values are redacted along with
the key material, because a covered header carries something like a session token, while the key ID
survives so the output stays worth logging.

#### What this does not preclude

The seam the round tripper depends on hands back a signer, not key material. A signer whose key
never leaves a hardware token or a platform keystore satisfies that interface. Delivering one is out
of scope here. The point of noting it is that plumbing a signer rather than a key costs nothing now
and keeps the option open.

### D4: server configuration lives in `AuthenticationConfiguration`

The verifier is configured by an `httpSignature` section in `AuthenticationConfiguration`
(`apiserver.config.k8s.io`), alongside `JWT` and `Anonymous`, gated by the
`HTTPSignatureAuthentication` alpha feature gate. It is a list, and each entry names one resolver:
its endpoint, which key IDs reach it, which request headers are relayed to it, how long its answers
may be cached, and the acceptance policy for the keys it vends.

No key material and no identity appears in this file. That was the original shape and D11 removed it.

**Scheme and authority are per entry and are required to agree.** Both describe *this server*, not any
resolver: the authority goes into the signature base, so two entries stating different values would
make one request verify under one entry and fail under another. There is no field position that
expresses "stated once for the whole section" without adding a sibling to the list, so the data model
tolerates the repetition and validation removes the ability to disagree. Two independently settable
fields are a place for them to disagree; the fix is to make the disagreement unrepresentable rather
than to pick a winner.

**Reload works.** The signature authenticator sits behind an `atomic.Pointer` and the union reads it
per request, the same indirection the JWT authenticator uses, so a resolver can be added, removed, or
repointed by editing the file. Three things follow from that mechanism and are worth stating:

- It is in the chain even when no resolver is configured, because an authenticator absent from the
  chain cannot be swapped into it later. With an empty list it draws no opinion about any request,
  including one carrying a signature, so a stray `Signature` header cannot break authentication that
  has nothing to do with signatures.
- A new generation is built and health-gated before either it or the new JWT authenticator is swapped
  in, so a reload is all or nothing. A file that changed both sections and applied one would leave
  the server in a state no configuration describes.
- The old generation's connections and metadata polls are cancelled after the same grace period the
  JWT side uses, because a request that read the old pointer may still be mid-lookup.

This closes what this section previously recorded as a defect: a change to `httpSignature` was
validated, ignored, and reported as a successful reload. That was found on the kind cluster in `e2e/`,
where correcting a bad key made the server log a reload and then keep rejecting requests until the
process restarted. Accepting a change and then ignoring it is worse than refusing it, and the metric
saying `status="success"` while nothing had been applied was the part that made it a defect rather
than a limitation.

The nonce question that section deferred to Q4 dissolved rather than got answered: nonce records live
at the resolver now, so a key surviving a configuration change has no local cache to preserve.

### D5: nonce records live at the resolver, and recording is optional but not local

Superseded by D11. The per-process nonce cache is gone, along with `maxNoncesPerKey`.

What that cache could honestly claim was narrow, and worth restating because the replacement is what
the claim needed: a nonce was remembered by one API server process, so with more than one API server
and no shared state a captured request could be replayed once against each server that had not seen
it, until its signature aged out. Sizing the cache, bucketing per key, and choosing an eviction policy
were all work in service of a guarantee that did not hold.

`ConsumeNonce` is an atomic check-and-record at the resolver, which is the only place the fact can be
recorded once for a cluster. Two decisions around it:

- **A failed call fails closed, and no setting changes that.** An error, including an unreachable
  resolver, rejects the request. The cost is real and is the right cost: a resolver outage rejects
  requests whose keys are still cached and still valid. This is distinct from the setting below, and
  the distinction is the point: configuration can say not to record nonces, but it cannot say to accept
  a request whose nonce this server tried and failed to record. An outage is not a policy decision.
- **It is called after the signature verifies**, last of everything. A caller who cannot produce a
  valid signature never reaches the resolver's nonce store, so filling it is not something an
  unauthenticated caller can do. A test asserts the call count is zero for a tampered request, because
  this property lives in call order and call order is not self-documenting.

**Two questions that were run together, and have different answers.** This section previously said
there was no option at all, on the grounds that offering one would let the same configuration file
describe a cluster with replay protection and one without. That argument was wrong, and it was wrong in
a way worth recording rather than quietly fixing.

*Per-API-server nonce tracking* is still refused, and the reasoning above is why: it offers a guarantee
that does not hold.

*Turning recording off* is now `nonceHandling: Ignore`, per resolver. The argument against it did not
survive contact with the alternative. A deployment whose resolver has no nonce store could always
implement `ConsumeNonce` as a stub that returns accepted, so the configuration file could already
describe a cluster without replay protection. What it could not do was *say so*. The stub is strictly
worse on three counts: it is a resolver that lies about the RPC's contract, it costs a round trip per
request for nothing, and an operator auditing the cluster would have to read a resolver's source to
find out. Refusing the field was protecting a property that was already bypassable, just invisibly.

Three things make the option defensible rather than a hole:

- **The zero value is Consume.** There is no defaulting pass for `AuthenticationConfiguration`, so this
  lives in the code rather than in a scheme, which also means a caller constructing the internal struct
  gets replay protection. A test pins it.
- **A typo is an error, not a default.** The value is checked against a closed set, because
  `nonceHandling: ignore` falling through to the safe value would leave protection on for an operator
  who meant to turn it off, and send them looking in the resolver for the reason.
- **It is discoverable without reading the file.** A startup log line names the resolver, and
  `apiserver_httpsig_resolver_nonce_tracking` is 0 or 1 per resolver, because "which of my clusters
  have replay protection off" is a fleet question and logs do not answer fleet questions.

**The nonce stays required when it is ignored.** A signature without one is rejected either way. It
costs a client nothing, it is covered by the signature regardless, and it means turning recording on is
a change to this server alone rather than to every client. So the setting gates exactly one thing, the
call, and not two.

### D6: new operational dependency on client clock sanity

A `created` timestamp with a bounded acceptance window requires the client clock to be roughly
correct. No existing Kubernetes authentication mode cares about the client clock. A workstation with
significant drift will fail authentication with this mode and succeed with a bearer token.

The requester scoped clock skew out of this work, so nothing here tries to solve it: the verifier
has a `maxClockSkew` setting and that is all. It stays written down because it is a behavior change
to state in the KEP's risks rather than something to discover in beta.

### D7: the round tripper depends on a signer, not on a key

A credential source produces the current signing identity:

```go
type CredentialSource interface {
	Credential(at time.Time) (*Credential, error)
}

type Credential struct {
	KeyID         string
	Signer        httpsig.Signer   // Sign(base []byte) ([]byte, error)
	SignedHeaders map[string]string
	NotAfter      time.Time
}
```

What travels through this interface is a signer, never key material. That single property is what
allows a key that cannot be exported: a TPM, a platform keystore, or a smart card holds the key and
answers signing requests, and the round tripper cannot tell the difference. Plumbing key bytes
instead would make hardware support a rewrite rather than an addition.

The interface is exported, along with a constructor that takes a source directly, so an
implementation can live outside `client-go` and outside Kubernetes. That is deliberate: hardware key
support should not have to be merged into `client-go` to be usable.

The round tripper asks the source on every request. That is what makes a long-lived client work,
because a controller outlives its credentials, and what makes a periodically rewritten secret or key
file take effect without a restart. A source has to be cheap when nothing has changed; the
file-backed ones compare modification time and size before re-reading.

The signing time is a parameter rather than something the source reads from the clock. A derived key
can be scoped to a date (D8), and the date it is scoped to has to be the same one the signature
carries in its `created` parameter. Passing the intended signing time makes that exact instead of a
race at midnight between two reads of the clock.

`NotAfter` is advisory to the caller, and the caller fails closed: a source that returns an expired
credential stops the request rather than producing a signature the server will reject. `Credential`
is returned by pointer and treated as immutable; a source that rotates returns a new one.

The four cases this has to serve, and how:

| Case | Source |
| --- | --- |
| A periodically updated shared secret | credential document, re-read on change |
| A periodically updated key pair on disk | key file, re-read on change |
| A key in a TPM, static or rotating | an implementation of `CredentialSource`, not built here |
| A signing key derived from a secret | derivation applied inside the source, see D8 |

What is deliberately not built: any TPM integration, and any kubeconfig syntax for naming a hardware
key. A kubeconfig field implies a registry of provider names, which is the shape of the auth
provider plugin framework that was retired for good reasons. There is one in-tree implementation
family today, so a registry has nothing to arbitrate. When a second exists, the argument can be made
with two concrete cases in hand rather than one imagined one.

One more thing is out of scope, and it is the question a reader of "TPM" asks next. Attesting that a
key really is in a TPM, through an endorsement key and a challenge and response exchange, is not
something Kubernetes does today. This design lets a client sign with a resident key. It does
not let a server verify where that key lives. Kubernetes does support a bootstrap kubeconfig for
kubelets, and that could be a potential mechanism for a TPM endorsement challenge and response.

### D8: a signing key may be derived through a shared ladder, so the API's secret is never the signing key

Derivation is described by two artifacts, split along the line of what is shared and what is local.
The mechanics are the signing library's `keyscope` package: the chain, the key ID format, staged
entry, scope checking, and the validation rules. Kubernetes declares the ladder as an API type,
converts it to the library's form, and fingerprints it.

That library form is the one thing nine declarations of a schema can get wrong. The Kubernetes types
are converted by their JSON encoding, so a field the library gains and Kubernetes does not is a
derivation Kubernetes cannot express, and a field whose name differs silently stops being carried. A
reflection test compares the JSON tags of both, and it fails when the library grows a field, which
is the event worth hearing about rather than a periodic review. Nothing else is duplicated: the
conversion passes the encoding through the library's own unmarshaler, so the kind, the hash, unique
step names, one input source per step, the closed set of date formats, and the separator bans are
all still checked by one implementation.

The **ladder** defines the derivation for an ecosystem. Every party that derives states the same
one: the client in its kubeconfig, the server in its authentication configuration, and a broker
wherever it keeps its configuration.

```yaml
keyDerivation:
  kind: hmac-ladder
  hash: sha-256
  secretPrefix: "EXAMPLE1"       # prepended to the root secret before step 1
  steps:
  - {name: day,        date: YYYYMMDD}
  - {name: cell,       scope: true}
  - {name: purpose,    scope: true}
  - {name: terminator, literal: example1_request}
```

**The ladder is typed rather than a file path or an embedded blob, and this reverses an earlier
decision.** It used to be a document referenced by path from both sides, which had one property this
does not: the two copies were the same bytes, so agreement was `sha256sum` on two files. Typed costs
that and buys more. A path means an operator distributes a second artifact to every client, when the
kubeconfig is already the artifact being distributed. A YAML string inside the kubeconfig would avoid
that but is unmanageable by `kubectl config` and reintroduces indentation as a failure mode. And
typed puts the ladder where a reader of the configuration can see it.

Two consequences follow, one of them a loss:

- **The digest now covers the parsed ladder, not the bytes.** There are no shared bytes to hash, so
  one function fingerprints the ladder after conversion and both sides log theirs. This is stronger
  as a comparison, because formatting and field order stop reporting drift that does not exist, and
  weaker as an operational tool, because comparing now needs both processes' logs rather than a shell
  one-liner. The digest is a diagnostic rather than a control, and a diagnostic that cries wolf is
  one nobody reads, so the trade is worth making. Q5 records the idea that would recover the
  ergonomics.
- **Two configurations state the ladder, so they can disagree.** D8 used to claim agreement was a
  checksum rather than "a hope that two hand-copied lists match", and with typed ladders in two
  files that claim is gone. It was always overstated: the client and the server are different
  machines with different owners, so the ladder always existed twice and the file form only made
  byte-comparison possible. What detects disagreement now is the digest, plus the fact that a wrong
  ladder fails closed.

In practice, clusters should never change the key derivation over the lifetime of a cluster. It is a
cluster-lifetime bound configuration that remains static.

One asymmetry is deliberate. The API server decodes its configuration strictly, so it refuses a
misspelled ladder field at startup with a precise error. Nothing decodes a kubeconfig strictly, so
the same typo there is dropped in silence and surfaces as a mismatched digest and a 401. The strict
side is the authoritative side, which is the right way round, and the loss on the client side is the
loss every other kubeconfig field already carries. This also deleted the hand-rolled strict pre-pass
the document form needed, because the platform now does that job where it matters.

Step names are arbitrary. `day`, `cell`, and `purpose` are this example's choice, and nothing in the
implementation treats a name, a prefix, or a literal as meaningful. See D9.

The chain it describes:

```
k0 = HMAC(secretPrefix + root secret, message of step 1)
ki = HMAC(k(i-1),                     message of step i+1)
signing key = the last k
```

Each step's message is a literal, a date rendered from the signing time, or a value the party
supplies under the step's name. Step names are unique, and neither a name, a literal, nor a scope
value may contain a slash, because those values are joined by slashes into the keyid. An existing
deployed chain is expressible verbatim, prefix included, which is what one test checks; see D9.

The **stage** is one party's position on the ladder. It travels with the key material it describes:
in the SigningCredential document on the client, written by the same producer in the same atomic
write as the material, and in the key entry on the server. The key's public name is not part of it;
that is the credential's key ID.

```yaml
stage:
  from: purpose                # my material is the output of the "purpose" step
  scope:                       # values of scope steps, and assertions for date
    day: "20260830"            # steps at or before from
    cell: cell-1
    purpose: api
```

An absent `from` means the material is the root secret, and the client folds the whole ladder at
signing time. A set `from` means the material is an intermediate rung. This is the point of a ladder
rather than a single HMAC. A broker holding the root hands a party the rung scoped to one day, one
cell, and one purpose. That party folds the remaining steps, and can never climb back up or move
sideways to a sibling scope.

The scope map must cover exactly the scope steps, plus the date steps at or before `from`. A missing
key and an unexpected key are both errors. A date assertion must be a date the step's layout
produces.

The **equivalence invariant** that makes staged entry sound, and the property the tests assert
across all four pairings of root and rung: deriving from the root through the whole ladder equals
deriving from any rung whose assertions match.

#### The keyid carries the claimed scope

A signature made with a derived key sets its `keyid` to the key's name followed by each step's
value, joined by slashes:

```
signer-1/20260830/cell-1/api/example1_request
```

The verifier compares every segment against its own scope and against the signature's `created`
before any signature math runs. Nothing in the keyid ever feeds derivation: the verifier derives
from its own configuration alone, so the comparison is an assertion check and not a key selection
mechanism.

This exists for diagnosability, and it does not come for free. Without it, a client scoped to the
wrong cell, a client holding yesterday's rung, and a client with a drifted ladder all fail the same
way: `signature does not match`, indistinguishable from tampering. With it, the rejection names the
step that disagreed and the value the peer claimed. The test for this is written so that removing
the check turns the failure back into a bare mismatch, which is what a reviewer should see it
protecting.

The error's peer-facing text carries only the step name and the value the peer already sent. What
the server expected is available separately, for logs, so a server that surfaces authentication
errors does not disclose its own scope configuration by doing so.

The API server's key lookup takes the name from the segment before the first slash, so one
configured key serves every scope it is entitled to.

The library also offers a keyid parser, for a lookup that fetches key material per claimed scope
from a broker. This PoC does not use it, for two reasons. The verifier already performs every check
the parser would, the length bound, the segment count, and the per-segment comparison, against the key
it selected, so calling it would validate the same string twice. And the parser needs the ladder
before it can parse, which a lookup cannot have before it has chosen a key, because each configured
key may name a different ladder. It becomes the right call when a lookup fetches key material per
request instead of reading it from configuration, which is Q4.

#### The clock is the signature's `created`, on both sides

The client renders a pending date step from the timestamp it is about to put in `created`. The
server renders it from the timestamp the signature carries, never from its own clock. The two sides
then agree by construction, including at day boundaries, and `created` is covered by the
signature, so an attacker cannot move the date without invalidating it. The verifier's existing
maximum age bounds how stale a `created`, and therefore a derived key, can be.

A date step at or before `from` is fixed in the material. The client fails closed when the `created`
it is about to sign with renders a different date than the assertion, with an error that says the
material has expired rather than letting the server reject the signature. A verifier holding the
root needs no assertion at all: it derives from `created`, and a stale client rung fails the keyid
comparison at the date step.

Derived keys are not cached. For a key that is not yet date-scoped, the date comes from the
request's `created`, so a cache keyed on it has attacker controlled cardinality; a date-scoped rung
derives in one HMAC or none. This reverses an earlier decision to cache the client's derived signer
per day: the saving is a few microseconds and the mechanism is a cache an unauthenticated caller can
drive.

#### Date formats are enumerated, not layout strings

The document crosses language boundaries. A Go reference-time layout such as `20060102` would be a
Go-ism another implementation misreads. A wrong layout that looks plausible produces a wrong key, and
then a signature failure with nothing in the error to say why. Formats are therefore named, from a
closed set the library defines: `YYYYMMDD` and `YYYY-MM-DD`, both UTC.

#### Encodings

Intermediate rungs are raw hash output rather than printable strings, so the encodings are explicit.
The credential document carries exactly one of `secret`, a UTF-8 string for a root secret, or
`secretBase64`. The server's `secretFile` must hold base64 when the key entry's stage sets `from`,
because the trailing newline trim applied to a plain secret would corrupt a rung ending in a newline
byte. A root secret stays plain even when a stage carries scope values, since the stage alone does
not make the material binary.

#### What is not built, and why

Derivation applies to `hmac-sha256` only. The document has a `kind`, so an asymmetric derivation
would be a new kind rather than a change to this one. It is deferred, not designed. The published
asymmetric variants of this construction derive the public key from the same shared secret, so the
trust model stays symmetric. What they buy is verification in many places without distributing the
secret, and one kube-apiserver does not need that. Doing it honestly for Kubernetes means registering
derived public keys, which is the Q4 key distribution design.

Derivation does not remove the objection to shared secrets in D3. A verifier holding the root can
still produce signatures attributable to any identity the root governs. What changes with a staged
verifier is the blast radius: an API server given a date-scoped rung instead of the root can mint
only within that scope, only for that day. State this precisely in the KEP rather than
presenting derivation as fixing the shared-secret problem: derivation bounds the value of a leaked
derived key and stops cross-domain reuse of the secret, and that is all it does.

### D9: a ladder is arbitrary, and that is enforced by test

Nothing in the implementation attaches meaning to a step's name, a secret prefix, or a literal. A
ladder names its own steps. A scope step looks up its value by its own name in the party's scope map.
The number of steps is arbitrary, and the key ID format follows from the ladder rather than from any
convention. `day`, `cell`, and `purpose` are one example's labels and have no standing in the code.

That is easy to state and easy to lose. The failure mode is someone special casing a step name, or a
date step's position, to fix a bug. After that, a ladder which does not resemble the examples stops
working, in silence, for everyone who did not write the special case.

A single test in `k8s.io/client-go/transport/httpsig` reproduces a published test vector from AWS
Signature Version 4, byte for byte, from its documented secret, date, and scope values. Reproducing
someone else's vector is a stronger check on the shape than any ladder written here: a schema that
expresses a scheme it was not designed around is general in a way self-consistent tests cannot
demonstrate. It also means material from an existing derivation of this form is usable without a
translation layer.

Examples in documentation use the same arbitrary labels as the tests, because an example is what a
reader copies, and one written in a particular scheme's vocabulary suggests the code cares about that
vocabulary when it does not.

### D10: the credential comes from an exec plugin, told what to produce

A signing credential is produced by the same mechanism that produces every other
credential a kubeconfig names: `user.exec`. The plugin returns key material in
`status.httpSignature` instead of a token, and the client signs each request with
it.

```yaml
users:
- name: signer
  user:
    exec:                    # the source: what rotates
      apiVersion: client.authentication.k8s.io/v1
      command: cluster-credential-helper
      args: [--cluster, my-cluster]
      provideClusterInfo: true
    httpSignature:           # the shape: what does not
      apiVersion: client.authentication.k8s.io/v1alpha1
      algorithm: hmac-sha256
      keyDerivation: {...}
      signedHeaders:
      - name: X-Session-Token
      ttl: 30s
```

#### The line between the two fields

One test decides where every value goes: **does it rotate, or must it be atomic
with something that rotates?** If yes it comes from the plugin, because the
producer is the only party that can keep it correct. If no it stays in the
kubeconfig, where it is a deployment fact an operator states and a reader can
audit.

| Value | Rotates | Home |
| --- | --- | --- |
| algorithm, ladder, covered header names, ttl | no | kubeconfig |
| key ID, key material, stage, header values, expiry | yes | plugin |

The stage is the interesting case. A rung and the stage describing it are one fact: a rung with the
wrong stage is simply a wrong key. So it travels with the material and never appears in
configuration.

`algorithm` staying in the kubeconfig is load-bearing rather than cosmetic.  Whether this identity
uses `hmac-sha256` decides whether the server holds material that can forge requests attributable to
this client, and an operator should declare that rather than learn it from whatever a plugin
returned. The cost is that a plugin cannot migrate a fleet from HMAC to an asymmetric key without a
kubeconfig change, which is the kind of change that should require touching configuration.

#### The plugin is told what to produce

`spec.httpSignature` carries the algorithm, the ladder, and the covered header names. This is not a
convenience:

- A plugin handing back an intermediate rung has to derive that rung, and it cannot without the
  chain.
- The covered header check is bidirectional. The client refuses a credential that sets a header it
  does not cover, because the value would travel uncovered. It also refuses one that omits a header it
  does cover. Without the names, a plugin has to guess a contract the client holds it to.

None of it is secret, so unlike cluster information it is not gated behind `provideClusterInfo`:
without it the plugin cannot satisfy the contract at all.

#### What the plugin may not answer

The client rejects a status carrying signing material alongside a token or a certificate. It would
send both, the server would authenticate whichever its authenticator chain reached first, and the
resulting identity would depend on server ordering rather than on this configuration. The client also
rejects material it did not ask for, and a missing answer when it requires one. A plugin that has
misread the request should hear about it rather than have its answer ignored in silence.

#### What this buys, and what it costs

What it inherits is everything the exec plugin already has: the versioned protocol, the allowlist
policy, install hints, interactive handling, metrics, per-cluster information, and per-configuration
caching. A program invoked this way is a credential plugin that existing tooling recognizes, rather
than a Kubernetes-specific subprocess convention.

Three costs are real and recorded rather than solved:

- **An alpha field in a GA API.** `clientauthentication/v1` has been GA since 1.22, and
  `status.httpSignature` is alpha. Adding optional fields to a GA API is allowed and there is
  precedent, `Cluster.DisableCompression` landed in 2022, but it is a permanent commitment to a
  shape an alpha feature chose. It is gated by the `ClientsAllowHTTPSignature` client-go feature
  gate, off by default, following `ClientsAllowCBOR`. Version skew is a clear error rather than a
  silent one: the exec decoder is not strict, so an old client-go drops the field and then reports
  that the plugin returned no token or cert/key pair.
- **Configuration errors move to the first request.** The bespoke command ran when the client was
  built, so a broken credential failed there. An exec plugin deliberately does not run at transport
  construction, because it may be interactive, so a plugin that returns unusable material now fails
  on the first request. That is how every exec plugin behaves, and consistency with the mechanism
  beats consistency with the thing being deleted.
- **`httpSignature` and `exec` are peer fields**, which reads oddly for one feature. The alternative
  that removes the wart, keeping the source nested under `httpSignature` but making it speak the
  standard protocol, was considered and for now rejected: it keeps a program that no tooling
  recognizes as a credential plugin, which is the thing this change is for. The rule that replaced
  the old exclusivity check is stricter and simpler than what it replaced: exactly one credential
  source among `keyFile`, `credentialFile`, and `exec`.

### D11: keys come from a resolver on a socket, which also records nonces

An `httpSignature` entry names a resolver process on a local Unix domain socket, in the shape the KMS
provider and the external JWT signer already use: `k8s.io/externalhttpsig`, a staging module with no
`k8s.io` dependencies so a resolver author imports it without pulling `k8s.io/apiserver`. Three unary
RPCs.

**The division of labor is the decision.** The API server does all of the cryptography: it builds the
signature base, verifies, enforces the covered component set, and checks the body digest. The resolver
holds key material and nonce state and never sees a request. A resolver returns data, never a verifier
and never a verdict, so no resolver has to get the cryptography right and none can get it wrong.

`Metadata`, once at startup and then polled, carries what is not per key: the derivation ladder, and
any narrowing of accepted signature age. It doubles as the health probe, which is what makes reload
health-gating possible; without it a new generation would go live blind. A resolver that cannot answer
it fails the server's start rather than every signed request afterwards.

`ResolveKey` carries the key ID unparsed, the algorithm, the signature's `created`, and the values of
configured relayed headers. Four decisions in that list:

- **The key ID is not parsed by the API server**, beyond taking the segment before the first slash to
  choose a resolver. A derived key's key ID carries its claimed scope, and decomposing it needs the
  ladder. D8 recorded a constraint that a lookup cannot have the ladder before it has chosen a key;
  that dissolves by giving the whole key ID to the party that holds the ladder.
- **The resolver's stated algorithm is authoritative and the signature's is advisory.** The verifier is
  built from the resolver's value, and the signing library rejects a signature whose own `alg`
  disagrees with the verifier's. Without that, a peer could claim `hmac-sha256` for a key whose material
  is a public key and have the public key used as a shared secret. A resolver that echoed the request's
  algorithm rather than stating its key's own would reopen it, which is why the field is documented as
  the thing it is rather than as a convenience.
- **Relayed headers are named in the API server's configuration, never requested by the resolver.** A
  named header present but not covered by the signature rejects the request before any lookup, so an
  intermediary cannot inject a value that selects a different key. The covered set is readable from
  `Signature-Input` without verifying anything, which is what makes that check available before there
  is a key to verify with. Covered is not verified: at lookup time the value is still a claim.
  Headers with their own configuration path — authorization, the signature fields, `Content-Digest`,
  the impersonation headers — cannot be relayed, because relaying is not a way around those paths.
- **Not-found is a gRPC status, not a field.** A response describing the absence of a key is a shape
  where a caller that mishandles one field authenticates a request it should have rejected.

**What a resolver returns is a claim, not a conclusion.** The identity is validated on arrival: a
non-empty username, and nothing under the `system:` prefix in the username or any group. This is the
same rule the static key list enforced, and it matters more here, not less. Whoever holds the
resolver's socket can vend an identity to the cluster, and a resolver able to claim a name Kubernetes
issues would be a strictly larger grant than one able to vend a key. CEL user-validation rules, which
section 6 argues for, are not built: they need the aggregate-cost problem this document records for the
JWT path solved first.

**Three material shapes, and what each bounds.** A PKIX DER public key; a whole shared secret; or a
rung of the ladder with its position on it, from which the API server derives per request using the
signature's `created`. PEM is not accepted for the public key, because a PEM block type is a second
statement of the key kind and a second thing to disagree with the stated algorithm. The rung is
`keyscope.Key.Derive`'s output verbatim — the library already calls that "the hand-off operation" — and
it is the shape worth preferring: a compromise of the API server's memory yields only what the rung's
scope covers, and for a rung past a date step, only until that date rolls.

**Caching, and why every property of it is forced.** The cache key is chosen by the peer, so the number
of distinct entries the API server could be asked to hold is not bounded by anything in the cluster.
Bounded size, a bounded negative-entry lifetime, and collapsing concurrent duplicates all follow from
that one fact. Two further points:

- The cache key covers the relayed header values, not the key ID alone. Keying on the key ID would
  serve a cached answer for a rotated session token, which is the case relayed headers exist for, so
  the rotation would be silently ignored. Values are hashed rather than concatenated, because a relayed
  value can be a secret held for the entry's lifetime, and because concatenating peer-chosen strings
  makes two distinct questions collide when one contains the separator.
- Resolved keys and unserved key IDs are two caches, so a flood of unknown key IDs cannot evict working
  keys. Eviction from either costs one lookup and never an authentication failure, which is what makes
  a bound safe to impose at all.

This is the third time the cardinality argument appears: D5 made it for nonce buckets, D8 made it for
not caching derived keys, and it makes it here. What is deliberately not copied is
`cached_token_authenticator`, whose cache is unbounded and striped for lock contention rather than for
size.

**Ordered resolution with an optional prefix selector.** Resolvers are consulted in configuration
order; one that does not serve a key ID is asked before the next is tried. `resolver.keyIDPrefixes` narrows which
key IDs reach an entry, turning an unknown key ID's cost from one call per resolver into one call or
none. Validation rejects two entries claiming one prefix, because which resolver serves a key ID would
then depend on list order and a key moved between resolvers would change identity silently. It also
rejects more than one entry with no prefixes, because two catch-alls fan out without saying so. Q6
records what is still unbounded here.

**The trust boundary is the socket's permissions.** No TLS, and the peer is not authenticated, which is
the KMS and external JWT model. It is worth stating rather than inheriting quietly, because relayed
headers mean this socket now carries client secrets, which neither of those two does.

**Health is a metric, not a readiness gate.** A resolver being down affects only requests signed by its
keys. Putting it in `/readyz` would remove the whole API server from service, a blast radius larger
than the failure. `apiserver_httpsig_resolver_metadata_success_timestamp` and
`apiserver_httpsig_resolver_request_total{code}` carry the signal, and the aggregated check exists and
is used to gate reload.

### D12: the seam is a data type, and what it deleted

Section 6 said both remaining paths need the same thing first: key resolution has to become an
interface, because that is what lets a CA and a resolver be two implementations rather than two branches
through one function. That is `KeyResolver` in `resolver.go`, and the shape it took is worth recording
because the obvious shape was worse.

It returns **data**, not a verifier. A `ResolvedKey` carries an algorithm, one of three material forms,
an identity, and two durations. Compiling it into a verifier happens in one function that also validates
it, so an answer that reaches the cache is one that has already been checked, and the x509-assertion path
can supply the same data type without touching any of the cryptography.

Deleted rather than adapted:

- `HTTPSignatureKey`, `HTTPSignatureUser`, `HTTPSignatureKeyDerivation`,
  `HTTPSignatureKeyDerivationStep`, and `HTTPSignatureKeyStage` from all four API versions. The
  derivation types remain in the client's kubeconfig and in the exec credential protocol, where a
  client still states the ladder it derives through.
- `maxNoncesPerKey`, with the local nonce cache (D5).
- `maxHTTPSignatureKeys`, the 64-key cap. Its stated reason was that every key got a nonce bucket,
  which is no longer true.
- `httpsig.ValidateKey`, which existed so configuration validation could reject unusable key material
  without a second copy of the rules. With no key material in the file, validation no longer touches
  the filesystem and no longer imports the verifier package.
- The PEM public key parser, replaced by PKIX DER.

One thing deliberately **not** reused: `transporthttpsig.DerivationFrom`, which converts a ladder by
round-tripping JSON and whose contract is "any type whose JSON encoding matches the ladder schema". A
protobuf-generated type is not one. `protoc-gen-go` writes the proto field name into the Go json tag, so
`secret_prefix` would not be read as `secretPrefix` and the prefix would be dropped with no error — a
conversion that silently drops a derivation input produces a key nobody can explain. The proto ladder is
converted field by field instead, guarded by a test that varies every field and asserts the digest
changes, plus a field count that fails if the proto grows one. That guard was checked by breaking the
converter and watching it fail.

### D13: the demo's resolver runs on the host, and starts before the cluster

Two decisions in the kind demo, both settled by testing rather than by argument, and both worth
recording because the obvious alternatives fail in ways that are hard to read.

**It runs on the host, not on the node.** The socket lives in a directory bind mounted into the node
and, through a kubeadm patch, into the API server pod. Two facts make that work, and both were checked
rather than assumed: a unix socket is reachable across a bind mount, and it is reachable across a
*read-only* one, because connecting is a permission check on the inode rather than a write to the
filesystem. So the mount is read only, which costs nothing and means nothing in the node can unlink the
socket and listen in the resolver's place.

The socket is mode 0600 owned by the user who ran the demo. kube-apiserver in a kind node runs as root
with no `runAsUser`, and root has `CAP_DAC_OVERRIDE`, so it connects; a non-root process that does not
own the socket gets `permission denied`. Both halves were verified against the real node image before
the design was committed to, because the alternative was a permissions puzzle discovered during a
cluster bring-up.

The honest cost: a resolver on the host is not what a deployment looks like. The alternatives were a
static pod, which needs a container image on the node that can execute the binary and therefore a
version-dependent image reference, and a process started on the node with `docker exec`, which cannot
be running before `kubeadm init` needs it. Neither cost buys anything the demo is trying to show.

**It starts before the cluster.** kube-apiserver fetches each resolver's metadata while building its
authenticator and refuses to start if it cannot. Started afterwards, the API server crash-loops through
`kubeadm init` and the cluster never comes up. This is the fail-closed behavior working as intended, and
it makes resolver-before-cluster an ordering the harness has to get right rather than a preference.

It also rules out the arrangement that first looked most elegant: bring the cluster up with no
`httpSignature` entries, start the resolver, then add the section and let reload apply it. That would
have demonstrated reload as a side effect, but it makes the demo's happy path depend on two features
instead of one, and a failure in either presents identically.

**What the demo now shows that the static list could not.** Editing the resolver's key file revokes a
key with no restart at either end, and the delay is the `cacheTTL` the file states, which makes the
revocation window a number an operator chose. Stopping the resolver refuses every signed request,
including for keys the API server has cached, because the nonce can no longer be recorded. Starting it
again recovers within seconds as gRPC reconnects, with no API server restart, which is worth knowing
because the opposite would make a resolver restart an outage.

### D14: three reload failure modes, observed rather than reasoned about

The kind demo produced three distinct reload failures by accident, and all three behaved correctly.
Recorded because reload is the feature most likely to be wrong in a way nobody notices, and because
these are the cases a unit test would not have thought to construct.

**An empty file.** A fixture regeneration truncated the authentication configuration for a moment. The
API server logged `failed to load authentication config: empty config data`, kept the configuration it
had, and carried on. Requests never noticed.

**A resolver that was not there.** A reload fired while the resolver was stopped, and the health gate
refused the swap: `failed to update authentication config: fetching metadata from resolver ... connect:
no such file or directory`. The old generation kept serving. This is the gate earning its place, and it
is why `Metadata` doubles as a health probe: without it the new generation would have gone live and
every signed request would have failed.

**A field the binary did not have.** A configuration using `nonceHandling` was reloaded by an API server
built before the field existed, and decoding rejected it: `strict decoding error: unknown field
"httpSignature[0].nonceHandling"`. The reload failed, the tracker was updated so it stopped retrying,
and the previous configuration kept serving.

That last one is worth keeping for its own sake, because it settles the rollout question for every field
added to this section. Decoding is strict, so a configuration written for a newer API server fails
loudly on an older one rather than being silently ignored. For `nonceHandling` specifically that is the
difference between an operator learning their setting did not apply and a cluster quietly running with
replay protection in the opposite state from the one the file describes.

It also cost an hour of chasing a wrong conclusion, which is the reason it is written down. Setting
`nonceHandling: Ignore` on the live cluster appeared not to work, and the tempting reading was that the
feature was broken. The API server log said otherwise in one line. The binary was two hours older than
the field; nothing was wrong except the thing being tested.

### D15: a certificate can be the assertion instead of a resolver

D11 answers "whose key is this" by asking a resolver process. This is the second
answer, and it is not a fallback: a client carries its leaf certificate, the server
validates it against configured trust anchors, and CEL expressions map the
certificate to an identity.

The two are alternatives because what the server depends on at request time differs,
and neither dependency dominates. A resolver gives revocation on the resolver's own
schedule and nonce records shared across every API server, and costs a process that
has to be reachable for anything to authenticate. A certificate costs nothing at
request time and holds nothing per client, and gives up both: a certificate's
lifetime is the withdrawal window, and there is no shared place to record a nonce, so
`maxAge` plus `maxClockSkew` is the replay window. That asymmetry is stated in the API
rather than left to be discovered, which is why `nonceHandling` sits inside `resolver`
rather than on the authenticator: on a certificate authenticator there is no such
field to set (D16).

**Key resolution is an interface**, which is what lets these be peers. A resolver
takes a signature and returns a verifier plus a way to name the signer. The socket
resolver and the certificate bundle are two implementations of it, and everything
around them, the coverage rules, the digest check, the age window, is shared.

Two rules keep the choice from depending on configuration order. A keyid beginning
`x509-sha256:` never reaches a socket resolver, whatever key ID prefixes it was
configured with. Without that, a resolver configured with no prefixes is asked about
every keyid including a certificate's, and a resolver willing to answer for one could
take over an identity the certificate authority is supposed to name. The reservation
used to be enforced against entries in the static key list; it lives in the resolver
now, because a resolver's key IDs are not in the file to be checked.

And a certificate selects exactly one authenticator, by the trust anchor its
`authorityKeyIdentifier` names (D17).

#### The keyid is the binding, not header coverage

D2 left open which coverage class the assertion header belongs to, and said the case
for the protected class had to be made rather than assumed. The answer is that
neither class is the mechanism.

A signature's parameters are always the last line of its signature base. So `keyid`
is covered by every signature that carries one, with no coverage rule involved.
Requiring `keyid` to be `x509-sha256:` followed by the leaf's digest, and recomputing
that digest from the bytes received, binds the certificate to the signature through a
value already covered.

Three things fall out of that:

- The discriminator sits inside the signature base. Which kind of authenticator
  handles a signature is stated by the signature, not inferred from whether an
  unsigned header happens to be present. Configuration validation refuses a
  configured key named with the prefix, so the two cannot collide.
- A substituted certificate is refused by name. Without the digest comparison the
  request still fails, because the signature has to verify against the key the
  certificate names, but it fails as a bare signature mismatch. A test confirms
  this by removing the check and observing exactly that error.
- The header is still put in the protected class, which is belt and braces rather
  than the mechanism. It costs a few kilobytes in each signature base and closes
  reasoning nobody should have to redo.

#### Verify before work does not actually invert

The section this replaces said the rule inverts, because the verification key has to
come from the certificate before there is anything to verify with. It does not,
because reading a certificate splits in two:

1. Recompute the leaf's digest and compare it to the keyid. One hash.
2. Parse the leaf and take its public key. One parse, size bounded.
3. Verify the signature. This proves the caller holds the leaf's private key, and
   grants nothing: the certificate is still untrusted.
4. Only then build the chain and evaluate the expressions.

So an unauthenticated caller can cause one hash and one bounded parse. Everything
expensive is behind proof of possession. Only the leaf is read from the request;
intermediates come from configuration, so the chain build is against a fixed pool.

#### Validation runs before mapping

The prerequisite section observed that the JWT authenticator maps before it
validates, and compensates with an AST walk for `email_verified`. This authenticator
validates first, so it needs no such patch. `x509.certificateValidationRules` run
against the certificate, then `x509.claimMappings` produce an identity, then
`userValidationRules`
run against that identity. What an assertion claims is a claim, not a conclusion, and
the user rules are the cluster's only say over what a certificate authority may mint.

#### The certificate is exposed as a declared type, not a claim map

A certificate is not a map of names to values, so `cert` is a declared
`kubernetes.Certificate` rather than the JWT side's `map(string, any)`. Two
consequences worth recording:

The declared type and the runtime value are generated from one table of fields, so a
field cannot be declared without being populated. The SubjectAccessReview types take
the other approach and carry a comment on each half asking the next person to
remember the other.

The environment declares no clock and no request. That is not an omission: it is what
makes an expression's result a pure function of the certificate, and therefore what
makes caching the mapped identity a memo rather than stale state. A test asserts the
absence.

Two things follow from exposing the validity bounds as timestamps rather than as a
precomputed lifetime. A rule can bound a certificate's lifetime itself, with
`cert.notAfter - cert.notBefore <= duration('24h')`, which is the only lever a
verifier has over the withdrawal window. The option of a `maxCertificateLifetime`
field was therefore dropped rather than adopted, because it would be a special case
of an expression that already works.

One hazard found while testing and recorded rather than worked around: the order of a
multi-valued distinguished name attribute does not survive DER encoding. A
multi-valued attribute is an ASN.1 SET, whose members are canonically ordered by
their encoding, so `[zzz, aaa]` reads back as `[aaa, zzz]`. Indexing positionally
into `organization` is a latent bug whose behavior depends on the bytes of the other
values, and `exists()` is the correct idiom. Sorting the list in the CEL value would
hide the fact and disagree with every tool that prints a subject.

#### Extended key usage is not checked

D2's predecessor left this unresolved, and it stays unresolved in the sense that no
registered usage means "may sign detached HTTP messages". Requiring client
authentication would silently enlist every certificate issued for connection
authentication, which its issuer never agreed to. Requiring a new usage would mean
reissuing for everyone.

So the trust anchor bundle is the opt-in, and it must be a bundle issued for this
purpose: pointing it at the cluster's client certificate authority would give every
existing client certificate the ability to sign detached messages that survive a
proxy. A deployment that has minted a usage requires it with a rule, since
`extendedKeyUsages` is exposed.

One mechanical note, because the obvious choice is wrong. Go's `x509.VerifyOptions`
with a nil `KeyUsages` defaults to `ExtKeyUsageServerAuth`, not to "no check", so
`ExtKeyUsageAny` has to be stated.

#### Replay, and one constraint an assertion adds to Q6

D5 says replay protection is unimplemented and the acceptance window is the bound.
That is unchanged here: a certificate is not a configured key, so there was never a
per-key bucket to lift, and `maxAge` bounds replay for both kinds of authenticator
equally.

What an assertion adds is one constraint on Q6, if a store is ever built. Q6 already
requires keying on the nonce together with the identity the signature authenticated
as, rather than on the nonce alone. Under a certificate that identity has to be the
leaf's own digest, and never the trust anchor: anchor-keyed records would put every
client under one authority into a single namespace of client-chosen values, which is
exactly the eviction that turns the store into a replay enabling mechanism.

The cardinality bound Q6 needs is also already solved once here, by the validation
cache below, and for the same reason: entries created only on success cost an
attacker a certificate the authority actually issued.

#### The validation cache, and the bound that is not decoration

Successful validations are memoized, keyed on the digest the server computed over the
presented bytes and never on the keyid the client claimed.

Failures are not cached. A negative cache would be keyed on bytes any caller can
choose, which is unbounded cardinality for anyone who can send a request, and it
would buy nothing: an untrusted certificate is rejected by one chain build. Because
entries are created only on success, occupying one requires a certificate the
configured authority actually issued.

Entry lifetime is the smallest of the configured TTL, the leaf's remaining life, and
the remaining life of every certificate in the validated chain. The chain clamp is
the one that matters: without it a TTL longer than a trust anchor's remaining life
would keep admitting requests after the anchor expired, which is the only case where
the cache would grant something the uncached path refuses. A test confirms it by
removing the clamp.

#### The exec plugin uses the GA fields

D10 records an alpha field in a GA API as a permanent cost. Under a certificate that
cost goes away: the plugin returns `clientCertificateData` and `clientKeyData`, which
have been GA for years.

D10's rule inverts rather than relaxes. It refuses a status carrying signing material
alongside a certificate, because the client would send both and identity would depend
on authenticator ordering. Here the pair serves one purpose, chosen by configuration:
when the client is configured to sign, the certificate and key go to the signer and
never to the TLS configuration. What is refused instead is a status carrying both a
certificate and key material, which asks to sign under two keys at once.

Whether the plugin will return a certificate or key material is not knowable before
it runs, so the algorithm is checked when the answer arrives rather than when the
client is built. That is the first point where both facts exist.

#### Bounding what an untrusted key costs to verify against

The verification key comes from a certificate the server has not yet decided to
trust, so one verification costs whatever the presented key costs. Two facts make
that a lever rather than a detail: `x509.ParseCertificate` does not check the
certificate's own signature, and neither Go's parser nor `crypto/rsa` bounds an RSA
modulus from above. `crypto/rsa` enforces a 1024-bit floor and no ceiling.

So a modulus nobody generated, an odd integer of any width in a certificate signed
by a throwaway key, is admitted and exponentiated against. Measured before the
bound existed:

| modulus | certificate size | verify |
| --- | --- | --- |
| 2048 | 483 B | 165 µs |
| 8192 | 1.3 kB | 2.6 ms |
| 32768 | 4.3 kB | 40 ms |
| 65536 | 8.4 kB | 158 ms |
| 131072 | 16.6 kB | 629 ms |

The 16 kB header cap bounds the parse and does not bound the crypto. So the key is
bounded before a verifier is built: RSA 2048 to 4096, which is what
`PodCertificateRequest` issues, with an odd exponent no larger than 65537; ECDSA on
P-256 or P-384 only; Ed25519. The number of signatures considered per request is
capped for the same reason, since the signing library caps nothing.

#### The cache supplies a key, never a conclusion

A cache hit returns a verification key and a mapped identity, and the signature is
verified against that key exactly as on a miss. This is worth stating because the
optimization that skips it is plausible-looking and its consequence is total:
anyone who has merely observed a certificate, from an intermediary, a log, or a
packet capture, would authenticate as its subject. A test presents a cached
certificate with a signature made by a different key and expects a refusal.

Cached identities are copied on read. The authenticated group adder builds a fresh
`user.Info` rather than appending to this one, but it carries the `Extra` map over
by reference, so a shared cached map would be reachable by anything downstream that
annotated it, and the failure that produces is one request's attributes appearing
on another's identity.

#### A mapping can hand identity selection to the certificate holder

`x509.claimMappings` derives from the certificate, so `groups: cert.subject.organization`
gives whoever can request a certificate the choice of group. With a general-purpose
authority in the bundle, a requester naming `system:masters` in their organization
would receive cluster administrator.

The control is a `userValidationRules` entry, shipped in the canonical example
config and in the kind demo, refusing the `system:` prefix on the username and on
every group. A rule rather than a hardcoded list, because the list would be a third
copy of a guard the static key list and the JWT authenticator already answer
differently, and it is a rule rather than a prefix ban in Go because mapping a
node's certificate to `system:node:<name>` is a legitimate use that a ban would
forbid.

Three names are refused unconditionally, and they are not policy. The server adds
`system:authenticated` or `system:unauthenticated` according to whether
authentication succeeded, and `system:anonymous` is what the anonymous authenticator
asserts about a request that carried no credential. An authenticator claiming one of
those is stating a falsehood rather than making a choice. The check is on the
mapping's evaluated output rather than on its text, since a derivation is invisible
in the text.

**The absence of this guard elsewhere is a separate question, and it is a question
rather than a finding.** The static key list refuses a `system:` username at
configuration time. The JWT authenticator's claim mappings do not. That is one guard
written once and not carried forward as paths were added, so the class is the defect
and hardening one instance makes the drift worse. What is unresolved is which layer
should enforce it: if the answer is the authentication framework, for every
authenticator, then a per-authenticator list here is a third parallel copy, which is
why there is no list here. Changing the JWT authenticator is out of scope and would
break anyone currently mapping to a `system:` name, and whether anyone does is the
fact that decides the fix.

#### What a certificate still does not solve

Revocation. The server holds no per-client state, which is the point, so there is
nothing to delete. The certificate's lifetime is the window, narrowed by the cache
TTL and by whatever lifetime rule a deployment writes. For pods, kube-apiserver caps
issuance at 24 hours.

### D16: each backend's settings live in that backend's struct

D15 made the two ways of resolving a signature peers, but the API kept them in one
flat struct: thirteen fields on `HTTPSignatureAuthenticator`, of which three applied
to both and ten to exactly one. Nine validation rules existed to police that, and
each one carried a paragraph explaining why a field an operator had written down was
not running.

The shape now is `resolver` and `x509` as peer sub-structs, with only `name`,
`maxAge`, `maxClockSkew` and `userValidationRules` left on the parent. Six of those nine
rules are gone, because `nonceHandling`, `keyIDPrefixes`, `relayedHeaders` and
`cache` cannot be written on a certificate authenticator and `claimMappings` and
`certificateValidationRules` cannot be written on a resolver. What used to produce a
validation error now fails to compile, and the test cases that asserted those errors
were deleted rather than rewritten.

Two of the nine survive, and they are not redundant with the sub-structs: two optional
pointer fields cannot express exactly-one, so naming both backends or neither is still
caught by a rule rather than by the compiler. What became structural is configuring a
field for the wrong backend, not selecting the backend.

Two smaller things fell out. `cache` and `certificateCache` were named apart only
because they shared one namespace; in their own structs both are `cache`, and the
paragraph explaining why they were distinct fields went with the rename. And the
runtime's exclusivity check, which existed because the struct permitted a combination
validation happened to catch, is now a two-arm nil switch.

**How the no-behaviour-change claim is checked, and how it was not.** It rests on two
tests written after the fact rather than on reading the diff: one decodes the reference
shape and asserts where every field landed, the other asserts that a field left in its
former place is a named error rather than a silent zero, which is what strict decoding
buys and why no conversion is needed for configurations written against the previous
shape.

Neither existed when the claim was first made, and the gap they cover is exactly the one
that bit: the Go tests were updated with the types and compiled clean, while the
integration suite builds its configuration as YAML text and went on writing `endpoint`
at the authenticator level. Twenty-five tests failed at server start, and it took
fourteen minutes of a run to find out, because nothing checked a field's place in a
document.

**`maxAge` stays on the parent**, though its role differs sharply: with a resolver
recording nonces it is a second line of defence, and with a certificate it is the
entire replay bound. That is one field with one meaning and a consequence that
depends on what is resolving, which is documentation rather than structure. The
tempting sort is by whether a backend can narrow it — a resolver can, a certificate
has nothing to narrow with — but that sorts by backend and would split `maxAge` into
two fields that mean the same thing.

**Rejected: `keyIDPrefixes` common to both.** It looks like the general question "which
authenticator handles this keyid", and both backends do answer exactly that, through
one `handles` method. But an x509 keyid is `x509-sha256:` followed by a digest of the
certificate, so it carries no operator-chosen namespace for a prefix to match, and
two certificate authenticators see identically shaped keyids. That is why they are
disambiguated by trust anchor uniqueness instead. The motivation does not carry over
either: prefixes exist to bound socket calls from an unauthenticated caller, and
selecting a certificate authenticator costs a string comparison. Hoisting the field
would have given an operator something to write that could never do anything, which
is worse than a rule that rejects it.

There is a version that would work: change the keyid form to
`<prefix>/x509-sha256:<digest>`. It buys prefix dispatch for certificates at the cost
of a wire format change and a keyid that is no longer purely content-derived, and
anchor uniqueness already provides determinism for nothing.

#### Clock skew is the server's own, so it moved up a level

`tolerance` was per authenticator and is now `maxClockSkew` on the section. The test
that decides this is whether the field has one true value per process. It does: a
verifier cannot measure a client's clock, so what is being set is a risk budget, and
the budget's justification is this server's own time synchronisation. Two
authenticators holding different values would be two answers to one question.

The argument the other way is not silly and is worth recording rather than skipping.
Skew is pairwise, so one could hold that the budget is a property of the client
population: resolver-backed clients being well-managed workloads while certificate
clients are edge devices with unreliable NTP is not a fantasy. It is rejected because
the server has no way to tell those populations apart at the point the comparison is
made, and picking a number per population would be asserting knowledge it does not
have.

The rename carries the reason. Nobody reads a field called `maxClockSkew` and wonders
whether it should be per authenticator, which is the naming and the placement agreeing.

**Rejected: collapsing `maxAge` and `maxClockSkew` into one window.** The two are
added together in one of the three time comparisons, which makes them look like one
value stated twice. They are not. Skew appears in all three comparisons because it is
grace on every clock reading; `maxAge` appears in one because it is a lifetime. Using
the sum everywhere would extend honouring an explicit `expires` by `maxAge`, and would
let a client pre-mint a signature `maxAge` into the future and hold it, which the
future-skew check exists to prevent. The only collapse that preserves behaviour keeps
skew in two of the comparisons and the sum in the third, which is a rename rather than
a simplification.

The resolver protocol is the second reason. A resolver may narrow `maxAge`, per
resolver or per key, and there is no field with which it can narrow skew. A single
field would have no coherent narrowing semantics, and honouring a narrowing on it
would let a backend shrink an allowance for a clock it knows nothing about.

Skew stays in the staleness comparison, where it reads like double-counting and is
not: the future bound constrains `created` from above only, so the staleness bound
needs its own grace for a signer whose clock is behind.

### D17: a certificate selects one authenticator by its issuer's key identifier

Every certificate authenticator used to claim every certificate-form keyid, and the
chain build was what told them apart: "the first whose anchors validate the
certificate wins". Selection was therefore emergent from failure rather than stated.

With N certificate authenticators configured, one request paid for N header reads, N
digests, N certificate parses, N signature verifications and N chain builds, all but
one of them failing. The signature verifications all succeeded, since it is the same
leaf key and the same signature every time; the chain build was the first step in the
pipeline that could distinguish them, and it was the last to run.

A leaf's `authorityKeyIdentifier` names the `subjectKeyIdentifier` of whatever issued
it. Indexing every certificate in each authenticator's bundle by SKI at load turns
selection into one map lookup. The leaf is parsed once per request, before any
authenticator is chosen, which is what makes the cost independent of how many are
configured. Anchor uniqueness is now checked by SKI collision rather than by
comparing DER, which is also stricter: two authenticators holding differently encoded
certificates for one authority key used to pass, and they are one trust decision.

**Both are required, and the RFC 5280 exemption does not reach either.** An anchor
without a `subjectKeyIdentifier` is refused at load, and a presented leaf without an
`authorityKeyIdentifier` is refused at request. §4.2.1.2 requires SKI on every
conforming certificate authority certificate and grants no exception. §4.2.1.1
requires AKI on every certificate a conforming issuer produces, excepting a
self-signed one, and this only ever reads the AKI of a leaf, which is not
self-signed. So the exemption covers exactly the case that is never consulted: a
self-signed root's own AKI. What is excluded is a non-conforming issuer, and the
alternative was a fallback to trying every authenticator, which would have kept the
fan-out for their sake.

**Rejected: a fast path with a fallback.** AKI selects when present, otherwise try
all. It keeps the cost win and gives up the rest, because the fallback still needs
the outcome buffering below and a second dispatch path to test. Requiring the
extension is the version that deletes something.

**Rejected: checking the AKI again against the built chain.** This looked necessary
while the AKI was described as unverified input that chooses an authenticator. The
property that makes it unnecessary is better stated positively:

> the trust decision is the chain build against exactly one operator-configured
> bundle, and bundles are disjoint, so at most one authenticator can ever validate a
> given leaf and misrouting only ever fails closed.

The first draft of this argument leaned on a leaf's AKI naming its real issuer, which
is what a conforming issuer produces. That premise is worthless here, because the
party that chose the certificate is the party being authenticated. The invariant above
holds for any leaf, conforming or not: a forged AKI reaches an authenticator whose
anchors cannot verify the leaf's signature, and reaching a second authenticator that
would accept it requires that authenticator's bundle to already trust the real issuer,
which is the operator having said so.

So the deletion rests on disjointness, which is enforced twice, at configuration
validation and at construction, and on two things rather than one: no two
authenticators may hold anchors with the same subjectKeyIdentifier, and none may hold
anchors with the same public key. The second is not redundant. A subjectKeyIdentifier
is whatever the issuer stamped, so one authority key can be certified twice under two
different identifiers; both bundles would then validate the same certificate, and
which authenticator's rules ran would be decided by whichever identifier the authority
put in the leaf rather than by the operator.

Identity never depends on which chain was built. The expression environment is the
leaf alone, and the built chain is read only to clamp the validation cache's lifetime,
so chain selection cannot change what a certificate authenticates as.

**The bundle must hold the direct issuer, not only the root.** Intermediates are never
read from the request, so a two-tier authority already required both certificates in
the bundle to build a chain at all. What changed is the symptom: a missing intermediate
is now reported as an unknown issuer at dispatch rather than as a chain failure, since
the leaf's AKI names the intermediate. That is stated in the API documentation in those
words, because two-tier is the ordinary case and the new error would otherwise send a
reader looking at the wrong thing.

#### Dispatch and refusal became different facts

The outcome counter used to buffer every authenticator's verdict and discard the lot
on success. Its comment said why: recording them as they happened "would make a
correct configuration report a rejection on every request, which is a metric nobody
could read". That was the fan-out above, plus a resolver saying it does not serve a
keyid, both recorded as refusals.

They are not refusals. An authenticator that was never asked, or that was asked and
said the keyid is not its, has decided nothing. With certificates dispatching to one
authenticator and `ErrKeyNotFound` treated as what it is, every remaining outcome is a
decision by an authenticator that owned the credential, so it is recorded when it
happens and the buffering is gone.

What that would have lost is visibility into requests no authenticator claimed, which
went from being one authenticator's `rejected_identity` to being counted nowhere. So
those get their own counter, `apiserver_httpsig_unclaimed_signatures_total`.

It has no authenticator label, and that is the reason it is a second counter rather
than a sentinel value on the existing one. A sentinel would be a lie in the label
dimension: every `sum by (authenticator)` would grow a permanent authenticator that
does not exist. The two also measure different stages, dispatch and verification.

Its reasons partition by who has to act, because that is what the label is read for:

| reason | who acts | what happened |
| --- | --- | --- |
| `unparseable_signature` | client | the signature fields were present and unreadable, or there were too many |
| `unknown_keyid` | operator | no resolver's prefixes admitted the keyid, so nothing was asked |
| `unserved_keyid` | client | a resolver was asked and answered that it does not serve it |
| `unreadable_certificate` | client | the header was absent, duplicated, oversized, not a certificate, or not usable for signing |
| `certificate_without_authority_key_id` | client | a well-formed certificate this server cannot route |
| `unknown_certificate_issuer` | operator | no bundle holds the trust anchor the certificate names |

`unknown_keyid` and `unserved_keyid` were one value at first. They send an operator to
different places, this server's configuration file against the resolver's key
inventory, so they are two.

The `unparseable_signature` and malformed-certificate cases were previously counted
nowhere at all, which is a gap this counter closes rather than creates: attributing
only the dispatch misses this change introduced would have been half a fix.

No reason carries a value a peer chooses, so none is a cardinality risk. That leaves
`unknown_certificate_issuer` unable to say *which* authority is missing, which is the
one thing an operator needs to fix it, so the key identifier is in the error message
instead.

#### One mechanism for what an authenticator may claim

The `system:` prefix was refused two different ways. On the resolver path it was
banned in Go, unconditionally. On the certificate path the same invariant was a
`userValidationRules` expression an operator writes, and `userValidationRules` was
*rejected* on a resolver authenticator. So the concern had two mechanisms and the
configurable one was refused on the side that used the hardcoded one.

Both paths now use the rule. `userValidationRules` applies whichever backend
produced the identity, the prefix ban in `validateResolvedUser` is gone, and the
three names the server asserts itself are refused on both paths instead of only on
the certificate path. What stays resolver-specific in `validateResolvedUser` is
protocol hygiene, an empty username or group name, which is a malformed answer
rather than a policy question.

The rules are evaluated after the signature verifies, matching the certificate path,
so an unauthenticated caller cannot drive CEL. They run before the nonce is
recorded: a request refused for its identity that had already burned a nonce would
fail differently on a retry, which reads as a flake rather than a rejection. They
therefore run per accepted request rather than once per cached key. The certificate
path caches its mapped identity because chain building is expensive; nothing here is.

**This loosens the resolver default and that is deliberate.** A resolver-backed
authenticator with no rules stated can now claim `system:masters`, where before it
could not. Three shapes were considered:

1. Symmetric, with the guidance in prose. Chosen.
2. A built-in default rule applied when `userValidationRules` is unset. It preserves
   safe-by-omission, but an operator who then writes one narrow rule silently loses
   the prefix ban, which is a worse footgun than the thing it fixes.
3. An unconditional ban on both paths, additive to the rules. It forbids mapping a
   node's certificate to `system:node:<name>`, which is a documented legitimate use.

The reason (1) is a correction rather than a concession is where the trust boundary
sits. The resolver's socket is documented as the whole trust boundary: nothing
authenticates the peer at either end, so whoever can serve on it can vend an
identity. A hardcoded ban there was defending against a *buggy* resolver, not a
hostile one, and a hostile one was never in scope. The certificate population is
broader and less controlled, which is why the operator's say is the mechanism there,
and it is the right mechanism for a resolver for the same reason.

What keeps the loosening from being silent is that the reference configuration and
the demo now both state the rule, and the example test requires it on every
authenticator rather than only on certificate ones. An operator copying either gets
it.

**Reviewed against the sibling authenticator, which settles it.** The JWT
authenticator in this same `AuthenticationConfiguration` has no hardcoded `system:`
bound of any kind, and its `userValidationRules` documentation says what this one now
says: the rules are where an invariant such as refusing the prefix belongs. So
symmetric-prose-only is consistent with the object this field lives in, and adding a
per-authenticator ban here would have been the divergence.

It would also have contradicted a decision recorded above: the guard exists on the
static key list and not on the JWT authenticator, the class is the defect rather than
any one instance, and what is unresolved is which layer should enforce it. A third
parallel copy is what that section declined, and it is what a `system:masters` ban
here would have been.


## 5. Open questions

### Q1: which components survive a conforming intermediary

Motivation 3 is authentication that survives a TLS-terminating intermediary.  The floor covers
`@authority`, `@path`, and `@query`, which are exactly what layer 7 intermediaries rewrite: host
rewriting, path prefix stripping, query manipulation, body recompression against the content digest.
Schemes that sign the host header survive only where the intermediaries in front of them were built
to preserve it. Ingress controllers, application load balancers, and `kubectl proxy` were not.

Either `@authority` comes out of the mandatory floor, or the KEP specifies what an intermediary must
preserve and accepts that existing ones may not. The library already provides the deployment escape
hatch: `Scheme` and `Authority` overrides in the verify policy state the external values the client
signed, rather than consulting untrusted `X-Forwarded-*` headers.

This has to be settled before the verifier is finished. If the load-bearing motivation is broken by
the floor in the deployments it targets, that gets found in review and it takes the framing with it.

### Q2: aggregated API servers

An extension API server behind the aggregation layer never sees the client's signature.
kube-apiserver authenticates the request, then re-originates it to the extension server with its own
client certificate and `X-Remote-User` headers. This composes correctly, and it also means the
properties above stop at kube-apiserver. The KEP has to say so rather than let a reader assume
end-to-end coverage.

Future work could support resigning the request to an aggregate using a client's derived HMAC key or
an API server's own identity. The same goes for validation, mutation, and conversion webhooks.

### Q3: a third-party dependency in client-go

`k8s.io/client-go` vendoring `github.com/micahhausler/httpsig` and `github.com/micahhausler/sfv` is
a review question independent of the design. Options: donate the libraries to `kubernetes-sigs`,
reimplement in tree, or argue for the external dependency. Not a PoC blocker; it is a KEP blocker.
I'm open to any outcome.

### Q4: remote key lookup, which the static list stood in for

**Answered. See D11 and D12.** This section previously listed five design questions; four are settled
and one changed shape.

- *Who serves it.* A process on a local Unix socket, following the KMS provider and the external JWT
  signer rather than the token authentication webhook. Not a cluster object read through an informer,
  which would have made authentication depend on the API server's own storage being available.
- *What the response is keyed on.* The key ID, the algorithm, the signature's `created` timestamp, and
  the values of headers the configuration names. Not the whole request. Naming the headers in the API
  server's own configuration is what keeps this from being the session token pattern this document
  rejects: a resolver cannot ask for more of the request than an administrator wrote down.
- *How caching and revocation interact.* The resolver states a duration per answer and the
  configuration caps it, so the revocation window is a number an operator can read. Zero means do not
  cache, which is the correct answer when the answer depended on a relayed value that rotates.
- *Failure behavior.* A resolver that fails takes down only the keys it serves. Another resolver may
  still answer for the same key ID, and a lookup failure is not remembered, because caching it would
  extend an outage past its end. Absence *is* remembered, briefly, because a peer that sends one
  unknown key ID usually sends it again.
- *Whether the API server derives at all.* Both. A resolver may hand back a whole secret, or a rung
  with its position on the ladder, and the API server folds the remaining steps per request. The
  ladder left the API server's configuration, as this section predicted it might, and now comes from
  the resolver's `Metadata`.

One thing this section got wrong: it framed the response as carrying a validity period and treated the
identity as the simple part. The identity is the part that needed rules. A resolver holds key material;
letting it claim a name Kubernetes issues would be a strictly larger grant than vending a key. See D11.

### Q5: recovering the ladder drift check as an operator can use it

**Partly answered.** The digest is now a metric label,
`apiserver_httpsig_resolver_key_derivation_info{resolver, sha256}`, alongside the log line it already
had. An operator compares one metric read against the digest a client logs, rather than grepping two
processes' logs. It is a label rather than a value because the operation is comparing it to another
party's, which a label supports and a float does not, and the series for a resolver is reset before the
new one is published so a ladder that changed leaves one series rather than two.

The digest is computed by the shared helper both sides use, not a second implementation, and a test
asserts that. A digest computed a second way would make the comparison meaningless while looking like
it worked.

The pressure on this got higher, not lower, and that is worth naming. Before, both copies of the ladder
were written by the same operator into two files. Now the server's copy comes from the identity system
and the client's stays hand-authored in a kubeconfig, so the two have different owners and drift is
*more* likely. The count of places the fact is stated did not change; who states them did.

Still not built, and still the better fix: putting the client's digest on the wire, so the verifier can
answer "ladder mismatch" rather than "signature does not match". It costs a covered component on every
request and puts an implementation detail into the protocol, so it needs the argument made properly
rather than assumed.

### Q6: what bounds resolver calls from an unauthenticated caller

Not answered, and the sharpest remaining question.

A key lookup happens before any signature has verified, because verifying needs the key. So an
unauthenticated caller drives a network call. Three things bound it today and none of them is a limit
on the rate:

- The key ID is length-capped before it becomes a cache key or a resolver argument.
- Signature age is checked before the lookup, so an ancient or future `created` costs nothing.
- Concurrent lookups for one cache key collapse to one call, and absence is remembered briefly, so a
  peer repeating one unknown key ID costs one call rather than one per request.

What is not bounded is a caller cycling through *distinct* key IDs. Each one is a cache miss, a
singleflight group of one, and a resolver call. `maxKeyIDPrefixes` narrows which resolvers see it and
`resolver.keyIDPrefixes` can reduce the fan-out to one, but nothing caps the rate.

Two places could hold the limit and it is not obvious which. The resolver is the party that knows its
own capacity, and it is already reachable only over a socket an administrator controls. The API server
has priority and fairness in front of every request, which bounds concurrency but is scoped to
resources rather than to authenticators. Adding a third limiter inside the authenticator would be a
knob whose right value nobody can state, which is the argument for not adding it yet and for measuring
first: `apiserver_httpsig_resolver_request_total` and `apiserver_httpsig_key_cache_lookup_total` are
what would say whether it is a real problem or a predicted one.

This is the "verify before work inverts" concern section 6 records against path B, arriving as a
concrete gap rather than a prediction.

### Q7: whether replay gets narrowed below the acceptance window

**Answered, and the answer was the first option.** See D5 and D11. This asked whether the fleet should
keep shared state on the request path or state non-replayability as a non-goal, and called the second
the honest default. The resolver's `ConsumeNonce` is the first: shared state, on the authentication path
of every accepted request, with its availability folded into the API server's for the keys it serves.

What changed the answer was that the store stopped being something Kubernetes would have to build. A
resolver already has to exist to answer for a key, it is already on the authentication path, and it is
already the one thing in the deployment that sees every API server's traffic. Given that, the marginal
cost of one more RPC to it is small, where the cost of introducing a store for this alone would not have
been. The second option is still available and now says so out loud: `nonceHandling: Ignore`.

Both constraints this section put on the store, if it were ever built, survived contact with building
it, and one of them survived in a stronger form:

- *Keyed on the nonce together with an identity, not the nonce alone.* Held: records are per key ID, so
  one client cannot evict another's. The reasoning was about eviction; the sharper version is that the
  same nonce value under two keys is two different facts, so pooling them would let one client's traffic
  reject another's outright rather than merely evict it.
- *Cardinality is peer-driven, so it needs a bound.* Held, and the demo resolver shows what the bound
  has to do: a full store **refuses** rather than evicting, because evicting a record permits the replay
  it was preventing. That is a third appearance of the argument D8 makes about derived keys.

One thing this section assumed that turned out not to hold. It expected the store's availability to
become the API server's availability, full stop. It is narrower than that: a resolver outage rejects
requests bearing the keys that resolver serves, and nothing else. Another resolver's keys keep working,
and so does every other authenticator.

### Q8: which layer bounds what an authenticator may claim, and this feature now depends on it

D16's subsection on the `system:` prefix deleted the last per-authenticator prefix ban in this feature,
on the grounds recorded under D15: the guard existed on the old static key list and not on the JWT
authenticator, the class is the defect rather than any one instance, and a third parallel copy is what
that finding declined. That reasoning holds, and it leaves this feature depending on a decision nobody
has made.

**What this authenticator relies on.** Nothing prevents a configured resolver or certificate authority
from asserting a `system:` identity, including `system:masters`, unless an operator writes a
`userValidationRules` expression refusing it. That matches the JWT authenticator in the same
`AuthenticationConfiguration`, which has no such bound either, so the two are consistent and an
operator's expectation carries between them. It is stated here rather than left as an absence because
promotion review reads this and a missing default is invisible in a diff.

**Where the positions currently differ, which is the part to resolve.** Three authenticators in one
configuration object, three answers:

| | `system:` prefix | the three names the server asserts itself |
| --- | --- | --- |
| static key list (removed) | refused at configuration time | not checked |
| JWT authenticator | not checked | not checked |
| httpSignature, both backends | not checked, left to `userValidationRules` | refused unconditionally |

The floor on the three names is not drift, and the reason matters for whoever resolves this. Those three
are assigned by the authentication machinery itself: two according to whether authentication succeeded,
and one by the anonymous authenticator about a request that carried no credential. A backend claiming one
is a layer confusion rather than a privilege grant, which is a different and stronger justification than
the `system:masters` ban had, and it is why the floor is unconditional where the prefix is not.

That also answers where it belongs. A check on values the machinery assigns belongs in the machinery,
not in a per-authenticator list, so if the framework grows it this copy goes. What should not happen is
the floor being harmonised away as though it were the same kind of rule as the prefix ban.

Deciding it needs a fact nobody has gathered: whether anyone maps a JWT identity to a `system:` name
today. That is what decides whether the framework can enforce a bound at all without breaking existing
clusters.

## 6. How the two paths were compared

Both paths in this section are now built: path A is D15 and path B is D11. The static key list they
were compared against is gone.

This section is kept as the record of the comparison, because the reason there are two mechanisms
rather than one is not visible from either implementation. Where the detail below reads as
prospective, it predates the implementations, and D11 and D15 are authoritative on what shipped. The
sub-sections that remain genuinely open say so.

Both paths answer the same question: how Kubernetes maps a credential ID to an identity. The static
list in D4 answered it in server configuration, and Q4 says why that did not survive contact with a
real deployment. The two replacements are a signed **assertion** and a **resolver**. An assertion
states who the signer is, and a party the cluster trusts makes it. Either the client carries the
assertion, or the server fetches it from a resolver. The signature then proves one thing only, that
the client holds the key the assertion names.

D9 applies here too. Each path is described by mechanism, and where a path follows something deployed
elsewhere, this section states the shape rather than the vendor.

### Two approaches to identity discovery

Compare them by what the server has to hold. That is what sets the revocation story and the blast
radius, and it is why both shipped rather than one: the two columns do not order.

| Path | The assertion is | Proof of possession is | The server holds | Revocation is |
| --- | --- | --- | --- | --- |
| Static list (deleted) | a key entry in server configuration | a signature verified by the configured public key | every public key, and every shared secret | editing a file, then a restart |
| A. Certificate (D15) | an X.509 certificate in a covered header | a signature by the certificate's key | a CA bundle | certificate expiry, and nothing else |
| B. Remote resolution (D11) | whatever the resolver says | a signature verified by the key the resolver returns | nothing | authoritative, at cache TTL |

One row is missing from the table and is the reason the choice is not a ranking: replay. Path B
records nonces at the resolver, which is a store every API server shares, so replay is closed. Path A
has no such store, so its replay window is the acceptance window. Path A therefore buys a smaller
thing to hold at the cost of a weaker guarantee, and neither dominates.

Two consequences fall out of the table, and both paths inherit them.

**Identity stops coming from configuration.** Once an assertion carries the identity, Kubernetes needs
a way to constrain what an assertion may claim. Both paths ship that constraint: path A through
`userValidationRules` and the `system:` prefix refusal, path B through the same refusal applied to
what a resolver returns.

**Anything keyed per credential loses its bound.** The static list caps the number of credentials the
server will ever see, and an assertion comes with no such list.

### Prerequisite: identity mapping with restrictions

Today the `httpSignature` section states a user name, UID, and groups per key, and refuses a name
starting with `system:`. That is enough to demonstrate signing on both sides. It is not a solution,
because it puts identities in server configuration, which is the thing both paths remove.

The prior art is what the JWT authenticator already has: claim validation rules, claim mappings with
an explicit prefix, extra mappings, and user validation rules, all written as CEL. Three notes on
applying it here.

**A certificate is not a claim map, so the CEL variable needs its own shape.** The JWT side declares
`claims` as `map(string, any)` and `user` as an object with four fields. A certificate needs a
declared object instead: subject common name, organization, organizational unit, the SAN types listed
separately for DNS, URI, and email, issuer, serial, validity bounds, and the leaf thumbprint. URI
SANs matter more than they look. Workload identity schemes put their identifier there, so a mappable
URI SAN is what lets path A interoperate with them. Without one, path A needs a Kubernetes-specific
subject convention.

**Mapping runs before claim validation on the JWT path, and a new authenticator should not inherit
that order.** A mapping expression sees claims that no validation rule has vetted. The JWT
authenticator compensates with a narrow fix. Setting `username.claim: email` gets an automatic
`email_verified` check, and a CEL expression does not. So validation walks the expression AST and
refuses a configuration that reads `claims.email` without also reading `claims.email_verified`
somewhere. That is a per-claim patch for a general ordering problem, and a new authenticator can
validate first instead.

One shared cost, recorded rather than solved. A cost limit bounds each CEL expression per call, and
nothing aggregates cost across the expressions of one authenticator. On the authentication path, with
peer-controlled input, the aggregate is what matters.

### Path A: the certificate is the assertion

Built. See D11. This section previously described it as unbuilt; what it argued for
is what shipped, with two things settled that it left open: which coverage class the
assertion header belongs to, and extended key usage. The third, how an assertion
bounds nonce buckets, was overtaken by D5 dropping nonce tracking altogether.

### Path B: remote resolution returning a key and an identity

The verifier calls a resolver, which returns a key and user information for the key ID the signature
claims. The verifier then checks the signature locally and admits the request only if it verifies. The
cryptography stays in the API server, and only the lookup is remote.

Q4 describes this shape and its open questions. Two refinements from where the design now stands:

**The lookup is keyed on the claimed scope, which makes the key ID parser the right call.** A
signature from a derived key carries its key name followed by each ladder step's value, joined by
slashes, and a resolver that vends per-scope material needs exactly that decomposition. D8 says the
library's parser is deliberately unused today, and names the condition that changes it: the verifier
fetching key material per request rather than reading it from configuration. This is that condition.
D8 also records a constraint, that parsing needs the ladder and a lookup cannot have the ladder before
it has chosen a key, if each key may name a different one. D4 settled on one ladder per section, so
that tension does not arise.

**The response carries an identity, and the cluster must still be able to constrain it.** A resolver
that returns final user information is simple, and it gives the cluster administrator no say: the
resolver could mint any identity, including a privileged one. The identity crosses a trust boundary,
so the user validation rules above apply to it on arrival. What a resolver returns is a claim, not a
conclusion.

This is an interface, not an API. It does not have to be a Kubernetes API type. The argument for
keeping it off the API surface is that it is infrastructure between a cluster and an identity system,
rather than something a cluster user configures. One out-of-tree implementation is a proxy to an
external authentication service that already holds the keys.

### Invariants these paths break

**Q6, a replay store keyed per credential.** Settled for path A in D11, which states the key it would
have to use. Q6 notes that a store narrowing the replay window would
have to be keyed per authenticated identity and bounded. With the static list, both come free: the
configured list caps the number of identities. An assertion lifts that ceiling. Keys then have to be
the credential's own identity, a leaf thumbprint or its equivalent, and never the trust anchor or the
resolver. Keying per anchor puts every client under one CA into one entry, which is the single shared
namespace Q6 says turns such a store into a replay enabling mechanism. A global ceiling on entry count
becomes necessary, which the static list never needed.

**D2, coverage.** Settled in D11: the keyid binds the certificate, so the header's class is redundancy
rather than the mechanism. The argument below is what D11 answers. Coverage protects against
removal for free, and the protected class exists to catch addition. Neither obviously applies here:
substituting a certificate breaks verification anyway, because the signature has to verify against
the key the certificate names, and adding one to a request that carried none is self-defeating for
the same reason. So the case for putting it in the protected class has to be made rather than
assumed, and this is the argument to write before path A ships.

**Verify before work.** Path A is bounded above. Path B is harder, because an unauthenticated caller
drives a network call instead of a local parse, and no size limit bounds a network call.

**D8, the derivation ladder.** The ladder has no role under a certificate. It is what path B is for: a
broker holds the root and vends a rung scoped to one date and one domain. D8 built staged entry for
exactly that, and path B is its only consumer here.

**D10, the exec plugin.** Path A could reuse the GA client certificate and key fields of the exec
credential status, which would remove the one cost D10 records as permanent, an alpha field in a GA
API. One wrinkle. D10 rejects a status carrying signing material alongside a certificate, because the
client would send both and identity would then depend on authenticator ordering. Under path A that
rule inverts rather than relaxes: the pair serves one purpose, chosen by configuration, so when
`httpSignature` is set the plugin's certificate and key go to the signer and never to the TLS
configuration. The client can check that at construction.

### The seam both paths need first

Both paths need the same thing before either can start, and it is not the CA or the resolver.

**Key resolution has to become an interface.** D4 and Q4 record what exists: the verifier holds a
`map[string]*key` populated once at construction, and the lookup is inlined at the call site,
including the fallback that cuts a scoped key ID at the first slash. Extracting that is step one for
both paths, because it is what lets a CA and a resolver be two implementations rather than two
branches through one function.

**The coverage rules are shared less than they look.** `FloorComponents` and `IsProtectedHeader` are
package-level values that both sides read, so a change to either list does reach the server. But
`Components`, the function that assembles the signer's component list, has one caller, the signer.
The verifier states the floor as its required component list and re-implements the presence check in
its own loop. The two agree today. What would diverge in silence is a conditional coverage rule added
inside `Components`, since nothing on the server side calls it, and path A introduces exactly that
kind of rule.

## 7. State of the PoC

Built and covered by tests:

- `AuthInfo.HTTPSignature` in the internal and v1 kubeconfig types, with validation and mutual
  exclusion against the other authentication methods.
- A signing round tripper installed through the `WrapTransport` slot, so impersonation and user
  agent headers are already set when it runs, and the SPDY and WebSocket upgrade paths are covered
  without extra work.
- Credential sources: an exec credential plugin returning key material (D10), a credential document
  on disk, a private key file, and a credential stated directly in `rest.Config`. The file and
  inline forms load once at construction, so a bad configuration fails when the client is built, and
  the files are re-read when they change. The plugin runs on first use and again when its credential
  expires, which is how every exec plugin behaves.
- An exported credential source interface, so an implementation holding a key it cannot export, such
  as one backed by a hardware token, works without changes here. A test proves that with a key held
  by a goroutine and reachable through no field.
- One credential program policy, applied where credential plugins are named, so a plugin that
  returns signing material answers to the same allowlist as one that returns a token.
- Key derivation through a ladder stated as a typed field in each party's configuration (D8), on the
  signing library's `keyscope` package, with staged entry: a client or a server may hold the root
  secret or an intermediate rung.  Signatures from a derived key carry their claimed scope in the
  keyid, and the verifier checks it before any signature math, so a scope or date disagreement is
  named rather than reported as a signature mismatch. The verifier derives per request from the
  signature's `created`.
- The floor and the protected header list as package-level values both sides read, so neither can
  disagree with the other about which headers matter. The signer assembles its component list with
  `Components`; the verifier states the floor as its requirement and checks presence in its own loop.
- An `httpSignature` section in `AuthenticationConfiguration` behind the
  `HTTPSignatureAuthentication` alpha feature gate, with validation, holding a list of named
  authenticators. `authority` and `scheme` sit on the section rather than on each authenticator,
  because they are consumed when a request's signatures are parsed, before any authenticator has
  been selected. No key material and no identity for any client appears in the file (D11, D15).
- Key resolution as an interface, with two implementations: a resolver process on a socket and a
  certificate authority bundle (D11, D15). A signature reaches one of them by its keyid, which is
  covered by every signature, so nothing about the choice depends on an unsigned header or on the
  order the authenticators appear in.
- `k8s.io/externalhttpsig`, a staging module carrying the resolver's proto API: `Metadata`,
  `ResolveKey`, and `ConsumeNonce`. No `k8s.io` dependencies, so a resolver author does not import
  `k8s.io/apiserver` to implement it.
- A gRPC client for it over a Unix socket, with per-call deadlines, a metadata poll that doubles as a
  health probe, and a bounded key cache with a separate bounded negative cache and singleflight on
  both (D11).
- Certificate-asserted identity (D15): `certFile` with `keyFile`, or `credentialBundleFile` for
  the one-file form a pod certificate projected volume writes. The key ID, the algorithm, and the
  credential's expiry are all derived from the certificate, so none of them is configurable. Two
  files are checked for being a pair, because reading them mid-rotation is what produces a
  mismatch, and the error names that rather than the key.
- A `kubernetes.Certificate` CEL type whose declared fields and runtime value are generated from
  one table, with `x509.certificateValidationRules`, `x509.claimMappings`, and
  `userValidationRules` evaluated in that order.
- A validation cache holding successful chain builds and their mapped identities, keyed on the
  digest the server computed, with entry lifetime clamped to the shortest remaining life in the
  validated chain.
- Metrics: an outcome counter per authenticator naming which check refused a signature, resolver
  call latency and status, key and certificate cache hit counters, and a per-resolver nonce-handling
  gauge. Labels come from configuration and from closed sets, so nothing a peer chooses becomes a
  label value.
- Reload of the `httpSignature` section, behind an `atomic.Pointer` read per request, health-gated
  before the swap and torn down after a grace period, so a resolver or a trust anchor can be added,
  removed, or repointed by editing the file. A section absent at startup and added by a reload takes
  effect (D4).
- `e2e/cmd/httpsig-resolver`, a resolver backed by a YAML file: keys nested by algorithm then key ID,
  PEM in the file and PKIX DER on the wire, all three material shapes including a ladder rung, identity
  chosen by a relayed header, reload on file change, and an atomic in-memory nonce store that refuses
  rather than evicting when full. Its socket permissions default to 0600 and world-writable is refused,
  because on Linux write permission on the socket is permission to vend an identity to the cluster.
- `spec.httpSignature` and `status.httpSignature` in `clientauthentication` v1 and v1beta1, behind
  the `ClientsAllowHTTPSignature` client-go feature gate, so a plugin is told what to produce and
  can answer with key material instead of a token.
- An `authenticator.Request` verifier wired into the kube-apiserver authenticator chain ahead of the
  bearer token authenticator, with nonces recorded at the resolver, fail-closed, and only after a
  signature verifies (D5).
- A redaction test over every exported type that can hold key material, in every fmt verb, checking
  for the secret as a string and as the bytes an interface field prints, and requiring the key ID to
  survive so the output stays worth logging (D3).
- Unit tests on both sides, including the attack vectors from D2: a signature whose declared
  component list omits floor components, a request with an injected uncovered impersonation header,
  an altered body against a signed digest, a signature with no `created` parameter, a wrong key for a
  known key ID, and an algorithm substitution.
- Derivation tests, covering what Kubernetes adds rather than what the library already tests:
  - a ladder stated as an API type, reproducing a published test vector
  - the digest depending on what a ladder means, not on which API type it arrived in
  - the staged-entry equivalence invariant, across all four pairings of root and rung
  - a scope mismatch naming the step that disagreed
  - three arbitrary ladder shapes sharing nothing with each other (D9)
  - the daily cliff a date-scoped server rung falls off, recorded so a change to it is visible
  - a reflection test comparing the Kubernetes ladder types against the library's field for field, so
    the nine declarations of that schema cannot drift from the one that validates them
  - a drift guard on the proto-to-library ladder conversion: every field varied and asserted to change
    the digest, plus a field count that fails if the proto grows one (D12). Verified by breaking the
    converter and watching the guard fail, rather than by assuming it would
- Exec plugin tests: material that signs, a brokered rung that verifies against a root the client
  never sees, and the answers a plugin must not give, each rejected by name rather than as a
  signature the server refuses.
- Resolver tests, against an in-process resolver on a real socket rather than a fake or a direct call,
  because the parts most likely to be wrong are the ones a direct call skips: endpoint parsing, the
  dialer, the not-found status, and the difference between a resolver that says not-found and one that
  is not there.
  - all three material shapes, including every pairing of root and rung across client and server
  - ordered fallthrough across resolvers, and a prefix selector proven to skip one entirely
  - a cached key, a resolver stating zero cache duration and being obeyed, a remembered absence, and a
    resolver failure deliberately *not* remembered
  - a relayed value reaching the resolver, an uncovered one rejected before any lookup, a repeated one
    refused rather than joined, and a rotated one busting the cache
  - `system:` usernames and groups refused, and each material-versus-algorithm mismatch refused by name
  - `ConsumeNonce` asserted *not* called for a signature that failed to verify, because that property
    lives in call order and call order is not self-documenting
  - a stale signature rejected without the resolver being called at all
- Integration tests against a real kube-apiserver, with a resolver on a real socket:
  - a kubeconfig-configured client authenticating, reading, and writing with a body, and one resolver
    call serving four requests
  - an unknown key rejected with 401, both as an unserved key ID and as a served one with wrong material
  - a captured request replayed over the wire and rejected, by the resolver's nonce record
  - two resolvers routed by key ID prefix, each vending a different identity, each proven not to be
    asked about the other's keys
  - a session token relayed to the resolver, which chooses the identity from it
  - signed impersonation accepted, injected impersonation rejected
  - a brokered rung with the ladder stated by the resolver, and a rung scoped to another cluster
    rejected with 401
  - a resolver that goes away rejecting requests whose keys are still cached, because the nonce cannot
    be recorded
  - a resolver added by rewriting the configuration file taking effect without a restart
- Integration tests against the resolver command as a separate process, which is the only place several
  things are exercised at all: the key file parsed by the code that will parse it, PEM surviving
  conversion to the DER the wire takes, a socket created by one process and dialed by another, and a
  resolver that actually died rather than one told to return an error.
  - a key file a person could have written authenticating a signed request, identity and extras intact
  - a captured request replayed and refused by the resolver's own nonce store
  - a key removed from the file stopping authentication, with the delay being the cacheTTL the file set
  - the resolver killed, and requests refused because the nonce can no longer be recorded
  - a rung vended with the ladder stated in Metadata, folded per request by the API server
  - a key file claiming a `system:` identity refusing to start, naming the rule
  - the resolver README's example key file loaded, so a documented example cannot rot
  - an exec plugin whose material signs four requests, runs once for all four, and is shown to have
    been told the algorithm and the covered headers it had to satisfy

Deliberately not built:

- A resolver worth deploying. `httpsig-resolver` holds plaintext key material in a file next to the
  identity it authenticates, which is the objection this API exists to answer moved one process over,
  and keeps nonce state in memory in one process, which is correct only while there is exactly one of
  it. Both are recorded in its README rather than hidden.
- A rate limit on resolver calls driven by an unauthenticated caller (Q6). Bounded key ID length, an
  age check before the lookup, singleflight, and a negative cache all reduce it; nothing caps the rate
  for distinct key IDs.
- CEL user-validation rules over a resolver's claimed identity. The hard rules are enforced; the
  configurable ones need the aggregate-cost problem recorded for the JWT path solved first (D11).
- Resolver health in `/readyz`. Deliberate: a resolver being down affects only requests signed by its
  keys, and gating readiness on it would remove the whole API server from service (D11).
- Nonce records for a certificate-asserted signature (D15). The parameter is required and covered,
  so recording can begin later without a change at any client, but there is no store every API server
  shares to record it in. A bucket keyed on the trust anchor would put every client under one
  authority into one shared, peer-driven cache, which is the arrangement that turns replay tracking
  into a replay enabling mechanism. Pointing a certificate authenticator at a resolver purely for
  nonces was considered and rejected: `endpoint` would mean two different things depending on whether
  `x509` was also set, and it would cost a round trip per request for a client whose key the resolver
  never sees.
- The client's ladder digest on the wire, which would let the verifier answer "ladder mismatch" rather
  than "signature does not match" (Q5).
- A ladder discovery endpoint for clients. A ladder is not secret and could be published, but a client
  has to state it to work at all, so a new public API surface buys nothing.
- Hardware-backed or non-exportable keys (D3), which the signer seam allows and nothing here
  delivers.
- Asymmetric key derivation (D8), which is a new ladder kind and a key distribution design.
- More than one ladder per resolver, which needs named ladders and a key referring to one. A
  deployment needing two can run two resolvers.
- An inline credential in a kubeconfig (D3), which the file would then carry around.

Two implementation notes worth keeping, because both are places where the obvious choice would have
been wrong:

Client-side signing uses the wire-level `httpsig.Sign` rather than the library's
`sigconfig.SigningProfile` and `client.NewTransport`, because a profile's coverage is static by
design and the protected header class is covered only when present.  The conditional coverage rule
stays in Kubernetes instead of becoming a configuration language in the library. The library's
content digest mode is the one existing precedent for conditional coverage, and it is the pattern
being generalized.

Server-side verification uses `ParseSignatures` and `Signature.Verify`, reading the covered set from
`Signature.Components()`, rather than the library's server middleware, whose policy can express a
minimum coverage set but not a presence-conditional requirement.
