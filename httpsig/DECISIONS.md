# HTTP Message Signatures in Kubernetes: PoC decisions and assumptions

Status: working document for a proof of concept on a fork. Not a KEP.

This records the reasoning behind decisions made as well as open questions.

## What this PoC is, and what it is not

It is a porcelain and plumbing layer for the client and the server: the kubeconfig surface, the
credential sources behind it, the signing round tripper, the wire format and coverage rules, the
verifier, and the mapping from a verified key to an identity. Those are the parts
meant to be read as proposals.

Key distribution and key lookup are **unsolved and out of scope**, and the static key list in the API
server's configuration is a naïve stand-in that exists so the rest can be demonstrated. It does not
scale, it has no revocation beyond editing a file on every control plane node, it puts identities in
server configuration, and a change to it does not take effect without a restart. Q4 is the missing
design. The reload gap recorded in D4 is a defect in the plumbing around the stand-in.

The asymmetry says where the gap is. Getting a credential to the **signer** has a real answer here:
an exec plugin, or a broker handing out a scoped rung, with a versioned protocol and expiry handling
(D3, D10). Getting verification material to the **verifier** has none. Everything unsolved is on one
side, and the eventual answer is a lookup the API server calls rather than a list it is configured
with (Q4).

A demo of the working parts, on a kind cluster with a source-built API server and kubectl, is in
`e2e/`. It is where the reload gap in D4 was found.

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

The verifier is configured by a new `httpSignature` section in `AuthenticationConfiguration`
(`apiserver.config.k8s.io`), alongside `JWT` and `Anonymous`, gated by the
`HTTPSignatureAuthentication` alpha feature gate. The section carries the acceptance policy (maximum
signature age, clock tolerance, and the external authority and scheme for a server behind a
TLS-terminating proxy), the derivation ladder, and a list of keys. Each key states its own
algorithm, its public key inline or a path to a shared secret file, where its own material sits on
the ladder, and the user name, UID, and groups it authenticates as.

The API server reads the `httpSignature` section once at startup and builds the verifier from it. The
file watcher that hot-reloads JWT authenticators does not rebuild it,
and it does not refuse the change either: it validates the new section, ignores it, and logs a
successful reload. Demonstrated on the kind cluster in `e2e/`, where correcting a bad key made the
server log a reload at that moment and then keep rejecting requests until the process restarted.

Accepting a change and then ignoring it is worse than refusing it, so making the reload fail loudly
is the part worth doing first, and it does not depend on Q4. Supporting reload properly means
swapping the verifier under an atomic pointer. That belongs with Q4 rather than in front of it,
because the static key list is the thing being reloaded and it is a placeholder.

A static key list is a PoC choice, not a proposal. It avoids the problem of defining an external
lookup API. The verifier holds its keys in a map and indexes that map in one function, so replacing
the static list with something else is a contained change. It is not an interface today, and calling
it one would overstate what is built. Informer-backed lookup of cluster objects, the bootstrap token
authenticator's pattern, is the likely successor and needs its own design.

### D5: replay protection is unimplemented

The acceptance window is the whole of the replay bound. A captured request can be replayed as itself,
unchanged, against any API server until its signature ages out.

Detecting a replay means recognising a signature the fleet has already accepted, which takes state
shared by every API server. A per-instance cache does not provide that: with more than one API server
a captured request is replayable once against each instance that has not seen it. Building one and
calling the result replay protection would claim a property the deployment does not have, which is
worse than not building it, because the claim is what an operator would rely on.

Whether Kubernetes should have shared state for this, or should state non-replayability as a non-goal
and leave the window as the bound, is Q6. The client attaches a `nonce` to every signature either
way, so whatever consumes one later needs no change on the client side.

### D6: new operational dependency on client clock sanity

A `created` timestamp with a bounded acceptance window requires the client clock to be roughly
correct. No existing Kubernetes authentication mode cares about the client clock. A workstation with
significant drift will fail authentication with this mode and succeed with a bearer token.

The requester scoped clock skew out of this work, so nothing here tries to solve it: the verifier
has a `tolerance` setting and that is all. It stays written down because it is a behavior change to
state in the KEP's risks rather than something to discover in beta.

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

### Q4: remote key lookup, which the static list stands in for

The static key list in D4 is the API integration surface, not the key distribution answer. It is
enough to prove that the authenticator and the coverage rules work. It is also
wrong for any real deployment: it does not scale past a handful of identities, it has no revocation
beyond editing a file on every control plane node, and it puts human identities in server
configuration.

A real implementation needs to resolve a key ID to key material at request time, from something
outside the API server's own configuration. The shape that fits the existing surface area is a
request-response API, one analogous to `TokenReview` but asking a different question. `TokenReview`
asks "who does this token belong to" and gets back a `UserInfo`. The question here is "what key
verifies signatures from this key ID, and who is it", so call it `KeyRequest` for now: the key ID
goes in, and public key material plus a `UserInfo` and a validity period comes back. Note the
difference from `TokenReview` that makes this worth doing at all: the response is cacheable across
requests, because a key is stable while a token is not. The verifier does the cryptography locally
and only the key lookup is remote.

Design questions this raises, none of them settled:

- Who serves it. A webhook, following the token authentication webhook, keeps key distribution
  outside the cluster where an external identity system already holds the keys. A cluster object
  read through an informer, following the bootstrap token authenticator, keeps it inside and avoids
  a network dependency on the authentication path, at the cost of a bootstrap ordering problem.
- What the response is keyed on. A key ID alone is the simple form. The lookup could instead see the
  whole request, which is what lets key material travel in a request header, and which is exactly
  the session token pattern this document rejects for in-tree use.
- How caching and revocation interact. A cached key is a key that stays usable after it is revoked.
  The `serviceaccount.PublicKeysGetter` interface already models this with a declared maximum cache
  age and listener based invalidation, and is the right thing to copy rather than reinvent.
  What not to copy: `cached_token_authenticator`'s cache is an unbounded `utilcache.NewExpiring`, and
  its striping is for lock contention rather than size. A lookup keyed on a key ID and a claimed scope
  is keyed entirely on peer-chosen input, so it needs a bounded cache and a tight negative TTL. This
  is the same cardinality argument D8 makes for not caching derived keys, arriving a second time.
- Failure behavior. A key lookup that is unreachable must fail closed for that key without taking
  down authentication for anything else.
- Whether the API server derives at all. If the lookup answers for the scope it was asked about, it
  returns the verification key for that scope and the API server does no derivation: it verifies with
  what it was handed. `keyDerivation` then leaves the server's configuration entirely and the ladder
  becomes a client and broker concern, which retires the server-wide ladder in D4 rather than
  extending it. Worth settling before anything is built on the current shape, because it is a
  deletion and the alternative is a normalization.

Key resolution happens in one function, which indexes a map built at startup. Nothing in the
coverage or acceptance logic depends on where a key came from, so a lookup can replace that map
without disturbing either. That containment is the part of the static list decision meant to survive, and it
is not an interface today.

### Q5: recovering the ladder drift check as an operator can use it

D8 gave something up when the ladder became a typed field in each party's own configuration. Two
parties no longer share bytes, so the digest is computed over the parsed ladder, and comparing
digests now means reading two processes' logs rather than running `sha256sum` on two files.

That is a diagnostic regression, not a security one: a mismatched ladder fails closed, and both
sides log their digest at load. But the failure it produces at the server is a bare signature
mismatch, and the operator who has to notice is the one least likely to be reading API server logs.

Two shapes would fix it, and neither is built:

- **Put the client's digest on the wire.** The verifier could then answer "ladder mismatch" rather
  than "signature does not match", which is the same diagnosability argument that put the claimed
  scope in the key ID. It costs a component on every request and puts an implementation detail into
  the protocol, so it needs the argument made properly rather than assumed.
- **Make the digest computable offline.** The helper is exported, so a small tool could read a
  kubeconfig and an authentication configuration and report whether they agree. This is the cheap
  half and probably the right first move, because it serves the operator without changing anything
  on the wire.

### Q6: whether replay gets narrowed below the acceptance window

D5 leaves the acceptance window as the whole of the replay bound. Narrowing it means recognising a
signature the fleet has already accepted, which is shared state on the request path, and the question
is whether that is worth having at all rather than how to build it.

The two answers are not a spectrum. Either the fleet keeps shared state, which puts a store on the
authentication path of every request and makes its availability the API server's availability, or
non-replayability is stated as a non-goal and the window is documented as the bound. The second is
the honest default and costs nothing; the first needs a threat that the window does not already
bound, stated concretely, before the operational cost is worth arguing about.

Whatever consumes a nonce later needs no client change: the client already attaches one to every
signature. Two constraints on the store, if it is ever built. It has to be keyed on the nonce
together with the identity the signature authenticated as, not on the nonce alone, because a single
namespace of client-chosen values lets one client evict another's records and turns the store into a
replay enabling mechanism. And its cardinality is peer-driven, so it needs a bound, which is the same
argument D8 makes for not caching derived keys.

## 6. Paths not taken yet

Nothing in this section is built. It records where the mechanism goes next, in enough detail to argue
about rather than to implement.

Both paths answer the same question: how Kubernetes maps a credential ID to an identity. The static
list in D4 answers it in server configuration, and Q4 says why that does not survive contact with a
real deployment. The two replacements are a signed **assertion** and a **resolver**. An assertion
states who the signer is, and a party the cluster trusts makes it. Either the client carries the
assertion, or the server fetches it from a resolver. The signature then proves one thing only, that
the client holds the key the assertion names.

D9 applies here too. Each path is described by mechanism, and where a path follows something deployed
elsewhere, this section states the shape rather than the vendor.

### Two approaches to identity discovery

Compare them by what the server has to hold. That is what sets the revocation story and the blast
radius.

| Path | The assertion is | Proof of possession is | The server holds | Revocation is |
| --- | --- | --- | --- | --- |
| Static list (built) | a key entry in server configuration | a signature verified by the configured public key | every public key, and every shared secret | editing a file, then a restart (D4) |
| A. Certificate | an X.509 certificate in a covered header | a signature by the certificate's key | a CA bundle | certificate expiry, and nothing else |
| B. Remote resolution | whatever the resolver says | a signature verified by the key the resolver returns | nothing | authoritative, at cache TTL |

Two consequences fall out of the table, and both paths inherit them.

**Identity stops coming from configuration.** Once an assertion carries the identity, Kubernetes needs
a way to constrain what an assertion may claim. That prerequisite is next, and neither path can ship
without it.

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

A client signs with an X.509 keypair and carries the leaf certificate in a covered header. The server
validates the certificate against a configured CA, extracts the public key, verifies the signature
with it, and maps the subject to an identity.

This is not a key format change. An X.509 keypair is the keypair the client already signs with, and
`parsePrivateKey` already accepts PKCS#8, PKCS#1, and SEC1. The signing path does not change at all.
What changes is that key resolution stops being a lookup and becomes a validation.

So this is mTLS with the handshake replaced by a message signature. The alternatives table rejects
mTLS because it authenticates the connection and dies at the first TLS-terminating hop. This path
keeps everything else: the same CA, the same issuance, the same certificate tooling, the same subject
convention. It moves only the point of authentication into the message, and distribution and rotation
come for free.

#### The pod case is mostly built already

Kubernetes already has three pieces in tree:

- `PodCertificateRequest`, where kubelet requests a certificate for a pod's service account. The
  request carries the pod UID, service account name, node name, and node UID, and proves possession
  of the requested key. kube-apiserver bounds the lifetime through `maxExpirationSeconds`, 24 hours
  by default and one hour minimum. The in-tree signers never issue longer than 24 hours.
- `PodCertificateProjection`, a projected volume source. Kubelet generates the keypair itself, from
  RSA 3072 or 4096, ECDSA P-256, P-384, or P-521, or Ed25519, submits the request, and writes the
  result into the pod.
- `credentialBundlePath`, which writes one file whose first PEM block is a PKCS#8 private key and
  whose remaining blocks are the issued certificate chain, leaf first. The API documentation gives
  the reason: one atomic read returns a consistent key and chain, where separate paths can be read
  mid-rotation.

For pods, then, the credential delivery mechanism, the key generation, the proof of possession at
issuance, and the rotation all exist. Two pieces are missing from the PoC: a client credential source
that reads a credential bundle, and a server that treats the chain as an assertion.

Two mechanical notes. `parsePrivateKey` calls `pem.Decode`, which returns the first block only, and
the bundle's first block is the private key, so reading the key from a bundle works today with no
change. Reading the chain needs a loop. Second, D3 justified `credentialFile` on the grounds that a
projected volume rewrites a credential in place and nothing has to fork a process to pick it up. This
is that case arriving.

#### What path A does not solve

**Revocation.** The server holds no per-client state, which is the point, so there is nothing to
delete. The certificate's lifetime is the revocation window. For pods, kube-apiserver caps it.
Everywhere else the CA administrator decides, and the verifier has no say unless a maximum accepted
lifetime becomes verifier policy. This section records that option and does not adopt it.

**A separate CA, deliberately.** Pointing this at the cluster's existing client CA would give every
existing client certificate the ability to sign detached messages that survive a proxy, with nobody
opting in. Its own CA bundle is the decision. That costs issuance for anything not already using pod
certificates, and buys an explicit trust boundary.

**Extended key usage is unresolved.** Requiring client authentication usage means every certificate
issued for connection authentication also signs messages, which its issuer never agreed to. Requiring
a distinct usage means new issuance for everyone. No registered usage fits, and the in-tree default
verify options require client authentication.

**Verify-before-work inverts.** The verifier checks the signature before it reads a body or touches a
cache, so an anonymous caller cannot make the server do work. Here the server has to parse and
chain-validate a certificate before a verifier exists at all. That needs bounding: leaf only, size
limited, and intermediates from configuration rather than from the request. The per-request work is
then one parse and one chain build against a fixed pool.

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

**Q6, a replay store keyed per credential.** Q6 notes that a store narrowing the replay window would
have to be keyed per authenticated identity and bounded. With the static list, both come free: the
configured list caps the number of identities. An assertion lifts that ceiling. Keys then have to be
the credential's own identity, a leaf thumbprint or its equivalent, and never the trust anchor or the
resolver. Keying per anchor puts every client under one CA into one entry, which is the single shared
namespace Q6 says turns such a store into a replay enabling mechanism. A global ceiling on entry count
becomes necessary, which the static list never needed.

**D2, coverage.** Which class the assertion header belongs to is unresolved. Coverage protects against
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
  `HTTPSignatureAuthentication` alpha feature gate, with validation, carrying the deployment's
  ladder once and each key's own position on it.
- `spec.httpSignature` and `status.httpSignature` in `clientauthentication` v1 and v1beta1, behind
  the `ClientsAllowHTTPSignature` client-go feature gate, so a plugin is told what to produce and
  can answer with key material instead of a token.
- An `authenticator.Request` verifier wired into the kube-apiserver authenticator chain ahead of the
  bearer token authenticator.
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
- Exec plugin tests: material that signs, a brokered rung that verifies against a root the client
  never sees, and the answers a plugin must not give, each rejected by name rather than as a
  signature the server refuses.
- Integration tests against a real kube-apiserver:
  - a kubeconfig-configured client authenticating, reading, and writing with a body
  - an unknown key rejected with 401
  - signed impersonation accepted, injected impersonation rejected
  - the HMAC credential document path
  - a brokered rung: the client holds a rung scoped to one cluster, the server re-derives from the
    root, and a rung scoped to another cluster is rejected with 401
  - an exec plugin whose material signs four requests, runs once for all four, and is shown to have
    been told the algorithm and the covered headers it had to satisfy

Deliberately not built:

- Any key lookup beyond the static list (Q4), and therefore any key retirement story.
- Hot reload of the `httpSignature` section. A change to it is accepted, ignored, and reported as a
  successful reload, which is a defect rather than a decision (D4).
- Hardware-backed or non-exportable keys (D3), which the signer seam allows and nothing here
  delivers.
- Asymmetric key derivation (D8), which is a new ladder kind and a key distribution design.
- More than one ladder per API server (D4), which needs named ladders and a key referring to one.
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
