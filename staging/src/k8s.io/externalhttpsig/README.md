> ⚠️ **This is an automatically published [staged repository](https://git.k8s.io/kubernetes/staging#external-repository-staging-area) for Kubernetes**.   
> Contributions, including issues and pull requests, should be made to the main Kubernetes repository: [https://github.com/kubernetes/kubernetes](https://github.com/kubernetes/kubernetes).  
> This repository is read-only for importing, and not used for direct contributions.  
> See [CONTRIBUTING.md](./CONTRIBUTING.md) for more details.

# ExternalHTTPSig

This repository contains the proto API kube-apiserver uses to authenticate
requests carrying an HTTP message signature (RFC 9421) against keys held outside
its own configuration.

A resolver implementing this API answers two questions:

- Which key verifies signatures from this key ID, and whose identity is it?
- Has this nonce already been used for this key?

kube-apiserver does all of the cryptography. The resolver holds key material and
nonce state; it never sees a request, and it never decides whether a signature is
valid.

## Community, discussion, contribution, and support

ExternalHTTPSig is a sub-project of [SIG-Auth](https://github.com/kubernetes/community/tree/master/sig-auth).

You can reach the maintainers of this project at:

- Slack: [#sig-auth](https://kubernetes.slack.com/messages/sig-auth)
- Mailing List: [kubernetes-sig-auth](https://groups.google.com/forum/#!forum/kubernetes-sig-auth)

Learn how to engage with the Kubernetes community on the [community page](http://kubernetes.io/community/).

### Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).
