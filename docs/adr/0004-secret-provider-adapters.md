# ADR 0004: Compile-time secret-provider adapters

Status: accepted

## Context

Charon must support secret stores without making a store, account, item, or
credential reference caller-selectable. Provider implementations execute in the
credential-holding process and therefore join Charon's trusted computing base.

## Decision

Charon uses the `SecretProvider` Rust trait as its adapter boundary. An adapter:

- receives a typed opaque `SecretRef` borrowed from validated local policy;
- exposes a credential-free readiness check;
- returns only `secrecy::SecretString`;
- reports only the closed, provider-neutral `ProviderError` taxonomy;
- owns any backend client, authentication session, and bounded cache; and
- never derives backend routing from workload requests or signed manifests.

Adapters are registered and selected from deny-unknown-fields configuration at
compile time. The current binary includes environment and Vaultwarden adapters.
Adding another backend requires:

1. a narrowly scoped configuration variant;
2. backend-specific validation before listener bind;
3. an adapter implementation and construction branch;
4. locked, unavailable, missing, rotation, cache, and leakage tests; and
5. threat-model and operator-documentation updates.

The closed failure taxonomy is `Locked`, `Unavailable`,
`ReferenceNotMapped`, `SecretUnavailable`, and `InvalidResponse`. Variants
carry no backend error, account, item, reference, or secret material. Backend
SDK and protocol errors must be reduced to one of these values inside the
adapter.

Every production adapter must run the same behavioral contract: credential-free
health, successful resolution of a policy-owned mapping, fail-closed rejection
of an unmapped reference, secret-holding return types, and provider-neutral
errors. Backend-specific suites additionally cover lock, outage, deletion,
rotation, bounded caching, protected runtime material, and leakage.

One isolated realm owns one provider instance. This keeps accounts, sessions,
caches, readiness, and failure domains aligned with the persona boundary.

## Multiple backends

The adapter interface supports any number of implementations in the codebase,
but one running realm currently selects exactly one. Supporting several
instances in one realm would require trusted policy to bind every service to a
configured provider ID. The workload and manifest would still carry neither
provider ID nor secret reference.

That extension requires a follow-up ADR proving:

- provider IDs and references cannot be confused across adapters;
- readiness and failure of one provider cannot cause fallback to another;
- caches and sessions remain isolated;
- duplicate references are rejected or explicitly namespaced; and
- audit output reveals neither provider routing nor references.

## Rejected alternatives

- **Caller-selected backend or item:** creates a credential-discovery and
  confused-deputy interface.
- **Online control-plane secret resolution:** couples request-path availability
  to an application and sends credential material across an additional
  boundary.
- **Dynamically loaded native plugins:** arbitrary plugin code would execute
  inside the credential boundary and make the reviewed binary non-reproducible.
- **Provider subprocess protocol by default:** adds environment, argument,
  standard-I/O, lifecycle, and binary-authenticity leakage surfaces. A future
  sandboxed protocol may be proposed separately when a backend cannot safely be
  linked.
- **Automatic provider fallback:** makes outages capable of changing credential
  identity and violates fail-closed routing.
