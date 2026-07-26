# Integration boundaries

Charon is an orchestrator-neutral credential-injection data plane. It has no
application database client and makes no request-path call to an integrating
control plane. Integrations are explicit, versioned, and fail closed.

## Boundary map

| Boundary | Direction | Protocol and contract | Trust | Charon owns |
| --- | --- | --- | --- | --- |
| Workload | workload → Charon | HTTP forward proxy; `CONNECT` for HTTPS; signed manifest in `Proxy-Authorization` | untrusted | destination, operation, placeholder, size, redirect, replay, and expiry enforcement |
| Identity issuer | control plane → workload → Charon | Ed25519 signed compact manifest; [`workload-claims.schema.json`](../contracts/workload-claims.schema.json) | trusted only to assert identity and capability | offline signature verification and independent concrete-operation policy |
| Operator configuration | operator → Charon | deny-unknown-fields TOML; example in [`examples/charon.toml`](../examples/charon.toml) | trusted administrative input | validation before listener bind |
| Secret provider | Charon → provider adapter | Rust `SecretProvider`; opaque policy-owned reference in, `SecretString` out | trusted with only its realm's secrets | readiness, bounded caching, non-disclosure, fail-closed errors |
| Realm reconciler | operator → runtime | declarative desired/observed objects; schemas in [`contracts/`](../contracts/) | privileged control plane | no lifecycle mutation API; only runtime health and identity |
| Runtime probe | operator → Charon | HTTP origin endpoints; [`openapi.yaml`](../contracts/openapi.yaml) | network-restricted observer | liveness and credential-free readiness |
| Destination | Charon → exact host | HTTP(S), optionally through configured egress | untrusted response source | credential injection after authorization; redirects disabled |
| Upstream egress | Charon → proxy | HTTP(S) forward proxy with optional protected file-backed Basic auth | routing dependency, not an authorization source | exact destination authorization remains local |
| PKI | operator → Charon/workload | offline root and one realm intermediate | operator trust boundary | exact-host leaf issuance; PKI never selects persona or capability |
| Audit sink | Charon → logs | structured JSON events | may observe approved identifiers only | no headers, bodies, manifests, nonces, provider references, sessions, or keys |

## Workload protocol

The workload sends a normal absolute-form HTTP proxy request, or an HTTP
`CONNECT` request followed by TLS. It supplies a signed manifest but cannot
select a realm, provider, provider account, item, secret reference, destination
outside configured policy, or credential rendering rule.

OpenAPI does not model a general forward proxy or `CONNECT` tunnel accurately,
so the workload boundary is specified by the manifest JSON Schema, the policy
configuration, ADR 0001, ADR 0002, and protocol integration tests.

## Issuer contract

Any system may be an issuer if it:

1. protects the configured Ed25519 private key;
2. emits claims matching the versioned schema and configured issuer/audience;
3. binds an authenticated tenant, persona, workspace, active lease, workload,
   operation, and capability;
4. uses unpredictable single-use `jti` values and short validity windows; and
5. never places realm, endpoint, provider, account, item, secret reference,
   hostname, method, or path selection in the manifest.

Charon keeps only the public key and does not call the issuer. Issuer
availability therefore affects creation of new manifests, not verification of
an already issued request.

## Provider adapter contract

`SecretProvider` is the in-process adapter boundary. A provider receives only an
opaque reference selected by trusted service policy and returns a
`secrecy::SecretString`. Provider values must not implement `Debug`,
serialization, or response conversion.

The current binary registers environment and Vaultwarden adapters at compile
time. Adding a provider requires a configuration variant, validation, adapter
construction, and fail-closed tests. Charon intentionally does not load
third-party dynamic plugins into its credential-holding process.

One provider instance belongs to one realm. If a future realm needs several
providers, local policy—not a manifest or request—must bind each service to a
named provider instance. That change requires a new ADR because it expands
configuration and failure-isolation complexity.

## Reconciler contract

Charon exposes no create, rotate, revoke, or delete endpoint. An external
operator reconciles the versioned desired object into isolated files,
networking, provider state, PKI, and an immutable Charon process, then publishes
a redacted observation. The schemas describe exchanged data; they do not grant
authority or prescribe a transport.

This separation prevents an Internet-facing credential data plane from also
becoming a privileged lifecycle control plane.

