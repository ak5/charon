# Machine-readable contracts

- `openapi.yaml` describes Charon's origin-style liveness and readiness
  endpoints. It deliberately does not pretend that forward-proxy or `CONNECT`
  traffic is a REST API.
- `forward-proxy.md` is the normative public protocol contract for HTTP
  absolute-form requests, `CONNECT`, signed manifests, authorization ordering,
  and fail-closed responses.
- `transparent-gateway.md` defines routing-bound transparent TLS interception,
  capability references, typed hydration sinks, response streaming modes,
  compression, correlation strength, and Infra ownership.
- `data-plane-receipt.schema.json` defines the metadata-only network receipt
  and hash-chain envelope.
- `workload-claims.schema.json` validates the JSON payload signed by a workload
  identity issuer. The compact wire form remains
  `base64url(payload).base64url(ed25519_signature)`.
- Charon's operator TOML is defined by the Rust configuration types and the
  validated example in `examples/charon.toml`. A generated configuration schema
  is intentionally deferred until it can be produced from those types rather
  than maintained as a second hand-written source of truth.
- `realm-desired.schema.json` validates the secret-free desired realm object
  accepted by an external reconciler.
- `realm-observation.schema.json` validates the redacted state an external
  reconciler may report.
- `tool-operation.schema.json` defines the metadata-only operation submitted by
  a workload integration for admission.
- `tool-admission-decision.schema.json` defines the bounded local allow/deny
  response. It is not a Charon manifest and cannot select a credential.
- `tool-receipt.schema.json` defines the metadata-only execution result emitted
  by a workload integration. Raw arguments and outputs are excluded.
- `tool-integration.md` defines the bounded local transport, digest encoding,
  single-use admission binding, receipt journal, and failure behavior.

Schemas reject unknown properties. They define data shape, not authorization:
transport authentication, idempotency, ownership-marker checks, filesystem
permissions, and network policy remain operator responsibilities documented in
[`docs/persona-realm-contract.md`](../docs/persona-realm-contract.md).

Charon's built-in allow-once Telegram gate is documented in
[owner operations](../docs/admin.md) and [ADR 0009](../docs/adr/0009-local-telegram-allow-once.md).

Tool admission and receipt contracts are also implemented outside Charon.
Their first adapter is [`charon-hermes`](../integrations/hermes/README.md).

## Exclusive Hermes network gateway

The [exclusive workload gateway](workload-gateway.md) provides a separate
`--gateway-config` mode for ordinary HTTP(S) proxy clients, including reusable
CONNECT tunnels. It binds one fixed isolated workload, supports secretless
forwarding and typed credential sinks, and requires its own validated schema.
Signed proxy authentication, transparent service lanes, and Hermes tool
admission remain independent controls. Infra owns isolation, trust and cutover.

- [Owner administration](admin.md): independent HTTPS enrollment, passkey sign-in, and vault unlock/lock.
