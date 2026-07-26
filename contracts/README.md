# Machine-readable contracts

- `openapi.yaml` describes Charon's origin-style liveness and readiness
  endpoints. It deliberately does not pretend that forward-proxy or `CONNECT`
  traffic is a REST API.
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

Schemas reject unknown properties. They define data shape, not authorization:
transport authentication, idempotency, ownership-marker checks, filesystem
permissions, and network policy remain operator responsibilities documented in
[`docs/persona-realm-contract.md`](../docs/persona-realm-contract.md).
