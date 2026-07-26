# Owner security review: CONNECT interception

- Reviewer: repository owner (`ak5`)
- Date: 2026-07-22
- Scope: TLS interception, CA custody, CONNECT parsing, SNI and authority
  rebinding, HTTP/2 and HTTP/1.1 behavior, streaming, limits, audit output, and
  the disposable secretless `gh` fixture
- Decision: approved

## Evidence reviewed

- `docs/adr/0002-connect-interception.md`: trust model, CA custody and
  distribution, one-authorized-operation semantics, and rejected alternatives;
- `src/tls.rs`: protected CA-key loading, certificate/key agreement, and
  exact-host leaf issuance;
- `src/proxy.rs`: CONNECT authority parsing, manifest authentication, SNI and
  decrypted authority binding, method/path authorization, redirect denial,
  streaming, bounds, and timeouts;
- `tests/connect_proxy.rs`: unlisted destinations, SNI/authority mismatch,
  malformed decrypted headers, unrelated-CA misuse, ALPN, HTTP/2
  pseudo-authority, and intermediate rotation;
- `tests/http_proxy.rs`: redirect denial, identity-before-provider ordering,
  streaming, and request/response bounds;
- `integration/vertical`: an unmodified `gh` client, isolated workload network,
  provider lock, policy denials, and evidence leakage scans; and
- the complete `mise run check` quality and dependency-policy gate.

## Findings

- CONNECT accepts only exact configured hosts on port 443.
- TLS SNI and the decrypted HTTP/1.1 `Host` or HTTP/2 `:authority` must agree
  with the CONNECT target before credential resolution.
- Conflicting authorities, non-HTTPS absolute targets, unlisted destinations,
  redirects, malformed headers, and unrelated trust anchors fail closed.
- TLS advertises HTTP/2 and HTTP/1.1 through ALPN. A single-use manifest permits
  one authorized operation; replay or an additional operation is denied.
- Request and response bodies use backpressured counted streams with independent
  16 MiB aggregate limits. Declared oversized requests fail before provider
  work, and unknown-length overflow terminates the stream.
- The CA private key remains outside workloads. Audit and error output exclude
  credentials, manifests, sessions, nonces, headers, bodies, and provider
  values.

No unresolved findings were identified.

## Residual risk

A Charon interception CA is intentionally trusted by its assigned workload.
Compromise of a deployed realm intermediate can therefore mint certificates
trusted by that workload. Exact endpoint reachability, direct-egress denial,
short-lived leaves, per-realm isolation, protected key custody, and rapid realm
revocation remain mandatory; PKI does not replace Charon authorization.

