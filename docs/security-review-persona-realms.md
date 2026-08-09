# Owner security review: persona-isolated realms

- Reviewer: Alexander Ververis, repository owner
- Date: 2026-07-23
- Scope: persona realm configuration, workload bindings, readiness,
  delegated CA chain, reconciler contract, two-persona fixture, and documentation
- Review target: the implementation represented by the public source tree and
  its complete `mise run check` evidence
- Decision: approved for publication; production credential activation
  remains gated on the operator and integrating control plane's combined fixture

## Evidence reviewed

- `mise run check`: formatting, Clippy with warnings denied, all unit and
  integration targets, fail-closed deployment tests, and dependency policy;
- `tests/persona_realms.rs`: two Alice workspaces, Bob isolation, wrong endpoint,
  replay, expiry, provider failure, independent operation, and readiness IDs;
- `tests/connect_proxy.rs`: leaf/authority checks plus two independently issued
  intermediates chaining to one unchanged workspace root;
- `tests/vaultwarden_provider.rs`: bounded cache, rotation after restart, lock,
  outage, deletion, and credential-free health behavior;
- `integrations/vertical`: internal-only workload network, direct-egress denial,
  locked provider, secretless `gh`, artifact/log scans, and offline-root fixture;
- ADRs 0001–0003, the threat model, deployment guide, and the external
  reconciler/filesystem contract.

## Checklist and findings

| Area | Result |
| --- | --- |
| One process/config/provider/cache/listener per persona | Mixed-persona capabilities and Vaultwarden mappings now fail validation before bind |
| Caller-controlled routing | Manifests contain no realm, vault, account, item, or secret reference; endpoint derivation remains an integrating-control-plane/operator responsibility |
| Stable identity context | Tenant, persona, workspace, active lease, workload, operation, capability, nonce, and validity are signed; realm ownership is independently configured |
| Audit leakage | Only authenticated correlation fields are logged; manifests, nonces, headers, bodies, references, sessions, item UUIDs, and keys remain excluded |
| Provider readiness | `/readyz` checks Vaultwarden status using the protected session without resolving an item and fails `503` when locked/unavailable |
| Delegated CA | The offline root key is never mounted; Charon serves the persona intermediate in the leaf chain; rotation works with unchanged root trust |
| Redirect/authority controls | Existing no-redirect and CONNECT/SNI/authority exact-match controls remain unchanged and pass |
| Cross-persona and replay | Wrong endpoint/persona/tenant, replay, and expiry fail before provider resolution |
| Independent failure | Alice provider failure makes Alice unready and denies use while Bob remains ready and operational |
| Direct bypass | The vertical workload remains on an internal-only Docker network; the direct GitHub attempt fails |

Review found and corrected two security-relevant implementation gaps: Charon
previously omitted the intermediate certificate from the served leaf chain, and
process liveness alone could have been mistaken for provider readiness. The
implemented chain and credential-free provider health check close those gaps.

## Residual risk and production hold

DNS name constraints are not assumed to be reliably enforced. A compromised
trusted intermediate may mint outside the intended persona namespace, so
per-workspace endpoint isolation, direct-egress denial, exact Charon policy,
short-lived leaves, and rapid realm revocation remain mandatory.

The Rust fixture proves application isolation; it does not prove host UID,
mount, firewall, backup, or removal isolation. Production credentials remain
prohibited until the operator applies `docs/persona-realm-contract.md`, runs the
combined two-persona infrastructure fixture, proves the offline root private key
absent from runtime hosts and containers, and the integrating control plane
proves endpoint derivation and lease revocation end to end.
