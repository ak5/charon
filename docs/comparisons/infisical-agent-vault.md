# Charon and Infisical Agent Vault

Use **Infisical Agent Vault** when you want a credential broker that also manages
agent access and credential lifecycles. Use **Charon** when you already manage
secrets in KeePass and want a focused gateway with operator-defined request
policy and manual owner unlock.

Both proxy outbound requests and inject credentials outside the agent runtime.
That mechanism is shared; it is not a Charon differentiator. This comparison is
with [Agent Vault](https://github.com/Infisical/agent-vault), rather than the
entire Infisical secrets-management platform. Reviewed on 2026-10-12 against
its published documentation and Charon's current KeePass implementation.

## Use Infisical Agent Vault when

- You want agents to discover services and propose new credentials or access,
  then let a person review those proposals in a browser.
- You need multiple vaults, users, agent memberships, and access roles.
- You need OAuth authorization and automatic access-token refresh, or want to
  connect an existing Infisical credential store.

Agent Vault documents these workflows in its
[agent protocol](https://docs.agent-vault.dev/agents/protocol),
[vault management](https://docs.agent-vault.dev/learn/vaults), and
[credential management](https://docs.agent-vault.dev/learn/credentials) guides.
Charon does not provide these management features.

## Use Charon when

- KeePass is already your source of truth. You want to mount a read-only KDBX,
  map exact entry UUIDs, and keep editing and backing up secrets with your
  existing KeePass tools.
- You accept an owner signing in with a passkey and entering the KeePass master
  password over HTTPS after a restart. Credential routes stay unavailable
  until unlock; the master password is discarded after decryption.
- You have a small, known destination inventory and want exact hostnames,
  methods, paths, and credential locations specified by the operator.
- You want selected requests to require a private Telegram allow-once decision,
  with denial or unavailable approval preventing credential lookup and forwarding.
- Your deployment already supplies workload identity or network isolation, and
  you want the gateway's request path independent of an orchestrator database.

See [owner operations](../admin.md),
[the workload contract](../../contracts/workload-gateway.md), and
[integration boundaries](../integration-boundaries.md).

## Practical differences

| Decision | Infisical Agent Vault | Charon |
| --- | --- | --- |
| Where secrets are managed | Built-in encrypted credentials or an external credential store | Operator-managed read-only KeePass database |
| Changing access | Agent proposals can request service and credential changes for human review | Operator changes local configuration and KeePass mappings |
| Approval scope | Browser proposals can change stored credentials and service access | Telegram decision authorizes one pending request without changing policy |
| Destination policy | Host/path patterns; unmatched traffic is forwarded by default, with a configurable strict deny mode | Exact configured destinations; unmatched access denied |
| OAuth lifecycle | Authorization flows and automatic refresh | No built-in OAuth refresh; operator maintains stored values |
| Operations | Vault, user, and agent management | One isolated realm, local configuration, HTTPS owner access, and optional Telegram |

Agent Vault's [services guide](https://docs.agent-vault.dev/learn/services)
documents its matching and unmatched-host policy. Strict deny mode can be
configured there too; deny-by-default is a Charon default, not an exclusive
capability.

## Limits to consider

Charon's lightweight aim means fewer management responsibilities and one
concrete secret backend. It is not a demonstrated binary-size, memory, or
performance advantage: there are no comparative benchmarks yet. Charon is
also early-stage. Its connected synthetic E2E and browser checks cover the
KeePass/admin/approval/proxy flow; container deployment and real Telegram
verification remain separate checks. See [verification evidence](../security-verification-keepass-admin.md).

The Telegram token is stored in an operator-only KeePass entry and becomes
available after HTTPS owner unlock. Charon's deployment env files contain only
nonsecret settings. HTTPS and interception TLS keys still need separate operator
provisioning. Manual vault unlock means credential-bearing workloads need an
owner after a restart, and Telegram cannot send a locked-boot notification.
