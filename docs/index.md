# Documentation

Start with the document that owns the question you are trying to answer.

## Use and operate Charon

- [README](../README.md): product overview and fastest development path.
- [Telegram/BotFather setup](telegram-setup.md): bot creation, owner ID and live approval testing.
- [Owner enrollment and vault operations](admin.md): HTTPS setup, passkeys, unlock, recovery, and Telegram decisions.
- [Deployment](deployment.md): deployment configuration and operating steps.
- [Hermes single outbound gateway](hermes-gateway.md): exclusive-workload
  explicit proxy, exact destination inventory and deployment verification.
- [Workload gateway contract](../contracts/workload-gateway.md): ordinary client
  CONNECT, secretless forwarding and typed credential routes.
- [Transparent gateway contract](../contracts/transparent-gateway.md):
  capability references, typed hydration, streaming mediation, and routing.
- [Approval broker operations](approval-broker-operations.md): approval-broker
  integration and operational behavior.
- [Vertical integration example](../integrations/vertical/README.md): isolated
  end-to-end demonstration.
- [Hermes Agent integration](../integrations/hermes/README.md): fail-closed tool
  admission, receipts, and deployment.
- [Hermes v2026.8.3 compatibility](hermes-v2026.8.3-compatibility.md): exact
  Telegram inventory, classifications, runtime gates, and upgrade contract.

## Compare alternatives

- [Infisical Agent Vault and Charon](comparisons/infisical-agent-vault.md): practical selection guide.

## Understand the design

- [Integration boundaries](integration-boundaries.md): system ownership and
  external integration boundaries.
- [Threat model](threat-model.md): security invariants, trust boundaries, and
  known risks.
- [Persona and realm contract](persona-realm-contract.md): current pre-1.0
  identity context.
- [Architecture decisions](adr/): decisions and their rationale.
- [Local Telegram approval scope](adr/0009-local-telegram-allow-once.md):
  capability-level decisions, prompt limits, and failure behavior.
- [Machine-readable contracts](../contracts/README.md): protocol schemas,
  OpenAPI documents, and canonicalization rules.

## Contribute

- [Contributing](../CONTRIBUTING.md): branch, review, attribution, release, and
  security-reporting policy.
- [Repository conventions](conventions.md): commands, repository shape,
  documentation ownership, scratch space, and bootstrap choices.
- [Exclusive gateway implementation review](security-review-workload-gateway.md):
  reviewed boundaries, regression evidence and deployment limitations.
- [KeePass/admin verification](security-verification-keepass-admin.md): implementation evidence and deployment verification limits.
