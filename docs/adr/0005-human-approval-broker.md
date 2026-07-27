# ADR 0005: External human approval broker

Status: accepted for contract-first implementation

## Context

Some capability requests require an authenticated human decision before the
identity issuer may mint Charon's existing short-lived, single-use workload
manifest. Telegram is the first requested user interface, but it must not become
a credential source, policy engine, request-path dependency, or component of
Charon's credential-holding data plane.

Reusable decisions such as “this session” or “GitHub issue operations” create
new authorization state. Natural-language matching, workload-selected scope,
unbounded duration, or a reusable Charon bearer token would violate Charon's
deny-by-default boundary.

## Decision

Human approval is implemented by an external approval broker between the
integrating control plane and its workload-identity issuer:

1. The control plane derives a normalized approval request from authenticated
   tenant, persona, workspace, active lease, workload, and operation state.
2. The broker validates its schema and canonical digest.
3. The broker atomically evaluates durable, revocable reusable rules.
4. If no rule applies, the broker sends a redacted presentation through an
   `ApprovalChannel`.
5. An allowlisted numeric Telegram user/chat may deny or choose one of the
   broker-provided bounded grant options.
6. The broker records a terminal decision, optionally creates one structured
   rule, and signs a short-lived approval assertion with a dedicated Ed25519
   key.
7. The identity issuer verifies and consumes the assertion, rechecks current
   lease and policy generation, then mints a fresh Charon manifest for exactly
   one operation.

Charon does not receive approval requests, decisions, rules, assertions,
Telegram messages, or callbacks. It continues verifying workload manifests
offline and independently enforcing concrete service, hostname, method, path,
and injection policy.

The versioned contracts are:

- `approval-request.schema.json`;
- `approval-decision.schema.json`;
- `approval-rule.schema.json`;
- `approval-assertion.schema.json`;
- `approval-canonicalization.md`;
- `approval-channel.md`; and
- `approval-broker.openapi.yaml`.

Normalized command tokens contain no credentials or provider references and are
encrypted at rest. The operator-owned action registry supplies a deterministic
redacted presentation renderer; presentation text is not an authorization
input. An action that cannot be rendered precisely without exposing sensitive
content is non-reusable and requires a higher-risk allow-once confirmation.

## Trust boundaries

- **Control plane:** trusted to authenticate lifecycle state and construct the
  exact normalized operation. It cannot approve its own request.
- **Approval broker:** trusted to validate digests, evaluate rules atomically,
  authenticate channel events, persist decisions, enforce expiry/revocation,
  rate-limit prompts, and protect its signing key.
- **Approval channel:** trusted only to deliver a presentation and authenticate
  channel-native numeric actor/conversation IDs. It has no rule or assertion
  authority.
- **Human approver:** trusted within an operator-defined tenant/persona/risk
  scope. Account takeover remains an external authorization risk.
- **Identity issuer:** trusts the broker's dedicated public key but must recheck
  current lifecycle and policy state before minting a manifest.
- **Charon:** trusts only its existing issuer key and local policy; approval
  cannot widen a Charon capability.

The broker API uses operator-managed mutual TLS identities. Issuers and
administrators have distinct authorization roles and tenant scopes.

## Grant semantics

- **Deny:** terminal; creates no assertion or rule.
- **Allow once:** one short-lived assertion bound to the request and command
  digest; creates no reusable rule.
- **Session:** rule bound to the exact tenant, persona, workspace, active lease,
  workload, service, resource, actions, risk tiers, and policy generation.
- **Exact operation:** rule additionally binds the exact command digest and has
  a maximum use count of one.
- **Operation class:** rule contains an explicit finite action set. It never
  matches natural language, prefixes, wildcards, regular expressions, or
  workload-supplied predicates.

All reusable rules have creation and expiry times, maximum uses, maximum
manifest TTL, resource and risk bounds, policy generation, provenance decision,
and revocation state. Session rules additionally have an inactivity timeout.

A session ends at the earliest of lease termination or replacement, workspace
disposal, persona reassignment, policy-generation change, explicit revocation,
inactivity timeout, configured maximum duration, or emergency disable. Broker
restart does not extend state; pending callbacks and rules live in durable
transactional storage.

## Non-reusable operations

Critical-risk operations never offer session, exact, or class grants. The
operator registry initially classifies these as critical:

- credential, secret-store, signing-key, or certificate changes;
- approval rule creation, widening, revocation disablement, or approver changes;
- branch-protection, repository-visibility, package-visibility, or workflow
  permission changes;
- destructive repository/package deletion or history rewrite;
- production deployment-policy or network-boundary changes; and
- any unknown or unclassified action.

High-risk operations may allow only once unless an operator-owned action
registry explicitly permits a narrower reusable grant. The workload cannot
change risk classification or the set of buttons presented.

## Telegram lifecycle

Telegram authorization uses operator-configured numeric user and chat IDs.
Usernames and display names are presentation-only. Bot-token rotation preserves
no pending callback tokens. Bot removal, account recovery, or chat migration
activates emergency disable until an administrator updates the allowlist,
rotates the bot token, invalidates pending requests, and explicitly re-enables
issuance.

The bot token is a channel credential, never a secret-store backend for Charon.

## Keys and assertions

Approval assertions use a dedicated broker Ed25519 key, separate from the
workload-manifest issuer key. The issuer pins the broker public key and
atomically consumes assertion `jti` values. Assertions are audience-bound,
shorter-lived than the pending approval, and constrain manifest TTL.

Key rotation is additive with explicit key IDs in deployment configuration.
There is no fallback to unknown or retired keys. Emergency disable stops new
assertions and manifest minting; Charon continues to handle already minted,
still-valid single-use manifests according to its own policy.

## Failure and audit behavior

Timeout, ambiguous delivery, duplicate callback, invalid actor/chat, broker
outage, Telegram outage, persistence failure, signature failure, stale lease,
stale policy generation, unknown action, and emergency disable all fail closed.
An approval outage does not interrupt unrelated already authorized realms.

Audit events correlate request, delivery, terminal decision, rule creation,
rule match, assertion issuance, issuer result, revocation, timeout, rate limit,
and emergency state using approved identifiers and digests. They exclude
commands when sensitive, callback tokens, message contents, manifests, nonces,
signatures, keys, credentials, provider references, and Telegram bot tokens.

## Rejected alternatives

- **Telegram inside Charon:** would add an online chat dependency to the
  credential data plane and hold requests open near resolved credentials.
- **Telegram as policy engine:** presentation text and callback buttons are not
  canonical authorization inputs.
- **Issuer-internal unsigned decision:** prevents independently verifiable
  broker/issuer separation and safe key rotation.
- **Reusable Charon manifest:** turns one approval into a bearer credential and
  defeats single-use replay protection.
- **Natural-language or wildcard rules:** cannot be inspected or proven not to
  widen scope.
- **Automatic channel fallback:** changes the authenticated human boundary
  during an outage.
- **Approval overriding local Charon policy:** converts human intent into
  caller-selected destination or secret routing.

## Consequences

Approval semantics can be implemented and tested independently of Telegram and
Charon. Other channels may implement the same adapter contract. The additional
broker, durable state, signing key, approver lifecycle, and notification
availability expand the trusted control plane, but not Charon's audited
credential boundary.
