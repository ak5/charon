# ADR 0009: Local capability-level Telegram approvals

Status: accepted

## Decision

The lightweight KeePass-backed deployment uses an optional built-in Telegram
gate. After workload identity and local policy checks, Charon waits for an
Allow once or Deny decision before credential lookup or upstream forwarding.
The approval is scoped to one use of an exact configured capability or route.
It does not assert semantic review of request bodies or individual resources.

Each gated name requires a public operator-written authority description.
Prompts display it, the policy name, method, and approval scope. Descriptions
come only from trusted local configuration and must not contain secrets or
private resource information. Callback handles bind one pending request through
an in-memory one-shot receiver; they are not normalized-operation digests or
reusable grants. Actor, private chat, original message, expiry, and one-use
checks apply before a callback can release that request. Local policy remains
authoritative and cannot be widened by a human decision.

## Failure and lifecycle

The bot token resides in a protected, operator-only KeePass entry. Locked boot
makes no Telegram calls. HTTPS passkey authentication and KeePass master-password
unlock remain independent of Telegram. Lock cancels pending requests and the
channel; restart retains neither the unlocked snapshot nor pending approvals.

The gate fails closed on denial, expiry, cancellation, capacity exhaustion, or
lack of a valid decision. Waiting lasts at most two minutes; exclusive gateway
operation deadlines may shorten it. Per-process prompt admission is limited to
10 per rolling minute and 32 pending requests. Completion or cancellation does
not refund the rate budget; lock/unlock does not reset it. Restart resets the
in-memory budget. Ungated requests do not use this budget. Operator unlock
notifications are separate. A workload may exhaust the budget, so deployment
traffic/resource limits remain necessary.

## Consequences and alternatives

Telegram adds an external availability and account-takeover boundary. It receives
public policy descriptions and metadata, never credential values or request
bodies. Token rotation requires updating KeePass and lock/unlock; owner changes
require trusted configuration and restart. Operator recovery is documented in
[owner operations](../admin.md) and [bot setup](../telegram-setup.md).

An external broker, signed approval assertions, sessions, reusable rules, and a
generic channel interface are unnecessary for this bounded flow. The separate
[broker design](0005-human-approval-broker.md) is not required to deploy it.
Precise resource/body approval would require trusted parsing, presentation, and
execution binding and is outside this decision. Full request dumps would expose
private data without establishing those semantics.

Local synthetic tests establish component behavior. Real Telegram delivery and
deployed HTTPS/network isolation require separate operator verification; neither
is implied by passing unit tests or container builds.
