# ApprovalChannel adapter contract

Version: 1

`ApprovalChannel` is the approval broker's delivery boundary. Telegram is the
first adapter; decision semantics and reusable-rule policy remain
channel-independent.

The Telegram adapter reads exactly two identity/credential environment values at
startup: `CHARON_TELEGRAM_BOT_TOKEN` and `CHARON_TELEGRAM_USER_ID`. The user ID
is one positive numeric Telegram ID and is immutable for the process lifetime.
The adapter has no runtime pairing, rebinding, allowlist, group, channel, or
username-based authorization path.

An adapter accepts a presentation model containing:

- opaque pending-message ID;
- redacted tenant, persona, workspace, workload, service, and resource labels;
- structured action and an operator-registry-produced, redacted command
  presentation;
- risk tier and request expiry; and
- the broker-selected finite set of available decision buttons.

It returns only:

- opaque pending-message ID;
- opaque single-use callback token;
- authenticated channel name;
- channel-native numeric actor and conversation IDs; and
- channel event timestamp.

The adapter does not receive signing keys, workload manifests, credentials,
provider references, reusable-rule predicates, or authority to widen a grant.
It cannot select a request, construct a rule, alter expiry, or decide whether a
callback is authorized.

The broker's action registry defines the renderer for each known action and the
argument positions safe to display. It must preserve security-relevant values
such as repository and issue number while excluding free-form bodies or other
private content. A presentation is never hashed back into authorization state;
the stored normalized request and digest remain authoritative. An operation
that cannot be rendered precisely without exposing sensitive data is
non-reusable and requires an explicit higher-risk confirmation.

## Required behavior

- Accept a Telegram update only when `chat.type == "private"`, `from.id` equals
  `CHARON_TELEGRAM_USER_ID`, and `chat.id` equals that same configured value.
  Usernames, display names, groups, channels, lists, pairing, and
  first-user-wins behavior are never authorization inputs.
- Use random opaque callback tokens; Telegram callback data contains no request
  digest, identity, command, rule, or secret.
- Deliver one mutable message for each pending approval and allow only its
  current callback tokens.
- Edit the message to a terminal redacted state after decision, timeout, or
  cancellation.
- Treat duplicate, stale, edited, migrated-chat, unknown-user, unknown-chat,
  forwarded/copied, and mismatched-message events as denials.
- Bound delivery retries and callback age.
- Rate-limit per issuer, tenant, workload, chat, and action to prevent approval
  notification flooding.
- Return coarse channel failures without copying Telegram response bodies into
  broker logs or API responses.

## Interface sketch

```text
deliver(Presentation) -> DeliveryReceipt
receive(AuthenticatedChannelEvent) -> OpaqueCallback
finalize(PendingMessageId, TerminalPresentation) -> ()
health() -> Ready | Unavailable
```

Concrete language bindings may use asynchronous methods and typed error enums,
but must preserve these data-flow constraints. Additional channels implement
the same interface and conformance suite without changing broker policy.

## Failure behavior

Channel unavailability, delivery ambiguity, callback ambiguity, or finalization
failure defaults to deny. An unavailable channel cannot interrupt unrelated
requests already authorized by valid assertions or rules. There is no automatic
fallback to a second channel because fallback changes the authenticated human
identity boundary.
