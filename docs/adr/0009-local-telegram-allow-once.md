# ADR 0009: Local Telegram request approvals

Status: accepted

## Decision

The lightweight KeePass-backed deployment uses an optional built-in Telegram
gate. After workload identity and local policy checks, Charon waits for an
Allow once or Deny decision before credential lookup or upstream forwarding.
The approval releases one pending HTTP request under an exact configured
capability or route, using a redacted preview derived from that request.

Each gated name requires a public operator-written authority description.
Prompts display it and the actual method/destination/path. Request details show
all forwarded headers, query values and the complete UTF-8 body before credential
substitution. Charon references remain visible in place of KeePass values;
recognized caller credential headers and workload identity are masked. Basic
references are decoded into explicit base64 notation. Gated bodies are buffered
within 64 KiB and ten seconds and retained unchanged. Non-UTF-8 bodies or previews
over 3500 bytes deny before lookup rather than hiding or truncating fields.
Ungated streams are unchanged.
Callback handles bind one pending request through
an in-memory one-shot receiver; they are not normalized-operation digests or
reusable grants. Actor, private chat, original message, expiry, and one-use
checks apply before a callback can release that request. Local policy remains
authoritative and cannot be widened by a human decision.

The compact prompt offers Show request details, which expands the same pending
message into a redacted native `http` code block. This action checks owner,
private chat, original message and handle expiry without consuming the decision
or extending its lifetime. It never resolves a workload credential. An accepted
decision replaces the code block with a plain action sentence naming the HTTP
method and destination/path, and removes all buttons. Explicit
UTF-16 text entities keep request content inert rather than parsing it as markup.

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
public policy descriptions and complete pre-substitution application requests.
Operators must consider custom headers, query values and all body fields before
enabling a gate. Resolved KeePass values are never sent; unrelated inline secrets
cannot be automatically detected and must be replaced with Charon references.
Token rotation requires updating KeePass and lock/unlock; owner changes
require trusted configuration and restart. Operator recovery is documented in
[owner operations](../admin.md) and [bot setup](../telegram-setup.md).

An external broker, signed approval assertions, sessions, reusable rules, and a
generic channel interface are unnecessary for this bounded flow. The separate
[broker design](0005-human-approval-broker.md) is not required to deploy it.
The preview does not reconstruct an original shell command. It lets the owner
review the application request with public credential references before lookup;
client-generated framing is outside this preview.

Local synthetic tests establish component behavior. Real Telegram delivery and
deployed HTTPS/network isolation require separate operator verification; neither
is implied by passing unit tests or container builds.

## Contract-version review

Gateway contract version 1 is retained. Workload wire identity, typed references
and credential hydration are unchanged. Enabling local Telegram approval adds
explicit body buffering, UTF-8 and display-size bounds before lookup. Operators
must review full request-content disclosure and deploy the binary with its
complete validated policy. Ungated streaming behavior is unchanged.
