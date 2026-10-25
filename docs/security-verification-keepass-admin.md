# KeePass and owner-admin verification

This implementation verification covers the concrete credential store, owner
HTTPS boundary and optional local Telegram gate. It does not constitute an
owner production-activation review or a live deployment proof.

## Verified behavior

- On 2026-10-25, the opt-in live test passed against the official Telegram Bot
  API using an operator-owned KDBX: Allow once returned successful JSON from the
  first API, and Deny returned 403 for the second with no additional credential
  lookup or upstream API call. Accepted prompts were replaced with decision
  messages. This is local harness evidence, not deployed-host isolation proof.

- `tests/e2e/` connects a real encrypted two-password KDBX, HTTPS admin,
  software passkey, actual Telegram worker with local Bot API transport, curl
  workload, intercepted TLS and a password-checking Rust JSON API. It verifies
  both mappings, deny-before-lookup, actor/replay/timeout rejection, lock and
  component restart without persisted credential values.

- Real synthetic encrypted KDBX tests cover locked boot, wrong passwords,
  required optional key file, exact mapped lookup, unknown references, missing
  entries, unprotected Password fields, private-file permissions, symlink
  rejection, read-only database behavior, and loss of unlocked state on lock.
- A software WebAuthn authenticator exercises first enrollment, one-shot challenge
  replay rejection, passkey sign-in, authenticated unlock, origin rejection,
  wrong master passwords, recovery-key enrollment, logout and restart with
  persisted public keys but a locked store. Code expiry is enforced at finish.
  Overlapping registration/login tests enforce the eight-key and 32-session
  limits again when ceremonies complete.
- A real headless Chrome proof uses an isolated synthetic profile and virtual
  passkey to exercise the actual UI: enrollment, sign-in, unlock, lock, logout
  and sign-in again. It checks that password/code inputs clear. The separate
  HTTPS test verifies certificate trust and real network JSON parsing.
- Telegram callback tests bind private actor/chat identity and original message
  ID, reject unsent/expired/canceled handles, consume decisions once, and exercise
  the allow-once wait path. A local fake bot API verifies post-unlock notifications,
  prompt buttons and callback polling. Worker regression tests verify that
  decision feedback removes the buttons before releasing either an allowed or
  denied request; a mocked edit failure preserves the authenticated decision.
  The final message retains trusted action context; the live-test notification
  omits the reserved fixture admin URL.
  Preview tests verify full method/destination/path/query/header/body display,
  nested JSON, public credential references, recognized caller credential masking,
  readable Basic references, Unicode escaping and byte-preserving body replay.
  Non-UTF-8 or oversized previews deny before a prompt.
  Detail-action tests cover owner/chat/message rejection, unchanged decision and
  expiry, post-consumption rejection, and inert payload formatting with UTF-16
  code-block offsets. The connected test expands details before choosing and
  verifies that viewing causes no workload lookup or forwarding.
  An intercepted TLS request proves that
  denial causes no credential lookup and allow-once permits exactly one lookup.
  Unknown policy names and missing/extra/blank/oversized/nonprintable authority
  descriptions fail configuration validation. Concurrent-request tests verify
  that a decision releases only its own request. Prompt-rate tests verify the
  10-per-minute budget persists after decisions, recovers after expiry, and
  does not block ungated capability authorization. The connected fixture loads
  an operator-only protected bot entry from KDBX, proves no locked bot messages,
  notification-failure retry without losing HTTPS, pending cancellation on lock,
  and rejection of pre-lock callbacks after restart. Store tests reject bot entry
  overlap with workload mappings and missing/unprotected/malformed bot values.
- A gateway regression leaves a gated request waiting without any approval
  worker and verifies that ungated forwarding and credential routes still
  succeed, with only the ungated credential lookup performed. Pending-capacity
  exhaustion separately rejects a new gated request without queuing a prompt.
- Existing signed, transparent and exclusive gateway suites use real synthetic
  KeePass snapshots and continue to verify denial before credential lookup,
  destination/identity/sink enforcement, no redirects, response non-disclosure,
  TLS/SNI/authority agreement, limits, and realm isolation.

The complete `mise run check` includes formatting, warnings-denied Clippy, all
Rust targets, dependency policy, deployment-script tests, Hermes admission tests
and strict Python/HTTPX CONNECT-chain verification. Run it for the final tree;
focused results do not replace this required gate.

## Boundaries and deployment limits

The master password enters only the HTTPS admin boundary, is parsed into a
secret-holding type, and is discarded after decrypt. Mapped protected passwords
remain in memory until lock/restart. The parser temporarily handles other
database content. Operator-controlled database KDF/decompression settings can
consume substantial resources; apply process resource bounds.

TLS issuance/renewal, DNS, network isolation, backup, runtime UID/mount ownership,
passkey-device recovery and deployment startup remain operator responsibilities.
The bot token is a protected operator-only KeePass entry, excluded from workload
mappings. Telegram stays idle before unlock and stops on lock; no bot token
environment variable or master-password file exists. Use a dedicated approval bot inaccessible to the
workload. Telegram sees policy descriptions and the complete pre-substitution
application request, including forwarded headers, query values and UTF-8 body.
Public Charon references stand for KeePass values; recognized caller credential
headers are masked. Unrelated inline secrets cannot be detected automatically.
Original shell commands are not verified; the channel has no vault unlock authority.

The Docker vertical fixture requires an operator-controlled Docker daemon,
browser-trusted admin TLS, an encrypted disposable KDBX, and approved egress.
It requires manual HTTPS unlock before issuing test manifests. Container builds,
actual host/firewall isolation and live Telegram delivery must be verified on
that deployment; local software-authenticator and callback tests alone do not
prove those external conditions.
