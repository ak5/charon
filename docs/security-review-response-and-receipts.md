# Response and receipt security review

Date: 2026-10-29. Scope: repository source, response mediation, owner administration,
Hermes admission/receipts, dependencies and their contracts. This is a source and
regression-test review, not an independent security certification.

## Findings and fixes

| Finding | Enforced behavior | Regression evidence |
| --- | --- | --- |
| JSON-escaped credential echoes escaped byte matching | Match raw and decoded JSON characters, including mixed escapes and surrogate pairs, in bodies and retained headers | `response::tests::redacts_json_escapes_and_replacement_text_at_every_chunk_boundary`, HTTP text/structured echo tests |
| A credential matching replacement text could loop forever | Scan original input only; consume the longest complete match and never rescan replacement markers | Replacement-marker and one-byte chunk tests in `src/response.rs` |
| Ambient proxies could bypass direct DNS policy | Ignore ambient proxy discovery; accept only explicit trusted egress configuration | Subprocess environment-proxy test and explicit authenticated-proxy test in `tests/http_proxy.rs` |
| Unauthenticated requests could exhaust the owner's lock budget | Separate authenticated and unauthenticated budgets; exempt authenticated vault locking | `admin::tests::unauthenticated_rate_limit_cannot_block_owner_lock` |
| Stalled request bodies lacked deadlines | Ten-second admin/structured body reads; signed request lifetime includes buffering, approval and upstream work | Paused-clock body tests and `operation_deadline_includes_structured_request_buffering` |
| Hermes receipts could change admitted metadata or outlive their authorization | Bind shared identity fields and argument digest; check the independent one-day receipt window at acceptance | Metadata mutation, optional task, expiry and replay tests in the Hermes suite |
| Hermes could acknowledge incomplete or unsynced journal appends | Complete short writes and sync before acknowledgment; roll back failures and reject writes after failed recovery | Short-write, disk/sync failure, retry and partial-tail recovery tests |
| Response length was checked after removing Content-Length | Check original headers against the effective response limit | Upstream sends oversized headers and never completes; Charon immediately rejects |
| Buffered JSON used the larger streaming limit before checking its own bound | Apply the smaller limit while reading into one buffer; stop on the first error | Fragmented chunked upstream exceeds the smaller limit and never completes; Charon immediately rejects |
| An unused external approval subsystem expanded the shipped surface | Built-in Telegram remains the approval implementation; no external broker API, SQLite store or extra AEAD implementation is shipped | Full compilation, contract tests and dependency review |

Duplicate Content-Encoding headers are also all checked before forwarding. An
`identity` value cannot hide a later compressed encoding.

KeePass still uses ChaCha20. Its key-state zeroization feature is enabled
explicitly and checked by a compile-time trait-bound test, independently of
other consumers' feature selection.

## Contract review

Wire contract versions remain unchanged: these changes enforce existing
non-disclosure, resource bounds and admission binding. Whole rendered credentials
may now become one `[REDACTED]` marker. Operation budgets include approval waits;
operators must budget time for the human decision. Explicit egress proxies remain
responsible for destination DNS/address enforcement. No KDBX or passkey state is
rewritten, and no deployment or policy migration is performed.

## Verification and limits

Required checks are `mise run check` and `mise run e2e-flow`, with synthetic
credentials and local secret environment variables excluded. The connected E2E
uses a two-password KDBX, HTTPS admin, mock Telegram decisions, proxy/API endpoints,
lock and restart. Relative documentation file links are checked separately.

Real Telegram delivery, Chrome passkey UI and deployed network isolation are
separate checks. The Hermes upstream-source compatibility test requires an
explicit pinned source checkout. None is inferred from local unit tests.

Known-secret matching does not defeat arbitrary transformations by a hostile
destination. Streaming cannot retract bytes already delivered. Unauthenticated
flooding can still delay new owner sign-in, so admin reachability and connection
limits remain deployment responsibilities. The Hermes journal is locally
hash-chained, not independently signed; detecting malicious rewrites requires a
trusted prior digest.

## Second pass: 2026-10-30

The second pass follows the connected code and concurrent failure paths. It
assumes one Charon realm and one local Hermes admission process, not a shared
multi-tenant gateway.

| Finding | Fix and regression |
| --- | --- |
| An unlock upload begun before lock could commit afterward | Capture the generation before upload, recheck before decryption and commit; delayed-body lock/logout test |
| A logged-out session could finish enrolling a recovery passkey | Recheck the bound live session under the registration lock after reading the body; real synthetic WebAuthn registration race test |
| Local Hermes clients could retain unbounded threads/admission records, or extend a read deadline with trickled bytes | 32 connections, five-second server reads, absolute client deadlines, 4096-record caches; capacity, slow-socket and malformed-frame tests |
| Reused tool-call IDs across Hermes sessions could swap receipt outcomes | Correlate hooks by session, tool, call ID and argument digest; reverse-order completion regression |
| A denied reused nonce could overwrite its original expiry | Check membership before inserting, bound the cache without eviction; shortened-expiry replay regression |
| Separate writers could fork either receipt hash chain | Exclusive journal file locks through recovery and append; second-writer rejection tests in Rust and Python |
| Redacting a credential after JSON serialization could produce invalid JSON | Redact decoded strings, protected keys and matching primitive values before serialization; numeric, quoted-string and SSE JSON tests |
| Adversarial nearly matching escaped responses could monopolize a worker beyond upstream-read deadlines | Cooperative scanning and an outer mediation deadline; long escaped-prefix cancellation regression |

Hermes recovery also validates bounded closed receipt envelopes, and failed
journals cannot continue admitting work after an irrecoverable write failure.

Final local evidence includes `mise run check` with the exact pinned Hermes
source, the connected offline two-password E2E, and the isolated Chrome passkey
UI flow. These checks do not attest the live Telegram service or deployed k3s
network policy. No independent security certification is claimed.
