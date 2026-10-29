# Owner enrollment and vault operations

Charon boots locked. The owner admin page runs on an independent HTTPS listener;
workload listeners do not expose enrollment, passkey authentication, or unlock.
There is no admin username or default password.

## Provision

Configure `[keepass]` with an absolute private KDBX path. Mount it read-only.
`keepass.items` is required; use `items = []` for a purely secretless gateway.
Map exact canonical entry UUIDs using `[[keepass.items]]`; each mapping must use
the realm's persona. The Password field must be protected, nonempty, and at most
16 KiB. An optional `key_file` must also be a private regular file, at most 1 MiB.
Database input is at most 64 MiB. Charon does not modify the database.

The binary requires `[admin]` in both `--config` and `--gateway-config` modes.
Configure it with a separate listener, canonical stable HTTPS DNS origin
without a trailing slash, certificate chain, independent private TLS key, and
absolute `passkeys_file` path. The parent of the public passkey file must already
exist, be a real directory, and have mode 0700. Private input files must have no
group/other permissions. Container deployments must give Charon's UID access to
the inputs and write access to the admin-state and receipt directories.

Use a browser-trusted certificate for the exact origin. The operator owns DNS,
certificate issuance and renewal, port/firewall policy, and TLS-file provisioning.
The admin certificate does not replace the workload interception CA. A changed
certificate for the same origin does not change the passkey identity; changing the
origin, including its port, requires new enrollment. Charon loads TLS files on startup, so restart after certificate
rotation and unlock again. Do not expose the enrollment code in shared logs.

## First boot

1. Start Charon. Retrieve its enrollment code from the operator console over SSH.
   It expires after five minutes and is not sent through Telegram.
2. Open the configured HTTPS origin on your own device. Enter the code and create
   a passkey with your browser's authenticator. The private key stays there.
3. Sign in with the passkey. Enter the KeePass master password and unlock.
4. While signed in, add a second passkey on a recovery device or security key.

Charon persists only public passkey registration data and signature counters.
Challenges and opaque admin sessions remain in process memory. Admin cookies are
Secure, HttpOnly and SameSite Strict; sessions expire after ten minutes. Unlock,
lock and registration require a valid session and the exact configured Origin.
First enrollment requires the console code instead of a session. There is a
separate limit of 30 origin-accepted non-GET requests per 60-second window
for authenticated and unauthenticated clients. Authenticated vault locking is
exempt, so exhausted budgets cannot stop an existing owner session from locking.
Unauthenticated flooding can still delay sign-in; restrict admin network access.
JSON bodies must arrive within ten seconds. Challenges are bounded to
32 pending ceremonies, sessions to 32 active tokens, and registrations to eight
passkeys. Capacity is rechecked when ceremonies finish.

## Normal boot and lock

Existing public registrations survive restart; the decrypted snapshot and admin
sessions do not. Sign in and enter the master password after every restart.
Explicit lock drops the mapped values and cancels any in-flight unlock commit.
Signing out revokes that browser session; it does not lock the vault.
Lock denies future lookups; requests that already obtained a credential may
finish within their configured operation bounds. A failed unlock does not replace an already unlocked snapshot. To load an updated KDBX,
lock and unlock again. Policy mapping changes require a configuration restart.

A secretless forwarding route can work while the store is locked. Credential
routes fail closed until unlock. Workload liveness is independent of unlocked
readiness. Signed/transparent `/readyz` returns realm identity as JSON with
`200` or `503`, checking the store and optional receipt writer. Exclusive gateway
`/readyz` returns `204` or `503`, checking the journal and checking the store when
any route mediates credentials. Pure forwarding gateways can be ready while locked.
Neither readiness probe verifies Telegram delivery or host/network isolation.

## Telegram

Follow the [BotFather setup guide](telegram-setup.md) to create a dedicated bot,
pin your private numeric ID, and run a live approval test.

Create a dedicated bot and start a private chat with it. Charon talks directly
to `https://api.telegram.org` using outbound HTTPS and long polling; this channel
does not use `upstream_proxy` or ambient proxy variables. Permit Charon-only
HTTPS/DNS egress to that host when Telegram is enabled. Configure its owner as
one immutable positive numeric `user_id`, and configure `approval_capabilities`
with exact capability names (signed/transparent mode) or route names (exclusive
gateway mode). Unknown names are configuration errors. Set `approval_descriptions`
to a map with exactly the same names and a public operator-written description of each
capability's authority. Descriptions must be nonblank printable ASCII, at most
240 bytes each; missing, extra, or invalid descriptions reject configuration.
No name or description is inferred from request content. Store the bot token in a
dedicated protected Password field in KeePass. Set
`keepass.telegram_bot_token_entry_id` to that entry's canonical UUID.
It must not appear in `keepass.items`: workload credential mappings cannot access
it. There is no environment token or master-password file. Deployment env files
contain only nonsecret listener/image/revision settings.

Charon starts HTTPS while the vault is locked and makes no Bot API calls until
unlock. After passkey sign-in and successful master-password unlock, it loads the
bot token and sends an unlocked notification with the admin URL. A missing,
unprotected or malformed mapped token rejects unlock with the same generic error
as any invalid mapped entry. Missing token-entry configuration rejects startup.
A network or Telegram failure leaves HTTPS available; the bot retries and gated
requests fail closed while no valid decision is available.

Selected requests receive allow-once and deny buttons before credential resolution
or upstream forwarding. The callback must match the owner, private chat, exact
sent message and random expiring request handle. A decision consumes it once.
After accepting a decision, Charon attempts to replace the prompt with a fixed
decision message without buttons and acknowledge the callback before releasing
the waiting request. Prompts lead with the public action description and the
actual HTTP method/destination/path. **Show request details** expands the same
message into a redacted `http` code block with all headers, query values and the complete body while
keeping Allow once / Deny available. Viewing requires the same owner, private
chat, original message and live handle checks; it neither approves the request
nor consumes the decision or extends its expiry. Expired/consumed prompts cannot
reveal details. The final message names the decision, HTTP method and destination/path, for
example `Allowed once: send authenticated POST request to https://api.example/items`.
It removes the code block and buttons. This records authorization, not upstream
success. Telegram controls highlighting; Charon sends
explicit text entities rather than parsing request data as Markdown or HTML.
Each feedback call has a two-second timeout. Display updates
are best-effort: an outage or stopped process may leave stale buttons visible,
but the consumed handle cannot authorize another request. The displayed choice
does not establish that the upstream operation succeeded.
Decisions do not create durable rules or bypass identity, sink, destination,
method, path, receipt, or resource checks. Approval expires after two minutes or
the gateway's shorter deadline. Lock drops the token snapshot, cancels polling
and pending decisions; unlocking starts a fresh channel session. Decisions from
before a lock cannot authorize requests after another unlock. Restart requires
owner unlock and cannot send a locked-boot notification.

The bot receives capability names, public action descriptions, and the complete
request before credential substitution: method, destination, path, query values,
forwarded headers and the full UTF-8 body, including nested JSON and form data.
`{{charon.<capability>}}` references remain visible; KeePass values are resolved
only after approval and never enter the preview. Path references are decoded for
readability; query/form encoding and body bytes are retained. Basic authentication
is displayed as `Basic base64(username:{{charon.<capability>}})` so the password
reference can be read. Transport framing added by the HTTP client is not part of
this application request preview. Headers removed by forwarding policy are not
shown; Host is derived from the authorized destination.

Recognized caller credential headers (Authorization, Cookie, API-key/token headers,
headers marked sensitive, and Charon workload identity) retain their names but
show `[redacted caller credential]`, unless they are the validated Charon
credential sink containing a public reference. No secret lookup is needed to
build this view. Unrelated inline secrets in custom headers, query values or
body content cannot be identified automatically. Enabling a gate authorizes
sending that request content to Telegram; use Charon references for credentials.
Enrollment codes and master passwords are never added to previews.

Every gated request body is buffered before approval within the smaller of
64 KiB and the route byte limit, with a ten-second read timeout. Original bytes
are retained for forwarding. Non-UTF-8 bodies and request previews exceeding
3500 bytes are denied before lookup or egress, never truncated. Control and
non-ASCII characters are escaped to prevent misleading rendering. Empty bodies
are supported. Ungated requests retain their existing streaming behavior.

Approval releases only the waiting request represented by the preview; it does
not verify an original shell command or establish upstream success.

Each process admits at most 10 approval prompts in a rolling 60-second window
and holds at most 32 pending approvals. Excess gated requests fail closed
without queuing a prompt. Completed, canceled, and denied prompts still consume
the rate budget; lock/unlock does not reset it. Ungated requests do not consume
this budget. A process restart resets the in-memory budget. A workload can
exhaust it and temporarily deny approvals; enforce workload traffic limits at
the network boundary. These bounds do not limit owner unlock notifications.
Workload Telegram traffic must use a different bot identity; do not share the
approval bot token with it.

The local gate has no durable approval history or reusable grants. Workload
request failures use the gateway's redacted denial logs; exclusive gateway
receipts record denied requests with policy metadata, without distinguishing an
owner denial from timeout or unavailable approval. Channel failures produce a
generic warning without the Bot API URL or token. Callback handles and message
contents are not audit fields. A successful approval means permission to proceed,
not proof that the upstream operation succeeded.

## Recovery

Use a second enrolled passkey if one device is lost. There is no password fallback.
If all passkeys are lost, stop Charon, move the public registration file out of its
configured path using trusted console access, and restart to enroll again. Keep
the old file privately if needed for investigation. This resets all admin sessions
and requires unlock again. Console access is recovery authority. Changing the
origin requires the same deliberate reset and new registrations. There is no
unauthenticated HTTP reset endpoint.

Back up the encrypted KDBX, optional key file, and public registration state under
operator policy. Preserve the database's master-password recovery independently;
a passkey authenticates the admin page and cannot decrypt a lost KeePass key.
