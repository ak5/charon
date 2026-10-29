# Owner administration

The owner API runs only on the separate configured HTTPS admin listener. It is
absent from workload routers. This interface does not expose credential values,
select credential references, mutate policy, or issue workload manifests.

Every POST requires the exact configured `Origin`. Endpoints with structured
input limit JSON bodies to 16 KiB and ten seconds, accept exactly `application/json`, and reject
unknown fields. Endpoints listed with no input do not parse a request body. Challenges expire after five minutes and are stored server-side.
The listener gives authenticated and unauthenticated requests separate budgets
of 30 origin-accepted non-GET requests per 60-second window. Authenticated vault
locking is exempt from these budgets. Responses use
no-store caching, restrictive CSP, HSTS, no-referrer and nosniff headers.

| Endpoint | Input | Authorization | Success |
| --- | --- | --- | --- |
| `GET /` | none | public | owner UI |
| `GET /admin.js`, `GET /admin.css` | none | public | static local assets |
| `GET /api/status` | none | public; session controls unlocked-state visibility | `{enrolled, authenticated, unlocked}` booleans |
| `POST /api/register/start` | `{code}` | first enrollment: unexpired console code; subsequent enrollment: session | `{id, options}` WebAuthn creation challenge |
| `POST /api/register/finish` | `{id, credential}` | unexpired one-shot ceremony, bound session for additional keys | `204` after verified credential and atomic public-state persistence |
| `POST /api/login/start` | none | existing enrollment | `{id, options}` WebAuthn assertion challenge |
| `POST /api/login/finish` | `{id, credential}` | unexpired one-shot ceremony and valid assertion | `204` and session cookie |
| `POST /api/unlock` | `{password}` | session | `204` after complete mapped snapshot decrypts |
| `POST /api/lock` | none | session | `204`, retained values discarded |
| `POST /api/logout` | none | session revoked if present | `204`, cookie cleared |

`credential` uses the standard JSON representation consumed by `webauthn-rs`.
The browser converts binary WebAuthn fields to unpadded base64url. The passkey's
RP ID is the exact configured DNS hostname, and verification checks its HTTPS
origin. There is one owner, at most eight registered keys, 32 pending ceremonies and
32 active sessions, and no username or
password fallback. Recovery-key enrollment excludes existing credential IDs.

The opaque session token is in a `__Host-charon-admin` cookie with Path `/`,
Secure, HttpOnly, SameSite Strict and a ten-minute lifetime. Only its hash is
stored server-side. Restart revokes every session. Logout does not lock the vault.

Capacity is checked at both ceremony start and finish. First enrollment code
state is random, hashed in memory, single-use and expires
five minutes after boot. Expiry is checked at both ceremony start and finish.
There is no HTTP endpoint to retrieve or reset that code. Invalid authorization
and unlock failure return generic `403` responses; unavailable state returns
`503`; rate saturation returns `429`. Passwords and backend errors are never
returned. Credential-store unlock runs on a blocking thread behind a single gate.

Public registrations and signature counters persist to a private atomic file.
The KeePass master password, parsed database, mapped decrypted snapshot,
challenges and sessions do not persist. See [owner operations](../docs/admin.md)
for configuration, TLS renewal and console recovery.

When Telegram is configured, `keepass.telegram_bot_token_entry_id` identifies a
dedicated protected Password entry outside workload mappings. Its validation is
part of unlock. Telegram starts after unlock and has no environment-token input.
Lock discards the token snapshot and cancels polling and pending decisions;
restart starts locked without a Telegram notification. Channel outages retry
without taking down the owner HTTPS listener.

Lock invalidates unlock requests from before the lock, including incomplete
uploads and queued decryption jobs. Logout revokes the session and invalidates
pending unlocks but retains an already unlocked snapshot. Registration checks
its bound session again at commit; logout or expiry during upload cannot enroll
a recovery passkey.
