# ADR 0004: Concrete KeePass store and interactive owner unlock

Status: accepted

## Decision

Charon uses one concrete, read-only `KeePassStore` per realm. There is no generic
provider trait, backend selector, credential plugin or fallback source. Local
policy maps an opaque reference and exact realm persona to one canonical entry
UUID. The mapped protected Password field resolves as `SecretString`; failures
use the data-free `StoreError` taxonomy. Workloads never select entries.

The process starts locked. The owner enters the master password through a
separate HTTPS admin page after passkey authentication. A blocking decrypt holds
no persistent master password and retains only mapped password values in
secret-holding memory. Explicit lock drops those values and invalidates in-flight
unlock work. Restart discards all unlocked state. The optional key file is a
private operator-provisioned input, distinct from the master password.

## Owner authentication

The admin listener uses one stable canonical HTTPS DNS origin and an independent
browser-trusted TLS certificate/key. First startup creates a random console-only
code that expires after five minutes. Successful WebAuthn enrollment consumes
it and atomically persists public registration data. Challenges remain server-side;
passkey authentication issues bounded ten-minute opaque sessions in Secure,
HttpOnly, SameSite Strict cookies. Administrative POSTs check the exact Origin.
An authenticated owner can add a recovery passkey. Console access is recovery
authority if every passkey is lost; there is no unauthenticated reset endpoint.

## Telegram

A dedicated protected KeePass Password entry, excluded from workload mappings,
enables post-unlock notifications and optional exact-name allow-once gates.
Telegram is idle before unlock; lock cancels polling and pending decisions. No
bot token is read from the environment, and locked boot cannot notify the owner. Telegram transports the admin URL and capability/method metadata,
never the master password, enrollment code or credential values. Each decision
binds an immutable private numeric user/chat ID, original message ID, random
expiring token, and one pending request. No durable approval rule is created.
Denial, outage, timeout, saturation and cancellation fail closed. This additional
gate cannot widen network or identity policy and does not query a control-plane API.

## Consequences

Deployment needs the encrypted database, optional key file, public registration
state and TLS inputs, without a vault service or CLI session. Restart requires
manual unlock. Public passkey state needs private write access; the KDBX remains
read-only. The operator owns backup, TLS renewal, passkey recovery, and database
rotation. The parser temporarily handles the full decrypted database and joins
the trusted computing base; process resource bounds remain necessary.
