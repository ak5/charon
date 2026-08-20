# Approval canonicalization and digest contract

Version: 1

Approval prompts, callbacks, decisions, reusable rules, and assertions bind to a
single byte-stable representation of the normalized request. Display text,
Telegram message IDs, usernames, and callback payloads are never authorization
inputs.

## Request digest

Given an `approval-request.schema.json` document:

1. Validate the complete document and reject unknown properties.
2. Select the value of its `request` property.
3. Serialize that value using the JSON Canonicalization Scheme defined by
   RFC 8785 (JCS), encoded as UTF-8.
4. Compute SHA-256 over those exact bytes.
5. Encode the digest as lowercase
   `sha256:<64 lowercase hexadecimal characters>`.
6. Compare it in constant time with `request_digest`.

The normalized `request` includes its unpredictable, single-use `request_id`;
authenticated identity and active lease; exact service and resource; structured
action; complete command token array; risk tier; policy generation; requested
manifest TTL; and validity window. Changing any field changes the digest.

Implementations must not canonicalize arbitrary unvalidated JSON, accept
duplicate object keys, normalize Unicode, coerce numbers, reorder command
arguments, resolve aliases, expand shell syntax, or infer omitted defaults.
The issuer constructs the normalized request from authenticated state and a
parsed operation model before serialization.

Command tokens are authorization inputs, not a place for credentials. The
issuer must reject operations containing tokens, passwords, session values,
private keys, signed manifests, provider references, or other secret material
before constructing a request. Normalized requests are encrypted at rest and
excluded from general logs; only approved structured fields and digests enter
audit records.

## Resource and command digests

`resource_digest` is JCS SHA-256 of the validated `request.resource` object.
`command_digest` is JCS SHA-256 of the validated `request.command` object.
They use the same lowercase `sha256:` representation.

An exact-operation rule binds `command_digest`. An operation-class rule cannot
contain it and instead binds an explicit finite `actions` set plus the exact
tenant, persona, workload, service, resource, risk tiers, policy generation,
expiry, use bound, and optional workspace/lease predicates.

## Decision binding

Every callback contains only an opaque random callback token. The approval
broker resolves that token to one pending request and verifies:

- callback token is single-use and unexpired;
- Telegram reports a private chat and its numeric actor and chat IDs both equal
  the adapter's immutable `CHARON_TELEGRAM_USER_ID`;
- pending request ID and stored request digest match;
- message is the current pending message;
- requested grant is permitted for the action and risk tier; and
- no decision or timeout has already reached a terminal state.

The broker stores the decision and edits the presentation to a terminal,
redacted result before returning an assertion. It never trusts a request ID,
digest, grant scope, or rule predicate received back from Telegram.

## Signed assertion

An allowed decision produces claims matching
`approval-assertion.schema.json`, signed by a dedicated approval-broker Ed25519
key as:

`base64url(jcs(claims)).base64url(ed25519_signature)`

The identity issuer holds only the corresponding public key. It verifies the
assertion offline from Telegram, atomically consumes its `jti`, rechecks current
lease and policy generation, ensures the requested manifest TTL does not exceed
the assertion bound, and mints a fresh single-use Charon workload manifest.
Charon does not receive or verify the approval assertion.

Approval assertions are short-lived authorization evidence, not credentials
and not reusable Charon bearer tokens.
