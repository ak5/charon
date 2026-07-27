# Approval broker operator runbook

This runbook applies to the optional external human-approval broker specified by
ADR 0005. It is not deployed inside Charon and receives no credential-provider
access.

## Provisioning

1. Deploy the broker on a private control-plane network with mutually
   authenticated issuer and administrator clients.
2. Provision a dedicated Ed25519 approval-signing key. Give only its public key
   to the workload-identity issuer.
3. Provision transactional durable storage for requests, callback hashes,
   decisions, rules, assertion nonces, rate limits, emergency generation, and
   audit correlation. Encrypt storage and backups with operator-managed keys.
4. Create a Telegram bot and store its token in the broker's protected runtime
   secret mechanism. Do not place it in Charon, workload images, repository
   settings, command arguments, logs, or messages.
5. Configure exact Telegram numeric user and chat IDs. Verify IDs through an
   authenticated enrollment procedure; never copy authorization from a username
   or display name.
6. Load an operator-owned action/risk registry. Unknown actions default to
   critical and offer only deny or allow once.
7. Start with emergency disable enabled. Exercise delivery, callback expiry,
   duplicate callback denial, assertion verification, rule revocation, audit
   export, and restore before enabling issuance.

## Routine checks

- Broker health is independent of Charon health.
- Pending approvals have bounded age and current message IDs.
- Callback tokens are stored only as keyed hashes and expire with the request.
- Rules have finite expiry/use bounds and current policy generation.
- Session rules reference an active workspace lease and inactivity deadline.
- Assertion nonce consumption is atomic at the issuer.
- Prompt and callback rate limits are enforced per issuer, tenant, workload,
  action, user, and chat.
- Audit sinks contain approved identifiers and digests, never request commands
  when classified sensitive, callback tokens, assertions, keys, bot tokens,
  credentials, provider references, or message bodies.

## Rule inspection and revocation

Use the mutually authenticated broker API to list rules by tenant and optionally
persona. Inspect exact subject, resource, action set, risk tiers, policy
generation, TTL bound, use bound, expiry, source decision, and revocation state.

Rule deletion is idempotent and records `revoked_at`. Revocation prevents new
assertions but does not modify Charon state. To invalidate assertions not yet
consumed, enable emergency disable and rotate or revoke the broker verifier key
at the issuer according to incident scope.

## Telegram outage

New requests without a matching valid rule remain pending only until their
bounded timeout, then deny. Do not fall back to a different chat, user, bot, or
channel automatically. Already minted Charon manifests and unrelated valid rule
matches continue according to their own bounds.

## Bot token rotation

1. Enable emergency disable.
2. Invalidate all pending callback tokens and terminally mark their messages
   when possible.
3. Rotate the Telegram bot token and protected runtime value.
4. Reverify bot identity, numeric allowlists, delivery, callback binding, and
   terminal message edits.
5. Increment emergency generation and explicitly re-enable issuance.

## Account recovery or chat migration

Treat human account recovery, bot removal, ownership transfer, or chat migration
as an authorization incident:

1. Enable emergency disable.
2. Revoke affected rules and invalidate pending requests.
3. Remove old numeric user/chat IDs.
4. Complete an out-of-band operator identity check.
5. Enroll new numeric IDs and rotate the bot token when exposure is possible.
6. Review audit records from the last known-good human authentication event.
7. Re-enable only after two-person operator review.

## Signing-key rotation

Use an explicit key ID and additive rotation:

1. Generate a new dedicated broker key.
2. Configure its public key at the issuer without removing the old verifier.
3. Switch broker signing to the new key.
4. Wait for the maximum assertion lifetime plus clock skew.
5. Remove the old verifier and destroy the retired private key.

Unknown key IDs and silent fallback fail closed.

## Emergency disable

The emergency endpoint accepts a monotonically increasing generation. Enabling
it stops new assertions and identity-issuer manifest minting from approval
evidence. It does not weaken Charon policy or revoke already consumed
single-use manifests.

Enable emergency disable for:

- broker signing-key or database compromise;
- Telegram bot-token exposure;
- allowlisted account recovery or chat migration;
- unexplained rule creation or widening;
- replay, callback-binding, or audit-integrity failure; or
- inability to prove current lease or policy generation.

Record the incident, preserve redacted audit evidence, rotate affected
credentials/keys, revoke affected rules, invalidate pending requests, and
require explicit reviewed re-enable.
