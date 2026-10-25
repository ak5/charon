# KeePass, owner admin, approval and proxy E2E

Run the deterministic local flow:

```sh
mise run e2e-flow
```

Run it plus the real Chrome owner UI proof:

```sh
mise run e2e
```

The connected test requires curl. The browser proof additionally requires Chrome
and Node 22+. Every listener uses a free loopback port. No Docker, live bot,
external API, real KeePass file or real credential is needed. The fixture creates
private files in a disposable system temporary directory and removes them on
exit; it never writes them into the repository. All seeds are synthetic:

| KDBX input | Value |
| --- | --- |
| Master password | `synthetic-master-e2e-only` |
| Protected Password field, entry UUID `00000000-0000-0000-0000-000000000001` | `synthetic-first-password-e2e` |
| Protected Password field, entry UUID `00000000-0000-0000-0000-000000000002` | `synthetic-second-password-e2e` |
| Operator-only protected bot Password, entry UUID `00000000-0000-0000-0000-000000000003` | `synthetic:token` |

`fixture.rs` writes and reopens that real encrypted KDBX and verifies the two API
protected fields; the actual bot worker loads the third from the same KDBX. The test rejects plaintext seeds in the encrypted file,
response body, public registration state, and receipt files; it also proves that
Charon never modifies the database.

`password_api.rs` is a small Rust TLS HTTP server. Its `/first` and `/second`
POST endpoints require the matching Bearer password and return only
`{"ok":true,"endpoint":"first"}` or the corresponding second endpoint JSON.
A wrong credential returns 401 and `ok:false`, without reflecting the password.

`request.sh` is an ordinary curl workload. It sends public capability references
through Charon's actual explicit proxy and trusts the fixture's public CA.
The fixture and API know the synthetic seed values; the workload script knows
neither password. Charon loads the mapped values from KDBX and writes them only
into the mediated upstream request. Its proxy URL and public CA path are supplied
by the harness; the API and proxy stop after each run.

`telegram_api.rs` is an offline Bot API transport. The actual Telegram worker
sends notifications and buttons, long-polls updates, and validates callbacks.
The connected test covers locked boot, HTTPS passkey enrollment and sign-in,
unauthenticated/wrong-master rejection, correct unlock, both mapped passwords,
Allow once, Deny, wrong actor, replay, no-decision timeout, explicit lock
canceling an outstanding prompt, no bot activity while locked,
component restart, persisted passkey sign-in and another unlock. A pre-lock
callback cannot approve a request after restart. The bot entry cannot be mapped
to a workload credential reference. Assertions prove
that denied requests never reach the password API and that human denial performs
no credential lookup. Existing callback tests separately cover wrong chat/message
and expired/unsent handles, concurrent request binding, description validation,
and prompt-rate exhaustion/recovery. Prompts include a public configured authority
summary and explicitly describe capability-level approval rather than resource
or request-body review.

The connected flow uses a cryptographic software WebAuthn authenticator over
real HTTPS. `browser-admin-check` separately exercises the actual HTML/JavaScript
with an isolated Chrome profile and virtual passkey. Test-only seams route the
reserved `password.test` host and Bot API to local fixtures. They do not exist
in the production binary or relax its DNS/HTTPS/configuration rules. This is an
assembled-component E2E proof, not a deployed container or firewall proof.

## Live Telegram pass

Create a dedicated test bot using [the BotFather setup guide](../../docs/telegram-setup.md).
Stop other consumers of that bot. Discover your numeric private ID if needed:

```sh
mise exec -- python tests/e2e/live_telegram.py --discover-owner
```

Create a separate operator-owned KDBX in your KeePass application, outside this
repository, with three protected Password fields: `synthetic-first-password-e2e`,
`synthetic-second-password-e2e`, and your dedicated test bot token. Record the
canonical UUID of each entry. Keep the file private (mode `0600`). The harness
reads this file and never writes it, copies it, or adds real tokens to generated
fixtures. Do not use your production vault.

Then explicitly run the live pass with your actual private ID and entry UUIDs:

```sh
mise exec -- python tests/e2e/live_telegram.py \
  --user-id 123456789 --database /absolute/path/to/test-bot.kdbx \
  --bot-entry-id YOUR_BOT_ENTRY_UUID \
  --first-entry-id YOUR_FIRST_ENTRY_UUID --second-entry-id YOUR_SECOND_ENTRY_UUID
```

The wrapper asks for the KeePass master password without echo and passes it over
child stdin, never through environment variables, command arguments, or a file.
Environment values contain only the public entry UUIDs, file path, and owner ID.
The bot token is read from the supplied encrypted database by the production
store/channel code after HTTPS unlock. Start the bot's private chat first; it
must have no webhook or competing poller. The discovery helper can check the
webhook and obtain candidate IDs with a hidden token prompt; it does not launch
Charon or persist that token.

The live test runs the password API and proxy against this operator-owned KDBX.
It scripts owner enrollment/unlock and sends real Telegram messages. In your
bot's private chat, press **Allow once** for `first`: curl must get successful
JSON. Then press **Deny** for `second`: curl must get 403 and the second API must
not be called. Each decision expires after two minutes. The unlocked notification
URL uses the reserved fixture hostname; do not use it as a production admin
address. This pass verifies real delivery/buttons/polling; Chrome verifies UI.

The live test is opt-in and is never run by `mise run check` or `mise run e2e`.
Run it only against a test bot, then rotate/revoke that token if disposing of it.
Cloud TLS issuance, container builds, public DNS and host network isolation need
separate deployment verification. Review the chosen E2E passes before shipping the change.
