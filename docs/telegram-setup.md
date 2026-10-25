# Set up the Charon approval bot

Use a dedicated bot for Charon and a different bot for disposable live testing.
The approval bot token must not be shared with the workload or an external broker.

## BotFather

1. Open Telegram's official BotFather:

   https://t.me/BotFather

2. Send `/newbot`. Choose a display name and an available username ending in
   `bot`, for example your own unique `charon_approval_test_bot` username.
3. Keep the returned token private. Store it in a dedicated protected KeePass Password
   entry. The ID-discovery helper also accepts it at a hidden prompt. Do not paste it
   into this repository, chat, a browser URL or a command argument.
4. Send `/setjoingroups`, select this bot, and disable group joining. Charon accepts
   only the configured private user/chat even if the bot is added elsewhere.
5. Open your new bot's private chat and press **Start** (or send `/start`) before
   starting Charon. A bot cannot initiate this private conversation itself.

These commands and username rules are documented in Telegram's
[official BotFather guide](https://core.telegram.org/bots/features#botfather).
The private-chat requirement is described in its
[bot tutorial](https://core.telegram.org/bots/tutorial#sending-messages).
No `/setcommands`, inline mode, Telegram login widget, webhook or bot web app is
required for Charon's inline Allow once/Deny buttons.

## Find and pin your private numeric ID

With Charon stopped and a fresh `/start` sent to the dedicated test bot:

```sh
mise exec -- python tests/e2e/live_telegram.py --discover-owner
```

Enter the token at the hidden prompt. The helper uses the official Bot API,
prints only recent private-chat numeric IDs, and does not enroll a user or print
messages. Verify your own ID explicitly; never authorize a username, display
name or whichever user contacted the bot first.

Configure Charon using your actual numeric ID and exact local policy names:

```toml
# In the existing [keepass] section, before any [[keepass.items]]:
[keepass]
telegram_bot_token_entry_id = "00000000-0000-4000-8000-000000000003"

[admin.telegram]
user_id = 123456789
approval_capabilities = ["first", "second"]
approval_descriptions = { first = "Call the first test API using its saved password", second = "Call the second test API using its saved password" }
```

The example names belong to the E2E fixture. For deployment, use names that exist
in your `capabilities` (`--config`) or `routes` (`--gateway-config`). Use your bot
entry's actual UUID and never include it in workload `keepass.items` mappings.
Descriptions are public operator-written authority summaries, not workload-provided
operation claims. Every gated name requires exactly one nonblank printable ASCII
description of at most 240 bytes; unknown or missing description keys reject
configuration. Do not put private resource names or secrets in descriptions.
Request details show the complete request before credential substitution,
including headers, query values and the full UTF-8 body. Charon references remain
visible instead of KeePass values; recognized caller credential headers are
masked. Enabling a gate discloses this request content to Telegram. See
[preview limits and redaction](admin.md#telegram) before enabling sensitive routes.

No bot token goes into environment variables or deployment env files. Rotate the
token by editing KeePass, then lock/unlock to reload it. Changing the owner ID or
entry UUID requires a configuration update and restart; workload input cannot
change either.

Charon uses long polling. Use a new dedicated bot with no webhook and no other
poller. If reusing a bot, deliberately remove its previous webhook through
Telegram's `deleteWebhook` API; Charon does not silently change bot ownership or
webhook state. Telegram documents the polling/webhook exclusion in the
[Bot API](https://core.telegram.org/bots/api#getupdates).

Prompt delivery preserves the active long poll. API failures log only the method,
HTTP status, or transport flags; token-bearing URLs and Telegram response bodies
are never logged. A `getUpdates` HTTP 409 indicates a polling conflict; check for
another running Charon instance or test using the same bot.

## Verify

Run the [offline E2E](../tests/e2e/README.md) first. For live delivery, follow that
guide to create an operator-owned test KDBX with two synthetic API passwords and
the test bot token. The wrapper reads that database, prompts privately for its
master password and sends it only over child stdin. No real token is generated
into test fixtures or passed through the environment. You Allow once for the
first password API and Deny for the second; the test checks lookup/upstream
behavior. Ordinary automated checks send no real messages.

For a deployed Charon, open the configured HTTPS admin URL yourself, sign in with
a passkey and unlock. The bot then sends an unlocked notification and can prompt
for a gated route. Confirm Deny/timeout blocks it and Allow once authorizes only
that pending request. Lock should cancel pending decisions and stop the channel;
restart remains locked and sends no notification until another owner unlock.
A missing/unprotected/invalid token entry rejects unlock. Wrong ID, a bot you have
not started, network failure, or an active competing webhook/poller prevents
reliable approvals and must be corrected before treating the channel as ready.
