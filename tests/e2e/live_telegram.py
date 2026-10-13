#!/usr/bin/env python3
"""Explicit live Telegram test using an operator-owned encrypted KeePass file."""
import argparse
import getpass
import json
import os
from pathlib import Path
import re
import subprocess
import uuid
import urllib.error
import urllib.request


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def call(token, method, payload):
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())
    try:
        with opener.open(request, timeout=15) as response:
            data = response.read(262145)
        if len(data) > 262144:
            raise ValueError("oversized reply")
        reply = json.loads(data)
        if reply.get("ok") is not True:
            raise ValueError("API denial")
        return reply.get("result")
    except (urllib.error.URLError, ValueError, OSError):
        # HTTP exceptions may contain the token-bearing URL; do not expose them.
        raise SystemExit("Telegram API unavailable; check the dedicated test bot and network.") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discover-owner", action="store_true", help="Read recent private-chat numeric IDs; does not configure an owner")
    parser.add_argument("--user-id", type=int, help="Explicit positive private owner ID for the live test")
    parser.add_argument("--database", type=Path, help="Existing operator-owned KDBX containing the test passwords and bot entry")
    parser.add_argument("--bot-entry-id", help="Canonical UUID of the dedicated bot Password entry")
    parser.add_argument("--first-entry-id", help="UUID of the first synthetic API password entry")
    parser.add_argument("--second-entry-id", help="UUID of the second synthetic API password entry")
    args = parser.parse_args()
    if args.discover_owner:
        token = getpass.getpass("Dedicated TEST bot token (hidden): ")
        if not re.fullmatch(r"[A-Za-z0-9:_-]{1,256}", token):
            raise SystemExit("Invalid token format.")
        info = call(token, "getWebhookInfo", {})
        if not isinstance(info, dict) or info.get("url"):
            raise SystemExit("The test bot has a webhook. Use a fresh dedicated bot; Charon requires long polling.")
        updates = call(token, "getUpdates", {"timeout": 0, "allowed_updates": ["message"]})
        ids = set()
        for update in updates or []:
            message = update.get("message", {})
            chat = message.get("chat", {})
            actor = message.get("from", {})
            user = actor.get("id")
            if chat.get("type") == "private" and isinstance(user, int) and user > 0 and user == chat.get("id"):
                ids.add(user)
        if not ids:
            raise SystemExit("No private ID found. Stop Charon, send /start to the test bot, then retry.")
        print("Recent private user IDs (verify your own ID; none is enrolled automatically):")
        for user in sorted(ids):
            print(user)
        return
    if args.user_id is None or args.user_id <= 0:
        parser.error("--user-id must explicitly name a positive private owner ID")
    if args.database is None or not args.database.is_file() or not args.bot_entry_id:
        parser.error("--database and --bot-entry-id are required; provision the KDBX yourself")
    for entry in (args.bot_entry_id, args.first_entry_id, args.second_entry_id):
        try:
            if str(uuid.UUID(entry)) != entry:
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            parser.error("all three entry IDs must be canonical UUIDs")
    password = getpass.getpass("KeePass master password (hidden; child stdin only): ")
    if not password or len(password) > 4096 or "\n" in password or "\r" in password:
        raise SystemExit("Invalid master password input.")
    env = os.environ.copy()
    env.pop("CHARON_TELEGRAM_BOT_TOKEN", None)
    env["CHARON_E2E_TELEGRAM_USER_ID"] = str(args.user_id)
    env["CHARON_E2E_KDBX"] = str(args.database.resolve())
    env["CHARON_E2E_BOT_ENTRY"] = args.bot_entry_id
    env["CHARON_E2E_FIRST_ENTRY"] = args.first_entry_id
    env["CHARON_E2E_SECOND_ENTRY"] = args.second_entry_id
    print("Live test: reads your KDBX without modifying it; sends an unlocked notification and two approval prompts.", flush=True)
    command = ["mise", "exec", "--", "cargo", "test", "--lib", "gateway::e2e::live_telegram_allow_and_deny", "--", "--ignored", "--nocapture"]
    result = subprocess.run(command, env=env, input=password + "\n", text=True, check=False)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit("Live test canceled.") from None
