"""Generate, validate, and probe the pinned Charon-Hermes deployment."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .canonical import canonical_json
from .compatibility import HERMES_COMMIT, HERMES_VERSION, PROFILE, policy_document
from .protocol import ProtocolError, request
from .service import Policy


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("generate", help="write the exact recommended policy to stdout")
    validate = commands.add_parser("validate", help="validate a policy for the pinned profile")
    validate.add_argument("policy", type=Path)
    validate.add_argument(
        "--recommended", action="store_true",
        help="also require every deployment-profile tool",
    )
    health = commands.add_parser("health", help="check admission-service readiness")
    health.add_argument("--socket", required=True, type=Path)
    health.add_argument("--timeout-ms", type=int, default=250)
    return parser


def main() -> None:
    args = _parser().parse_args()
    if args.command == "generate":
        sys.stdout.buffer.write(canonical_json(policy_document()) + b"\n")
        return
    if args.command == "validate":
        Policy.load(args.policy)
        value = json.loads(args.policy.read_text(encoding="utf-8"))
        if args.recommended and value != policy_document():
            raise SystemExit("policy is valid but differs from the reviewed recommended policy")
        print(f"valid: {HERMES_VERSION} {HERMES_COMMIT} {PROFILE}")
        return
    if not args.socket.is_absolute() or not 10 <= args.timeout_ms <= 5000:
        raise SystemExit("health socket must be absolute and timeout must be 10-5000 ms")
    try:
        response = request(args.socket, {"kind": "health"}, args.timeout_ms)
    except ProtocolError as error:
        raise SystemExit(f"not ready: {error}") from error
    expected = {
        "version": 1, "status": "ready", "hermes_version": HERMES_VERSION,
        "hermes_commit": HERMES_COMMIT, "profile": PROFILE,
    }
    if response != expected:
        raise SystemExit("not ready: incompatible admission response")
    print(f"ready: {HERMES_VERSION} {PROFILE}")
