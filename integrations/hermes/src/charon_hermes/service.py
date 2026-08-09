"""Exact-policy local admission and receipt journal service."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import signal
import socketserver
import stat
from threading import Thread
from threading import Lock
import time
from typing import Any
import uuid

from .canonical import canonical_json, sha256_digest
from .protocol import MAX_MESSAGE

CLASSIFICATIONS = frozenset({"read", "mutation", "destructive", "secret-sensitive", "unknown"})
IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TOOL_NAME = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
ARGUMENT_KEY = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def _valid_identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(IDENTIFIER.fullmatch(value))


def _valid_operation(operation: Any) -> bool:
    if not isinstance(operation, dict):
        return False
    required = {
        "version",
        "operation_id",
        "integration",
        "session_id",
        "tool_call_id",
        "tool_name",
        "classification",
        "arguments_digest",
        "argument_keys",
        "requested_at",
    }
    if not required <= set(operation) or set(operation) - (required | {"task_id"}):
        return False
    identifiers = [operation.get(key) for key in ("operation_id", "session_id", "tool_call_id")]
    if "task_id" in operation:
        identifiers.append(operation["task_id"])
    keys = operation.get("argument_keys")
    return (
        operation.get("version") == 1
        and operation.get("integration") == "hermes"
        and all(_valid_identifier(value) for value in identifiers)
        and isinstance(operation.get("tool_name"), str)
        and bool(TOOL_NAME.fullmatch(operation["tool_name"]))
        and operation.get("classification") in CLASSIFICATIONS
        and isinstance(operation.get("arguments_digest"), str)
        and bool(DIGEST.fullmatch(operation["arguments_digest"]))
        and isinstance(keys, list)
        and len(keys) <= 64
        and len(keys) == len(set(keys))
        and all(isinstance(key, str) and bool(ARGUMENT_KEY.fullmatch(key)) for key in keys)
        and isinstance(operation.get("requested_at"), int)
        and operation["requested_at"] >= 0
    )


def _valid_receipt(receipt: Any) -> bool:
    if not isinstance(receipt, dict):
        return False
    required = {
        "version",
        "receipt_id",
        "operation_id",
        "integration",
        "session_id",
        "tool_call_id",
        "tool_name",
        "classification",
        "arguments_digest",
        "authorization_id",
        "started_at",
        "finished_at",
        "duration_ms",
        "outcome",
        "result_size",
        "raw_output_retained",
    }
    optional = {"task_id", "result_digest", "error_code"}
    if not required <= set(receipt) or set(receipt) - (required | optional):
        return False
    identifiers = [
        receipt.get(key)
        for key in ("receipt_id", "operation_id", "session_id", "tool_call_id", "authorization_id")
    ]
    if "task_id" in receipt:
        identifiers.append(receipt["task_id"])
    result_digest = receipt.get("result_digest")
    error_code = receipt.get("error_code")
    return (
        receipt.get("version") == 1
        and receipt.get("integration") == "hermes"
        and all(_valid_identifier(value) for value in identifiers)
        and isinstance(receipt.get("tool_name"), str)
        and bool(TOOL_NAME.fullmatch(receipt["tool_name"]))
        and receipt.get("classification") in CLASSIFICATIONS
        and isinstance(receipt.get("arguments_digest"), str)
        and bool(DIGEST.fullmatch(receipt["arguments_digest"]))
        and (result_digest is None or (isinstance(result_digest, str) and bool(DIGEST.fullmatch(result_digest))))
        and (error_code is None or _valid_identifier(error_code))
        and receipt.get("outcome") in {"succeeded", "failed", "interrupted", "unknown"}
        and all(isinstance(receipt.get(key), int) and receipt[key] >= 0 for key in ("started_at", "finished_at", "duration_ms", "result_size"))
        and receipt.get("raw_output_retained") is False
    )


class Policy:
    """Closed exact-name admission policy."""

    def __init__(self, value: dict[str, Any]):
        if set(value) != {"version", "allowed_tools"} or value.get("version") != 1:
            raise ValueError("policy has unknown or missing fields")
        allowed = value.get("allowed_tools")
        if not isinstance(allowed, list) or len(allowed) > 256:
            raise ValueError("allowed_tools must be a bounded list")
        self._tools: dict[str, frozenset[str]] = {}
        for entry in allowed:
            if not isinstance(entry, dict) or set(entry) != {"name", "classifications"}:
                raise ValueError("tool policy has unknown or missing fields")
            name = entry.get("name")
            classifications = entry.get("classifications")
            if (
                not isinstance(name, str)
                or not name
                or any(symbol in name for symbol in "*?[]")
                or not isinstance(classifications, list)
                or not classifications
                or not set(classifications) <= CLASSIFICATIONS
            ):
                raise ValueError("tool policy is invalid")
            if name in self._tools:
                raise ValueError("tool policy contains a duplicate exact name")
            self._tools[name] = frozenset(classifications)

    @classmethod
    def load(cls, path: Path) -> "Policy":
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
            raise ValueError("policy must be a non-writable regular file")
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
        if not isinstance(value, dict):
            raise ValueError("policy root must be an object")
        return cls(value)

    def decide(self, operation: dict[str, Any]) -> tuple[bool, str]:
        if not _valid_operation(operation):
            return False, "invalid-request"
        tool = operation.get("tool_name")
        classification = operation.get("classification")
        allowed = self._tools.get(tool)
        if allowed is None:
            return False, "tool-not-allowed"
        if classification not in allowed:
            return False, "classification-not-allowed"
        return True, "exact-policy-match"


class Journal:
    """Append metadata-only receipts to a hash-chained local journal."""

    def __init__(self, directory: Path):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077:
            raise ValueError("receipt state directory permissions are too broad")
        self._path = directory / "tool-receipts.jsonl"
        self._previous = "sha256:" + ("0" * 64)
        self._lock = Lock()
        if self._path.exists():
            file_metadata = self._path.lstat()
            if not stat.S_ISREG(file_metadata.st_mode) or file_metadata.st_mode & 0o077:
                raise ValueError("receipt journal permissions are too broad")
            with self._path.open("rb") as handle:
                for line in handle:
                    try:
                        value = json.loads(line)
                    except json.JSONDecodeError as error:
                        raise ValueError("receipt journal is corrupt") from error
                    if value.get("chain_previous") != self._previous:
                        raise ValueError("receipt journal chain is broken")
                    expected = sha256_digest({
                        "receipt": value.get("receipt"),
                        "chain_previous": value.get("chain_previous"),
                    })
                    if value.get("chain_digest") != expected:
                        raise ValueError("receipt journal digest is invalid")
                    self._previous = expected

    def append(self, receipt: dict[str, Any]) -> None:
        if not _valid_receipt(receipt):
            raise ValueError("receipt is invalid")
        with self._lock:
            envelope = {
                "receipt": receipt,
                "chain_previous": self._previous,
            }
            envelope["chain_digest"] = sha256_digest(envelope)
            flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(self._path, flags, 0o600)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                    raise ValueError("receipt journal permissions are too broad")
                os.write(descriptor, canonical_json(envelope) + b"\n")
            finally:
                os.close(descriptor)
            self._previous = envelope["chain_digest"]


class Server(socketserver.ThreadingUnixStreamServer):
    """Local exact-policy integration service."""

    daemon_threads = True

    def __init__(self, path: Path, policy: Policy, journal: Journal):
        self.policy = policy
        self.journal = journal
        self._admission_lock = Lock()
        self._seen_operations: dict[str, int] = {}
        self._authorizations: dict[str, tuple[str, int]] = {}
        super().__init__(str(path), Handler)
        os.chmod(path, 0o600)

    def admit(self, operation: Any) -> dict[str, Any]:
        """Evaluate and atomically consume one operation identifier."""

        allowed, reason = self.policy.decide(operation)
        operation_id = operation.get("operation_id", "invalid") if isinstance(operation, dict) else "invalid"
        response: dict[str, Any] = {
            "version": 1,
            "operation_id": operation_id,
            "decision": "deny",
            "reason_code": reason,
        }
        if not allowed:
            return response
        now = int(time.time())
        requested_at = operation["requested_at"]
        if abs(now - requested_at) > 30:
            response["reason_code"] = "invalid-request"
            return response
        with self._admission_lock:
            self._seen_operations = {
                key: expiry for key, expiry in self._seen_operations.items() if expiry >= now
            }
            self._authorizations = {
                key: value for key, value in self._authorizations.items() if value[1] >= now
            }
            if operation_id in self._seen_operations:
                response["reason_code"] = "invalid-request"
                return response
            self._seen_operations[operation_id] = now + 300
            authorization_id = f"authorization:{uuid.uuid4().hex}"
            self._authorizations[authorization_id] = (operation_id, now + 86400)
        response.update({
            "decision": "allow",
            "reason_code": "exact-policy-match",
            "authorization_id": authorization_id,
            "expires_at": now + 300,
        })
        return response

    def accept_receipt(self, receipt: Any) -> bool:
        """Consume one authorization and append its matching receipt."""

        if not _valid_receipt(receipt):
            return False
        authorization_id = receipt["authorization_id"]
        with self._admission_lock:
            expected = self._authorizations.get(authorization_id)
            if expected is None or expected[0] != receipt["operation_id"]:
                return False
            try:
                self.journal.append(receipt)
            except (OSError, ValueError, TypeError):
                return False
            self._authorizations.pop(authorization_id, None)
        return True


class Handler(socketserver.StreamRequestHandler):
    """Handle one bounded integration protocol request."""

    def handle(self) -> None:
        line = self.rfile.readline(MAX_MESSAGE + 1)
        if len(line) > MAX_MESSAGE or not line.endswith(b"\n"):
            self._send({"error": "invalid-request", "version": 1})
            return
        try:
            message = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send({"error": "invalid-request", "version": 1})
            return
        if not isinstance(message, dict) or set(message) not in (
            {"kind", "operation"},
            {"kind", "receipt"},
        ):
            self._send({"error": "invalid-request", "version": 1})
            return
        if message["kind"] == "admit":
            self._admit(message["operation"])
        elif message["kind"] == "receipt":
            self._receipt(message["receipt"])
        else:
            self._send({"error": "invalid-request", "version": 1})

    def _admit(self, operation: dict[str, Any]) -> None:
        self._send(self.server.admit(operation))  # type: ignore[attr-defined]

    def _receipt(self, receipt: dict[str, Any]) -> None:
        accepted = self.server.accept_receipt(receipt)  # type: ignore[attr-defined]
        self._send({"accepted": accepted, "version": 1})

    def _send(self, value: dict[str, Any]) -> None:
        self.wfile.write(canonical_json(value) + b"\n")


def main() -> None:
    """Run the local admission and receipt service."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    args = parser.parse_args()
    if not args.socket.is_absolute() or not args.state_dir.is_absolute():
        parser.error("--socket and --state-dir must be absolute paths")
    if args.socket.exists():
        parser.error("socket path already exists")
    policy = Policy.load(args.policy)
    journal = Journal(args.state_dir)
    server = Server(args.socket, policy, journal)

    def stop(signum: int, frame: object) -> None:
        del signum, frame
        Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        args.socket.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
