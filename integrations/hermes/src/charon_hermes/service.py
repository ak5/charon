"""Exact-policy local admission and receipt journal service."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import socketserver
import stat
from threading import Thread
from threading import BoundedSemaphore, Lock
import time
from typing import Any
import uuid

from .canonical import canonical_json, sha256_digest
from .compatibility import HERMES_COMMIT, HERMES_VERSION, PROFILE, classify_tool
from .protocol import MAX_MESSAGE, ProtocolError, receive_message

CLASSIFICATIONS = frozenset({"read", "mutation", "destructive", "secret-sensitive", "unknown"})
IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
TOOL_NAME = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
MAX_CONNECTIONS = 32
MAX_ADMISSIONS = 4096
REQUEST_TIMEOUT_SECONDS = 5

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
        type(operation.get("version")) is int and operation["version"] == 1
        and operation.get("integration") == "hermes"
        and all(_valid_identifier(value) for value in identifiers)
        and isinstance(operation.get("tool_name"), str)
        and bool(TOOL_NAME.fullmatch(operation["tool_name"]))
        and isinstance(operation.get("classification"), str)
        and operation["classification"] in CLASSIFICATIONS
        and isinstance(operation.get("arguments_digest"), str)
        and bool(DIGEST.fullmatch(operation["arguments_digest"]))
        and isinstance(keys, list)
        and len(keys) <= 64
        and all(isinstance(key, str) and bool(ARGUMENT_KEY.fullmatch(key)) for key in keys)
        and len(keys) == len(set(keys))
        and type(operation.get("requested_at")) is int
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
        type(receipt.get("version")) is int and receipt["version"] == 1
        and receipt.get("integration") == "hermes"
        and all(_valid_identifier(value) for value in identifiers)
        and isinstance(receipt.get("tool_name"), str)
        and bool(TOOL_NAME.fullmatch(receipt["tool_name"]))
        and isinstance(receipt.get("classification"), str)
        and receipt["classification"] in CLASSIFICATIONS
        and isinstance(receipt.get("arguments_digest"), str)
        and bool(DIGEST.fullmatch(receipt["arguments_digest"]))
        and (result_digest is None or (isinstance(result_digest, str) and bool(DIGEST.fullmatch(result_digest))))
        and (error_code is None or _valid_identifier(error_code))
        and isinstance(receipt.get("outcome"), str)
        and receipt["outcome"] in {"succeeded", "failed", "interrupted", "unknown"}
        and all(type(receipt.get(key)) is int and receipt[key] >= 0 for key in ("started_at", "finished_at", "duration_ms", "result_size"))
        and receipt.get("raw_output_retained") is False
    )


class Policy:
    """Closed exact-name admission policy."""

    def __init__(self, value: dict[str, Any]):
        if set(value) != {"version", "compatibility", "allowed_tools"} or value.get("version") != 2:
            raise ValueError("policy has unknown or missing fields")
        compatibility = value.get("compatibility")
        expected = {
            "hermes_version": HERMES_VERSION,
            "hermes_commit": HERMES_COMMIT,
            "profile": PROFILE,
        }
        if compatibility != expected:
            raise ValueError("policy compatibility does not match the pinned Hermes profile")
        allowed = value.get("allowed_tools")
        if not isinstance(allowed, list) or len(allowed) > 256:
            raise ValueError("allowed_tools must be a bounded list")
        self._tools: dict[str, str] = {}
        for entry in allowed:
            if not isinstance(entry, dict) or set(entry) != {"name", "classification"}:
                raise ValueError("tool policy has unknown or missing fields")
            name = entry.get("name")
            classification = entry.get("classification")
            if (
                not isinstance(name, str)
                or not name
                or any(symbol in name for symbol in "*?[]")
                or classification not in CLASSIFICATIONS - {"unknown"}
                or classify_tool(name) != classification
            ):
                raise ValueError("tool policy is invalid")
            if name in self._tools:
                raise ValueError("tool policy contains a duplicate exact name")
            self._tools[name] = classification

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
        if classification != allowed:
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
        self._failed = False
        descriptor = os.open(self._path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        self._handle = os.fdopen(descriptor, "r+b")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._handle.close()
            raise ValueError("receipt journal already in use") from None
        try:
            self._recover()
        except BaseException:
            self._handle.close()
            raise

    def _recover(self) -> None:
        file_metadata = os.fstat(self._handle.fileno())
        if not stat.S_ISREG(file_metadata.st_mode) or file_metadata.st_mode & 0o077:
            raise ValueError("receipt journal permissions are too broad")
        handle = self._handle
        end = 0
        while line := handle.readline(MAX_MESSAGE + 1):
            if len(line) > MAX_MESSAGE:
                raise ValueError("receipt journal entry exceeds its bound")
            if not line.endswith(b"\n"):
                handle.truncate(end)
                handle.flush()
                os.fsync(handle.fileno())
                break
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError("receipt journal is corrupt") from error
            if not isinstance(value, dict) or set(value) != {"receipt", "chain_previous", "chain_digest"} or not _valid_receipt(value["receipt"]):
                raise ValueError("receipt journal entry is invalid")
            if value.get("chain_previous") != self._previous:
                raise ValueError("receipt journal chain is broken")
            expected = sha256_digest({
                "receipt": value.get("receipt"),
                "chain_previous": value.get("chain_previous"),
            })
            if value.get("chain_digest") != expected:
                raise ValueError("receipt journal digest is invalid")
            self._previous = expected
            end += len(line)

    def close(self) -> None:
        """Release the journal's exclusive writer lock."""
        with self._lock:
            self._failed = True
            self._handle.close()

    def append(self, receipt: dict[str, Any]) -> None:
        if not _valid_receipt(receipt):
            raise ValueError("receipt is invalid")
        with self._lock:
            if self._failed:
                raise OSError("receipt journal unavailable")
            envelope = {
                "receipt": receipt,
                "chain_previous": self._previous,
            }
            envelope["chain_digest"] = sha256_digest(envelope)
            descriptor = self._handle.fileno()
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                raise ValueError("receipt journal permissions are too broad")
            start = metadata.st_size
            try:
                data = memoryview(canonical_json(envelope) + b"\n")
                while data:
                    written = os.write(descriptor, data)
                    if written <= 0:
                        raise OSError("receipt append made no progress")
                    data = data[written:]
                os.fsync(descriptor)
                parent = os.open(self._path.parent, os.O_RDONLY)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
            except OSError:
                try:
                    os.ftruncate(descriptor, start)
                    os.fsync(descriptor)
                except OSError:
                    self._failed = True
                raise
            self._previous = envelope["chain_digest"]


class Server(socketserver.ThreadingUnixStreamServer):
    """Local exact-policy integration service."""

    daemon_threads = True

    def __init__(self, path: Path, policy: Policy, journal: Journal):
        self.policy = policy
        self.journal = journal
        self._admission_lock = Lock()
        self._connections = BoundedSemaphore(MAX_CONNECTIONS)
        self._seen_operations: dict[str, int] = {}
        self._authorizations: dict[str, tuple[dict[str, Any], int]] = {}
        super().__init__(str(path), Handler)
        os.chmod(path, 0o600)

    def process_request(self, request, client_address) -> None:
        if not self._connections.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connections.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connections.release()

    def server_close(self) -> None:
        super().server_close()
        self.journal.close()

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
            if self.journal._failed or len(self._seen_operations) >= MAX_ADMISSIONS or len(self._authorizations) >= MAX_ADMISSIONS:
                response["reason_code"] = "service-unavailable"
                return response
            if operation_id in self._seen_operations:
                response["reason_code"] = "invalid-request"
                return response
            self._seen_operations[operation_id] = now + 300
            authorization_id = f"authorization:{uuid.uuid4().hex}"
            self._authorizations[authorization_id] = (
                {key: operation[key] for key in (
                    "version", "operation_id", "integration", "session_id", "tool_call_id",
                    "tool_name", "classification", "arguments_digest", "task_id",
                ) if key in operation},
                now + 86400,
            )
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
            if expected is None:
                return False
            if expected[1] <= int(time.time()):
                self._authorizations.pop(authorization_id, None)
                return False
            if any(receipt.get(key) != value for key, value in expected[0].items()) or (
                "task_id" not in expected[0] and "task_id" in receipt
            ):
                return False
            try:
                self.journal.append(receipt)
            except (OSError, ValueError, TypeError):
                return False
            self._authorizations.pop(authorization_id, None)
        return True

    def health(self) -> dict[str, Any]:
        """Return non-sensitive liveness and loaded-policy identity."""

        return {
            "version": 1,
            "status": "unavailable" if self.journal._failed else "ready",
            "hermes_version": HERMES_VERSION,
            "hermes_commit": HERMES_COMMIT,
            "profile": PROFILE,
        }


class Handler(socketserver.StreamRequestHandler):
    """Handle one bounded integration protocol request."""

    def handle(self) -> None:
        deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
        try:
            message = receive_message(self.request, deadline)
            kind = message.get("kind")
            if kind == "admit" and set(message) == {"kind", "operation"}:
                self._admit(message["operation"])
            elif kind == "receipt" and set(message) == {"kind", "receipt"}:
                self._receipt(message["receipt"])
            elif kind == "health" and set(message) == {"kind"}:
                self._send(self.server.health())  # type: ignore[attr-defined]
            else:
                self._send({"error": "invalid-request", "version": 1})
        except (ProtocolError, OSError, TimeoutError):
            return

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
