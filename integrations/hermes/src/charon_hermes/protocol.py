"""Bounded Unix-socket protocol used by the Hermes plugin."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
import time
from typing import Any

from .canonical import canonical_json

MAX_MESSAGE = 64 * 1024


class ProtocolError(RuntimeError):
    """A closed, data-free local protocol failure."""


def validate_socket(path: Path) -> None:
    """Require an operator-owned Unix socket with no access for other users."""

    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProtocolError("admission service unavailable") from error
    if not stat.S_ISSOCK(metadata.st_mode):
        raise ProtocolError("admission endpoint is not a socket")
    if metadata.st_uid != os.getuid():
        raise ProtocolError("admission socket owner mismatch")
    if metadata.st_mode & 0o077:
        raise ProtocolError("admission socket permissions are too broad")


def request(path: Path, payload: dict[str, Any], timeout_ms: int) -> dict[str, Any]:
    """Exchange one newline-delimited JSON message over a Unix socket."""

    validate_socket(path)
    encoded = canonical_json(payload) + b"\n"
    if len(encoded) > MAX_MESSAGE:
        raise ProtocolError("local request is too large")
    deadline = time.monotonic() + timeout_ms / 1000
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(max(0.001, deadline - time.monotonic()))
        client.connect(str(path))
        client.settimeout(max(0.001, deadline - time.monotonic()))
        client.sendall(encoded)
        return receive_message(client, deadline)
    except (OSError, TimeoutError) as error:
        raise ProtocolError("admission service unavailable") from error
    finally:
        client.close()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def receive_message(connection: socket.socket, deadline: float) -> dict[str, Any]:
    """Read one bounded message within an absolute monotonic deadline."""

    chunks = bytearray()
    while b"\n" not in chunks:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProtocolError("local message timed out")
        connection.settimeout(remaining)
        chunk = connection.recv(min(4096, MAX_MESSAGE + 1 - len(chunks)))
        if not chunk:
            raise ProtocolError("local message ended early")
        chunks.extend(chunk)
        if len(chunks) > MAX_MESSAGE:
            raise ProtocolError("local message is too large")
    line, _, trailing = bytes(chunks).partition(b"\n")
    if trailing:
        raise ProtocolError("local message contains trailing data")
    try:
        value = json.loads(line, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, ValueError, RecursionError) as error:
        raise ProtocolError("local message is invalid") from error
    if not isinstance(value, dict):
        raise ProtocolError("local message is invalid")
    return value
