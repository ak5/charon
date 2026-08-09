"""Bounded Unix-socket protocol used by the Hermes plugin."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import stat
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
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout_ms / 1000)
    try:
        client.connect(str(path))
        client.sendall(encoded)
        chunks = bytearray()
        while b"\n" not in chunks:
            chunk = client.recv(4096)
            if not chunk:
                raise ProtocolError("local response ended early")
            chunks.extend(chunk)
            if len(chunks) > MAX_MESSAGE:
                raise ProtocolError("local response is too large")
    except (OSError, TimeoutError) as error:
        raise ProtocolError("admission service unavailable") from error
    finally:
        client.close()
    line, _, trailing = bytes(chunks).partition(b"\n")
    if trailing:
        raise ProtocolError("local response contains trailing data")
    try:
        value = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("local response is invalid") from error
    if not isinstance(value, dict):
        raise ProtocolError("local response is invalid")
    return value
