"""Bounded canonical JSON and digest helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON for closed integration objects."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_digest(value: Any) -> str:
    """Return a namespaced SHA-256 digest of a JSON-compatible value."""

    return f"sha256:{hashlib.sha256(canonical_json(value)).hexdigest()}"
