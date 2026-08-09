"""Closed tool-operation and receipt models."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import time
from typing import Any
import uuid

from .canonical import sha256_digest

_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_TOOL_NAME = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

READ_TOOLS = frozenset({
    "read_file",
    "search_files",
    "web_search",
    "web_extract",
    "session_search",
    "skills_list",
})
MUTATION_TOOLS = frozenset({"write_file", "patch", "send_message", "cronjob"})
DESTRUCTIVE_TOOLS = frozenset({"delete_file"})
SECRET_TOOLS = frozenset({"terminal", "execute_code", "process"})


def _identifier(value: str, fallback_prefix: str) -> str:
    if _IDENTIFIER.fullmatch(value):
        return value
    return f"{fallback_prefix}:{uuid.uuid4().hex}"


def classify_tool(tool_name: str) -> str:
    """Classify known Hermes tools without interpreting model-supplied text."""

    if tool_name in READ_TOOLS:
        return "read"
    if tool_name in MUTATION_TOOLS:
        return "mutation"
    if tool_name in DESTRUCTIVE_TOOLS:
        return "destructive"
    if tool_name in SECRET_TOOLS:
        return "secret-sensitive"
    return "unknown"


@dataclass(frozen=True, slots=True)
class Operation:
    """Normalized metadata-only Hermes operation."""

    value: dict[str, Any]

    @classmethod
    def create(
        cls,
        tool_name: str,
        arguments: dict[str, Any],
        task_id: str,
        tool_call_id: str,
        session_id: str,
    ) -> "Operation":
        if not _TOOL_NAME.fullmatch(tool_name):
            tool_name = "invalid-tool-name"
        now = int(time.time())
        value: dict[str, Any] = {
            "version": 1,
            "operation_id": f"op:{uuid.uuid4().hex}",
            "integration": "hermes",
            "session_id": _identifier(session_id or task_id, "session"),
            "tool_call_id": _identifier(tool_call_id, "call"),
            "tool_name": tool_name,
            "classification": classify_tool(tool_name),
            "arguments_digest": sha256_digest(arguments),
            "argument_keys": sorted(
                key for key in arguments if re.fullmatch(r"[A-Za-z0-9._-]{1,128}", key)
            )[:64],
            "requested_at": now,
        }
        if task_id:
            value["task_id"] = _identifier(task_id, "task")
        return cls(value)


def receipt_for(
    operation: Operation,
    authorization_id: str,
    result: str,
    duration_ms: int,
    include_result_digest: bool,
    outcome: str = "succeeded",
) -> dict[str, Any]:
    """Create a compact receipt without retaining raw tool output."""

    finished = int(time.time())
    duration = max(0, int(duration_ms))
    receipt = {
        "version": 1,
        "receipt_id": f"receipt:{uuid.uuid4().hex}",
        "operation_id": operation.value["operation_id"],
        "integration": "hermes",
        "session_id": operation.value["session_id"],
        "tool_call_id": operation.value["tool_call_id"],
        "tool_name": operation.value["tool_name"],
        "classification": operation.value["classification"],
        "arguments_digest": operation.value["arguments_digest"],
        "authorization_id": authorization_id,
        "started_at": max(0, finished - ((duration + 999) // 1000)),
        "finished_at": finished,
        "duration_ms": duration,
        "outcome": outcome,
        "result_size": len(result.encode("utf-8", errors="replace")),
        "raw_output_retained": False,
    }
    if "task_id" in operation.value:
        receipt["task_id"] = operation.value["task_id"]
    try:
        parsed = json.loads(result)
    except (json.JSONDecodeError, TypeError):
        parsed = None
    if outcome == "succeeded" and isinstance(parsed, dict) and (
        parsed.get("error") is not None or parsed.get("success") is False
    ):
        receipt["outcome"] = "failed"
        receipt["error_code"] = "tool-error"
    if include_result_digest:
        receipt["result_digest"] = sha256_digest(result)
    return receipt
