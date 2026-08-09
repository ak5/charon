"""Hermes lifecycle-hook adapter."""

from __future__ import annotations

from collections import defaultdict, deque
from threading import Lock
from typing import Any

from .admission import AdmissionClient
from .config import Settings
from .exporter import ReceiptExporter
from .model import Operation, receipt_for


class CharonHermesPlugin:
    """Correlate Hermes tool calls with admissions and receipts."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._admission = AdmissionClient(settings)
        self._exporter = ReceiptExporter(settings)
        self._pending: dict[tuple[str, str, str], deque[tuple[Operation, str]]] = defaultdict(deque)
        self._lock = Lock()

    @staticmethod
    def _arguments(args: Any, kwargs: dict[str, Any]) -> dict[str, Any]:
        candidate = args
        if candidate is None:
            candidate = kwargs.get("params", kwargs.get("arguments", {}))
        return candidate if isinstance(candidate, dict) else {}

    @staticmethod
    def _call_id(kwargs: dict[str, Any]) -> str:
        value = kwargs.get("tool_call_id", "")
        return value if isinstance(value, str) else ""

    @staticmethod
    def _session_id(task_id: str, kwargs: dict[str, Any]) -> str:
        value = kwargs.get("session_id", task_id)
        return value if isinstance(value, str) else task_id

    def _pending_key(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        task_id: str,
        kwargs: dict[str, Any],
    ) -> tuple[str, str, str]:
        from .canonical import sha256_digest

        call_id = self._call_id(kwargs)
        if call_id:
            return ("call", call_id, "")
        return (self._session_id(task_id, kwargs), tool_name, sha256_digest(arguments))

    def pre_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        task_id: str = "",
        **kwargs: Any,
    ) -> dict[str, str] | None:
        """Admit one exact normalized tool call or block it safely."""

        arguments = self._arguments(args, kwargs)
        try:
            operation = Operation.create(
                tool_name=tool_name,
                arguments=arguments,
                task_id=task_id,
                tool_call_id=self._call_id(kwargs),
                session_id=self._session_id(task_id, kwargs),
            )
        except (TypeError, ValueError):
            return {
                "action": "block",
                "message": "Charon denied this tool call (invalid-request).",
            }
        admission = self._admission.admit(operation)
        if not admission.allowed:
            return {
                "action": "block",
                "message": f"Charon denied this tool call ({admission.reason_code}).",
            }
        key = self._pending_key(tool_name, arguments, task_id, kwargs)
        with self._lock:
            self._pending[key].append((operation, admission.authorization_id))
        return None

    def post_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        result: str = "",
        task_id: str = "",
        duration_ms: int = 0,
        **kwargs: Any,
    ) -> None:
        """Create a metadata-only receipt for an admitted call."""

        arguments = self._arguments(args, kwargs)
        key = self._pending_key(tool_name, arguments, task_id, kwargs)
        with self._lock:
            queue = self._pending.get(key)
            pending = queue.popleft() if queue else None
            if queue is not None and not queue:
                self._pending.pop(key, None)
        if pending is None:
            return
        operation, authorization_id = pending
        receipt = receipt_for(
            operation,
            authorization_id,
            result if isinstance(result, str) else "",
            duration_ms,
            self._settings.include_result_digest,
        )
        self._exporter.submit(receipt)

    def finalize(self, **kwargs: Any) -> None:
        """Bound receipt flushing at Hermes session finalization."""

        del kwargs
        with self._lock:
            interrupted = [pending for queue in self._pending.values() for pending in queue]
            self._pending.clear()
        for operation, authorization_id in interrupted:
            self._exporter.submit(
                receipt_for(
                    operation,
                    authorization_id,
                    "",
                    0,
                    False,
                    outcome="interrupted",
                )
            )
        self._exporter.flush()


def register(ctx: Any) -> None:
    """Register the Charon integration with Hermes Agent."""

    try:
        plugin = CharonHermesPlugin(Settings.from_environment())
    except ValueError as error:
        message = str(error)

        def block_unconfigured(**kwargs: Any) -> dict[str, str]:
            del kwargs
            return {"action": "block", "message": f"Charon integration unavailable: {message}"}

        ctx.register_hook("pre_tool_call", block_unconfigured)
        return
    ctx.register_hook("pre_tool_call", plugin.pre_tool_call)
    ctx.register_hook("post_tool_call", plugin.post_tool_call)
    ctx.register_hook("on_session_finalize", plugin.finalize)
