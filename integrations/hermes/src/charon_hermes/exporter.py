"""Bounded asynchronous receipt exporter."""

from __future__ import annotations

from queue import Empty, Full, Queue
from threading import Event, Thread
import time
from typing import Any

from .config import Settings
from .protocol import ProtocolError, request


class ReceiptExporter:
    """Send metadata-only receipts without delaying Hermes tool results."""

    def __init__(self, settings: Settings):
        self._settings = settings
        self._queue: Queue[dict[str, Any]] = Queue(maxsize=settings.queue_size)
        self._stop = Event()
        self._dropped = 0
        self._worker = Thread(target=self._run, name="charon-hermes-receipts", daemon=True)
        self._worker.start()

    @property
    def dropped(self) -> int:
        """Return the number of receipts rejected by bounded backpressure."""

        return self._dropped

    def submit(self, receipt: dict[str, Any]) -> bool:
        """Queue a receipt without blocking the tool-result path."""

        try:
            self._queue.put_nowait(receipt)
        except Full:
            self._dropped += 1
            return False
        return True

    def flush(self, timeout: float = 2.0) -> bool:
        """Wait for queued receipts to be acknowledged within a bound."""

        deadline = time.monotonic() + max(0, timeout)
        with self._queue.all_tasks_done:
            while self._queue.unfinished_tasks:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._queue.all_tasks_done.wait(remaining)
        return True

    def close(self) -> None:
        """Flush and stop the exporter."""

        self.flush()
        self._stop.set()
        self._worker.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.is_set() or not self._queue.empty():
            try:
                receipt = self._queue.get(timeout=0.1)
            except Empty:
                continue
            try:
                response = request(
                    self._settings.admission_socket,
                    {"kind": "receipt", "receipt": receipt},
                    self._settings.timeout_ms,
                )
                if response != {"accepted": True, "version": 1}:
                    self._dropped += 1
            except ProtocolError:
                self._dropped += 1
            finally:
                self._queue.task_done()
