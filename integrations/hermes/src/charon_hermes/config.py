"""Environment-backed integration configuration."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated settings for the Hermes plugin."""

    admission_socket: Path
    timeout_ms: int = 250
    queue_size: int = 1024
    include_result_digest: bool = False

    @classmethod
    def from_environment(cls) -> "Settings":
        """Load settings, requiring an absolute local admission socket."""

        raw_socket = os.environ.get("CHARON_HERMES_ADMISSION_SOCKET", "")
        if not raw_socket:
            raise ValueError("CHARON_HERMES_ADMISSION_SOCKET is required")
        socket_path = Path(raw_socket)
        if not socket_path.is_absolute():
            raise ValueError("CHARON_HERMES_ADMISSION_SOCKET must be absolute")
        digest = os.environ.get("CHARON_HERMES_RESULT_DIGESTS", "0")
        if digest not in {"0", "1"}:
            raise ValueError("CHARON_HERMES_RESULT_DIGESTS must be 0 or 1")
        return cls(
            admission_socket=socket_path,
            timeout_ms=_bounded_int("CHARON_HERMES_TIMEOUT_MS", 250, 10, 5000),
            queue_size=_bounded_int("CHARON_HERMES_QUEUE_SIZE", 1024, 16, 65536),
            include_result_digest=digest == "1",
        )
