"""Fail-closed tool admission client."""

from __future__ import annotations

from dataclasses import dataclass
import re
import time

from .config import Settings
from .model import Operation
from .protocol import ProtocolError, request

_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
_REASONS = frozenset({
    "exact-policy-match",
    "tool-not-allowed",
    "classification-not-allowed",
    "unknown-operation",
    "invalid-request",
    "service-unavailable",
})


@dataclass(frozen=True, slots=True)
class Admission:
    """Validated local admission result."""

    allowed: bool
    reason_code: str
    authorization_id: str = ""


class AdmissionClient:
    """Request exact tool admission from the protected local service."""

    def __init__(self, settings: Settings):
        self._settings = settings

    def admit(self, operation: Operation) -> Admission:
        try:
            response = request(
                self._settings.admission_socket,
                {"kind": "admit", "operation": operation.value},
                self._settings.timeout_ms,
            )
        except ProtocolError:
            return Admission(False, "service-unavailable")
        if set(response) - {
            "version",
            "operation_id",
            "decision",
            "reason_code",
            "authorization_id",
            "expires_at",
        }:
            return Admission(False, "invalid-request")
        if response.get("version") != 1 or response.get("operation_id") != operation.value["operation_id"]:
            return Admission(False, "invalid-request")
        reason = response.get("reason_code")
        if reason not in _REASONS:
            return Admission(False, "invalid-request")
        if response.get("decision") != "allow":
            return Admission(False, reason)
        authorization_id = response.get("authorization_id")
        expires_at = response.get("expires_at")
        now = int(time.time())
        if (
            not isinstance(authorization_id, str)
            or not _IDENTIFIER.fullmatch(authorization_id)
            or not isinstance(expires_at, int)
            or expires_at <= now
            or expires_at > now + 300
        ):
            return Admission(False, "invalid-request")
        return Admission(True, reason, authorization_id)
