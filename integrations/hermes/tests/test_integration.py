"""Tests for the Charon Hermes permission and receipt boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from threading import Thread
import unittest

from charon_hermes.admission import AdmissionClient
from charon_hermes.config import Settings
from charon_hermes.model import Operation, receipt_for
from charon_hermes.plugin import CharonHermesPlugin, register
from charon_hermes.service import Journal, Policy, Server


class FakeContext:
    """Minimal Hermes registration surface."""

    def __init__(self) -> None:
        self.hooks: dict[str, object] = {}

    def register_hook(self, name: str, callback: object) -> None:
        self.hooks[name] = callback


class ServiceFixture:
    """Run a protected local admission service for one test."""

    def __init__(self, root: Path) -> None:
        self.socket_path = root / "admission.sock"
        self.state = root / "state"
        self.policy = Policy(
            {
                "version": 1,
                "allowed_tools": [
                    {"name": "read_file", "classifications": ["read"]},
                    {"name": "write_file", "classifications": ["mutation"]},
                ],
            }
        )
        self.server = Server(self.socket_path, self.policy, Journal(self.state))
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.socket_path.unlink(missing_ok=True)


class ModelTests(unittest.TestCase):
    def test_operation_contains_only_argument_keys_and_digest(self) -> None:
        operation = Operation.create(
            "terminal",
            {"command": "token=do-not-store"},
            "task-1",
            "call-1",
            "session-1",
        )
        serialized = json.dumps(operation.value)
        self.assertNotIn("do-not-store", serialized)
        self.assertEqual(operation.value["argument_keys"], ["command"])
        self.assertEqual(operation.value["classification"], "secret-sensitive")

    def test_receipt_does_not_retain_result(self) -> None:
        operation = Operation.create("read_file", {"path": "safe"}, "task", "call", "session")
        receipt = receipt_for(
            operation,
            "authorization:1234567890abcdef",
            '{"secret":"do-not-store"}',
            4,
            False,
        )
        serialized = json.dumps(receipt)
        self.assertNotIn("do-not-store", serialized)
        self.assertFalse(receipt["raw_output_retained"])
        self.assertNotIn("result_digest", receipt)


class PolicyTests(unittest.TestCase):
    def test_policy_is_exact_and_rejects_wildcards(self) -> None:
        with self.assertRaises(ValueError):
            Policy(
                {
                    "version": 1,
                    "allowed_tools": [{"name": "read_*", "classifications": ["read"]}],
                }
            )

    def test_unknown_tool_is_denied(self) -> None:
        policy = Policy(
            {
                "version": 1,
                "allowed_tools": [{"name": "read_file", "classifications": ["read"]}],
            }
        )
        operation = Operation.create("terminal", {}, "task", "call", "session")
        self.assertEqual(policy.decide(operation.value), (False, "tool-not-allowed"))


class IntegrationTests(unittest.TestCase):
    def test_unavailable_service_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = Settings(Path(temporary) / "missing.sock")
            operation = Operation.create("read_file", {}, "task", "call", "session")
            decision = AdmissionClient(settings).admit(operation)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason_code, "service-unavailable")

    def test_plugin_admits_exact_tool_and_journals_metadata_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = ServiceFixture(root)
            try:
                plugin = CharonHermesPlugin(Settings(fixture.socket_path, timeout_ms=500))
                decision = plugin.pre_tool_call(
                    "read_file",
                    {"path": "/tmp/example"},
                    "task-1",
                    tool_call_id="call-1",
                    session_id="session-1",
                )
                self.assertIsNone(decision)
                plugin.post_tool_call(
                    "read_file",
                    {"path": "/tmp/example"},
                    '{"content":"sensitive result"}',
                    "task-1",
                    3,
                    tool_call_id="call-1",
                    session_id="session-1",
                )
                self.assertTrue(plugin._exporter.flush())
                lines = (fixture.state / "tool-receipts.jsonl").read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(lines), 1)
                self.assertNotIn("sensitive result", lines[0])
                envelope = json.loads(lines[0])
                self.assertEqual(envelope["receipt"]["tool_name"], "read_file")
                self.assertEqual(envelope["receipt"]["outcome"], "succeeded")
                self.assertTrue(envelope["chain_digest"].startswith("sha256:"))
            finally:
                fixture.close()

    def test_plugin_blocks_tool_not_in_exact_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ServiceFixture(Path(temporary))
            try:
                plugin = CharonHermesPlugin(Settings(fixture.socket_path, timeout_ms=500))
                decision = plugin.pre_tool_call("terminal", {"command": "true"}, "task")
                self.assertEqual(decision, {
                    "action": "block",
                    "message": "Charon denied this tool call (tool-not-allowed).",
                })
            finally:
                fixture.close()

    def test_finalize_records_interrupted_admitted_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ServiceFixture(Path(temporary))
            try:
                plugin = CharonHermesPlugin(Settings(fixture.socket_path, timeout_ms=500))
                self.assertIsNone(plugin.pre_tool_call("read_file", {"path": "safe"}, "task"))
                plugin.finalize()
                line = (fixture.state / "tool-receipts.jsonl").read_text(encoding="utf-8")
                self.assertEqual(json.loads(line)["receipt"]["outcome"], "interrupted")
            finally:
                fixture.close()

    def test_receipt_with_unknown_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            journal = Journal(root / "state")
            operation = Operation.create("read_file", {}, "task", "call", "session")
            receipt = receipt_for(
                operation,
                "authorization:1234567890abcdef",
                "{}",
                1,
                False,
            )
            receipt["raw_output"] = "must-not-cross"
            with self.assertRaises(ValueError):
                journal.append(receipt)

    def test_missing_configuration_registers_only_a_blocking_hook(self) -> None:
        previous = os.environ.pop("CHARON_HERMES_ADMISSION_SOCKET", None)
        try:
            context = FakeContext()
            register(context)
            self.assertEqual(set(context.hooks), {"pre_tool_call"})
            callback = context.hooks["pre_tool_call"]
            result = callback(tool_name="read_file")  # type: ignore[operator]
            self.assertEqual(result["action"], "block")
        finally:
            if previous is not None:
                os.environ["CHARON_HERMES_ADMISSION_SOCKET"] = previous


if __name__ == "__main__":
    unittest.main()
