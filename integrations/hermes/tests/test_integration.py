"""Tests for the Charon Hermes permission and receipt boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import tempfile
from threading import Thread
import time
import unittest
from unittest.mock import patch

from charon_hermes.admission import AdmissionClient
from charon_hermes.config import Settings
from charon_hermes.external_tools import BOTYARD_BROWSER
from charon_hermes.compatibility import CLASSIFICATIONS, DEPLOYMENT_TOOLS, classify_tool, policy_document
from charon_hermes.model import Operation, receipt_for
from charon_hermes.plugin import CharonHermesPlugin, register
from charon_hermes.service import Journal, Policy, Server
from charon_hermes.protocol import ProtocolError, receive_message, request


class FakeContext:
    """Minimal Hermes registration surface."""

    def __init__(self) -> None:
        self.hooks: dict[str, object] = {}

    def register_hook(self, name: str, callback: object) -> None:
        self.hooks[name] = callback


class ServiceFixture:
    """Run a protected local admission service for one test."""

    def __init__(self, root: Path, policy: Policy | None = None) -> None:
        self.socket_path = root / "admission.sock"
        self.state = root / "state"
        value = policy_document()
        value["allowed_tools"] = [
            {"name": "read_file", "classification": "read"},
            {"name": "write_file", "classification": "mutation"},
        ]
        self.policy = policy if policy is not None else Policy(value)
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
                    **policy_document(),
                    "allowed_tools": [{"name": "read_*", "classification": "read"}],
                }
            )

    def test_unknown_tool_is_denied(self) -> None:
        value = policy_document()
        value["allowed_tools"] = [{"name": "read_file", "classification": "read"}]
        policy = Policy(value)
        operation = Operation.create("terminal", {}, "task", "call", "session")
        self.assertEqual(policy.decide(operation.value), (False, "tool-not-allowed"))


class ExternalToolTests(unittest.TestCase):
    names = tuple(
        f"mcp__herdr_{host}__{method}"
        for host in ("mac", "mule", "dev")
        for method in ("ping", "agent_list", "agent_get", "agent_read", "agent_wait")
    )

    def test_herdr_requires_explicit_policy_and_matching_classification(self) -> None:
        default = Policy(policy_document())
        for name in self.names:
            with self.subTest(name=name):
                operation = Operation.create(name, {"classification": "mutation"}, "task", "call", "session")
                self.assertEqual(operation.value["classification"], "read")
                self.assertFalse(default.decide(operation.value)[0])
                value = {**policy_document(), "allowed_tools": [{"name": name, "classification": "read"}]}
                policy = Policy(value)
                self.assertTrue(policy.decide(operation.value)[0])
                operation.value["classification"] = "mutation"
                self.assertFalse(policy.decide(operation.value)[0])
                value["allowed_tools"][0]["classification"] = "mutation"
                with self.assertRaises(ValueError):
                    Policy(value)

    def test_unreviewed_mcp_names_and_annotations_cannot_grant_access(self) -> None:
        denied = (
            "mcp__herdr_mac__agent_prompt", "mcp__herdr_mule__agent_send_keys",
            "mcp__herdr_dev__session_list", "mcp__herdr_dev__session_create",
            "mcp__herdr_prod__agent_read", "mcp__other__agent_read",
            "mcp__herdr_mac__agent_read_extra", "mcp__herdr_mac__agent_read ",
            "MCP__herdr_mac__agent_read", "mcp__herdr_*__agent_read",
        )
        for name in denied:
            with self.subTest(name=name):
                self.assertEqual(classify_tool(name), "unknown")
                operation = Operation.create(name, {"readOnlyHint": True, "classification": "read"}, "task", "call", "session")
                self.assertEqual(operation.value["classification"], "unknown")
                with self.assertRaises(ValueError):
                    Policy({**policy_document(), "allowed_tools": [{"name": name, "classification": "read"}]})

    def test_all_herdr_tools_through_plugin_socket_and_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = {**policy_document(), "allowed_tools": [
                {"name": name, "classification": "read"} for name in self.names
            ]}
            path = root / "policy.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            path.chmod(0o444)
            fixture = ServiceFixture(root, Policy.load(path))
            plugin = CharonHermesPlugin(Settings(fixture.socket_path, timeout_ms=500))
            try:
                for index, name in enumerate(self.names):
                    args = {"target": "synthetic-private-marker", "lines": 120}
                    ids = {"tool_call_id": f"call-{index}", "session_id": "session"}
                    self.assertIsNone(plugin.pre_tool_call(name, args, "task", **ids), name)
                    plugin.post_tool_call(name, args, "synthetic-output-marker", "task", **ids)
                denied = plugin.pre_tool_call(
                    "mcp__herdr_dev__agent_prompt", {"readOnlyHint": True}, "task",
                    annotations={"readOnlyHint": True}, classification="read",
                )
                self.assertEqual(denied["action"], "block")
                forged = Operation.create("mcp__herdr_dev__agent_prompt", {}, "task", "forged", "session")
                forged.value["classification"] = "read"
                self.assertEqual(request(fixture.socket_path, {"kind": "admit", "operation": forged.value}, 500)["decision"], "deny")
                plugin.finalize()
                journal = (fixture.state / "tool-receipts.jsonl").read_text(encoding="utf-8")
                receipts = [json.loads(line)["receipt"] for line in journal.splitlines()]
                self.assertEqual({entry["tool_name"] for entry in receipts}, set(self.names))
                self.assertEqual(len(receipts), 15)
                self.assertTrue(all(entry["classification"] == "read" for entry in receipts))
                self.assertNotIn("synthetic-private-marker", journal)
                self.assertNotIn("synthetic-output-marker", journal)
            finally:
                plugin._exporter.close()
                fixture.close()


class BotyardToolTests(unittest.TestCase):
    def test_explicit_opt_in_and_classification_cannot_be_forged(self) -> None:
        default = Policy(policy_document())
        for name, classification in BOTYARD_BROWSER.items():
            with self.subTest(name=name):
                wrong = "mutation" if classification == "read" else "read"
                operation = Operation.create(
                    name, {"classification": wrong, "readOnlyHint": True}, "task", "call", "session"
                )
                self.assertEqual(operation.value["classification"], classification)
                self.assertFalse(default.decide(operation.value)[0])
                policy = Policy({**policy_document(), "allowed_tools": [
                    {"name": name, "classification": classification}
                ]})
                self.assertTrue(policy.decide(operation.value)[0])
                operation.value["classification"] = wrong
                self.assertFalse(policy.decide(operation.value)[0])
                with self.assertRaises(ValueError):
                    Policy({**policy_document(), "allowed_tools": [
                        {"name": name, "classification": wrong}
                    ]})

    def test_unknown_browser_tools_cannot_be_enabled(self) -> None:
        names = [f"mcp__botyard__botyard_browser_{suffix}" for suffix in (
            "click", "type", "evaluate", "cdp", "upload", "cookies", "snapshot_extra", "*",
        )] + [
            "mcp__other__botyard_browser_snapshot", "botyard_browser_snapshot",
            "mcp__botyard__botyard_browser_snapshot ", "MCP__botyard__botyard_browser_snapshot",
        ]
        for name in names:
            with self.subTest(name=name):
                self.assertEqual(classify_tool(name), "unknown")
                for classification in ("read", "mutation", "secret-sensitive"):
                    with self.assertRaises(ValueError):
                        Policy({**policy_document(), "allowed_tools": [
                            {"name": name, "classification": classification}
                        ]})

    def test_plugin_admission_and_receipts_share_all_seven_classifications(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            value = {**policy_document(), "allowed_tools": [
                {"name": name, "classification": classification}
                for name, classification in BOTYARD_BROWSER.items()
            ]}
            path = root / "policy.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            path.chmod(0o444)
            fixture = ServiceFixture(root, Policy.load(path))
            plugin = CharonHermesPlugin(Settings(fixture.socket_path, timeout_ms=500))
            try:
                for index, name in enumerate(BOTYARD_BROWSER):
                    args = {"browserRef": "synthetic-private-marker", "readOnlyHint": True}
                    ids = {"tool_call_id": f"call-{index}", "session_id": "session"}
                    self.assertIsNone(plugin.pre_tool_call(name, args, "task", **ids), name)
                    plugin.post_tool_call(name, args, "synthetic-page-marker", "task", **ids)
                name = "mcp__botyard__botyard_browser_evaluate"
                denied = plugin.pre_tool_call(name, {}, "task", annotations={"readOnlyHint": True}, classification="read")
                self.assertEqual(denied["action"], "block")
                forged = Operation.create(name, {}, "task", "forged", "session")
                forged.value["classification"] = "read"
                self.assertEqual(request(fixture.socket_path, {"kind": "admit", "operation": forged.value}, 500)["decision"], "deny")
                plugin.finalize()
                journal = (fixture.state / "tool-receipts.jsonl").read_text(encoding="utf-8")
                receipts = [json.loads(line)["receipt"] for line in journal.splitlines()]
                self.assertEqual(len(receipts), 7)
                self.assertEqual({r["tool_name"]: r["classification"] for r in receipts}, BOTYARD_BROWSER)
                self.assertNotIn("synthetic-private-marker", journal)
                self.assertNotIn("synthetic-page-marker", journal)
            finally:
                plugin._exporter.close()
                fixture.close()


class ProtocolTests(unittest.TestCase):
    def test_trickled_bytes_do_not_extend_the_deadline(self) -> None:
        reader, writer = socket.socketpair()
        def trickle():
            try:
                for _ in range(50):
                    writer.sendall(b" ")
                    time.sleep(0.01)
            except OSError:
                pass
            finally:
                writer.close()
        thread = Thread(target=trickle, daemon=True)
        thread.start()
        started = time.monotonic()
        try:
            with self.assertRaises((ProtocolError, TimeoutError)):
                receive_message(reader, started + 0.05)
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            reader.close()
            thread.join(timeout=1)

    def test_duplicate_fields_deep_json_and_trailing_bytes_are_rejected(self) -> None:
        for payload in [b'{"kind":"health","kind":"admit"}\n', b'[' * 1500 + b']' * 1500 + b'\n', b'{"kind":"health"}\nextra']:
            reader, writer = socket.socketpair()
            try:
                writer.sendall(payload)
                with self.assertRaises(ProtocolError):
                    receive_message(reader, time.monotonic() + 1)
            finally:
                reader.close()
                writer.close()


class JournalTests(unittest.TestCase):
    def receipt(self) -> dict:
        operation = Operation.create("read_file", {}, "task", "call", "session")
        return receipt_for(operation, "authorization:1234567890abcdef", "", 1, False)

    def test_second_writer_is_rejected_and_close_releases_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "state"
            journal = Journal(directory)
            with self.assertRaises(ValueError):
                Journal(directory)
            journal.append(self.receipt())
            journal.close()
            reopened = Journal(directory)
            self.assertEqual(reopened._previous, journal._previous)
            reopened.close()

    def test_short_writes_are_completed_and_synced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "state"
            journal = Journal(directory)
            original = os.write
            with patch("charon_hermes.service.os.write", side_effect=lambda fd, data: original(fd, data[:7])) as write, patch("charon_hermes.service.os.fsync", wraps=os.fsync) as sync:
                journal.append(self.receipt())
                self.assertGreater(write.call_count, 1)
                self.assertGreaterEqual(sync.call_count, 2)
            journal.close()
            reopened = Journal(directory)
            self.assertEqual(reopened._previous, journal._previous)
            reopened.close()

    def test_partial_write_failure_rolls_back_and_allows_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "state"
            journal = Journal(directory)
            receipt = self.receipt()
            original = os.write
            calls = 0
            def fail_after_partial(fd, data):
                nonlocal calls
                calls += 1
                if calls == 1:
                    return original(fd, data[:7])
                raise OSError("synthetic disk failure")
            with patch("charon_hermes.service.os.write", side_effect=fail_after_partial):
                with self.assertRaises(OSError):
                    journal.append(receipt)
            self.assertEqual(journal._path.read_bytes(), b"")
            journal.append(receipt)
            journal.close()
            reopened = Journal(directory)
            self.assertEqual(reopened._previous, journal._previous)
            reopened.close()

    def test_sync_failure_is_not_acknowledged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = Journal(Path(temporary) / "state")
            with patch("charon_hermes.service.os.fsync", side_effect=OSError("synthetic sync failure")):
                with self.assertRaises(OSError):
                    journal.append(self.receipt())
            with self.assertRaises(OSError):
                journal.append(self.receipt())
            journal.close()

    def test_recovery_discards_only_an_unterminated_tail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "state"
            journal = Journal(directory)
            journal.append(self.receipt())
            valid = journal._path.read_bytes()
            with journal._path.open("ab") as handle:
                handle.write(b'{"receipt":')
            journal.close()
            recovered = Journal(directory)
            self.assertEqual(recovered._previous, journal._previous)
            self.assertEqual(journal._path.read_bytes(), valid)
            with journal._path.open("ab") as handle:
                handle.write(b"corrupt complete record\n")
            recovered.close()
            with self.assertRaises(ValueError):
                Journal(directory)


class IntegrationTests(unittest.TestCase):
    def test_malformed_fields_deny_without_crashing_or_creating_admissions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ServiceFixture(Path(temporary))
            try:
                operation = Operation.create("read_file", {}, "task", "call", "session")
                for changes in [{"classification": []}, {"argument_keys": [{}]}, {"version": True}]:
                    response = request(fixture.socket_path, {"kind": "admit", "operation": {**operation.value, **changes}}, 500)
                    self.assertEqual(response["decision"], "deny")
                self.assertEqual(request(fixture.socket_path, {"kind": "admit"}, 500)["error"], "invalid-request")
                self.assertFalse(fixture.server._authorizations)
            finally:
                fixture.close()

    def test_admission_capacity_and_failed_journal_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ServiceFixture(Path(temporary))
            try:
                with patch("charon_hermes.service.MAX_ADMISSIONS", 1):
                    operation = Operation.create("read_file", {}, "task", "call", "session")
                    self.assertEqual(fixture.server.admit(operation.value)["decision"], "allow")
                    other = Operation.create("read_file", {}, "task", "call2", "session")
                    self.assertEqual(fixture.server.admit(other.value)["decision"], "deny")
                    self.assertEqual(len(fixture.server._authorizations), 1)
                fixture.server.journal._failed = True
                self.assertEqual(fixture.server.health()["status"], "unavailable")
                self.assertEqual(fixture.server.admit(other.value)["decision"], "deny")
            finally:
                fixture.close()

    def test_slow_socket_is_closed_and_connection_capacity_is_released(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with patch("charon_hermes.service.REQUEST_TIMEOUT_SECONDS", 0.05), patch("charon_hermes.service.MAX_CONNECTIONS", 1):
                fixture = ServiceFixture(Path(temporary))
                try:
                    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    client.settimeout(1)
                    client.connect(str(fixture.socket_path))
                    client.sendall(b'{')
                    self.assertEqual(client.recv(1), b'')
                    client.close()
                    # The handler releases its slot when it closes the first connection.
                    self.assertTrue(fixture.server._connections.acquire(timeout=1))
                    fixture.server._connections.release()
                    self.assertEqual(request(fixture.socket_path, {"kind": "health"}, 500)["status"], "ready")
                finally:
                    fixture.close()

    def test_same_call_id_in_different_sessions_keeps_receipts_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ServiceFixture(Path(temporary))
            plugin = CharonHermesPlugin(Settings(fixture.socket_path, timeout_ms=500))
            try:
                for session in ["first", "second"]:
                    self.assertIsNone(plugin.pre_tool_call("read_file", {}, session,
                        tool_call_id="same-call", session_id=session))
                plugin.post_tool_call("read_file", {}, "xx", "second",
                    tool_call_id="same-call", session_id="second")
                plugin.post_tool_call("read_file", {}, "x", "first",
                    tool_call_id="same-call", session_id="first")
                self.assertTrue(plugin._exporter.flush())
                receipts = [json.loads(line)["receipt"] for line in fixture.server.journal._path.read_text().splitlines()]
                self.assertEqual({item["session_id"]: item["result_size"] for item in receipts}, {"first": 1, "second": 2})
            finally:
                plugin._exporter.close()
                fixture.close()

    def test_receipt_is_bound_to_complete_admitted_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ServiceFixture(Path(temporary))
            try:
                operation = Operation.create("read_file", {}, "task", "call", "session")
                admission = fixture.server.admit(operation.value)
                receipt = receipt_for(operation, admission["authorization_id"], "", 1, False)
                for key, value in {
                    "operation_id": "op:other", "session_id": "other", "tool_call_id": "other",
                    "tool_name": "write_file", "classification": "mutation",
                    "arguments_digest": "sha256:" + "f" * 64, "task_id": "other",
                }.items():
                    with self.subTest(field=key):
                        self.assertFalse(fixture.server.accept_receipt({**receipt, key: value}))
                missing_task = dict(receipt)
                missing_task.pop("task_id")
                self.assertFalse(fixture.server.accept_receipt(missing_task))
                self.assertTrue(fixture.server.accept_receipt(receipt))
                self.assertFalse(fixture.server.accept_receipt(receipt))
            finally:
                fixture.close()

    def test_receipt_expiry_is_checked_without_another_admission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ServiceFixture(Path(temporary))
            try:
                operation = Operation.create("read_file", {}, "", "call", "session")
                admission = fixture.server.admit(operation.value)
                receipt = receipt_for(operation, admission["authorization_id"], "", 1, False)
                self.assertFalse(fixture.server.accept_receipt({**receipt, "task_id": "extra"}))
                expiry = fixture.server._authorizations[admission["authorization_id"]][1]
                with patch("charon_hermes.service.time.time", return_value=expiry):
                    self.assertFalse(fixture.server.accept_receipt(receipt))
            finally:
                fixture.close()

    def test_unavailable_service_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings = Settings(Path(temporary) / "missing.sock")
            operation = Operation.create("read_file", {}, "task", "call", "session")
            decision = AdmissionClient(settings).admit(operation)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason_code, "service-unavailable")

    def test_unresponsive_service_fails_closed_within_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "hung.sock"
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(path))
            server.listen(1)
            os.chmod(path, 0o600)

            def hang() -> None:
                connection, _ = server.accept()
                with connection:
                    time.sleep(0.25)

            thread = Thread(target=hang, daemon=True)
            thread.start()
            started = time.monotonic()
            try:
                operation = Operation.create("read_file", {}, "task", "call", "session")
                decision = AdmissionClient(Settings(path, timeout_ms=50)).admit(operation)
            finally:
                server.close()
                thread.join(timeout=1)
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.reason_code, "service-unavailable")
            self.assertLess(time.monotonic() - started, 0.5)

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
                    status="ok",
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

    def test_all_recommended_tools_are_admitted_without_touching_hermes_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "opt-data-marker"
            state.write_text("persistent memory and skill marker", encoding="utf-8")
            policy = Policy(policy_document())
            server = Server(root / "admission.sock", policy, Journal(root / "receipts"))
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                plugin = CharonHermesPlugin(Settings(root / "admission.sock", timeout_ms=500))
                for index, name in enumerate(DEPLOYMENT_TOOLS):
                    decision = plugin.pre_tool_call(
                        name, {"synthetic": "sensitive-marker"}, "task",
                        tool_call_id=f"call-{index}", session_id="session",
                    )
                    self.assertIsNone(decision, name)
                plugin.finalize()
                self.assertEqual(state.read_text(encoding="utf-8"), "persistent memory and skill marker")
                journal = (root / "receipts" / "tool-receipts.jsonl").read_text(encoding="utf-8")
                self.assertNotIn("sensitive-marker", journal)
                self.assertNotIn("persistent memory and skill marker", journal)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_health_reports_exact_ready_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = ServiceFixture(Path(temporary))
            try:
                response = request(fixture.socket_path, {"kind": "health"}, 500)
                self.assertEqual(response["status"], "ready")
                self.assertEqual(response["hermes_version"], "v2026.8.3")
                self.assertEqual(response["profile"], "telegram-browserless")
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
            self.addCleanup(journal.close)
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

    def test_required_autonomy_tools_are_explicit_and_recommended(self) -> None:
        required = {
            "memory", "skills_list", "skill_view", "skill_manage", "todo",
            "session_search", "clarify", "delegate_task", "read_file",
            "write_file", "patch", "search_files", "terminal", "process",
            "execute_code",
        }
        self.assertTrue(required <= set(CLASSIFICATIONS))
        self.assertTrue(required <= set(DEPLOYMENT_TOOLS))
        self.assertNotIn("unknown", {CLASSIFICATIONS[name] for name in required})

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
