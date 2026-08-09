"""Pinned Hermes source and reviewed-classification compatibility checks."""

from __future__ import annotations

import ast
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import unittest

from charon_hermes.compatibility import (
    BROWSER_TOOLS, CLASSIFICATIONS, DEPLOYMENT_TOOLS, HERMES_COMMIT,
    HERMES_VERSION, policy_document,
)
from charon_hermes.plugin import register

REVIEWED_CLASSIFICATION_DIGEST = "9af1c6e03f149e554ab7cc2fec992ce1a10199873cc5a3ea4f32dae5389c0dc9"


def _core_tools(source: Path) -> list[str]:
    module = ast.parse((source / "toolsets.py").read_text(encoding="utf-8"))
    for node in module.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "_HERMES_CORE_TOOLS"
            for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            if isinstance(value, list) and all(isinstance(item, str) for item in value):
                return value
    raise AssertionError("Hermes _HERMES_CORE_TOOLS was not found")


class CompatibilityTests(unittest.TestCase):
    def test_classification_changes_require_review(self) -> None:
        encoded = json.dumps(CLASSIFICATIONS, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), REVIEWED_CLASSIFICATION_DIGEST)

    def test_recommended_policy_is_exact_and_complete(self) -> None:
        policy = policy_document()
        entries = policy["allowed_tools"]
        self.assertEqual({entry["name"] for entry in entries}, set(DEPLOYMENT_TOOLS))
        self.assertEqual(len(entries), len({entry["name"] for entry in entries}))
        self.assertFalse(BROWSER_TOOLS & set(DEPLOYMENT_TOOLS))
        example = Path(__file__).parents[1] / "examples" / "policy.json"
        self.assertEqual(json.loads(example.read_text(encoding="utf-8")), policy)

    @unittest.skipUnless(os.environ.get("HERMES_SOURCE"), "set HERMES_SOURCE for upstream check")
    def test_exact_upstream_inventory_and_real_plugin_api(self) -> None:
        source = Path(os.environ["HERMES_SOURCE"]).resolve()
        self.assertEqual(set(_core_tools(source)), set(CLASSIFICATIONS))
        self.assertEqual(len(_core_tools(source)), len(CLASSIFICATIONS))
        pyproject = (source / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "0.20.0"', pyproject)
        executor = (source / "agent" / "tool_executor.py").read_text(encoding="utf-8")
        plugin_gate = executor.index("resolve_pre_tool_block(")
        hermes_guard = executor.index("agent._tool_guardrails.before_call", plugin_gate)
        self.assertLess(plugin_gate, hermes_guard)
        terminal = (source / "tools" / "terminal_tool.py").read_text(encoding="utf-8")
        self.assertIn("approval = _check_all_guards(", terminal)

        sys.path.insert(0, str(source))
        try:
            plugins = importlib.import_module("hermes_cli.plugins")
            manager = plugins.PluginManager()
            manifest = plugins.PluginManifest(
                name="charon-hermes", version=HERMES_VERSION,
                source="entrypoint", key="charon-hermes",
            )
            context = plugins.PluginContext(manifest, manager)
            old = os.environ.get("CHARON_HERMES_ADMISSION_SOCKET")
            try:
                os.environ["CHARON_HERMES_ADMISSION_SOCKET"] = str(source / "missing.sock")
                register(context)
            finally:
                if old is None:
                    os.environ.pop("CHARON_HERMES_ADMISSION_SOCKET", None)
                else:
                    os.environ["CHARON_HERMES_ADMISSION_SOCKET"] = old
            self.assertEqual(
                set(manager._hooks), {"pre_tool_call", "post_tool_call", "on_session_finalize"}
            )
            manager._hooks["pre_tool_call"][0].__self__._exporter.close()
            self.assertEqual(plugins.ENTRY_POINTS_GROUP, "hermes_agent.plugins")
            installed = {manifest.name: manifest for manifest in manager._scan_entry_points()}
            if os.environ.get("CHARON_HERMES_REQUIRE_ENTRYPOINT") == "1":
                self.assertIn("charon-hermes", installed)
            if "charon-hermes" in installed:
                self.assertEqual(installed["charon-hermes"].path, "charon_hermes")
                loaded_manager = plugins.PluginManager()
                previous_socket = os.environ.get("CHARON_HERMES_ADMISSION_SOCKET")
                try:
                    os.environ["CHARON_HERMES_ADMISSION_SOCKET"] = str(source / "missing.sock")
                    loaded_manager._load_plugin(installed["charon-hermes"])
                finally:
                    if previous_socket is None:
                        os.environ.pop("CHARON_HERMES_ADMISSION_SOCKET", None)
                    else:
                        os.environ["CHARON_HERMES_ADMISSION_SOCKET"] = previous_socket
                loaded = loaded_manager._plugins["charon-hermes"]
                self.assertTrue(loaded.enabled)
                self.assertIsNone(loaded.error)
                self.assertEqual(
                    set(loaded.hooks_registered),
                    {"pre_tool_call", "post_tool_call", "on_session_finalize"},
                )
                loaded_manager._hooks["pre_tool_call"][0].__self__._exporter.close()
        finally:
            sys.path.remove(str(source))

    def test_pin_is_immutable(self) -> None:
        self.assertEqual(HERMES_VERSION, "v2026.8.3")
        self.assertEqual(HERMES_COMMIT, "3c27eb6234bf91b8ceee9e9071591b31e9b148cb")
