"""Reviewed compatibility contract for pinned Hermes releases."""

from __future__ import annotations

from dataclasses import dataclass

HERMES_VERSION = "v2026.8.3"
HERMES_COMMIT = "3c27eb6234bf91b8ceee9e9071591b31e9b148cb"
HERMES_PACKAGE_VERSION = "0.20.0"
PROFILE = "telegram-browserless"

# Whole-tool classifications are intentionally conservative. Mixed read/write
# tools are mutations; tools capable of arbitrary execution or delegation are
# secret-sensitive. No model-supplied argument value affects classification.
CLASSIFICATIONS: dict[str, str] = {
    "web_search": "read", "web_extract": "read",
    "terminal": "secret-sensitive", "process": "secret-sensitive",
    "read_terminal": "read", "close_terminal": "mutation",
    "open_preview": "mutation", "focus_pane": "mutation",
    "react_to_message": "mutation", "read_file": "read",
    "write_file": "mutation", "patch": "mutation", "search_files": "read",
    "vision_analyze": "read", "image_generate": "mutation",
    "bfl_flux3_text_to_video": "mutation",
    "bfl_flux3_image_to_video": "mutation",
    "bfl_flux3_keyframes_to_video": "mutation",
    "bfl_flux3_video_continuation": "mutation",
    "bfl_flux3_get_result": "read", "bfl_flux3_prompting_guide": "read",
    "skills_list": "read", "skill_view": "read", "skill_manage": "mutation",
    "browser_navigate": "mutation", "browser_snapshot": "read",
    "browser_click": "mutation", "browser_type": "mutation",
    "browser_scroll": "mutation", "browser_back": "mutation",
    "browser_press": "mutation", "browser_get_images": "read",
    "browser_vision": "read", "browser_console": "secret-sensitive",
    "browser_cdp": "secret-sensitive", "browser_dialog": "mutation",
    "text_to_speech": "mutation", "todo": "mutation", "memory": "mutation",
    "session_search": "read", "clarify": "mutation",
    "execute_code": "secret-sensitive", "delegate_task": "secret-sensitive",
    "cronjob": "mutation", "ha_list_entities": "read", "ha_get_state": "read",
    "ha_list_services": "read", "ha_call_service": "mutation",
    "kanban_show": "read", "kanban_list": "read",
    "kanban_complete": "mutation", "kanban_block": "mutation",
    "kanban_heartbeat": "mutation", "kanban_comment": "mutation",
    "kanban_create": "mutation", "kanban_link": "mutation",
    "kanban_unblock": "mutation", "kanban_attach": "mutation",
    "kanban_attach_url": "mutation", "kanban_attachments": "read",
    "computer_use": "secret-sensitive",
}

BROWSER_TOOLS = frozenset(name for name in CLASSIFICATIONS if name.startswith("browser_"))
RUNTIME_GATED_TOOLS = frozenset({
    "read_terminal", "close_terminal", "open_preview", "focus_pane",
    "react_to_message", "ha_list_entities", "ha_get_state", "ha_list_services",
    "ha_call_service", "kanban_show", "kanban_list", "kanban_complete",
    "kanban_block", "kanban_heartbeat", "kanban_comment", "kanban_create",
    "kanban_link", "kanban_unblock", "kanban_attach", "kanban_attach_url",
    "kanban_attachments", "computer_use",
})
DEPLOYMENT_TOOLS = tuple(sorted(set(CLASSIFICATIONS) - BROWSER_TOOLS - RUNTIME_GATED_TOOLS))


@dataclass(frozen=True, slots=True)
class Compatibility:
    version: str = HERMES_VERSION
    commit: str = HERMES_COMMIT
    package_version: str = HERMES_PACKAGE_VERSION
    profile: str = PROFILE


def classify_tool(tool_name: str) -> str:
    """Return a reviewed classification or ``unknown`` for fail-closed denial."""

    return CLASSIFICATIONS.get(tool_name, "unknown")


def policy_document() -> dict[str, object]:
    """Build the exact recommended policy for the pinned deployment profile."""

    return {
        "version": 2,
        "compatibility": {
            "hermes_version": HERMES_VERSION,
            "hermes_commit": HERMES_COMMIT,
            "profile": PROFILE,
        },
        "allowed_tools": [
            {"name": name, "classification": CLASSIFICATIONS[name]}
            for name in DEPLOYMENT_TOOLS
        ],
    }
