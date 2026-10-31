"""Reviewed external tools, separate from the pinned Hermes core inventory."""

# Read authority depends on Infra's fixed-host, forced-command observation adapters.
HERDR_OBSERVATION: dict[str, str] = {
    "mcp__herdr_mac__ping": "read",
    "mcp__herdr_mac__agent_list": "read",
    "mcp__herdr_mac__agent_get": "read",
    "mcp__herdr_mac__agent_read": "read",
    "mcp__herdr_mac__agent_wait": "read",
    "mcp__herdr_mule__ping": "read",
    "mcp__herdr_mule__agent_list": "read",
    "mcp__herdr_mule__agent_get": "read",
    "mcp__herdr_mule__agent_read": "read",
    "mcp__herdr_mule__agent_wait": "read",
    "mcp__herdr_dev__ping": "read",
    "mcp__herdr_dev__agent_list": "read",
    "mcp__herdr_dev__agent_get": "read",
    "mcp__herdr_dev__agent_read": "read",
    "mcp__herdr_dev__agent_wait": "read",
}

# Botyard contract b01024745e350cb842a67906784ea84e20234916, docs/browser-mcp.md.
# Botyard enforces profile grants, context ownership and consequential-action policy.
BOTYARD_BROWSER: dict[str, str] = {
    "mcp__botyard__botyard_browser_targets": "read",
    "mcp__botyard__botyard_browser_open": "mutation",
    "mcp__botyard__botyard_browser_status": "read",
    "mcp__botyard__botyard_browser_navigate": "mutation",
    "mcp__botyard__botyard_browser_snapshot": "read",
    "mcp__botyard__botyard_browser_back": "mutation",
    "mcp__botyard__botyard_browser_close": "mutation",
}
