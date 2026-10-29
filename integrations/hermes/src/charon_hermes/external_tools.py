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
