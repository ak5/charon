# Hermes v2026.8.3 compatibility

This is the human-readable inventory for the Charon-Hermes compatibility
contract. The executable source of truth is
[`compatibility.py`](../integrations/hermes/src/charon_hermes/compatibility.py).

## Pin and effective posture

- Upstream: `NousResearch/hermes-agent`
- Tag: `v2026.8.3`
- Commit: `3c27eb6234bf91b8ceee9e9071591b31e9b148cb`
- Python package version reported upstream: `0.20.0`
- Platform bundle: `hermes-telegram`
- Deployment-disabled toolset: `browser`
- Deployment image: no browser binaries or payload
- Persistent Hermes state: `/opt/data`, outside the plugin and service mounts

Hermes's Telegram bundle statically names 61 core tools. Registry `check_fn`
conditions then hide tools whose platform, provider, credential, or worker mode
is unavailable. Charon policy does not enable a Hermes tool; it only admits an
exact name if Hermes registered and selected that tool independently.

The deployment profile has three explicit sets:

### Eligible and recommended (27)

These names are in the browserless Telegram profile and its recommended exact
Charon policy. Provider-backed media tools still appear only when their Hermes
runtime checks succeed.

| Classification | Exact tool names |
| --- | --- |
| `read` | `bfl_flux3_get_result`, `bfl_flux3_prompting_guide`, `read_file`, `search_files`, `session_search`, `skill_view`, `skills_list`, `vision_analyze`, `web_extract`, `web_search` |
| `mutation` | `bfl_flux3_image_to_video`, `bfl_flux3_keyframes_to_video`, `bfl_flux3_text_to_video`, `bfl_flux3_video_continuation`, `clarify`, `cronjob`, `image_generate`, `memory`, `patch`, `skill_manage`, `text_to_speech`, `todo`, `write_file` |
| `secret-sensitive` | `delegate_task`, `execute_code`, `process`, `terminal` |

`memory` is a mutation because one schema combines search/get/add/update/delete.
`todo` and `skill_manage` similarly combine observation with state changes.
This conservative choice avoids inspecting raw arguments. `delegate_task` is
secret-sensitive because a child agent can exercise delegated tool authority.

### Known but disabled browser tools (12)

| Classification | Exact tool names |
| --- | --- |
| `read` | `browser_get_images`, `browser_snapshot`, `browser_vision` |
| `mutation` | `browser_back`, `browser_click`, `browser_dialog`, `browser_navigate`, `browser_press`, `browser_scroll`, `browser_type` |
| `secret-sensitive` | `browser_cdp`, `browser_console` |

These classifications prevent a future browser enablement from becoming
`unknown`; they do not put the tools in the current policy.

### Known but runtime/configuration gated (22)

| Gate | Classification and exact tool names |
| --- | --- |
| Hermes Desktop | read: `read_terminal`; mutation: `close_terminal`, `focus_pane`, `open_preview`, `react_to_message` |
| Home Assistant token/config | read: `ha_get_state`, `ha_list_entities`, `ha_list_services`; mutation: `ha_call_service` |
| Kanban worker or explicit toolset | read: `kanban_attachments`, `kanban_list`, `kanban_show`; mutation: `kanban_attach`, `kanban_attach_url`, `kanban_block`, `kanban_comment`, `kanban_complete`, `kanban_create`, `kanban_heartbeat`, `kanban_link`, `kanban_unblock` |
| Computer-use driver | secret-sensitive: `computer_use` |

Adding any of these to a deployment requires an explicit policy/profile review.
They are classified but omitted from the recommended policy.

## Upgrade contract

For a Hermes upgrade, update the immutable tag and commit, run the compatibility
test against that exact checkout, review every added/removed/changed name and
classification, update the reviewed digest and policy, then rerun the real
`PluginContext` test. A new upstream tool makes the inventory equality test fail
and remains `unknown` and denied until that review is complete.
