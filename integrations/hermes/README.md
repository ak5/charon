# Charon for Hermes Agent

`charon-hermes` adds exact, fail-closed semantic tool admission and
metadata-only receipts to Hermes Agent. This release supports Hermes
`v2026.8.3` at commit `3c27eb6234bf91b8ceee9e9071591b31e9b148cb` and the
browserless Telegram deployment profile.

It preserves Hermes autonomy. When admitted, `memory`, skill management,
planning, session recall, clarification, delegation, filesystem mutation,
terminal, process, and code execution behave as Hermes implements them. The
plugin never reads, clears, relocates, or writes `/opt/data`; Hermes continues
to persist memories, learned/custom skills, sessions, and other state there.

## What each boundary does

| Boundary | Responsibility |
| --- | --- |
| Charon-Hermes plugin and admission service | Admit an exact semantic Hermes tool name and write metadata-only receipts. |
| Hermes approval system | Inspect dangerous terminal commands and ask the Telegram operator for once/session/always/deny approval. Charon does not replace or bypass it. |
| Charon explicit proxy | Enforce a signed single-use workload manifest and exact remote destination/method/path policy, then hydrate a capability reference without exposing the credential to Hermes. |
| Charon transparent gateway | Independently authorize an Infra-isolated Hermes lane, capability reference, destination, request shape, and streamed response. Generic clients do not provide trustworthy tool-call correlation. |
| Network isolation | Prevent Hermes from reaching remote services around Charon. Tool admission alone does not provide egress control. |
| Workload identity issuer | Issue short-lived, single-use Charon manifests. Neither this plugin nor its policy stores or issues manifests. |

Hermes calls the plugin before its tool guardrail and before execution. A
Charon-admitted terminal call still reaches Hermes's command-aware approval
guard. A Charon denial never executes the tool.

## Compatibility and policy

The reviewed core inventory is in
[`compatibility.py`](src/charon_hermes/compatibility.py). All 61 names in
Hermes's pinned `_HERMES_CORE_TOOLS` list have an explicit classification.
Browser tools remain classified for upgrade review but are absent from the
recommended policy because `agent.disabled_toolsets: [browser]` and the
derivative image both disable them. Desktop, Home Assistant, Kanban, and
computer-use tools are runtime/configuration-gated and also excluded from this
profile. Separately reviewed external names are described below. Other names
classify as `unknown`, cannot appear in policy, and are denied.

Classification is whole-tool and does not inspect argument values. Mixed tools
such as `memory` and `todo` are conservatively `mutation`; `delegate_task`,
`terminal`, `process`, `execute_code`, and `computer_use` are
`secret-sensitive`. A classification edit changes a checked review digest, so
it cannot pass unnoticed.

Generate and validate the exact policy:

```sh
charon-hermes-policy generate > hermes-policy.json
chmod 0444 hermes-policy.json
charon-hermes-policy validate --recommended hermes-policy.json
```

The checked example is [`examples/policy.json`](examples/policy.json). Omit
`--recommended` to validate an explicit selection of reviewed core and external tools.
Wildcards, duplicate names, unreviewed classifications, different Hermes pins,
and unknown fields are rejected. Removing an exact entry is the supported way
to deny a deployment-eligible tool.

### Optional Herdr observation catalog

Version 0.2.2 adds a separate reviewed catalog in
[`external_tools.py`](src/charon_hermes/external_tools.py). The Herdr names are
`mcp__herdr_mac__`, `mcp__herdr_mule__`, and `mcp__herdr_dev__`, each followed by
exactly `ping`, `agent_list`, `agent_get`, `agent_read`, or `agent_wait`: 15
explicit entries, all `read`. This notation describes the catalog; policy and
classification use exact string equality, never prefix or wildcard matching.
The core inventory, its review digest, schema version 2 and default policy are
unchanged. Neither model arguments nor MCP server annotations affect classification.

To opt in, add the selected exact entries to `allowed_tools`, each with
`"classification": "read"`. For the full reviewed observation set plus the
recommended core policy, use the installed matching wheel:

```sh
python - <<'PY' > hermes-policy.json
import json
from charon_hermes.compatibility import policy_document
from charon_hermes.external_tools import HERDR_OBSERVATION
policy = policy_document()
policy["allowed_tools"].extend(
    {"name": name, "classification": classification}
    for name, classification in HERDR_OBSERVATION.items()
)
print(json.dumps(policy, indent=2))
PY
chmod 0444 hermes-policy.json
charon-hermes-policy validate hermes-policy.json
```

Omitted entries remain denied. Herdr mutating methods, session operations, additional
hosts, lookalike names and unreviewed MCP tools cannot be added to policy. Both
the plugin and admission policy loader use the same reviewed classifier.

Infra must bind these names to its dedicated observation adapters: fixed SSH
hosts, forced-command keys, only these five remote methods, reads limited to
120 lines and waits to 30 seconds. Charon does not inspect raw arguments or
enforce those remote limits. `read` means no mutation; observed terminal output
can contain sensitive data and must be authorized for the observing workload.
Install the matching wheel and companion from the same immutable image before
delivering an opt-in policy. This does not change the Charon network gateway.

### Optional Botyard browser catalog

Version 0.2.3 adds `BOTYARD_BROWSER` in
[`external_tools.py`](src/charon_hermes/external_tools.py), reviewed against
Botyard contract commit
[`b01024745e350cb842a67906784ea84e20234916`](https://github.com/ak5/botyard/blob/b01024745e350cb842a67906784ea84e20234916/docs/browser-mcp.md)
and its [generated tool schemas](https://github.com/ak5/botyard/blob/b01024745e350cb842a67906784ea84e20234916/docs/browser-mcp-tools.json).
The Hermes MCP server namespace must be `botyard`.

| Exact tool name | Classification |
| --- | --- |
| `mcp__botyard__botyard_browser_targets` | `read` |
| `mcp__botyard__botyard_browser_open` | `mutation` |
| `mcp__botyard__botyard_browser_status` | `read` |
| `mcp__botyard__botyard_browser_navigate` | `mutation` |
| `mcp__botyard__botyard_browser_snapshot` | `read` |
| `mcp__botyard__botyard_browser_back` | `mutation` |
| `mcp__botyard__botyard_browser_close` | `mutation` |

Opt in by adding only the selected exact names and matching classifications to
`allowed_tools`. The default policy, runtime profile, core catalog and Herdr
catalog are unchanged. Install the paired 0.2.3 wheel and companion from the
same immutable image before enabling these entries. Unknown names, wildcards,
general JavaScript, file, cookie and unreviewed browser tools remain denied.

Classification is not approval: an explicitly allowed mutation passes semantic
admission without a human prompt. Botyard must enforce owner-selected profile
IDs, per-target operations, document origins, context ownership, TTL/revocation,
and consequential-action policy at execution time. There is no all-profile
grant. `read` does not mean public data: snapshots may expose authenticated page
content, and target metadata may identify accounts. Navigation and history can
cause website/account side effects even without click or form tools.

The reviewed snapshot accepts only `browserRef`; status does not renew a lease,
and navigation/back return no page content. Charon classifies whole tools; it
does not validate these remote argument schemas or enforce browser limits.
The catalog therefore requires the reviewed Botyard implementation, not a
same-named arbitrary MCP server or server-supplied annotations.

Browser execution stays on Botyard. The integration uses the fixed HTTPS
`POST /mcp/browser` endpoint, MCP `2025-06-18`, and JSON responses. Infra owns a
separate connector with an Infisical-managed caller-owned Bearer credential
hidden from Hermes, routed through Charon's exact HTTPS destination/path policy.
This is forwarding-only transport authentication; it does not bypass KDBX
credential mediation. No WSS, local Playwright, gateway change, live profile
grant or activation is included in this catalog release. Remote execution and
authorized disposable/persistent lifecycle checks remain deployment prerequisites.

## Container deployment contract

Release CI publishes
`ghcr.io/<owner>/<repository>-hermes:sha-<40-character-charon-commit>` with provenance and
an SBOM. Pin it by digest in `ak5/infra`; do not use a mutable tag.

The image serves two purposes:

For this repository, GitHub resolves the placeholders from the repository
owner and name. Use the same immutable reference for both purposes:

1. Run it as the separate admission-service container.
2. Copy `/opt/charon-hermes/wheels/charon_hermes-*.whl` from the same immutable
   image into the downstream Hermes derivative and install that wheel into the
   same Python environment as Hermes. No Charon source needs to be vendored.

The admission image uses a digest-pinned Python 3.15.0 slim base. It does not
contain Hermes, its credentials, or `/opt/data`; the wheel is compatible with
Hermes's supported Python range.

A downstream derivative can consume the wheel without a source checkout:

```dockerfile
ARG CHARON_HERMES_IMAGE
FROM ${CHARON_HERMES_IMAGE} AS charon_hermes_artifact
FROM <pinned-hermes-v2026.8.3-image>
COPY --from=charon_hermes_artifact \
  /opt/charon-hermes/wheels/charon_hermes-0.2.3-py3-none-any.whl /tmp/
RUN python -m pip install --no-deps \
  /tmp/charon_hermes-0.2.3-py3-none-any.whl \
  && rm /tmp/charon_hermes-0.2.3-py3-none-any.whl
```

Set `CHARON_HERMES_IMAGE` to the immutable Charon-Hermes tag and registry
digest. The wheel has no runtime Python dependencies outside the standard
library.

Enable pip discovery explicitly in Hermes configuration:

```yaml
plugins:
  enabled:
    - charon-hermes
agent:
  disabled_toolsets:
    - browser
```

Run both containers as UID/GID `10000:10000`. Mount one dedicated socket volume
at `/run/charon-hermes` in both containers. Mount the read-only policy and a
private receipt-state volume only in the admission container. Do not share
Docker's socket, Charon manifests, KeePass state, credential references, or
credentials.

```text
Hermes container                         admission container
/opt/data (persistent; unchanged)        /etc/charon/policy.json (0444)
/run/charon-hermes/admission.sock <----> /run/charon-hermes (0700, UID 10000)
                                         /var/lib/charon-hermes (0700)
```

Start the service with:

```sh
charon-hermes-admission \
  --socket /run/charon-hermes/admission.sock \
  --policy /etc/charon/policy.json \
  --state-dir /var/lib/charon-hermes
```

Set only this plugin configuration in Hermes:

```sh
CHARON_HERMES_ADMISSION_SOCKET=/run/charon-hermes/admission.sock
CHARON_HERMES_TIMEOUT_MS=250
CHARON_HERMES_QUEUE_SIZE=1024
CHARON_HERMES_RESULT_DIGESTS=0
```

The socket directory must already exist, be owned by UID 10000, and have mode
`0700`. The service creates a mode-`0600` socket. Configure the admission
container to restart unless stopped and make Hermes depend on this readiness
probe:

```sh
charon-hermes-policy health \
  --socket /run/charon-hermes/admission.sock \
  --timeout-ms 250
```

Readiness proves that the socket is protected, the service responds, and the
loaded service matches the pinned Hermes/profile identity. Missing service,
wrong ownership/mode, invalid data, replay, timeout, or incompatible response
denies within the configured timeout. Receipt failure does not reverse a tool
that already completed.

## Rollout and rollback

1. Back up and retain the existing `/opt/data` volume. Never mount it into the
   admission container.
2. Pin the Charon-Hermes image by digest. Extract and install its wheel while
   building the pinned Hermes derivative.
3. Generate and validate policy with that same release. Confirm the readiness
   probe before enabling the plugin.
4. In a non-production Telegram session, prove memory read/write; skills
   list/view/create/update; todo; session search; clarification; delegation;
   file read/write/patch; and an explicitly permitted terminal command. Use a
   dangerous disposable command to confirm Hermes still prompts for approval.
5. Remove one harmless exact tool from a policy copy and confirm it is denied
   before execution. Stop the service and confirm calls deny within the timeout.
6. Inspect the journal and logs using synthetic marker strings; verify arguments,
   outputs, credentials, and memory contents are absent.
7. Restart both containers and confirm the `/opt/data` state is unchanged.

Rollback by removing `charon-hermes` from `plugins.enabled` and restoring the
previous digest-pinned Hermes image. This restores the previous Hermes tool
posture; it does not delete `/opt/data`. Stop and remove only the admission
container/socket after Hermes no longer loads the plugin. Retain or archive the
receipt journal according to operator policy.

## Receipt behavior

Receipts contain identifiers, exact tool name, reviewed classification,
argument-key names, an argument digest, timing, Hermes's hook outcome, result
size, and optional result digest. Raw arguments and results never cross the
socket or enter the journal. Result digests default off because low-entropy
values can be guessed by comparison.

The in-process queue is bounded and non-blocking. Full queues, service loss,
invalid acknowledgements, and shutdown timeouts increment an in-memory loss
counter and discard receipts; they do not block a completed tool. The journal
hash chain detects edits only when a trusted earlier digest exists. It is not a
signature and a compromised host can rewrite the journal and chain.

## Development

```sh
HERMES_SOURCE=/path/to/hermes-agent-v2026.8.3 mise run hermes-check
mise run check
```

CI checks out the immutable upstream commit and fails if its Telegram inventory
contains an unclassified tool, the recommended policy is incomplete, the
reviewed classification digest changes, or the real `PluginContext` hook API is
incompatible.

## Exclusive Hermes network gateway

The [exclusive workload gateway](../../contracts/workload-gateway.md) provides a separate
`--gateway-config` mode for ordinary HTTP(S) proxy clients, including reusable
CONNECT tunnels. It binds one fixed isolated workload, supports secretless
forwarding and typed credential sinks, and requires its own validated schema.
Signed proxy authentication, transparent service lanes, and Hermes tool
admission remain independent controls. Infra owns isolation, trust and cutover.

### Admission and journal bounds

The local service accepts at most 32 simultaneous connections and gives each
request five seconds to arrive. Client deadlines include all reads; slow bytes
do not extend the configured timeout. Up to 4096 unexpired operation IDs and
4096 receipt authorizations are retained. Exhaustion denies new calls and does
not evict existing authorizations. Duplicate or malformed protocol fields deny.

Only one process can hold a receipt journal's OS file lock. Do not replace its
file while the service is running. Recovery validates bounded lines and rejects
complete corrupt records. Irrecoverable journal failure reports unavailable
readiness and denies new admissions until restart. These controls complement
filesystem isolation; they do not turn an in-process plugin into an independent
security boundary.
