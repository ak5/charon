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

The reviewed inventory is in
[`compatibility.py`](src/charon_hermes/compatibility.py). All 61 names in
Hermes's pinned `_HERMES_CORE_TOOLS` list have an explicit classification.
Browser tools remain classified for upgrade review but are absent from the
recommended policy because `agent.disabled_toolsets: [browser]` and the
derivative image both disable them. Desktop, Home Assistant, Kanban, and
computer-use tools are runtime/configuration-gated and also excluded from this
profile. Unknown names classify as `unknown`, cannot appear in policy, and are
denied.

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
`--recommended` to validate a deliberately narrowed exact subset.
Wildcards, duplicate names, unreviewed classifications, different Hermes pins,
and unknown fields are rejected. Removing an exact entry is the supported way
to deny a deployment-eligible tool.

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

The admission image uses a digest-pinned Python 3.12.10 slim base. It does not
contain Hermes, its credentials, or `/opt/data`; the wheel is compatible with
Hermes's supported Python range.

A downstream derivative can consume the wheel without a source checkout:

```dockerfile
ARG CHARON_HERMES_IMAGE
FROM ${CHARON_HERMES_IMAGE} AS charon_hermes_artifact
FROM <pinned-hermes-v2026.8.3-image>
COPY --from=charon_hermes_artifact \
  /opt/charon-hermes/wheels/charon_hermes-0.2.1-py3-none-any.whl /tmp/
RUN python -m pip install --no-deps \
  /tmp/charon_hermes-0.2.1-py3-none-any.whl \
  && rm /tmp/charon_hermes-0.2.1-py3-none-any.whl
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
Docker's socket, Charon manifests, Vaultwarden state, provider references, or
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
