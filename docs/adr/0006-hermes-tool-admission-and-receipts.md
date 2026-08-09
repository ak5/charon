# ADR 0006: Hermes tool admission and receipts

Status: accepted for Hermes v2026.8.3 production integration

## Context

Hermes Agent exposes semantic tool calls before they become shell processes,
file mutations, MCP requests, or network traffic. Charon sees only authorized
network requests and cannot reconstruct one logical tool invocation from one or
more HTTP exchanges. Operators need a workload-facing permission gate and
compact execution evidence without adding Hermes to Charon's credential-holding
process.

Hermes plugin hooks run inside the untrusted workload process. Hook failures are
observational by design, and a compromised workload can modify or bypass an
in-process plugin. The integration therefore cannot replace direct-egress
denial, signed manifests, or Charon's exact request policy.

## Decision

The repository provides a separately packaged `charon-hermes` Python plugin
under `integrations/hermes`.

Before a tool call, the plugin sends a normalized metadata-only operation over
an operator-owned Unix socket. The local integration service applies an exact
tool-name and classification policy. Unknown tools, missing service state,
timeouts, malformed responses, replayed operation IDs, and negative decisions
block execution.

Compatibility is pinned to an immutable Hermes tag and commit. A reviewed
whole-tool catalog classifies every name in the Telegram core bundle. Mixed
read/write tools use the more sensitive mutation classification; classifications
never depend on raw argument values. Browser names remain known but are omitted
from the browserless deployment policy.

After an admitted call, the plugin emits a metadata-only receipt through a
bounded asynchronous queue. The integration service binds the receipt to the
single admission authorization and appends it to a mode-`0600`, hash-chained
JSON Lines journal. Raw arguments and raw output never cross this boundary.

The plugin and service do not hold API credentials, Charon manifests, provider
references, secret-store access, or signing keys. Tool admission cannot widen a
Charon capability. Charon core has no Python or Hermes dependency.

## Trust and failure behavior

Filesystem ownership and a mode-`0600` Unix socket prevent unrelated local
users from connecting. They do not isolate a service running under the same OS
identity from a compromised Hermes process. Strong attestation requires an
independently isolated tool gateway that performs execution and signs receipts.

Admission is synchronous, local, bounded, and fail-closed. Receipt export is
asynchronous and bounded because Hermes post-tool hooks cannot revoke an
already completed operation. Export failure increments a loss counter and does
not affect Charon authorization.

Hermes evaluates the Charon pre-tool hook before its tool guardrail. Charon
returns allow or block only. An admitted terminal or code call continues into
Hermes's existing command-aware Telegram approval system; this integration
neither bypasses nor replaces that human approval.

The journal hash chain detects modification when a trusted copy of a previous
digest exists. It is not a digital signature and does not prove integrity after
full compromise of the service host.

## Rejected alternatives

- **Generate semantic receipts inside Charon:** one tool can make several
  requests or no network request, and Charon deliberately excludes bodies.
- **Store raw hook arguments and results:** tool content can contain credentials,
  private data, manifests, and arbitrary terminal output.
- **Use a shell hook per invocation:** subprocess startup adds unnecessary
  latency and expands the parsing boundary.
- **Allow tools when the integration service is unavailable:** this silently
  removes the requested permission boundary.
- **Treat the in-process plugin as strong enforcement:** the workload can modify
  code in its own trust boundary.

## Consequences

Hermes receives a coherent Charon integration with low receipt overhead and an
explicit fail-closed semantic gate. Additional workload adapters can implement
the shared contracts without entering Charon core. Resource-aware policies,
manifest issuance, signed receipt export, and an isolated tool gateway remain
separate future capabilities.
