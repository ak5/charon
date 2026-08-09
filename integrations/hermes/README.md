# Charon for Hermes Agent

`charon-hermes` is the first-party Hermes Agent integration for Charon. It adds
fail-closed tool admission before every Hermes tool call and emits compact,
metadata-only execution receipts after admitted calls finish.

The package does not put Charon inside Hermes. It contains no API credentials,
Charon manifests, provider references, secret-store access, or signing keys.
Charon remains the independent credential-injection proxy and continues to
enforce its own exact destination, method, and path policy.

The normative data and transport rules are in the
[`tool-integration` contract](../../contracts/tool-integration.md). The
architectural decision and rejected alternatives are recorded in
[`ADR 0006`](../../docs/adr/0006-hermes-tool-admission-and-receipts.md).

## Architecture

```text
Hermes pre_tool_call
  -> charon-hermes plugin
  -> protected Unix admission service
  -> exact tool-name/classification policy
  -> allow or block

Hermes post_tool_call
  -> metadata-only receipt
  -> bounded in-process queue
  -> protected Unix service
  -> mode-0600 hash-chained JSONL journal
```

Permission admission is synchronous and bounded. Receipt export is asynchronous
and never copies raw arguments or raw tool output. A missing socket, malformed
decision, timeout, unknown tool, or classification mismatch denies the tool
call.

## Install

Install this package into the same Python environment as Hermes:

```sh
python -m pip install ./integrations/hermes
```

Enable the pip-discovered plugin in Hermes:

```yaml
plugins:
  enabled:
    - charon-hermes
```

## Start the local integration service

Copy `examples/policy.json` to an operator-owned path and list only exact tool
names. Wildcards are rejected. Protect the policy from group or other writes.

```sh
chmod 0644 /etc/charon/hermes-policy.json
install -d -m 0700 /run/user/1000/charon-hermes
install -d -m 0700 /var/lib/charon-hermes

charon-hermes-admission \
  --socket /run/user/1000/charon-hermes/admission.sock \
  --policy /etc/charon/hermes-policy.json \
  --state-dir /var/lib/charon-hermes
```

Configure Hermes with the absolute socket path:

```sh
export CHARON_HERMES_ADMISSION_SOCKET=/run/user/1000/charon-hermes/admission.sock
```

Optional settings:

- `CHARON_HERMES_TIMEOUT_MS`: admission and receipt-export timeout, 10–5000 ms;
  default 250 ms.
- `CHARON_HERMES_QUEUE_SIZE`: bounded receipt queue, 16–65536; default 1024.
- `CHARON_HERMES_RESULT_DIGESTS`: `0` by default. Set `1` only when output
  digest retention has a reviewed purpose; hashes can disclose low-entropy
  results by comparison.

## Permission limits

The included service provides exact Hermes tool-level admission. It does not
issue workload manifests and cannot widen Charon policy. A production workload
still needs an external identity issuer and network isolation that prevents
direct egress around Charon.

The socket uses filesystem ownership and mode `0600`. Running Hermes and the
service under the same operating-system identity provides operational policy,
not protection from a fully compromised Hermes process. Strong isolation
requires the service and issuer to run under a separate identity and a brokered
transport with authenticated peer identity.

## Receipt semantics

A receipt records identifiers, exact tool name, classification, argument
digest, authorization ID, timing, outcome, result size, and an optional result
digest. It never records raw arguments or raw output. The local journal adds a
hash chain for tamper evidence; it is not a digital signature or independent
proof against a compromised service host.

Receipt-export failure does not change a completed tool result because Hermes
post hooks are observational. The exporter increments an in-memory dropped
counter and remains bounded. Workflows that require “no receipt, no execution”
must execute the tool behind an external trusted tool gateway instead of relying
on an in-process Hermes hook.

## Development

```sh
mise run hermes-check
```
