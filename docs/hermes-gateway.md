# Hermes single outbound HTTP(S) gateway

The exclusive workload gateway is specified by
[its contract](../contracts/workload-gateway.md). Its complete synthetic policy
is [hermes-gateway.toml](../examples/hermes-gateway.toml). Use a distinct process
and `charon --gateway-config /etc/charon/hermes-gateway.toml`; do not pass this
schema to `--config`. Validate the candidate against the exact released binary
with `charon gateway validate /etc/charon/hermes-gateway.toml`.

Infra owns Compose isolation, CA installation/trust, provider mappings, image
pins, Ansible, backup and cutover. Charon owns the protocol and validated schema.
This repository neither modifies live infrastructure nor removes its full
convergence guard. Config-only CD and the independent Hermes tool admission
service continue to have their own contracts.

## Exact destination inventory

The example is a reviewable provider profile, not every Hermes provider/tool.
Remove inactive provider routes. A custom model base URL, new provider, web
search, external download, MCP server, or redirect destination requires a new
exact hostname and operation grant. No wildcard/allow-all destination exists.

| Exact destination | Allowed purpose in example | Ownership |
| --- | --- | --- |
| `auth.openai.com` | POST `/oauth/token`, `/api/accounts/deviceauth/usercode`, `/api/accounts/deviceauth/token` | Caller-owned device login and token refresh |
| `chatgpt.com` | GET/POST `/backend-api/codex/` prefix | Caller-owned Codex OAuth, account/session headers, streaming |
| `portal.nousresearch.com` | POST `/api/oauth/device/code`, `/api/oauth/token`, `/oauth/code`, `/oauth/token` | Caller-owned Nous OAuth |
| `inference-api.nousresearch.com` | GET/POST `/v1/` prefix | Caller-owned Nous model credential |
| `openrouter.ai` | GET/POST `/api/v1/` prefix | Caller-owned OpenRouter model credential |
| `api.openai.com` | GET/POST/DELETE `/v1/` prefix | Caller-owned models and file uploads/downloads |
| `api.telegram.org` | GET/POST `/` prefix | Caller-owned bot-token paths, polling, upload and file download |
| `api.github.com` | API operations under `/` | Caller-owned gh/SDK Authorization |
| `github.com` | GET/POST `/` with Basic capability | Policy-owned synthetic Git credential |

Source inventory: pinned Hermes
`3c27eb6234bf91b8ceee9e9071591b31e9b148cb`,
[`hermes_cli/auth.py`](https://github.com/NousResearch/hermes-agent/blob/3c27eb6234bf91b8ceee9e9071591b31e9b148cb/hermes_cli/auth.py)
and
[`plugins/platforms/telegram/adapter.py`](https://github.com/NousResearch/hermes-agent/blob/3c27eb6234bf91b8ceee9e9071591b31e9b148cb/plugins/platforms/telegram/adapter.py).
Model path prefixes accommodate vendor file/response identifiers without
recording them. Telegram bot tokens appear inside its request paths: they must
never appear in receipts, request diagnostics, traces or captures. Browser
login takes place in the operator's browser; redirects to interactive login
hosts are not automatically granted to the workload.

GitHub alternate hosts (`raw.githubusercontent.com`, `objects.githubusercontent.com`,
`codeload.github.com`, release asset domains and Copilot endpoints) are absent
and denied. Infra must inventory the actual workload's required routes and
independently grant any needed exact destination. Adding a hostname does not
bypass the CONNECT/SNI/authority or public-address checks.

## Client trust and proxy settings

Install the public CA/root chain in the workload's OS trust store. Keep its
signing key readable only by Charon; never mount it into Hermes. Python's
certifi-based clients also need a CA bundle containing both the deployment root
and ordinary public roots. Set `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and
`CURL_CA_BUNDLE` to that bundle as appropriate. Configure Node with
`NODE_EXTRA_CA_CERTS` if used. Confirm Go/gh and Git trust the installed root.
Never use TLS verification disable flags.

Set HTTP_PROXY/HTTPS_PROXY and lowercase equivalents to the exclusive listener,
for example `http://charon:18080`, without proxy authentication. Set Telegram's
explicit `TELEGRAM_PROXY` to that same URL where the Hermes adapter needs it.
NO_PROXY may name local control/admission endpoints only. Hermes must not gain
a direct-egress lane when variables are absent or a library ignores them.

For a caller-owned route, curl, gh and SDKs supply their usual credentials.
For the example Git Basic grant, use fixed username `x-access-token` and the
synthetic capability password `{{charon.github-git}}`. The private Git token
is the Charon-only `CHARON_SYNTHETIC_GITHUB_TOKEN` provider value, never a client
variable. Real deployments should map that reference through Vaultwarden and
use protected provider inputs. No secret values belong in TOML or command logs.

## Feature verification and Infra handoff

Before a release, `mise run check` includes real local TLS fixtures. To rerun
just the new feature:

```sh
mise exec -- cargo test gateway --lib
mise exec -- cargo run -- gateway validate examples/hermes-gateway.toml
```

The client fixture requires curl and, on Linux, gh. Linux CI exercises both
unmodified clients. On macOS it exercises curl only: existing Go/gh builds use
Keychain trust rather than the fixture's `SSL_CERT_FILE`. Deployment verification
must still prove gh with the installed CA; tests do not change system trust.

The fixture upstream uses a separate synthetic CA and verified TLS; its local
routing override is confined to tests. Runtime has no private-address exception
or custom trust override. Verify the candidate deployment with synthetic
credentials and status-only assertions, without verbose curl traces or body
captures:

1. Validate its complete policy using the pinned image. Test OS, Python, curl,
   gh and SDK trust without disabling certificate validation.
2. Send an ordinary secretless request; confirm streaming, session headers,
   upload/download and no provider lookup. Send a typed credential reference
   and assert the fixture origin receives hydration only at its permitted sink.
3. Reuse one TLS tunnel for an allowed request, a denied operation, another
   allowed request, and a mismatched authority. Test HTTP/2 separately. Denials
   must happen before provider work.
4. Assert unknown hosts, metadata/private DNS, alternate ports, wrong SNI,
   untrusted upstream TLS, nested CONNECT, compression, and WebSocket upgrades
   fail closed. Follow a redirect only by a separately authorized request.
5. Inspect metadata receipts and fixed errors for fake sentinel values; ensure
   no URL, OAuth token path/query, prompt or body was recorded.
6. Independently prove direct TCP egress remains blocked with all proxy
   variables removed, IPv6/QUIC cannot escape, and alternate GitHub routes are
   denied. Charon's unit tests cannot prove host/network rules.
7. Confirm config CD, independent tool admission and encrypted backup behavior
   remain intact. Retain the installed Compose layout, immutable pins and config
   revision for rollback before any convergence.

Only Infra's reviewed completion and operator-authorized cutover can remove its
full convergence guard. Rollback restores the installed layout and pins; it
never restores unrestricted egress. An immutable release reference is published
by successful trusted `main` CI as `ghcr.io/<repository-owner>/<repository>:sha-<main-commit>`;
operators must record the actual registry digest, not infer one from a Git SHA.
