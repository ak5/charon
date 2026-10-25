# Charon

<p align="center">
  <a href="https://github.com/ak5/charon/actions/workflows/ci.yml"><img src="https://github.com/ak5/charon/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://github.com/ak5/charon/pkgs/container/charon"><img src="https://img.shields.io/badge/container-ghcr.io%2Fak5%2Fcharon-blue" alt="Container image"></a>
  <a href="https://github.com/ak5/charon/blob/main/Cargo.toml"><img src="https://img.shields.io/badge/rust-1.99%2B-orange" alt="Rust 1.99 or newer"></a>
  <a href="https://github.com/ak5/charon/blob/main/LICENSE"><img src="https://img.shields.io/github/license/ak5/charon" alt="MIT license"></a>
</p>

<p align="center">
  <img
    src="https://github.com/ak5/charon/releases/download/readme-assets/charon.jpg"
    alt="Charon ferrying souls across the river Styx"
    width="900"
  >
</p>

Charon is a transparent gateway and forward proxy that adds credentials to
approved outbound requests. It also forwards secretless and caller-authenticated
traffic through an exclusive workload gateway for ordinary proxy clients.
It lets a workload call an API without putting the API credential in that
workload's environment, filesystem, or container image.

AI agents are workloads from Charon's point of view. Charon can give an agent
narrowly scoped access to an authenticated API without placing the long-lived
credential inside the agent runtime. The same model works for CLIs, builds,
development containers, and other programs.

For credential mediation, the workload sends an opaque capability reference instead of a real credential. Charon
checks authorization, matches the request against local policy, obtains the
credential from its unlocked KeePass database, and hydrates the reference only in
the request sent upstream.

```text
workload                         Charon                     API
no stored credential  ──▶  verify + apply policy  ──▶  authenticated request
capability reference        resolve credential + sanitize response
```

Charon is an early-stage project. Its explicit proxy, transparent TLS gateway,
authorization, structured hydration, response mediation, KeePass credential storage,
metadata-only receipts, and isolated tests are implemented.

## Why use it?

AI agents and other software often need authenticated access to external
services such as email, calendars, cloud platforms, customer-support systems,
payment providers, or an organization's own APIs. Giving every workload a
long-lived credential makes that credential available to the workload and to
anything that compromises it.

Charon moves the credential into a smaller, separately operated process. A
request is allowed only when all of these agree:

- a signed, short-lived, single-use manifest in signed proxy mode, or an
  Infra-isolated listener bound to one workload in transparent/exclusive mode;
- a named capability in Charon's configuration; and
- the actual destination hostname, HTTP method, and path.

The workload cannot choose a secret, a secret-store item, or an unconfigured
destination. Charon does not return brokered credentials to workloads and does not
follow redirects after adding one.

Applications keep using their ordinary credential settings. The configured
value is public policy identity, not a credential:

```dotenv
GH_TOKEN={{charon.github.read}}
POSTMARK_SERVER_TOKEN={{charon.postmark.send}}
```

An SDK or CLI treats these as normal values. Charon recognizes them only in the
policy-declared authentication location and replaces them at the final outbound
boundary.

## Concepts

These names appear in the configuration and protocol:

| Term | Meaning |
| --- | --- |
| **Workload** | The program making the outbound request, such as an AI agent, CLI, build, or development container. |
| **Manifest** | A short-lived, signed authorization used by explicit-proxy clients. It identifies the workload and names one capability. Each manifest can be used once. |
| **Capability** | A named permission in Charon's local policy, for example “read the current GitHub user.” It maps to one service and an exact set of methods and paths. |
| **Capability reference** | Public syntax such as `{{charon.github.read}}`. It names local policy, never a database entry or secret. |
| **Service** | An exact destination, typed hydration rule, KeePass reference, response mode, and resource limits. |
| **KeePass store** | A read-only KDBX database unlocked by its owner through the HTTPS admin page. Only exact mapped Password fields resolve. |
| **Realm** | One isolated Charon deployment: a process, configuration, KeePass database and unlocked memory, and policy. |

The current pre-1.0 manifest also carries tenant, persona, workspace, and lease
identifiers supplied by the issuer. They are integration context, not secret
selectors or core Charon concepts. This part of the public contract is under
review before 1.0.

## How a signed credential request works

1. A trusted issuer gives the workload a signed manifest for a named
   capability.
2. The workload sends a normal proxy request to Charon with
   `Proxy-Authorization: Charon <manifest>` and the configured public
   capability reference in the configured authentication sink. In transparent
   mode, Infra routes an isolated workload to its policy-bound listener and no
   proxy setting or manifest header is required.
3. Charon verifies the signature, expiry, realm identity, and single-use nonce.
4. Charon resolves the capability from its own configuration and checks the
   request's exact host, method, and path.
5. When configured, Charon requests a Telegram allow-once decision. It then
   resolves the policy-owned reference from its unlocked KeePass snapshot.
6. Charon hydrates only the declared sink at the outbound boundary, mediates
   the response using its explicit streaming mode, and writes a metadata-only
   receipt.

For HTTPS, the workload connects through Charon using HTTP `CONNECT` and trusts
the operator-provided Charon CA. The
[forward-proxy contract](contracts/forward-proxy.md) specifies that wire
protocol. The [transparent-gateway contract](contracts/transparent-gateway.md)
specifies interception, capability references, hydration, response modes, and
the Infra routing boundary. Charon's ordinary health endpoints are described by
[OpenAPI](contracts/openapi.yaml).

## Development

The project requires Rust 1.99 or newer. [mise](https://mise.jdx.dev/) is
optional; it installs the pinned toolchain and provides short names for common
development commands.

```sh
mise install
mise run check
```

`mise run <task>` means “run a task defined in `mise.toml`.” For example,
`mise run dev` runs the task named `dev`:

```sh
mise run dev
```

That command is equivalent to:

```sh
cargo run -- --config examples/charon.dev.toml
```

The development example contains synthetic paths and identifiers. Provision
its KeePass file, private admin-state directory, and HTTPS certificate before
starting it. Its workload proxy listens on `127.0.0.1:3129`; the separate admin
listener uses the configured HTTPS origin. The store starts locked. Tests create
disposable synthetic KDBX files without requiring operator setup.

Run the individual checks directly if you do not use mise:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo deny check
```

## Configuration

[`examples/charon.dev.toml`](examples/charon.dev.toml) is a minimal local
configuration. [`examples/charon.toml`](examples/charon.toml) shows the
KeePass, HTTPS admin, TLS, identity, capability, and service settings used in an
operator-managed explicit proxy. [`examples/transparent-gateway.toml`](examples/transparent-gateway.toml)
shows a synthetic policy-bound transparent listener.

Configuration is deny-by-default:

- destination hosts are exact names; wildcards are not supported;
- capabilities list exact HTTP methods and paths;
- remote destinations require HTTPS on port 443;
- redirects are disabled;
- request and response bodies have independent size limits; and
- response parsing, compression, duration, idle time, and opaque media types
  are explicit policy;
- unknown configuration fields are rejected.

### KeePass and owner enrollment

Charon uses one concrete, read-only KeePass KDBX store. `[keepass]` names the
private database and optional private key file. Each `[[keepass.items]]` maps a
local `secret_ref` and realm persona to an exact canonical entry UUID. Charon
reads only that entry's protected Password field; workloads cannot select entries.

The process boots locked. On first startup it prints a random enrollment code
to the operator console, valid for five minutes. Retrieve it over SSH and open
the configured HTTPS admin origin on your own device. Enter the code and create
a passkey. Charon persists public registration data, never the passkey private
key. Sign in with that passkey, enter the KeePass master password, and unlock.
The master password is discarded after decryption; mapped values remain in
secret-holding memory until explicit lock or process restart. Enroll a second
passkey while signed in for recovery. There is no default admin password.

The admin listener needs a stable DNS origin, browser-trusted certificate, and
its own TLS key. It is separate from workload listeners and the interception CA.
Keep public passkey state in a private writable directory. See
[owner operations](docs/admin.md) for configuration and recovery.

`[admin]` is required by the binary in either serving mode.
`mise run browser-admin-check` separately verifies the UI with Chrome and Node 22+.
The main quality gate does not run that browser-dependent test.

### Telegram decisions

See [BotFather setup](docs/telegram-setup.md) and the
[two-password E2E fixture](tests/e2e/README.md).

Optional `[admin.telegram]` settings select one positive private user/chat ID
and exact capability or route names requiring approval, each with a required
public `approval_descriptions` authority summary. Store the bot token in
an operator-only protected KeePass Password field and set
`keepass.telegram_bot_token_entry_id` to its exact UUID, outside workload mappings.
Start a private chat with the bot before using it. After HTTPS owner unlock,
Charon sends an unlocked notification and allow-once/deny buttons for selected
requests. Lock cancels pending approvals and stops the channel; restart requires
another owner unlock. No bot token or master password is read from environment
variables or password files. Each decision expires after at most two minutes;
gateway deadlines may shorten it. Unavailable delivery, timeout, denial, and
cancellation fail closed. Telegram never receives the vault password, enrollment
code, or workload credential values. Approval covers one use of the configured
capability; it does not review a particular resource or request body. Prompt
admission is limited to 10 per rolling minute and 32 pending per process.

## Project boundaries

Charon owns the request-time data path: identity or isolated-listener binding,
local policy, credential lookup, typed hydration, response mediation, proxying,
metadata-only receipts, owner enrollment, and optional local Telegram decisions.

It does not own:

- user, workspace, or lease management;
- issuance of workload manifests;
- secret-store provisioning and backup;
- deployment or network policy; or
- external control-plane approval rules and manifest issuance.

Those systems integrate through signed data and versioned contracts; Charon
does not query an application's database on the request path. See the
[integration boundary map](docs/integration-boundaries.md) and
[machine-readable contracts](contracts/README.md).

## Security

Charon handles credentials, so changes to authorization, proxying, KeePass
storage, admin authentication, Telegram decisions, TLS, or logging deserve careful review. Please read
[`SECURITY.md`](SECURITY.md) before reporting a vulnerability and see the
[threat model](docs/threat-model.md) for the detailed guarantees, assumptions,
and remaining risks.

The full local quality gate is:

```sh
mise run check
```

## Other projects like Charon

- [Infisical Agent Vault](docs/comparisons/infisical-agent-vault.md): when to use
  its credential-management workflows and when to use Charon with KeePass.

## Contributing and releases

Create feature branches from `main` and open pull requests to `main`. Required
checks protect this single long-lived branch. Successful CI on merged commits
publishes immutable container images; deployment remains an operator action.
See [the contribution policy](CONTRIBUTING.md).

## Documentation

- [Documentation index](docs/index.md)
- [Contributing](CONTRIBUTING.md)
- [Forward-proxy protocol](contracts/forward-proxy.md)
- [Transparent gateway protocol](contracts/transparent-gateway.md)
- [Hermes Agent integration](integrations/hermes/README.md)
- [Configuration and integration boundaries](docs/integration-boundaries.md)
- [Threat model](docs/threat-model.md)
- [Deployment guide](docs/deployment.md)
- [Architecture decisions](docs/adr/)
- [Human-approval contracts](contracts/README.md)

## License

Charon is licensed under the [MIT License](LICENSE).

## Exclusive Hermes network gateway

The [exclusive workload gateway](contracts/workload-gateway.md) provides a separate
`--gateway-config` mode for ordinary HTTP(S) proxy clients, including reusable
CONNECT tunnels. It binds one fixed isolated workload, supports secretless
forwarding and typed credential sinks, and requires its own validated schema.
Signed proxy authentication, transparent service lanes, and Hermes tool
admission remain independent controls. Infra owns isolation, trust and cutover.
