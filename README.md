# Charon

<p align="center">
  <a href="https://github.com/ak5/charon/actions/workflows/ci.yml"><img src="https://github.com/ak5/charon/actions/workflows/ci.yml/badge.svg" alt="CI status"></a>
  <a href="https://github.com/ak5/charon/pkgs/container/charon"><img src="https://img.shields.io/badge/container-ghcr.io%2Fak5%2Fcharon-blue" alt="Container image"></a>
  <a href="https://github.com/ak5/charon/blob/main/Cargo.toml"><img src="https://img.shields.io/badge/rust-1.97%2B-orange" alt="Rust 1.97 or newer"></a>
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
approved outbound requests.
It lets a workload call an API without putting the API credential in that
workload's environment, filesystem, or container image.

AI agents are workloads from Charon's point of view. Charon can give an agent
narrowly scoped access to an authenticated API without placing the long-lived
credential inside the agent runtime. The same model works for CLIs, builds,
development containers, and other programs.

The workload sends an opaque capability reference instead of a real credential. Charon
checks authorization, matches the request against local policy, obtains the
credential from the configured secret store, and hydrates the reference only in
the request sent upstream.

```text
workload                         Charon                     API
no stored credential  ──▶  verify + apply policy  ──▶  authenticated request
capability reference        resolve credential + sanitize response
```

Charon is an early-stage project. Its explicit proxy, transparent TLS gateway,
authorization, structured hydration, response mediation, provider adapters,
metadata-only receipts, and isolated tests are implemented.

## Why use it?

AI agents and other software often need authenticated access to external
services such as email, calendars, cloud platforms, customer-support systems,
payment providers, or an organization's own APIs. Giving every workload a
long-lived credential makes that credential available to the workload and to
anything that compromises it.

Charon moves the credential into a smaller, separately operated process. A
request is allowed only when all of these agree:

- a signed, short-lived, single-use workload manifest in explicit-proxy mode,
  or an Infra-isolated listener bound to one workload in transparent mode;
- a named capability in Charon's configuration; and
- the actual destination hostname, HTTP method, and path.

The workload cannot choose a secret, a secret-store item, or an unconfigured
destination. Charon does not return credentials to workloads and does not
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
| **Capability reference** | Public syntax such as `{{charon.github.read}}`. It names local policy, never a provider item or secret. |
| **Service** | An exact destination, typed hydration rule, provider reference, response mode, and resource limits. |
| **Secret provider** | The adapter Charon uses to obtain a credential. The current implementations are an environment provider for disposable development and a Vaultwarden provider. |
| **Realm** | One isolated Charon deployment: a process, configuration, secret-provider session, and policy. |

The current pre-1.0 manifest also carries tenant, persona, workspace, and lease
identifiers supplied by the issuer. They are integration context, not secret
selectors or core Charon concepts. This part of the public contract is under
review before 1.0.

## How a request works

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
5. Charon asks its configured provider for the policy-owned secret reference.
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

The project requires Rust 1.97 or newer. [mise](https://mise.jdx.dev/) is
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

The development configuration listens only on `127.0.0.1:3129`, uses the
environment provider, and contains no real credential. It is suitable for
starting the process and inspecting its health endpoints; exercising an
authenticated proxy request also requires issuing a valid test manifest.

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
Vaultwarden, TLS, identity, capability, and service settings used in an
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

### Secret-store adapters

Secret stores sit behind the Rust `SecretProvider` interface. An adapter
receives an opaque reference chosen by local policy and returns a
`SecretString`; callers never choose a backend item.

The binary currently includes:

- `environment`, intended only for disposable local development; and
- `vaultwarden`, using an isolated Bitwarden CLI session and exact item UUID
  mappings.

More backends can be added without changing the workload protocol. Providers
are compiled into the binary and selected by trusted realm configuration;
Charon does not load credential-handling plugins dynamically or fall back to a
different provider during an outage. The extension rules are documented in
[ADR 0004](docs/adr/0004-secret-provider-adapters.md).

## Project boundaries

Charon owns the request-time data path: identity or isolated-listener binding,
local policy, credential lookup, typed hydration, response mediation, proxying,
and metadata-only receipts.

It does not own:

- user, workspace, or lease management;
- issuance of workload manifests;
- secret-store provisioning and backup;
- deployment or network policy; or
- human-approval workflows.

Those systems integrate through signed data and versioned contracts; Charon
does not query an application's database on the request path. See the
[integration boundary map](docs/integration-boundaries.md) and
[machine-readable contracts](contracts/README.md).

## Security

Charon handles credentials, so changes to authorization, proxying, provider
adapters, TLS, or logging deserve careful review. Please read
[`SECURITY.md`](SECURITY.md) before reporting a vulnerability and see the
[threat model](docs/threat-model.md) for the detailed guarantees, assumptions,
and remaining risks.

The full local quality gate is:

```sh
mise run check
```

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
