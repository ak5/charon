# Repository conventions

## Repository shape and commands

Charon is a Rust package with contracts, deployment examples, first-party
integrations, and durable design documentation in the same repository. Cargo
owns Rust build and test behavior. Each integration owns its native package and
tests under `integrations/<name>/`. `mise.toml` and CI pin Rust 1.99.0; the
container build uses the patched Rust 1.99.1 image. The local compiler profile
is minimal plus Clippy/rustfmt. `mise.toml` also pins Python and `cargo-deny`
and provides stable operator tasks across formatting, linting, tests, deployment-contract
tests, and dependency policy. This cross-tool quality gate is why
`mise run check` exists.
Its `strict-tls-check` also selects Python 3.13.5 and HTTPX 0.28.1 in a
disposable venv to verify generated CONNECT chains with Hermes-matched strict
TLS clients. This client test does not change the admission package's Python pin.
`mise run browser-admin-check` is an additional owner-UI proof that requires
Chrome and Node 22 or newer. It starts isolated synthetic HTTPS/Chrome state,
uses a virtual passkey, and stops its server and browser when finished.

`mise run e2e-flow` runs the connected offline KDBX/admin/approval/proxy/API
fixture using curl. `mise run e2e` runs it and the Chrome proof. See
[the E2E guide](../tests/e2e/README.md); live Telegram is a separate explicit opt-in.

Repository-root `tmp/` is an ignored workspace for disposable artifacts. Use
`tmp/<task-name>/` to avoid collisions. Never store credentials there. Move
anything durable to its owned tracked path.

## Branch and release policy

`main` is the only long-lived branch, the default branch, and the production
source. Feature branches start from `main`; ordinary changes, dependency updates,
and hotfixes all reach it through pull requests with required checks.
Maintainers SHOULD squash a single-result change and CAN use a merge commit
when preserving contributor or integration ancestry matters. Shared history is
never rewritten.

`main` requires pull requests and blocks force pushes and deletion. The project
does not use a merge queue. Successful CI on a merged `main` commit publishes
immutable container images; deployment is an operator decision. No release
branch or promotion PR is required. The `mise run dev` task is a local development
command, not a branch.

## Documentation ownership

| Changed surface | Documentation owner |
| --- | --- |
| Public purpose, quick start, KeePass and owner enrollment summary | `README.md` |
| HTTP and workload wire behavior | `contracts/` |
| Configuration schema or integration responsibility | `docs/integration-boundaries.md` and examples |
| Trust boundary, credential flow, authorization, redirects, or logging | `docs/threat-model.md` |
| Operator deployment behavior | `docs/deployment.md` |
| Request approvals | `docs/admin.md` and `docs/adr/0009-local-telegram-allow-once.md` |
| Architectural decision | `docs/adr/` |
| Contributor, branch, merge, or release policy | `CONTRIBUTING.md` and this document |
| Commands or tool versions | `mise.toml`, `README.md`, and this document |
| Workload integration behavior | `integrations/<name>/`, shared `contracts/`, and `docs/integration-boundaries.md` |

## Repository bootstrap

- Profile: Full public Rust security service.
- Canonical entry points: `README.md`, `docs/index.md`, and `CONTRIBUTING.md`.
- Enabled capabilities: conventions, agent operation, teaching, documentation
  parity, PR workflow, Vibe Session readiness, GitHub hygiene, automation, and
  environment.
- Vibe Session readiness: enabled.
- Starter/template adoption: intentionally omitted because this is an
  established Rust codebase.
