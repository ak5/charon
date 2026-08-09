# Repository conventions

## Repository shape and commands

Charon is a Rust package with contracts, deployment examples, first-party
integrations, and durable design documentation in the same repository. Cargo
owns Rust build and test behavior. Each integration owns its native package and
tests under `integrations/<name>/`. `mise.toml` pins Rust, Python, and
`cargo-deny` and provides
stable operator tasks across formatting, linting, tests, deployment-contract
tests, and dependency policy. This cross-tool quality gate is why
`mise run check` exists.

Repository-root `tmp/` is an ignored workspace for disposable artifacts. Use
`tmp/<task-name>/` to avoid collisions. Never store credentials there. Move
anything durable to its owned tracked path.

## Branch and release policy

`dev` is the integration and default branch. Ordinary pull requests target
`dev`. Maintainers SHOULD squash a single-result change and CAN rebase an
approved commit series whose commits pass independently.

`main` is production. Only `dev` release pull requests and emergency
`hotfix/*` pull requests target it. Releases MUST use merge commits because
squash or rebase would break the shared ancestry required for repeated
`dev`-to-`main` promotion. After a hotfix, maintainers MUST merge `main` back
into `dev`.

Both long-lived branches require pull requests and block force pushes and
deletion. The project does not use a merge queue.

## Documentation ownership

| Changed surface | Documentation owner |
| --- | --- |
| Public purpose, quick start, supported provider summary | `README.md` |
| HTTP and workload wire behavior | `contracts/` |
| Configuration schema or integration responsibility | `docs/integration-boundaries.md` and examples |
| Trust boundary, credential flow, authorization, redirects, or logging | `docs/threat-model.md` |
| Operator deployment behavior | `docs/deployment.md` |
| Approval broker behavior | `contracts/approval-*` and `docs/approval-broker-operations.md` |
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
