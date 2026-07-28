# Agent Guidance

Charon is a credential-handling security boundary. Prefer a small, explicit,
fail-closed design over convenience.

- Agents MUST NOT commit, log, snapshot, or fixture real credentials.
- Destination access MUST remain deny-by-default and use exact hostnames.
  Agents MUST NOT add wildcard or caller-selected credential references.
- Credential values MUST use secret-holding types and MUST NOT implement
  `Debug`, serialization, or response conversion.
- Redirects MUST remain disabled unless every hop is independently re-authorized.
- The data plane MUST remain independent of any orchestrator. Integrators issue
  signed workload identity and policy; Charon does not query an application's
  database or control-plane API.
- Agents MUST update `docs/threat-model.md` when a trust boundary or credential
  flow changes.
- Agents MUST run `mise run check` before committing.

Read [the documentation index](docs/index.md), [repository
conventions](docs/conventions.md), and [the contribution
policy](CONTRIBUTING.md) before changing public contracts or workflows.

Use `tmp/<task-name>/` for disposable task artifacts. Agents MUST NOT use `tmp/`
for credentials. Promote retained work to its owned tracked path and remove only
scratch files created by the current task.

Branch workflow:

- Agents MUST create feature branches from `dev` and target ordinary pull
  requests to `dev`.
- Only release pull requests from `dev` CAN target `main`.
- Maintainers MUST merge `dev` into `main` with a merge commit to preserve
  ancestry.
- Agents MUST treat `main` as production and release immutable container
  versions from it.
- Agents MUST NOT rewrite shared branch history.
