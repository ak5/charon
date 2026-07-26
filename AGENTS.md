# Agent Guidance

Charon is a credential-handling security boundary. Prefer a small, explicit,
fail-closed design over convenience.

- Never commit, log, snapshot, or fixture real credentials.
- Destination access is deny-by-default and uses exact hostnames. Do not add
  wildcard or caller-selected credential references.
- Credential values must use secret-holding types and must never implement
  `Debug`, serialization, or response conversion.
- Redirects remain disabled unless every hop is independently re-authorized.
- Keep the data plane independent of any orchestrator. Integrators issue signed
  workload identity and policy; Charon does not query an application's database
  or control-plane API.
- Update `docs/threat-model.md` when a trust boundary or credential flow changes.
- Run `mise run check` before committing.

Branch workflow:

- Create feature branches from `dev` and target ordinary pull requests to `dev`.
- Only release pull requests from `dev` target `main`.
- Treat `main` as production and release immutable container versions from it.
