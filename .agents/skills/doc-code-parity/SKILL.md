---
name: doc-code-parity
description: Check Charon documentation against code, contracts, configuration, and workflows.
---

# Documentation and code parity

Default to the current diff. Use a full sweep when explicitly requested.

1. Read `docs/conventions.md` and its documentation ownership table.
2. Inspect changed source, contracts, examples, deployment files, workflows,
   and `mise.toml`.
3. Compare behavior with the owning documents. Search exact flags, fields,
   endpoints, commands, host rules, and provider names with `rg`.
4. Distinguish a stale document from an implementation regression. Preserve
   security intent; do not normalize a code regression into prose.
5. Update `docs/threat-model.md` whenever a trust boundary or credential flow
   changes.
6. Check all relative Markdown links and run `mise run check`.
7. Report corrected drift and unresolved judgment calls separately.

For a full sweep, include `README.md`, `CONTRIBUTING.md`, `SECURITY.md`,
`docs/`, `contracts/`, `.github/`, `deploy/`, `examples/`, `integration/`,
`src/`, `tests/`, and `mise.toml`.
