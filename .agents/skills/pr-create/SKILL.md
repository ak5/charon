---
name: pr-create
description: Prepare an honest Charon pull request using the staged release policy.
---

# Create a pull request

1. Read `CONTRIBUTING.md`, `docs/conventions.md`, and the current diff.
2. Confirm the branch started from `dev`. Ordinary work MUST target `dev`;
   only `dev` releases and `hotfix/*` repairs target `main`.
3. Preserve intent, decisions, evidence, caveats, known warts, excluded
   follow-up work, security impact, documentation parity, risk, and rollback.
4. Run `$doc-code-parity` and `mise run check`.
5. Review commits and changed files for secrets or unrelated work.
6. Push and create the PR only when authorized. Never merge it in this skill.

Use `.github/PULL_REQUEST_TEMPLATE.md` for ordinary changes and
`.github/PULL_REQUEST_TEMPLATE/release.md` for `dev` to `main`.
