---
name: pr-create
description: Prepare an honest Charon pull request using the main-only PR policy.
---

# Create a pull request

1. Read `CONTRIBUTING.md`, `docs/conventions.md`, and the current diff.
2. Confirm the branch started from `main`. Feature, dependency, and hotfix
   pull requests MUST target the protected default branch `main`.
3. Preserve intent, decisions, evidence, caveats, known warts, excluded
   follow-up work, security impact, documentation parity, risk, and rollback.
4. Run `$doc-code-parity` and `mise run check`.
5. Review commits and changed files for secrets or unrelated work.
6. Push and create the PR only when authorized. Never merge it in this skill.

Use `.github/pull_request_template.md` for all changes. Successful CI on merged
`main` commits publishes immutable images; deployment is a separate operator action.
