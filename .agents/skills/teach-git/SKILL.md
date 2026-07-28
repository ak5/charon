---
name: teach-git
description: Teach Charon's dev-to-main Git workflow and verification habits.
---

# Learn the Git workflow

Explain state before mutation. Use `git status`, `git diff`, and `git log` as
evidence.

- Feature branches start from `dev`; ordinary PRs target `dev`.
- Maintainers squash one result or deliberately rebase an independently valid
  commit series.
- Release PRs go from `dev` to `main` and MUST use a merge commit.
- Hotfixes target `main`, then `main` is merged back into `dev`.
- Shared history is never rewritten.

Teach the operator to inspect the exact diff, run checks, and approve pushing
or opening a PR separately. Recover with revert or a corrective commit.
