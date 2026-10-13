---
name: teach-git
description: Teach Charon's main-only PR workflow and verification habits.
---

# Learn the Git workflow

Explain state before mutation. Use `git status`, `git diff`, and `git log` as
evidence.

- `main` is the only long-lived, protected default branch.
- Feature branches start from `main`; feature, dependency, and hotfix PRs target it.
- Maintainers squash one result or preserve useful ancestry with a merge commit.
- Required checks pass before merge; immutable images come from verified main commits.
- Deployment is a separate operator decision. Shared history is never rewritten.

Teach the operator to inspect the exact diff, run checks, and approve pushing
or opening a PR separately. Recover with revert or a corrective commit.
