---
name: teach-ship
description: Teach how verified Charon changes move through main pull requests into production.
---

# Learn to ship

Reconcile intent, diff, tests, documentation, risk, rollback, and excluded
follow-up work. Run `$doc-code-parity` and `mise run check`, then use `$pr-create`
for a PR from a feature branch into the protected default branch `main`.
Wait for required checks and merge only with operator authority.

After merge, verify the resulting main commit and its successful CI run.
Production images use that exact commit in their immutable tag. There is no
release-branch promotion PR. Publishing and deploying remain distinct operations;
CI publishes on successful main pushes, while deployment requires operator authority.
