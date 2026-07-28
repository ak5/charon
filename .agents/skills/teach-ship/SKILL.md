---
name: teach-ship
description: Teach how verified Charon changes move through dev into production.
---

# Learn to ship

For ordinary work, reconcile intent, diff, tests, documentation, risk,
rollback, and excluded follow-up work. Run `$doc-code-parity` and
`mise run check`, then use `$pr-create` for a PR to `dev`.

For a release, record the `dev` source SHA, open `dev` to `main`, wait for fresh
checks, and use a merge commit. After merge, verify:

```sh
git merge-base --is-ancestor <release-source-sha> main
```

Production images originate from `main`. Merging, publishing, and deploying
each require explicit operator authority.
