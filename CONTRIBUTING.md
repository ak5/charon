# Contributing to Charon

Thank you for helping improve Charon. Because Charon handles credentials,
security boundaries receive the same care as implementation details.

## Before changing code

Read the [documentation index](docs/index.md), [repository
conventions](docs/conventions.md), [security policy](SECURITY.md), and
[threat model](docs/threat-model.md). Never use real credentials in code,
tests, logs, examples, captures, or fixtures.

Install the pinned tools and run the complete local quality gate:

```sh
mise install
mise run check
```

## Pull requests

Create a feature branch from `dev` and open the pull request against `dev`.
A pull request is a proposal, not an entitlement to merge. Merge-ready work has
a clear purpose, focused scope, passing checks, documentation parity, and an
explicit account of security impact.

Maintainers SHOULD squash a change that represents one result. They CAN use a
rebase merge when every preserved commit is independently coherent and passes
the required checks. Work that is not merge-ready can be revised, split,
rewritten on a maintainer-owned `integrate/pr-N` branch, or declined.
Maintainers MUST NOT silently rewrite a contributor-owned branch. Material
rewrites require fresh CI and review.

The final commit records the primary author. Use `Co-authored-by` trailers for
material contributions retained in that commit. If maintainers replace an
implementation rather than retain it, the pull request discussion and release
notes SHOULD acknowledge the original proposal without claiming false commit
authorship.

## Releases and hotfixes

Only a release pull request from `dev` targets `main`. Maintainers MUST use a
merge commit for that pull request so `dev` remains an ancestor of `main`.
Squash and rebase release merges are prohibited.

Emergency `hotfix/*` branches CAN target `main`. After merging a hotfix,
maintainers MUST merge `main` back into `dev` before the next release.

## Security reports

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md)
and use GitHub private vulnerability reporting.
