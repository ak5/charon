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

Create a feature branch from `main` and open the pull request against `main`.
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

## Merges and releases

`main` is the only long-lived branch, the default branch, and the source of
production container images. It remains protected and PR-only. Feature,
dependency, and hotfix pull requests all target `main` and must pass its required
checks. Maintainers SHOULD squash a single-result change and CAN use a merge
commit when preserving contributor or integration ancestry matters. Do not
rewrite shared history.

A successful CI run for a push to `main` publishes immutable images tied to that
exact commit. Merging makes a change releasable; deployment remains a separate
operator action. There is no separate release-branch promotion step.

## Security reports

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md)
and use GitHub private vulnerability reporting.
