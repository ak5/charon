# Security audit — 2026-07-27

## Scope and method

This owner audit reviewed the complete public repository at the initial release
boundary:

- policy parsing and fail-closed configuration;
- signed workload identity, capability binding, time validation, and replay;
- HTTP forward proxying, CONNECT interception, TLS authority binding, header
  handling, redirects, and body limits;
- secret-provider abstraction, environment and Vaultwarden adapters, caching,
  subprocess execution, and protected files;
- container/runtime isolation, deployment artifacts, GitHub Actions, dependency
  policy, and public repository settings;
- contracts, tests, logging fields, documentation, and public-history residue.

The review combined manual data-flow and trust-boundary analysis with Rust unit
and integration tests, adversarial protocol tests, Clippy, rustfmt,
`cargo-deny`, shell syntax and ShellCheck, container builds, secret-pattern
scanning, GitHub configuration inspection, and a complete `mise run check`.

This is not an independent third-party audit and does not claim formal
verification.

## Remediated findings

### High — remote plaintext and alternate-port credential forwarding

An authorized workload could select `http://` or an alternate HTTPS port while
matching an allowed hostname and path. Charon would inject the credential into
that request.

Resolution: remote requests now require HTTPS on port 443. URL user information
is rejected. Literal loopback HTTP remains available only for local fixtures.
Regression tests cover plaintext, alternate ports, user information, and the
allowed HTTPS case.

### High — authority confusion through a caller-supplied Host header

The absolute request URI selected the network destination, but the original
`Host` header could be forwarded. A virtual host behind an allowed endpoint
could therefore receive a credential under a conflicting authority.

Resolution: a supplied `Host` must agree with the absolute target, CONNECT
`Host` must agree with its authority, and caller-supplied `Host` is never
forwarded. Existing CONNECT SNI, pseudo-authority, and inner-authority checks
remain in force.

### Medium — incomplete hop-by-hop header removal

The fixed denylist removed standard hop-by-hop headers but did not remove
extension fields named by `Connection`. Request framing fields were also copied
into a newly streamed request.

Resolution: Charon parses every `Connection` token, rejects malformed nominated
field names, strips nominated fields in both directions, and removes caller
framing fields before building the upstream stream.

### Medium — provider subprocess inherited ambient secrets

The Vaultwarden CLI child inherited Charon's process environment. This could
expose unrelated environment-provider values or host credentials to a
compromised CLI process.

Resolution: the child environment is cleared and rebuilt with only a fixed
system path, `BW_SESSION`, and `BITWARDENCLI_APPDATA_DIR`. A fixture asserts that
ambient environment variables are absent.

### Medium — inconsistent protected-file enforcement

The interception key checked Unix mode bits, but the Vaultwarden session,
encrypted state directory, and upstream-proxy password did not receive the same
runtime enforcement. Symlink/file-type ambiguity also remained.

Resolution: protected inputs must be private regular files, vault state must be
a private directory, and the CLI must be a regular owner-executable file that
is not group/world writable. Checks use symlink metadata and fail before the
listener opens.

### Medium — unbounded signed identity metadata and policy windows

A trusted or compromised issuer could create unusually large replay keys and
audit fields or configure very long token/replay windows.

Resolution: encoded tokens and decoded claims are bounded; audit-visible
identifiers are limited to 128 safe characters; token TTL is capped at five
minutes; and clock skew is capped at 30 seconds.

### Medium — mutable container build inputs and missing attestations

The Rust builder and distroless runtime stages used mutable tags.

Resolution: both stages are pinned by multi-platform manifest digest. Release
and pull-request builds request maximum BuildKit provenance plus SBOM
attestations. Dependabot now covers Docker as well as Cargo and GitHub Actions.

### Low — unsafe injection policy accepted until request time

Configuration could select routing, framing, proxy-authentication, or
hop-by-hop fields as the injection header, and malformed placeholders were not
validated until use.

Resolution: those header names are forbidden and placeholders must parse as a
valid non-empty HTTP header value during startup validation. Environment
provider references are restricted to the `CHARON_` namespace.

## Residual risks and deployment requirements

1. Replay state is in-memory and process-local. Do not horizontally replicate a
   realm until a shared atomic nonce store or issuer-side one-shot exchange is
   implemented.
2. Charon does not implement application-level connection/rate limiting.
   Constrain listener reachability, connection counts, CPU, memory, and process
   count at the network/container/service layer.
3. The Vaultwarden CLI is part of the trusted computing base. Runtime enforces
   its exact path and permissions but deployment must pin and verify its
   artifact digest.
4. DNS resolution and the configured WebPKI roots remain trusted for allowed
   destinations. Exact host policy does not replace trusted DNS/network
   operation.
5. A Charon-issued intermediate can impersonate allowed TLS names to workloads
   that trust its root. Preserve per-realm key isolation, offline-root handling,
   and direct-egress denial.
6. Unknown-length request bodies can transmit their allowed prefix before an
   over-limit stream is terminated. This is inherent to bounded streaming; use
   tighter capability-specific limits before enabling write operations.
7. The environment provider remains a disposable development adapter. Use the
   locked Vaultwarden adapter or another reviewed compile-time adapter for
   durable credentials.
8. Secret bytes necessarily exist briefly inside the trusted process and HTTP
   client header representation while the upstream request is sent. They are
   never returned, serialized, deliberately logged, or retained beyond the
   client/request/provider cache lifetimes.

## Public repository posture

The audit verified enforced `main` protection, required Rust/supply-chain/image
checks, linear history, no force pushes or deletions, read-only default workflow
tokens, Dependabot security updates, dependency alerts, secret scanning, push
protection, and private vulnerability reporting. Merge policy is rebase-only.

GitHub default code scanning was enabled for the repository, but GitHub's
default-setup API does not support Rust for this repository. Rust coverage
therefore remains Clippy, adversarial tests, `cargo-deny`, locked dependencies,
and human review. GitHub's non-provider-pattern and validity-check secret
scanning options were not available to enable; provider-pattern scanning and
push protection are active.

## Release gate

The code remains pre-release. A production credential cutover requires:

- an independent review of this audit and the current commit;
- a pinned and verified Vaultwarden CLI/runtime image;
- private file and directory modes that satisfy startup checks;
- one isolated process, listener, cache, session, and intermediate per persona;
- direct workload egress denial and resource/rate limits;
- a documented key/session/revocation rotation exercise;
- confirmation that the published GHCR package and attestations correspond to
  the reviewed commit.
