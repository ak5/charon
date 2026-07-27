# Charon

Charon is a persona-aware credential injection proxy for secretless workloads.
An untrusted developer container sends a public placeholder credential; Charon
authorizes the destination, resolves the real credential outside the container,
injects it into the upstream request, and emits a redacted audit event.

```text
developer workload (no real secrets)
  -> Charon (policy + credential injection)
      -> configured egress (optional Squid)
          -> GitHub / vendor API
```

## Status

Milestone 0 is an intentionally constrained proxy proof:

- exact-host allowlisting;
- exact placeholder replacement;
- provider abstraction with environment and locked-by-default Vaultwarden
  implementations;
- optional upstream HTTP proxy with protected file-backed authentication;
- backpressured request and response streaming with independent 16 MiB limits;
- HTTPS `CONNECT` interception with HTTP/2 and HTTP/1.1 ALPN;
- redirects disabled;
- JSON audit events without headers or bodies;
- fail-closed tests.

HTTPS `CONNECT` interception, signed workload identity, and the Vaultwarden
provider are implemented but not yet selected by the milestone-0 deployment.
The owner CONNECT security review and disposable secretless `gh api user`
vertical proof are complete. See [`docs/threat-model.md`](docs/threat-model.md).

## When Charon resolves a credential

An HTTP request alone cannot select or retrieve a credential. Before resolution,
Charon verifies a signed, short-lived, single-use workload manifest and binds it
to the configured issuer, audience, realm tenant/persona, workspace, active
lease, workload, operation correlation, and named capability. It
then requires the policy's exact destination hostname, method, path, and public
placeholder. For HTTPS, the CONNECT hostname, TLS SNI, and decrypted request
authority must also agree.

Remote credential-bearing requests require HTTPS on port 443. Plaintext HTTP
is accepted only for literal loopback addresses used by local fixtures.

The capability persona maps to a caller-independent credential reference; the
Vaultwarden provider maps that reference and persona to one exact configured
item UUID. After every check passes, Charon replaces the public placeholder only
in the outbound request to the destination. It never returns the resolved value
to the workload, and it never follows redirects with an injected credential.

The Vaultwarden account is itself a trust boundary: production runs one isolated
Charon realm and least-privilege account per persona. Every mapping and
capability must match the realm's declared persona. Do not connect Charon to a
personal, broadly privileged, or cross-persona vault. See
the complete invariants and residual risks in
[`docs/threat-model.md`](docs/threat-model.md).

## Development

[mise](https://mise.jdx.dev/) pins Rust 1.97.1. Rust 2024 implies Cargo's
Rust-version-aware resolver, and `rust-version` documents the supported compiler.

```sh
mise install
mise run check
```

CI uses GitHub-hosted Linux runners so forks work without repository
configuration. Dependabot targets `dev`; release pull requests alone flow from
`dev` to protected `main`.

Run the development service with a disposable test token in Charon's process:

```sh
export CHARON_GITHUB_TOKEN=test-only
mise run run
```

Use real credentials only in the reviewed disposable vertical fixture. The
milestone-0 deployment remains limited to its disposable environment credential
until the documented Vaultwarden cutover is provisioned.

The immutable non-production release, verification, rollback, and removal
contract is documented in [`docs/deployment.md`](docs/deployment.md).
The internal-network, secretless `gh api user` integration fixture is documented
in [`integration/vertical/README.md`](integration/vertical/README.md).

## Integration ownership

- This repository owns the generic Rust binary, container image, policy format,
  tests, and security documentation.
- The operator owns listeners, network policy, secret-store connectivity,
  backups, deployment, and the external realm reconciler.
- The integrating control plane owns tenant/persona/workspace lifecycle and
  issues short-lived signed workload manifests.
- Charon never calls either system on its request path.

The integration boundaries are indexed in
[`docs/integration-boundaries.md`](docs/integration-boundaries.md).
Machine-readable schemas and the normative
[`forward-proxy protocol`](contracts/forward-proxy.md) live in
[`contracts/`](contracts/). The production persona-realm boundary and external
reconciler contract are in
[`ADR 0003`](docs/adr/0003-persona-realms.md) and
[`docs/persona-realm-contract.md`](docs/persona-realm-contract.md).
The secret-store extension contract and its fail-closed constraints are in
[`ADR 0004`](docs/adr/0004-secret-provider-adapters.md).
The optional external human-approval broker and channel adapter are specified
by [`ADR 0005`](docs/adr/0005-human-approval-broker.md) and the
[`approval contracts`](contracts/README.md); Charon has no Telegram dependency
or online approval lookup.
