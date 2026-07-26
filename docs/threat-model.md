# Threat model

## Goal

Allow an untrusted developer workload to exercise an explicitly granted remote
capability without placing the underlying credential in that workload.

## Trust boundaries

- **Untrusted workload:** agent, shell, tools, repository contents, and anything
  reachable from the workspace filesystem.
- **Charon:** trusted credential-injection data plane. It receives workload
  identity, resolves secrets, enforces destination policy, and emits redacted
  audit events.
- **Credential provider:** a configured adapter that resolves opaque,
  policy-owned references. Vaultwarden is the production implementation;
  milestone 0 uses Charon-process environment variables only to exercise the
  boundary.
- **Upstream egress:** an optional authenticated forward proxy. It controls
  network route/source IP but does not decide which persona credential to use.
  Its Basic-auth password is a Charon-only protected file, never URL/config
  text, environment state, a command argument, or workload-visible material.
- **Destination service:** GitHub in the first real vertical slice.
- **Workload identity issuer:** an integrating control plane owns an Ed25519
  private signing key and issues short-lived, single-use manifests. Charon owns
  only the public key and never queries control-plane state from the data plane.
- **Persona realm:** one Charon process/container, Vaultwarden identity/session,
  configuration, cache, listener, runtime filesystem, and delegated
  intermediate CA per control-plane persona. No realm can read another realm's
  state.
- **Realm reconciler:** infrastructure control plane implementing the declarative
  lifecycle in `docs/persona-realm-contract.md`. It supplies caller-independent
  vault/item and endpoint routing and never retrieves credential values.
- **Offline root CA:** signs persona intermediates. Its private key is absent
  from runtime hosts, containers, workspace images, backups, and artifacts;
  workspace images contain only the root certificate.
- **Release path:** only a successful trusted `main` CI run may publish an
  immutable image. An operator-selected protected GitHub environment holds the
  SSH deploy key; pull-request jobs receive neither that key nor package-write
  permission. The operator confines the deploy account to Charon's host path. The
  trusted deploy job streams its short-lived, job-scoped `packages: read` token
  over SSH stdin into an isolated Docker config that is removed after the pull;
  no persistent registry credential is provisioned on the host.

## Security invariants

1. The workload never receives the real credential.
2. Direct workload internet access is denied; otherwise it can bypass Charon.
3. Policies use exact destination hosts and caller-independent secret references.
4. A credential is injected only when the expected public placeholder is present.
5. Redirects are disabled so credentials cannot cross authorization boundaries.
6. Hop-by-hop and proxy-authorization headers are not forwarded.
7. Forwarded-request audit events contain service, host, method, path, status,
   and outcome. Denial/error events contain only the applicable fields known at
   the failure boundary. No audit event contains request headers, bodies,
   provider responses, or credentials.
8. Provider or policy failure denies the request.
9. Deployment selects a full commit-SHA image tag, verifies the running OCI
   revision, health, and credential-less denial, and restores the prior image
   and project-owned configuration on failure. Mutable image tags are not used.
10. Every forwarded request carries a signed manifest bound to the exact
    issuer, audience, workload, persona, named capability, validity window, and
    single-use nonce. Identity and operation authorization complete before
    credential resolution.
11. Vaultwarden references map an exact persona to an exact configured item
    UUID; capability and mapping personas must agree. Unlock material is
    readable only by Charon, is never placed on a command line, and provider
    output is zeroized after conversion to a secret-holding type. Resolved values
    expire from the in-memory cache within the configured bound.
12. CONNECT allows only exact configured hosts on port 443. Charon-issued leaf
    identity, TLS SNI, the HTTP/1.1 `Host` or HTTP/2 `:authority`, service,
    method, and path must all agree before the single-use manifest is consumed
    and a secret resolves. Conflicting authority forms and non-HTTPS absolute
    request targets fail closed. The CA private key remains on the Charon side
    of the trust boundary.
13. The vertical test workload joins only an internal Docker network. Charon
    alone joins the upstream network and chains through the configured Squid
    egress, so a workload cannot bypass policy with a direct connection.
14. Request and response bodies stream through backpressured counted adapters
    with independent 16 MiB aggregate limits. Declared oversize requests fail
    before identity and provider work; declared oversize responses fail before
    downstream headers; unknown-length overflows terminate their stream.
15. An authenticated upstream proxy uses a fixed configured username and an
    absolute protected password file. Embedded URL credentials, incomplete
    authentication configuration, whitespace-bearing values, and unavailable
    files fail closed before Charon listens.
16. One process serves exactly one declared tenant/persona realm. Every
    capability and Vaultwarden item mapping must match it. Workloads cannot
    choose a realm, provider, account, item, listener, or credential reference.
17. Manifests and successful receipts bind stable tenant, persona, workspace,
    active lease, workload, operation correlation, and named capability context.
    These identifiers are non-secret but are accepted only from a verified
    issuer, never from routing inputs.
18. Each realm has isolated config, encrypted `bw` app-data, tmpfs session,
    cache, listener, and intermediate key. Lock, revocation, failure, rotation,
    or removal of one realm does not expose or interrupt another.
19. Workspace images trust one offline root certificate. Only a realm's
    root-signed intermediate key is deployed. PKI does not replace endpoint
    isolation, exact request authorization, or direct-egress denial.

## Known milestone-0 limitations

- CONNECT interception supports HTTP/2 and HTTP/1.1 with one authorized inner
  request or stream per tunnel. The owner security review and disposable
  secretless GitHub vertical proof are complete; production credentials remain
  gated on the documented deployment cutover.
- The deployment policy still selects the disposable environment provider until
  the operator provisions the pinned CLI, encrypted vault state, session credential,
  and exact item mapping. The Vaultwarden provider itself is implemented and
  tested through both a disposable CLI-compatible fixture and the live
  disposable vertical proof.
- Production uses one process per persona; a shared multi-realm process requires
  a separate ADR and review meeting ADR 0003's criteria. The current in-memory
  replay cache is intentionally per-realm and single-instance; horizontal
  replicas require a shared atomic nonce store or issuer-side one-shot exchange.
