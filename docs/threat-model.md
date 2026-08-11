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
- **Transparent workload lane:** an Infra-owned network namespace and dedicated
  listener bind one realm workload to one exact service. This is an identity
  boundary only while other workloads cannot reach or spoof it and the
  workload has no direct-egress route.
- **Human approval broker:** optional external control-plane component that
  validates normalized requests, persists bounded rules and terminal decisions,
  authenticates approval-channel events, and signs short-lived assertions for
  the workload identity issuer. Charon never calls it.
- **Approval channel and human:** Telegram is the first presentation adapter.
  Numeric user/chat allowlists authenticate the human boundary; usernames and
  display text do not. The channel cannot create rules or assertions.
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
  immutable image. Pull-request jobs receive no package-write permission. The
  public workflow uses GitHub-hosted runners, digest-pinned build/runtime bases,
  a commit-SHA image tag, and BuildKit provenance and SBOM attestations. It has
  no deployment-host access or deployment credential.
- **Workload tool adapter:** optional integration code inside an untrusted agent
  runtime. It can request local semantic admission and emit metadata-only
  receipts, but it cannot select a Charon credential, capability, destination,
  provider, or secret reference. Its observations are not trusted against a
  compromised workload unless execution moves behind an isolated tool gateway.

## Security invariants

1. The workload never receives the real credential.
2. Direct workload internet access is denied; otherwise it can bypass Charon.
3. Policies use exact destination hosts and caller-independent secret references.
4. A credential is injected only when the canonical public capability reference
   is present in its policy-declared sink.
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
20. Credential-bearing remote requests require HTTPS on port 443. Plaintext
    HTTP is accepted only for literal loopback addresses used by local fixtures.
    URL user information, conflicting `Host`/authority values, and alternate
    TLS ports fail before identity consumption or credential resolution.
21. Static and `Connection`-nominated hop-by-hop fields, caller-supplied
    `Host`, and caller-supplied framing headers are removed before forwarding.
    Credential injection headers cannot be configured as routing, framing,
    proxy-authentication, or hop-by-hop headers.
22. Workload manifests, audit identifiers, TTL, and clock skew have explicit
    size/time bounds. Audit identifiers accept only a small printable
    identifier alphabet.
23. Vaultwarden subprocesses inherit no ambient Charon environment. The
    executable is an exact absolute non-writable file; vault state is a private
    directory; and session, interception-key, and upstream-proxy password inputs
    are private regular files.
24. Public container builds pin both Docker stages by manifest digest and emit
    provenance and SBOM attestations. Dependabot covers Rust, GitHub Actions,
    and Docker dependencies.
25. Secret-store adapters return only `SecretString` values and the closed,
    data-free `ProviderError` taxonomy. Raw backend errors, account identifiers,
    item identifiers, policy references, and response bodies cannot cross the
    adapter boundary. Each realm selects exactly one adapter instance; there is
    no automatic fallback.
26. Human approval is resolved before manifest issuance by an external broker.
    Assertions bind the normalized request digest, active lease, resource,
    action, risk tier, policy generation, and TTL bound. The issuer consumes
    each assertion and mints a new single-use manifest; Charon never performs an
    online approval lookup.
27. Reusable approvals are structured, expiring, use-bounded, revocable, and
    cannot contain wildcards or natural-language predicates. Critical and
    unknown operations cannot receive reusable approval. Telegram callbacks are
    opaque, random, single-use, expiring, and bound server-side to one pending
    request and numeric allowlisted actor/chat.
28. Workload tool adapters submit only tool name, classification, argument-key
    names, identifiers, and a digest of canonical arguments for admission. They
    exclude raw arguments, commands, credentials, manifests, and provider
    references. Unknown tools and unavailable admission fail closed.
29. Tool receipts contain no raw arguments or raw tool output. Receipt export is
    bounded and asynchronous; its failure cannot weaken Charon authorization.
    In-process receipts are operational evidence, not independent attestation
    against a compromised workload.
30. The Hermes adapter accepts only classifications from its immutable,
    version-reviewed Telegram tool catalog. Browserless deployment policy omits
    browser tools; newly introduced, unclassified, or policy-omitted names fail
    closed. Charon semantic admission does not replace Hermes command approval,
    Charon proxy enforcement, workload-manifest issuance, or network isolation.
31. Capability references use canonical `{{charon.<capability>}}` syntax and
    identify local policy, never a provider or secret. Charon accepts one only
    from the configured Authorization, named header, Basic, Git smart-HTTP,
    path, query, JSON, or form sink. Unknown, malformed, nested, concatenated,
    and misplaced references fail before credential resolution.
32. A transparent listener binds exactly one service and DNS hostname. TLS SNI,
    HTTP authority, listener destination, capability service, persona, method,
    and path must agree. URL paths and source IPs do not authenticate a
    workload.
33. Authorized service DNS is exact, IPv4-only, and pinned after the first
    accepted process-lifetime resolution. IPv6 listeners and answers are
    rejected. Charon has no UDP or HTTP/3 transport; Infra rejects UDP/443 and
    blocks direct egress so QUIC cannot bypass mediation.
34. Response policy explicitly selects structured SSE/NDJSON streaming,
    bounded JSON buffering, rolling text streaming, or allowlisted opaque
    streaming. Authentication, session, and framing headers are removed first.
35. Compression is identity-only or rejected. Opaque compressed response
    policy is reserved and fails validation until bounded decompression and
    sanitization exist. WebSocket upgrade is denied. Sanitization failure after
    partial delivery stops the stream without appending upstream details.
36. Data-plane receipts contain only the closed metadata schema. New requests
    fail before resolution when the bounded queue or writer is unavailable.
    The hash chain is meaningful only relative to an independently retained
    checkpoint; it is neither a signature nor evidence against a compromised
    Charon process. Startup replays the bounded journal as the source of truth,
    reconciles a stale checkpoint, and rejects an invalid chain or unrecognized
    checkpoint. Journal data is synced before checkpoint replacement.

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
- Charon has bounded requests, responses, handshakes, tunnels, provider
  commands, and manifest lifetimes, but no application-level connection or
  request-rate limiter. Deployments must bound connections and resources at the
  listener/container/network layer.
- The configured Vaultwarden CLI and the system WebPKI/DNS path are trusted
  dependencies. Runtime validates CLI path/type/permissions but does not
  independently attest the executable digest; deployment must pin and verify
  that artifact.
- The optional approval broker, its durable rule/nonce store, signing key,
  Telegram bot account, allowlisted human accounts, and identity issuer checks
  extend the trusted control plane. Telegram outage or account-recovery
  ambiguity fails closed for new approvals but does not change Charon's
  credential boundary.
- The Hermes integration's exact local admission service does not issue Charon
  manifests or enforce network isolation. Filesystem-protected Unix sockets
  provide an operator boundary only when the service runs under an identity the
  workload cannot impersonate. Its hash-chained journal is tamper-evident, not
  digitally signed.
- Transparent listener identity depends on Infra isolation and is weaker than
  a signed per-request manifest. Generic clients cannot securely correlate a
  network request to one Hermes tool call, so Charon authorizes it independently.
- Structured request hydration buffers JSON and form bodies to the request
  limit. WebSockets, IPv6, UDP, and QUIC are denied rather than partially
  supported.
