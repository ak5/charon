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
- **KeePass database:** one private, read-only KDBX file per realm. Local policy
  maps exact entry UUIDs to references. The process starts locked and retains
  only mapped protected Password fields after an operator unlocks it.
- **HTTPS admin and owner:** an independent TLS listener on one stable DNS
  origin. An expiring console-only enrollment code authorizes initial passkey
  registration. WebAuthn verifies registration and authentication; only public
  registration data persists. Authenticated, origin-checked sessions can unlock
  or lock the store and enroll a recovery passkey. The master password enters
  only this HTTPS boundary and is not stored in a password file.
- **Local Telegram approval:** an optional outbound HTTPS bot uses an operator-only
  protected KeePass token entry, never the KeePass master password. The token UUID
  cannot also be a workload mapping. No Bot API call occurs before unlock; lock
  drops the snapshot, cancels polling and pending decisions. Exact configured capabilities require a
  fresh allow-once decision before credential lookup or upstream forwarding.
  Callbacks bind the private actor, chat, message, random token, and expiry.
  Required operator-written public descriptions explain capability authority;
  they must not contain secrets or private resource names. Approval covers one
  capability use, not semantic review of a resource or request body. Charon
  admits at most 10 prompts per rolling minute and 32 pending per process;
  cancellation/denial does not refund the rate budget, and lock/unlock does not
  reset it. A workload can exhaust the budget and deny gated requests until it
  recovers. Restart resets the in-memory budget. Owner unlock notifications are
  outside this limit; network-layer workload limits remain necessary.
  Telegram transports the admin URL and metadata, never enrollment codes,
  passwords, credential values, or request bodies.
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
  One immutable positive numeric user ID authenticates a private chat only when
  actor ID, chat ID, and configured ID are equal; usernames and display text do
  not. The channel cannot create rules or assertions.
- **Persona realm:** one Charon process/container, KeePass database,
  configuration, unlocked snapshot, listener, runtime filesystem, and delegated
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
  database, or secret reference. Its observations are not trusted against a
  compromised workload unless execution moves behind an isolated tool gateway.

## Security invariants

1. The workload never receives a Charon-brokered credential. Caller-owned
   OAuth/session tokens on exclusive forwarding routes remain client-owned.
2. Direct workload internet access is denied; otherwise it can bypass Charon.
3. Policies use exact destination hosts and caller-independent secret references.
4. A brokered credential is injected only when the canonical public capability reference
   is present in its policy-declared sink.
5. Redirects are disabled so credentials cannot cross authorization boundaries.
6. Hop-by-hop and proxy-authorization headers are not forwarded.
7. Forwarded-request audit events contain service, host, method, path, status,
   and outcome. Denial/error events contain only the applicable fields known at
   the failure boundary. No audit event contains request headers, bodies,
   store responses, or credentials.
8. Credential-store or policy failure denies the request.
9. Deployment selects a full commit-SHA image tag, verifies the running OCI
   revision, health, and credential-less denial, and restores the prior image
   and project-owned configuration on failure. Mutable image tags are not used.
10. Each signed-mode forwarded request carries a manifest bound to the exact
    issuer, audience, workload, persona, named capability, validity window, and
    single-use nonce. Identity and operation authorization complete before
    credential resolution.
11. KeePass references map one exact persona to one configured entry UUID.
    Only protected, nonempty, bounded Password fields can resolve. The master
    password is discarded after decryption; mapped values use `SecretString`.
    Explicit lock and process restart remove the retained snapshot. A concurrent
    lock prevents an in-flight unlock from committing. Files are private regular
    files, not symlinks; database and optional key-file reads are bounded.
12. CONNECT allows only exact configured hosts on port 443. Charon-issued leaf
    identity, TLS SNI, the HTTP/1.1 `Host` or HTTP/2 `:authority`, service,
    method, and path must all agree before the single-use manifest is consumed
    and a secret resolves. Conflicting authority forms and non-HTTPS absolute
    request targets fail closed. The CA private key remains on the Charon side
    of the trust boundary.
13. The vertical test workload joins only an internal Docker network. Charon
    alone joins the upstream network and chains through the configured Squid
    egress, so a workload cannot bypass policy with a direct connection.
14. Signed/transparent request bodies stream through backpressured counted
    adapters with a 16 MiB aggregate limit; response bounds are policy-selected.
    Exclusive gateway uploads/downloads have explicit independent route limits. Declared oversize requests fail
    before identity and credential lookup; declared oversize responses fail before
    downstream headers; unknown-length overflows terminate their stream.
15. An authenticated upstream proxy uses a fixed configured username and an
    absolute protected password file. Embedded URL credentials, incomplete
    authentication configuration, whitespace-bearing values, and unavailable
    files fail closed before Charon listens.
16. One process serves exactly one declared tenant/persona realm. Every
    capability and KeePass entry mapping must match it. Workloads cannot
    choose a realm, provider, account, item, listener, or credential reference.
17. Manifests and successful receipts bind stable tenant, persona, workspace,
    active lease, workload, operation correlation, and named capability context.
    These identifiers are non-secret but are accepted only from a verified
    issuer, never from routing inputs.
18. Each realm has isolated config, encrypted KDBX, public passkey state,
    unlocked snapshot, listener, and intermediate key. Lock, revocation, failure, rotation,
    or removal of one realm does not expose or interrupt another.
19. Workspace images trust one offline root certificate. Only a realm's
    root-signed intermediate key is deployed. PKI does not replace endpoint
    isolation, exact request authorization, or direct-egress denial.
20. Credential-bearing remote requests require HTTPS on port 443.
    Signed/transparent plaintext HTTP is limited to literal loopback fixtures.
    Exclusive forwarding can explicitly grant secretless public HTTP on port 80.
    URL user information, conflicting `Host`/authority values, and alternate
    TLS ports fail before identity consumption or credential resolution.
21. Static and `Connection`-nominated hop-by-hop fields, caller-supplied
    `Host`, and caller-supplied framing headers are removed before forwarding.
    Credential injection headers cannot be configured as routing, framing,
    proxy-authentication, or hop-by-hop headers.
22. Workload manifests, audit identifiers, TTL, and clock skew have explicit
    size/time bounds. Audit identifiers accept only a small printable
    identifier alphabet.
23. KeePass decryption runs on a blocking thread behind a single unlock gate.
    The database is never written by Charon. TLS interception keys, admin TLS
    keys, optional key files, and upstream-proxy passwords remain private inputs.
    The admin TLS key is independent of the interception CA.
24. Public container builds pin both Docker stages by manifest digest and emit
    provenance and SBOM attestations. Dependabot covers Rust, GitHub Actions,
    and Docker dependencies.
25. The concrete KeePass store returns only `SecretString` and the closed,
    data-free `StoreError` taxonomy. Parser errors and database content never
    enter responses or logs. There is no fallback credential source.
26. External broker approval is resolved before manifest issuance.
    Assertions bind the normalized request digest, active lease, resource,
    action, risk tier, policy generation, and TTL bound. The issuer consumes
    each assertion and mints a new single-use manifest. Charon never queries that
    broker. Its optional local Telegram gate runs after local authorization,
    before credential resolution, and cannot widen destination policy.
27. External broker reusable approvals are structured, expiring, use-bounded, revocable, and
    cannot contain wildcards or natural-language predicates. Critical and
    unknown operations cannot receive reusable approval. Telegram callbacks are
    opaque, random, single-use, expiring, and bound server-side to one pending
    request and the immutable equal private actor/chat ID. The local gate also
    binds the original message ID and creates no reusable rule.
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
    identify local policy, never a database entry or secret. Charon accepts one only
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
34. Signed/transparent response policy explicitly selects structured SSE/NDJSON streaming,
    bounded JSON buffering, rolling text streaming, or allowlisted opaque
    streaming. Authentication, session, and framing headers are removed first in those modes.
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

37. A separate exclusive-workload explicit listener binds a fixed realm/workload
    through mandatory Infra network isolation. It is never a shared anonymous
    proxy and does not weaken the signed manifest listener. Every reused HTTP/1.1
    request or HTTP/2 stream is authorized independently.
38. Exclusive forwarding grants perform no credential lookup. Caller-owned OAuth,
    bot tokens, cookies, and session headers pass only under declared route
    policy. Brokered grants require a typed header/Basic capability sink;
    credential references are always local policy. All HTTPS terminates, with
    CONNECT/SNI/HTTP authority agreement and verified upstream certificates.
39. Gateway DNS public-address authorization precedes credential resolution;
    the connector uses the same process pin. Concurrent DNS resolution cannot
    replace an accepted pin. Shared-address, benchmark, private, metadata,
    multicast, reserved and IPv6 addresses are denied. Ambient upstream proxy
    variables cannot bypass this resolver.
40. Exclusive gateway receipts replace the request path with a policy route
    identifier, never record queries/URLs, and reserve journal capacity before
    execution. Prestream denials finalize metadata receipts. TLS/authority
    failures emit only fixed log outcomes. The executable restricts gateway
    logging to Charon metadata even if RUST_LOG requests dependency traces.
    The binary applies this restriction in every mode. Enrollment codes are
    emitted separately only to the trusted operator console.
41. Exclusive gateway streams have configured upload/download, total-time and
    idle bounds. Identity-only compression, protocol upgrade denial, caller-
    followed independently authorized redirects, known-secret redaction and
    session response policy are explicit. Streaming overflow cannot retract a
    partial upload or already delivered response.

The [workload gateway contract](../contracts/workload-gateway.md) and
[Hermes deployment handoff](hermes-gateway.md) own the complete exclusive-mode
schema, exact host inventory, isolation requirements and feature verification.
Infra isolation is part of workload identity: any other principal able to
reach the listener gains that workload's grants. The interception CA/key and
plaintext TLS traffic are trusted Charon assets; compromise exposes caller-owned
and brokered credentials. The network gateway cannot prove that a socket came
from an admitted Hermes tool. The separate tool admission service is unchanged.

## Current limitations

- Signed CONNECT interception supports HTTP/2 and HTTP/1.1 with one authorized inner
  request or stream per tunnel. Recorded security reviews apply to their
  recorded revisions. The current KeePass/admin
  changes have implementation verification in
  `docs/security-verification-keepass-admin.md`; container builds, live Telegram
  delivery and combined host/network isolation require deployment verification.
- The operator must provision a private KDBX file, exact UUID mappings, a
  browser-trusted HTTPS certificate, and a stable admin DNS origin. Changing
  origin requires a deliberate enrollment migration; passkeys are origin-bound.
  Losing all passkeys requires console access and explicit enrollment-state reset.
- Unlock is manual after every process restart. Telegram starts only after
  unlock, so it cannot notify the owner while booted locked. No bot token or
  master password is read from the environment. Bot
  compromise exposes approval metadata and permits decisions as the configured
  Telegram user, but does not reveal the vault password or values.
- KeePass parsing and cryptography are trusted dependencies. Only mapped
  protected values are retained; the parser also temporarily allocates other
  database content. Encrypted input is bounded, but operator-supplied KDF and
  decompression parameters can consume substantial resources. Deployment must
  bound process memory and CPU and exclude untrusted database writers.
- Production uses one process per persona; a shared multi-realm process requires
  a separate ADR and review meeting ADR 0003's criteria. The current in-memory
  replay cache is intentionally per-realm and single-instance; horizontal
  replicas require a shared atomic nonce store or issuer-side one-shot exchange.
- Charon has bounded requests, responses, handshakes, tunnels, approval
  waits, and manifest lifetimes. The admin listener limits origin-accepted
  non-GET requests to 30 per minute, with at most eight passkeys, 32 pending
  ceremonies and 32 sessions. Capacity is checked at ceremony start and finish.
  Workload listeners have no connection/request-rate limiter; deployments must
  bound connections and resources at the listener/container/network layer.
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
- Signed/transparent structured request hydration buffers JSON and form bodies to the request
  limit. WebSockets, IPv6, UDP, and QUIC are denied rather than partially
  supported.

- Workload/admin network isolation is enforced by Infra. A separate listener and
  owner-IP host publication do not block workload access through a container
  interface when admin listens on all interfaces. Infra must deny those paths.
- Local Telegram calls go directly to `api.telegram.org` over verified HTTPS;
  they ignore upstream and ambient proxies. Permit only Charon to use that
  egress. Signed/transparent local decisions wait at most two minutes;
  exclusive decisions additionally count against the route operation deadline.
