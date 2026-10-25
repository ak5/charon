# Integration boundaries

Charon is an orchestrator-neutral credential-injection data plane. It has no
application database client and makes no request-path call to an integrating
control plane. Integrations are explicit, versioned, and fail closed.

## Boundary map

| Boundary | Direction | Protocol and contract | Trust | Charon owns |
| --- | --- | --- | --- | --- |
| Exclusive workload | workload → Charon | dedicated explicit HTTP proxy / intercepted CONNECT; fixed realm/workload | Infra network isolation | exact host/method/path grants, typed header/Basic sinks, caller-session policy, metadata-only receipts; no manifest |
| Signed workload | workload → Charon | HTTP forward proxy; `CONNECT` for HTTPS; signed manifest in `Proxy-Authorization` | untrusted | destination, operation, capability reference, size, redirect, replay, and expiry enforcement |
| Transparent workload lane | Infra-routed workload → dedicated Charon listener | intercepted TCP/TLS; capability reference in one policy sink; [`transparent-gateway.md`](../contracts/transparent-gateway.md) | trusted only when isolated routing prevents spoofing and bypass | exact listener/service binding, SNI/authority agreement, capability, hydration, response mediation |
| Identity issuer | control plane → workload → Charon | Ed25519 signed compact manifest; [`workload-claims.schema.json`](../contracts/workload-claims.schema.json) | trusted only to assert identity and capability | offline signature verification and independent concrete-operation policy |
| Approval broker | control plane ↔ broker → identity issuer | normalized request and signed approval assertion; [`approval-broker.openapi.yaml`](../contracts/approval-broker.openapi.yaml) | trusted control-plane authorization component | outside Charon; cannot select destinations, secrets, or widen local policy |
| External broker approval channel | broker ↔ Telegram/human | [`ApprovalChannel`](../contracts/approval-channel.md) presentation and opaque callback contract | trusted only for delivery and numeric actor/chat authentication | outside Charon; no decision, rule, assertion, or credential authority |
| Operator configuration | operator → Charon | deny-unknown-fields TOML; example in [`examples/charon.toml`](../examples/charon.toml) | trusted administrative input | validation before listener bind |
| KeePass store | Charon → private read-only KDBX | exact policy-owned entry UUID; `SecretString` out, data-free `StoreError` | trusted operator database and parser | locked boot, mapped protected Password fields, explicit lock, non-disclosure |
| Owner admin | owner browser → separate Charon HTTPS listener | console-code first enrollment; origin-bound passkeys; short-lived opaque sessions | trusted owner and browser authenticator | public registrations, origin checks, bounded challenges, authenticated unlock/lock |
| Local Telegram decisions | Charon ↔ private Telegram owner | outbound bot HTTPS and long-poll callbacks | dedicated bot token and immutable private numeric owner ID | exact-policy allow-once gate, callback actor/chat/message binding, bounded pending state |
| Realm reconciler | operator → runtime | declarative desired/observed objects; schemas in [`contracts/`](../contracts/) | privileged control plane | no lifecycle mutation API; only runtime health and identity |
| Runtime probe | operator → Charon | HTTP origin endpoints; [`openapi.yaml`](../contracts/openapi.yaml) | network-restricted observer | liveness and credential-free readiness |
| Destination | Charon → exact host | HTTPS on port 443, optionally through configured egress; literal loopback HTTP only for local fixtures | untrusted response source | credential injection after authorization; redirects disabled |
| Upstream egress | Charon → proxy | HTTP(S) forward proxy with optional protected file-backed Basic auth | routing dependency, not an authorization source | exact destination authorization remains local |
| PKI | operator → Charon/workload | offline root and one realm intermediate | operator trust boundary | exact-host leaf issuance; PKI never selects persona or capability |
| Receipt journal | Charon → protected JSONL/state files | [`data-plane-receipt.schema.json`](../contracts/data-plane-receipt.schema.json) | local operator evidence | bounded metadata and delivery outcome; journal replay is authoritative and reconciles the checkpoint; no headers, queries, bodies, provider references, sessions, or keys |
| Workload tool adapter | workload runtime ↔ local integration service | normalized operation, admission decision, and metadata-only receipt; schemas in [`contracts/`](../contracts/) | advisory inside the workload boundary unless isolated by OS identity and transport | outside Charon; cannot select destinations, capabilities, providers, or secrets |

## Workload protocol

In signed proxy mode, the workload sends a normal absolute-form HTTP proxy request, or an HTTP
`CONNECT` request followed by TLS. It supplies a signed manifest but cannot
select a realm, provider, provider account, item, secret reference, destination
outside configured policy, or credential rendering rule.

OpenAPI does not model a general forward proxy or `CONNECT` tunnel accurately,
so the workload boundary is specified by the manifest JSON Schema, the policy
configuration, ADR 0001, ADR 0002, and protocol integration tests.

Transparent mode does not trust a path-like “agent URL.” One listener is bound
to one realm workload and one exact service. Infra makes that endpoint
reachable only from the intended workload network namespace, redirects the
exact destination traffic, rejects UDP/QUIC, and blocks every direct-egress
alternative. The capability reference identifies policy, not the workload. A
shared lane needs a future cryptographic workload transport; source IP alone is
not sufficient identity.

## Issuer contract

Any system may be an issuer if it:

1. protects the configured Ed25519 private key;
2. emits claims matching the versioned schema and configured issuer/audience;
3. binds an authenticated tenant, persona, workspace, active lease, workload,
   operation, and capability;
4. uses unpredictable single-use `jti` values and short validity windows; and
5. never places realm, endpoint, provider, account, item, secret reference,
   hostname, method, or path selection in the manifest.

Charon keeps only the public key and does not call the issuer. Issuer
availability therefore affects creation of new manifests, not verification of
an already issued request.

## Human approval contract

When an operation requires human approval, the control plane submits a
schema-validated normalized request to the external approval broker. The broker
either atomically matches one bounded reusable rule or obtains a terminal human
decision through an `ApprovalChannel`, then returns a short-lived signed
approval assertion to the identity issuer.

The issuer verifies and consumes that assertion, rechecks the current
tenant/persona/workspace/lease tuple and policy generation, and mints one fresh
single-use Charon manifest. The data plane never calls the external broker or receives its rules and
assertions. Its optional local Telegram gate uses a dedicated operator-only KeePass bot token
and pending callback handles, and narrows the configured network policy. Caller-owned Telegram network requests are a
separate exclusive forwarding route. ADR 0005 and the approval artifacts in
[`contracts/`](../contracts/) define this separate control-plane boundary.

Resident-agent semantic approval uses the same grant engine but terminates at a
local admission decision; it cannot manufacture a capability or skip Charon's
independent network authorization. Session coding harnesses keep their native
inline approval systems. The external broker's Telegram adapter and broker are separate optional
processes joined by a protected Unix socket: the broker has durable state and
the assertion key but no Telegram token, while the adapter has the token and
immutable private-user binding but no rule or assertion authority.

## KeePass and owner administration

One concrete `KeePassStore` belongs to one realm. Trusted configuration names a
private KDBX file and optional private key file. Each exact canonical entry UUID
maps to a policy reference and the realm's persona. The workload protocol cannot
select a database, entry, password field, or fallback source. Only protected,
nonempty, bounded Password fields resolve as `SecretString`; parser failures are
reduced to the closed data-free `StoreError` taxonomy.

The owner unlocks through an independent HTTPS admin listener on a stable DNS
origin. First enrollment requires a short-lived operator-console code; subsequent
sign-in verifies an enrolled passkey. Public key registrations persist in a
private directory; challenges and ten-minute sessions remain in memory. An
origin-checked session authorizes unlock, lock and recovery-passkey enrollment.
Master passwords are not persisted. Lock and restart discard the mapped snapshot.
The operator owns certificates and renewal, database backup and credential rotation.
See [owner operations](admin.md) and [ADR 0004](adr/0004-keepass-store.md).

Optional local Telegram approvals bind exact configured capability/route names.
Requests pass identity, policy and sink checks before they create a prompt, and
must receive a fresh allow-once decision before credential resolution or upstream
forwarding. Each callback verifies numeric actor and private chat identity,
original message ID, random token and expiry. Failure denies the request. The bot
receives required public operator-written `approval_descriptions`, the admin
URL and the complete pre-substitution application request: method, destination,
path, query values, forwarded headers and UTF-8 body. Public capability references
remain visible; recognized caller credential headers/workload identity are masked.
Unrelated inline secrets cannot be detected automatically. Enabling a gate
consents to disclosure of this request content to Telegram. Gated bodies are
buffered within 64 KiB and ten seconds and retained unchanged; non-UTF-8 or
oversized (3500-byte preview) requests fail closed before lookup/egress.
The one-use handle releases only that waiting request, not an original shell command.
Prompt admission is bounded
to 10 per rolling minute and 32 pending per process, including canceled/denied
prompts in the rate budget; ungated requests bypass this budget. It never transports
enrollment codes, master passwords or credential values. The bot token is loaded from an operator-only protected KeePass entry after
owner unlock. Lock cancels the channel and pending decisions. The token
belongs only to Charon and must not be shared with a workload's Telegram bot.

## Reconciler contract

Charon exposes no realm create, rotate, revoke, or delete endpoint. An external
operator reconciles the versioned desired object into isolated files,
networking, encrypted database, admin state, PKI, and an immutable Charon process, then publishes
a redacted observation. The schemas describe exchanged data; they do not grant
authority or prescribe a transport.

This separation prevents an Internet-facing credential data plane from also
becoming a privileged lifecycle control plane.

## Workload tool adapters and receipts

A workload-specific adapter can observe semantic tool calls before they become
network requests. The first adapter, [`charon-hermes`](../integrations/hermes/README.md),
uses Hermes lifecycle hooks to submit a metadata-only normalized operation to a
protected local admission service. Missing, malformed, expired, or negative
admission blocks the Hermes tool call.

The Hermes adapter pins a reviewed upstream version, commit, Telegram tool
inventory, and browserless deployment profile. It classifies mixed-operation
tools conservatively without interpreting argument values. Hermes independently
decides which registry-gated tools exist; Charon policy can only narrow that
set. Hermes's dangerous-command approval remains a separate later guard for an
admitted terminal call.

After an admitted call finishes, the adapter emits a compact execution receipt
asynchronously. The receipt excludes raw arguments and raw output. It is audit
evidence, not authorization and not proof that a destination's semantic state
changed. Charon independently records only its network-level outcome.

There is no trustworthy generic tool-call correlation for transparent `git`,
`gh`, `curl`, or SDK traffic because those clients do not carry a protected
tool-operation identifier. Charon independently authorizes the realm workload,
capability, destination, method, path, and request shape. A coincident
identifier can aid investigation but never grants access. Hermes admission,
Hermes human approval, Charon gateway authorization, network isolation, and
workload-manifest issuance are separate controls.

An in-process workload plugin remains part of the untrusted workload boundary.
It cannot replace direct-egress denial or Charon's manifest and local policy
checks. A deployment that needs receipts resistant to workload compromise must
place execution and receipt signing behind an independently isolated tool
gateway.

## Exclusive Hermes network gateway

The [exclusive workload gateway](../contracts/workload-gateway.md) provides a separate
`--gateway-config` mode for ordinary HTTP(S) proxy clients, including reusable
CONNECT tunnels. It binds one fixed isolated workload, supports secretless
forwarding and typed credential sinks, and requires its own validated schema.
Signed proxy authentication, transparent service lanes, and Hermes tool
admission remain independent controls. Infra owns isolation, trust and cutover.
