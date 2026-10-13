# ADR 0003: Persona-isolated realms and delegated CAs

Status: accepted for implementation

## Decision

Production Charon runs as one isolated process/container per control-plane persona
credential realm. Multiple workspaces owned by that persona may share the realm.
A realm declares one stable realm ID, tenant ID, and persona ID. Every
capability and KeePass mapping in its configuration must name that persona;
mixed-persona configuration is rejected before the listener opens.

Each realm has its own:

- immutable Charon container and runtime UID where the platform supports it;
- validated configuration and listener;
- private encrypted KDBX, optional key file, public admin registration state,
  and an unlocked in-memory snapshot;
- root-signed intermediate certificate and protected private key; and
- health, audit, restart, rotation, revocation, backup, and removal lifecycle.

The workload cannot name a realm, vault server/account, item UUID, or credential
reference. The integrating control plane derives the realm endpoint from authenticated tenant,
persona, workspace, and active-lease ownership. A signed manifest names the
tenant, persona, workspace, lease, workload, operation correlation ID, and named
capability. Charon checks all realm and operation bindings offline against its
deployed policy before resolving a credential.

## Delegated CA hierarchy

Workspace images trust one stable offline root CA certificate. The root private
key is never deployed to runtime hosts or containers. Infrastructure issues one
intermediate certificate/private key per persona realm. Charon uses only its
realm intermediate to issue short-lived exact-host leaf certificates.

Rotation stages a second root-signed intermediate in the same realm, validates
it, atomically selects it for new leaves, drains connections signed by the old
intermediate, then removes and destroys the old key. Workspace trust is
unchanged because both intermediates chain to the installed root. Credential,
admin passkey, signing-key, and intermediate rotations are independent.

Possession of a trusted intermediate may allow certificates outside the
persona's intended scope when client DNS-name-constraint enforcement is not
reliable. PKI is therefore not the persona authorization boundary. Exact Charon
authorization, short leaf lifetimes, per-realm network reachability, workspace
endpoint assignment, and direct-egress denial remain mandatory.

## Isolation contract

Infrastructure supplies the paths described in
`docs/persona-realm-contract.md`. The reconciler must confine paths and mounts
to the declared realm roots, verify ownership markers and exclude shared writable
ancestors. Charon validates absolute KeePass/admin paths, private-file type and
mode, the private admin-state parent, realm-consistent mappings, matching CA
certificates/keys, duplicate IDs, exact hosts and unknown fields. Charon does not
implement realm-root confinement or host mount/network policy. Runtime mounts
are deny-by-default; no parent containing another realm may be mounted.

Credential values remain in secret-holding types and never implement `Debug`,
serialization, or response conversion. The unlocked snapshot belongs to one realm and
is discarded on lock or restart. The master password is neither persisted nor
restored; the owner unlocks through its HTTPS admin listener. Configuration replacement is validate-then-atomic; failure
leaves the last validated generation active.

## External reconciler

Charon does not create realms or query the integrating control plane. A separately authorized
reconciler owns create, validate, start, health, replace, rotate, revoke, and
remove operations through the versioned declarative contract. Operations are
idempotent, use desired and observed generations, and return structured
secret-free results. Charon exposes workload liveness/readiness and redacted runtime identity. Its
separate owner HTTPS listener supports enrollment, authentication and vault
unlock/lock; it exposes no credential values or policy mutation API.

Revocation first prevents new manifest issuance and workspace network access,
then stops the realm, removes runtime policy, and destroys intermediate/runtime
material. Credential rotation is owned by the operator. Removal cannot target a
path unless its resolved realm ID and ownership marker match the request.

## Audit and correlation

Successful receipts may contain realm, tenant, persona, workspace, lease,
workload, operation, capability, service, exact host, method, path, status,
policy generation, and outcome. Denials contain only fields authenticated before
the failure. Receipts never contain a manifest/token, nonce, request/response
headers or bodies, credential reference, KeePass paths/entry IDs,
credential values, CA key, or upstream proxy password.

## Review model

This single-owner project requires a recorded owner security review for
security-sensitive production changes. The review must identify the reviewer as
the owner, commit and image digest, scope, evidence, findings, remediation, and
residual risk. It remains an explicit security gate; it is not blocked on an
independent third party. A third-party review is welcome but does not replace
the recorded owner decision.

## Rejected alternatives

- One multi-persona process or shared decrypted database expands a process
  compromise to unrelated personas and is not the first production design.
- One root/private CA in each workspace or runtime host exposes the global trust
  anchor and makes realm rotation unsafe.
- Per-realm roots in workspace images require image/trust-store churn when a
  persona is added or removed.
- Caller-selected realm/provider/item inputs create a confused deputy.
- Querying an integrating control plane on the request path couples the
  independent data plane to an application database and turns control-plane
  outage into unsafe ambiguity.

A future shared multi-realm process requires a separate ADR and security review
that proves OS-equivalent blast-radius isolation, independent stores
and unlocked snapshots, non-confusable routing, shared replay protection, and operational
benefit that justifies the larger trusted computing base.
