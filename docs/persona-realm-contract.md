# Persona realm runtime and reconciler contract

This is the version 1 contract consumed by the external infrastructure
reconciler. Fields are declarative and unknown fields fail validation.

## Desired realm

```text
api_version: charon/v1
realm_id: opaque stable random ID
tenant_id: stable integrating-control-plane tenant ID
persona_id: stable integrating-control-plane persona ID
generation: monotonically increasing integer
image_digest: sha256 OCI digest
listener: exact assigned internal IP and port
config_path: /etc/charon/realms/<realm_id>/charon.toml
state_root: /var/lib/charon/realms/<realm_id>
runtime_root: /run/charon/realms/<realm_id>
ca_generation: stable generation ID selected for new leaves
```

The renderer, not a caller or workload, supplies Vaultwarden account/session,
item mappings, endpoint, listener, and filesystem paths. The desired object
contains no credential value, unlock session, private key, or root-key input.

## Filesystem layout

```text
/etc/charon/realms/<realm_id>/
  charon.toml                 root:realm 0440
  ownership                  root:root 0444 (realm/tenant/persona marker)
/var/lib/charon/realms/<realm_id>/
  bw/                         realm:realm 0700 (encrypted CLI app-data)
/run/charon/realms/<realm_id>/            tmpfs, realm:realm 0700
  credentials/
    vaultwarden-session       realm:realm 0400
    upstream-proxy-password   realm:realm 0400 when configured
  ca/<ca_generation>/
    intermediate.pem          realm:realm 0444
    intermediate-key.pem      realm:realm 0400
```

Provider cache and nonce state are process memory and are never files. The root
certificate may be mounted read-only for chain validation; the root private key
is forbidden on the runtime host. A realm container receives only its exact
config/state/runtime subdirectories. Symlinks, traversal, shared writable
parents, and group/other-readable private files fail validation.

## Operations

All operations require `realm_id`, expected ownership marker, idempotency key,
and desired generation. They return an operation ID, observed generation,
coarse state, redacted reason code, and timestamps.

| Operation | Postcondition |
| --- | --- |
| `create` | isolated paths/account/listener exist; no process until validation |
| `validate` | image/config/files/permissions/CA chain and realm-persona consistency pass |
| `start` | immutable digest runs as realm UID; readiness reports expected IDs/generation |
| `health` | liveness plus config/provider-lock/network readiness, without fetching a credential |
| `replace` | candidate generation validates, atomically becomes active, old generation retained for rollback window |
| `rotate-ca` | new intermediate validates and signs new leaves; old connections drain during bounded overlap |
| `revoke` | issuance/network access disabled, process stopped, sessions/caches/keys invalidated |
| `remove` | ownership marker rechecked, runtime destroyed, durable non-secret tombstone/audit retained |

`replace` and `rotate-ca` are independent from credential replacement. No
operation falls back to another realm, account, listener, item, or generation.

## Health states

- `provisioning`: not routable;
- `ready`: exact observed generation is safe for issuance/routing;
- `degraded`: still denies unsafe operations; operator action required;
- `locked`: provider unavailable; all credential use denied;
- `revoked`: issuance and network reachability disabled;
- `removing` / `removed`: never routable.

The integrating control plane may mirror only state, observed generation,
reason code, and observation time. A stale or mismatched observation is not
ready.

## Network contract

A workspace can reach only its derived persona realm endpoint and necessary
internal control services. It cannot reach other realm listeners or governed
destinations directly. Charon alone can reach its persona Vaultwarden endpoint
and the configured Squid egress. Exact destination authorization occurs again
inside Charon. Network policy and Charon authorization are both required.

## CA overlap

At most two intermediate generations are mounted during rotation: one `active`
and one `retiring`. Both must chain to the offline root, assert CA usage, match
the realm ownership record, and have bounded validity. Only `active` signs new
leaves. `retiring` exists only for already established connections and is
removed after the maximum tunnel lifetime plus skew. Revocation isolates the
realm endpoint immediately; certificate revocation alone is not relied upon.

## Disposable acceptance fixture

The fixture creates Alice and Bob with separate Vaultwarden identities, item
mappings, app-data, sessions, configs, caches, listeners, UIDs/containers, and
intermediate keys under one disposable root. It must prove:

1. two Alice workspaces can use Alice's assigned endpoint;
2. Alice/Bob endpoint, persona, capability, workspace, lease, and item
   substitutions fail;
3. replayed and expired manifests fail;
4. direct governed egress fails;
5. locking/revoking/stopping/rotating/removing Alice does not interrupt Bob;
6. CA rotation does not change the workspace root certificate or image; and
7. logs, receipts, configs intended for workloads, environment/process captures,
   snapshots, and artifacts contain no seeded credentials, sessions, manifests,
   nonces, item UUIDs, or private keys.
