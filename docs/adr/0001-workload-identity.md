# ADR 0001: Signed single-use workload manifests

Status: accepted for the first vertical slice.

## Decision

An integrating control plane is the workload-identity issuer and Charon is an
offline verifier. The issuer signs a compact manifest with Ed25519. Charon
stores only the public verification key and does not call an application
database or control-plane API on the data plane.

The manifest payload contains:

- exact issuer and Charon audience;
- stable tenant, persona, workspace, active lease, workload, and operation
  correlation identifiers;
- one named capability configured independently in Charon;
- issued-at, not-before, and expiry timestamps;
- an unpredictable, single-use nonce.

The wire form is `base64url(payload).base64url(signature)`, carried as
`Proxy-Authorization: Charon <manifest>`. The signature covers the encoded
payload exactly. Unknown JSON fields, malformed encodings, ambiguous extra
segments, empty identities, lifetimes beyond the configured maximum, and clock
violations fail closed.

A Charon realm binds one exact tenant/persona, and a capability binds that
persona to one configured service plus
explicit HTTP methods and exact paths. The caller cannot supply hostnames,
credential references, methods, or paths in the manifest. After signature and
time validation, Charon resolves the named capability, rechecks the request's
service/method/path, and atomically consumes the nonce before asking the secret
provider for a credential.

Query parameters are denied until the capability model can authorize them
explicitly. This prevents a path-only rule from accidentally authorizing a
different operation selected through its query string.

The replay cache is in-memory and expires entries after the manifest window.
Therefore the first deployment remains a single Charon instance. Multiple
instances require a shared atomic nonce store or a design change to an
issuer-mediated one-shot exchange.

## Key and token lifecycle

- The issuer private key lives only in the trusted identity-issuing component.
- Charon configuration contains the corresponding public key.
- Developer images contain neither key. A workload receives a manifest only at
  launch or immediately before its one authorized request.
- Maximum lifetime is configuration-bounded; the first slice uses 60 seconds
  with two seconds of clock skew.
- Rotation is additive: deploy a newly configured verifier key before the
  issuer switches, or briefly support an explicit key-id/keyring extension.
  Silent fallback to an unknown or previous key is forbidden.
- Emergency revocation removes the public key/capability and restarts Charon;
  outstanding manifests then fail verification.

## Audit behavior

Successful events may contain realm, tenant, persona, workspace, lease,
workload, operation correlation, capability, service, method, path, status,
policy generation, and outcome. Logs never contain the manifest, nonce, signature,
request credential header, resolved credential, headers, or body. Denials use
stable reason classes rather than echoing claims or bearer material.

## Rejected alternatives

- **Caller-selected policy in a JWT:** rejected because signed-but-overbroad
  host or credential fields make issuer mistakes part of the data-plane policy.
- **Long-lived bearer/API key:** rejected because copying it enables replay and
  embeds durable identity in developer environments.
- **mTLS/SPIFFE for the first slice:** strong for channel and workload identity,
  but substantially expands certificate issuance, rotation, and sidecar
  machinery before one-host semantics are proven. It remains a future option.
- **Online control-plane lookup per request:** rejected because it couples
  Charon's credential data plane to application availability and database
  semantics.
- **Reusable short-lived token:** rejected because theft within its validity
  window still permits replay; each manifest is consumed once.

## Security consequences

Identity failures occur before credential lookup. A copied manifest cannot be
reused on the same instance, cannot change persona/capability, and cannot target
another service, method, or path. The issuer remains trusted not to sign the
wrong persona/capability pair, while Charon remains independently responsible
for the concrete operation policy.
