# Charon forward-proxy protocol contract

Version: 1

This document specifies Charon's public workload-facing data-plane protocol.
It complements `openapi.yaml`; OpenAPI describes only origin-style runtime
probes and cannot faithfully model an HTTP forward proxy or `CONNECT` tunnel.

## Transport

- A workload sends an HTTP absolute-form request to Charon for plaintext proxy
  traffic.
- For HTTPS, it sends `CONNECT exact-host:443`, completes TLS with the
  Charon-issued exact-host certificate, and sends an origin-form HTTP request
  inside that tunnel.
- Remote destinations require HTTPS on port 443. Literal loopback HTTP exists
  only for local integration fixtures.
- Redirect following is disabled. A redirected destination requires a new,
  independently authorized workload request.

## Authentication input

The workload sends exactly one signed compact manifest in
`Proxy-Authorization: Charon <payload>.<signature>`.

- `<payload>` is unpadded base64url JSON conforming to
  `workload-claims.schema.json`.
- `<signature>` is an unpadded base64url Ed25519 signature over the decoded
  payload bytes.
- The manifest selects a named capability, never a provider, account, item,
  secret reference, destination, HTTP method, or path.
- Each manifest is short-lived and single-use. Reusing its `jti` is denied.

## Authorization order

Before resolving a secret, Charon:

1. parses and bounds the request target and declared body size;
2. verifies the manifest signature, issuer, audience, realm bindings, validity,
   and replay state;
3. resolves the named capability from local policy;
4. authorizes the concrete service, exact hostname, method, path, and injection
   rule; and
5. removes proxy authentication plus static and dynamically nominated
   hop-by-hop headers.

Only then may Charon pass the policy-owned opaque reference to its configured
secret-store adapter.

## Credential rendering

Local service policy defines a typed hydration sink, formatting rule, response
mode, limits, and opaque provider reference. The workload supplies
`{{charon.<capability>}}` in that sink; the reference must name the same
capability as the signed manifest. Caller-supplied routing and framing headers
cannot be injection targets. The resolved value is never returned to the
workload, placed in a redirect, or included in logs, errors, or receipts.

## Responses

Charon intentionally exposes coarse outcomes:

| Status | Meaning |
| --- | --- |
| `400` | malformed or bounded-input violation |
| `401` | manifest missing, malformed, invalid, expired, replayed, or bound to another realm |
| `403` | authenticated capability does not authorize the concrete operation |
| `413` | configured request or response size limit exceeded |
| `502` | authorized destination, egress, TLS, or secret-store dependency failed |

Upstream response statuses otherwise pass through the policy-selected bounded
streaming sanitizer described by `transparent-gateway.md`. No response
distinguishes provider accounts, item existence, secret references, or secret
values.

## Non-contracts

Charon has no request-path callback to an issuer or application database. It
exposes no workload API to create, rotate, revoke, enumerate, or choose secrets,
providers, realms, or policy. Realm lifecycle objects are separate
operator/reconciler contracts.
