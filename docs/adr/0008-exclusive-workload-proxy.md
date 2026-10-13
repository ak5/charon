# ADR 0008: exclusive workload explicit proxy

- Status: accepted for implementation; deployment requires Infra verification
- Date: 2026-10-04

## Context

Ordinary Hermes HTTP clients, curl, gh, Git and SDKs use reusable explicit proxy
connections. Signed single-use manifests and a transparent listener per service
do not provide that transport. The owner authorizes TLS termination for every
policy-permitted HTTPS connection. Infra will use one outbound gateway and
retains separate Hermes tool admission and its convergence guard.

## Decision

Add a distinct `--gateway-config` process mode with schema version 1, one fixed
realm/workload, mandatory exclusive-network acknowledgement, required CA and
metadata receipts, and exact host/scheme/method/path grants. Preserve the
signed and transparent modes. Routing isolation is workload authentication;
this mode must not be exposed to a shared network.

Separate forwarding grants (no provider work) from credential grants with
closed header/Basic capability sinks. Caller-owned OAuth, bot tokens and
session headers can pass under explicit route policy. No client selects a
provider reference or asks for arbitrary body/path substitution.

Terminate every HTTPS CONNECT, compare SNI/HTTP authority, verify upstream TLS,
preauthorize public pinned DNS before credential lookup, and reauthorize every
request on HTTP/1.1 and HTTP/2 connections. Never splice. Keep redirects
caller-followed and independently authorized. Stream bounded uploads/downloads
with known-secret redaction; reject compression and WebSockets clearly.

## Consequences

The network namespace and listener reachability become a trusted identity
boundary. Compromising Charon or its CA exposes intercepted traffic, including
caller-owned secrets. The gateway cannot prove semantic tool-call origin.
Infra must block direct egress, IPv6/QUIC and other bypass routes and verify
trust, mediation, backups, config CD and tool admission before cutover.

The separate schema avoids a permissive fallback in signed authentication and
avoids forcing provider references/hydration onto ordinary routes. Its receipts
use policy identifiers instead of traffic paths because Telegram and OAuth can
put credentials in URLs. Executable logging excludes dependency traffic traces.

The implementation contract and verified synthetic configuration are owned by
[workload-gateway.md](../../contracts/workload-gateway.md) and
[hermes-gateway.md](../hermes-gateway.md). Publishing an image is not a deployment
or permission to remove Infra's convergence guard.
