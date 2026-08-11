# ADR 0007: Policy-bound transparent capability gateway

Status: accepted

## Context

Explicit HTTP proxying protects credentials but requires proxy configuration
and a signed manifest on every request. Unmodified applications, Git, CLIs, and
SDKs do not consistently support that transport. A URL path or source address
cannot safely identify a workload, and platform-specific original-destination
socket APIs would expand unsafe and portability-sensitive code.

Responses also cannot be generically buffered: SSE, Git packfiles, downloads,
and long-running APIs require backpressure and incremental delivery. Conversely,
streaming compressed or structured data without an explicit parser cannot be
called sanitized.

## Decision

Charon adds transparent TLS listeners to the existing canonical proxy and
provider path. Each listener is configured for one exact service and hostname.
Infra gives one realm workload exclusive reachability to that lane and owns
destination routing, direct-egress denial, IPv6 posture, and UDP/QUIC denial.
Charon verifies SNI and HTTP authority and treats the lane—not a URL—as the
workload binding.

Applications use canonical `{{charon.<capability>}}` references in one typed
policy sink. The reference names only local policy. Authorization completes
before the provider receives its opaque policy reference. Existing
`SecretProvider`, exact service/capability policy, TLS authority, request
forwarder, redirect denial, and size guards remain canonical; there is no
parallel proxy or provider system.

Every service selects structured SSE/NDJSON streaming, bounded JSON, rolling
text, or allowlisted opaque response mode plus explicit compression and resource
limits. Compressed opaque bodies are rejected until bounded decompression and
sanitization exist. Data-plane receipts finalize from actual stream delivery
through a bounded single-writer journal.

DNS answers are exact-name allowlisted, IPv4-only, and pinned after first use
for the process lifetime. WebSockets are denied until a protocol-specific frame
contract exists.

## Consequences

Transparent mode needs no application proxy setting or Charon SDK, but its
routing-bound identity is weaker than a signed manifest. One listener cannot be
shared safely between mutually untrusted workloads. A generic socket cannot be
reliably attributed to one Hermes tool call, so semantic admission and network
authorization remain independent.

JSON/form request hydration and bounded JSON response mode intentionally buffer
to strict limits. Other modes retain streaming and backpressure. Opaque mode is
an explicit non-inspection declaration, not a sanitization claim.

## Rejected alternatives

- Per-agent URL paths or bearer URLs: caller-selectable and leak-prone.
- Source-IP identity on a shared listener: spoofable without an external
  isolation guarantee.
- Environment replacement with real values: exposes credentials to the
  workload and process inspection.
- Blind replacement across headers and bodies: creates ambiguous confused
  deputy behavior.
- Buffer every response: breaks streaming protocols and unbounds memory.
- Claim compressed opaque bytes were scanned: false assurance.
- Dynamically loaded credential plugins: expands the trusted computing base.
