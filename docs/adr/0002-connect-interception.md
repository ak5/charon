# ADR 0002: HTTPS CONNECT interception

Status: accepted for non-production implementation; an explicit recorded
security review is required before any production credential is configured.

## Decision

Charon terminates CONNECT tunnels instead of blindly relaying them. It accepts
only an exact configured DNS hostname with an explicit port `443`, requires a
signed workload manifest on CONNECT, and issues a fresh per-connection leaf for
that hostname from a Charon-owned CA. TLS is restricted to safe rustls protocol
defaults and advertises HTTP/2 followed by HTTP/1.1 through ALPN.

After the handshake, Charon compares TLS SNI to the CONNECT hostname and the
decrypted HTTP/1.1 `Host` or HTTP/2 `:authority` to both. If both authority
forms are present, they must agree after normalizing the default HTTPS port, and
an absolute request target must use the `https` scheme. Charon reconstructs the
upstream URI from the already-authorized hostname; the workload cannot choose
the upstream authority through the request target. The signed capability is
then checked against the decrypted method and exact path. Its nonce is consumed
before the credential provider is called. Each CONNECT permits one HTTP/1.1
request or one HTTP/2 stream.

Standard proxy clients encode proxy URL credentials as Basic authentication.
For `HTTPS_PROXY=http://charon:<manifest>@proxy`, Charon accepts only the exact
username `charon` and treats the password as the signed manifest. The decoded
value is secret-held and is never logged or forwarded. The native
`Proxy-Authorization: Charon <manifest>` form remains supported.

Request and response bodies stream end to end through backpressured, counted
adapters and are each bounded to 16 MiB. A declared oversized request is denied
before workload identity or credential resolution, and a declared oversized
response is denied before downstream headers are sent. An unknown-length body
that crosses its limit terminates the stream. Upstream connect/request time is
bounded, TLS handshakes are bounded to ten seconds, and a tunnel is bounded to
one minute. Redirect following remains disabled, so an injected credential is
never replayed to a redirect target.

## CA ownership and distribution

The CA private key is a protected Charon runtime credential. Charon rejects a
Unix key file accessible by group or other. The key is parsed into a signer type
that implements no Charon `Debug`, serialization, or response conversion. It
never enters an image, repository, developer container, request, response, or
log.

Production workspace images contain only the public offline root certificate.
Each persona Charon receives a distinct root-signed intermediate and key and
serves the intermediate with each exact-host leaf. Intermediate rotation stages
a new realm key, selects it for new leaves, drains old tunnels, and removes the
retiring key without changing workspace trust. The offline root private key is
never deployed. See ADR 0003.

## Rejected alternatives

- Blind CONNECT relay cannot inspect the encrypted operation or inject a
  credential and therefore reduces policy to hostname-only egress.
- A wildcard leaf or caller-supplied certificate would broaden one hostname
  grant and is forbidden.
- Trusting CONNECT alone ignores SNI and decrypted authority confusion.
- Reusing one manifest for HTTP keep-alive requests or multiplexed HTTP/2
  streams weakens nonce and operation binding, so one HTTP/1.1 request or one
  HTTP/2 stream is permitted per tunnel. Later streams are denied.
- Installing the CA into a shared host trust store expands certificate misuse
  beyond the explicitly granted developer environment.

## Review gate

Before production credentials, the repository owner must explicitly review CA
key custody and rotation, leaf constraints, CONNECT and Basic parsing,
HTTP/1.1 `Host` and HTTP/2 `:authority` binding, malformed HTTP behavior,
streaming request/response bounds, redirect handling, and the end-to-end
`gh api user` proof. Findings and remediation are recorded in
`docs/security-review-connect-interception.md`.
For this single-owner project, a recorded owner review satisfies the gate when
it identifies the reviewed commit/image, evidence, findings, remediation, and
residual risk. The gate is not contingent on recruiting an independent third
party; an independent review remains welcome.
