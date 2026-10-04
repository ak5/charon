# Exclusive workload explicit proxy contract

Version: 1

Start `charon --gateway-config <path>` with a complete policy conforming to
`GatewayConfig` in `src/gateway.rs`. Validate it with
`charon gateway validate <path>` before enabling routing. Unknown fields and
unsupported versions fail closed. The exact synthetic deployment example is
[`examples/hermes-gateway.toml`](../examples/hermes-gateway.toml).

This is a separate process/listener mode from `--config`. The signed explicit
proxy continues to require a fresh signed single-use manifest. Transparent
service listeners continue to bind one service. Neither becomes an anonymous
shared proxy. Hermes semantic tool admission is independent and unchanged.

## Identity and transport

One listener binds one fixed `realm` and `workload`. `exclusive_network = true`
is a mandatory operator acknowledgement, not proof of isolation. Infra must
make the listener reachable only from that workload, block all direct remote
TCP egress, prevent access from other workloads/host namespaces, and deny IPv6,
UDP/443, QUIC, and alternate routes. Source IP, URL, header, or capability text
is not authentication. A shared listener is prohibited. Charon never queries
an orchestrator or application database.

Ordinary clients use an HTTP proxy URL without proxy authentication. HTTPS
requires `CONNECT exact-host:443`, TLS interception, and origin-form HTTP/1.1
or HTTP/2. CONNECT, TLS SNI, HTTP `Host`, and HTTP/2 `:authority` must agree;
conflicting/malformed/duplicate authority forms fail closed. All permitted
HTTPS terminates at Charon; no splice, direct tunnel, or TLS fallback exists.
Every request on a reused or multiplexed connection is authorized afresh.
Generated CAs carry critical CA Basic Constraints and signing Key Usage,
plus noncritical subject/authority key identifiers. Interception leaves carry
an exact DNS SAN, critical non-CA Basic Constraints and digital-signature Key
Usage, server-authentication EKU, and noncritical subject/authority key identifiers.
The leaf authority identifier matches the loaded issuer's subject identifier.
These chains support Python 3.13/OpenSSL strict verification without relaxing
certificate, hostname or upstream validation. A signing CA missing required
extensions must be regenerated and its public trust distributed by Infra.
CONNECT itself grants no operation or credential. Tunnels expire after one
hour; each operation has its own shorter configured time limits.

The runtime validates upstream certificates with platform trust and pins
public IPv4 DNS addresses for the process lifetime. Literal IP routes, private,
loopback, link-local, metadata, shared-address, benchmark, multicast, reserved,
and IPv6 destinations are unavailable. Authorized DNS is checked before any
provider lookup and the HTTP connector uses the same pin. Ambient proxy
variables cannot change Charon's upstream route. No upstream intermediary is
configured in this mode. Infra owns DNS, public CA trust, and egress isolation.

Secretless HTTP is available only through an explicit `scheme = "http"` route
on port 80; credential mediation requires HTTPS/443. The Hermes example grants
no plaintext route. Nonstandard ports, nested CONNECT, upgrades, HTTP/3, raw
TCP protocols, and WebSockets are denied. Clients receive a fixed denial;
TLS/CONNECT failures close the connection without upstream diagnostics.

## Operation grants and credential ownership

`routes` grant an exact DNS host, scheme, methods, exact `paths` and/or one
literal slash-terminated `path_prefix`, query permission, credential/session
header permission, mediation type, and stream limits. No hostname glob exists.
An explicit `/` prefix grants that named host's API surface; it does not grant
another destination. Overlapping grants for a host/scheme/method fail validation.
Encoded path separators, controls, traversal, URL user information, and routing
ambiguities fail before lookup. Query values are forwarded only when allowed
and are never recorded. Redirects are returned without following them; every
caller-followed hop must pass a new request authorization.

`mediation.kind = "forward"` performs **no secret-provider lookup or health
call**. Tokens in OAuth bodies, Telegram URL paths, and allowed caller-owned
Authorization/cookies remain client-owned. Ordinary API requests need no
capability placeholder. Explicit `caller_headers` permits the closed set
Authorization, Cookie, X-Api-Key, Api-Key, X-Goog-Api-Key, X-Auth-Token, and
X-Session-Token. Supplying these outside its grant is denied. Other application
headers (for example ChatGPT-Account-Id and SDK version headers) pass through;
hop-by-hop, framing, Host and proxy authentication do not.

Credential grants are closed typed sinks:

- `header`: Authorization or a named credential header from that set excluding
  Cookie, a policy-owned `secret_ref`, and a value template containing exactly
  one `{secret}`. Supply `{{charon.<route-name>}}` at that exact sink, rendered
  with the template (for example `Bearer {{charon.github-user}}`).
- `basic`: fixed `username` and policy-owned `secret_ref`. Supply standard Basic
  auth with password `{{charon.<route-name>}}`, usable by ordinary curl/Git
  credential configuration.

Authorization, framing, caller-header rules, capability sink presence, and
public address checks complete before resolution. A client cannot choose a
provider reference, inject into routing/framing, or ask for arbitrary string
replacement. There is no global body/path replacement. Other typed sinks
remain available through the signed/transparent contracts; this mode does not
pretend to support them. Credential routes accept only credentials of 8–16384
bytes. Provider failures return data-free denials.

## Streaming and sessions

Uploads and downloads use backpressure, cancellation, byte counts, total time
and idle bounds. The example allows 256 MiB uploads and 1 GiB downloads; these
are policy choices and do not change other listener modes. Unknown-length
uploads can reach the origin partially before an overflow; streaming cannot
retract a remote side effect. Total operation time includes provider/DNS work,
upstream headers and upload. Body streams stop on overflow, idle timeout, total
timeout, dependency error, or disconnect. Bodies are not buffered to completion.
SSE/model responses stream through rolling byte redaction, without semantic
prompt/body inspection. Binary downloads retain their bytes on secretless
routes. Credential routes redact known raw/rendered credentials and URL/base64
encodings even across chunk boundaries. This can alter an opaque payload that
contains a brokered credential; it is intentional fail-safe mediation.

HTTP/1.1 keepalive and HTTP/2 multiplexing are supported downstream; reqwest
negotiates HTTP/1.1 or HTTP/2 upstream with certificate validation. Compression
is identity-only: request Accept-Encoding is set to identity, encoded uploads
and non-identity encoded responses fail closed. Clients must handle the fixed
403 for unsupported compression or protocol. No compressed bytes silently
bypass redaction. WebSocket/101 upgrades fail closed.

`session_response_headers` can retain Set-Cookie, WWW-Authenticate,
Authentication-Info, and X-Session-Token on caller-owned routes. They are not
globally removed. Every retained header is checked for known brokered secret
material. Credentials reflected in Location or another retained header deny
the response. A provider credential cannot be returned as a session value.
Charon is not a sanitizer for secrets already owned by the caller, including
OAuth token responses; forwarding those to their owner is necessary behavior.

## Receipts, logs, and verification

The required receipt journal reserves capacity before any operation; failure
denies execution before lookup. Accepted and denied operations contain only
fixed realm/workload, policy capability/service, authorized destination/method,
status, counts, elapsed time, and outcome. Its existing `path` field contains
`/capability/<route-name>` (or `/denied`), **never a request URL/path/query**.
Preauthorization denials use fixed `denied` identifiers. Authority/handshake
failures have fixed metadata log outcomes, without a request receipt.
Streaming completion/cancellation uses the existing hash-chained journal.

Errors and logs omit headers, tokens, URLs, prompts, bodies and provider
references. Gateway commands enforce `off,charon=info` regardless of RUST_LOG
so dependency transport debug logs cannot expose traffic. Embedders must apply
the same logging restriction. The interception CA/key, provider credentials,
and decrypted traffic remain within the trusted Charon boundary.

`/healthz` and `/readyz` return 204 for process and journal availability; neither
proves mediation, provider readiness, isolation, or client trust. Run the real
TLS fixture suite (`mise exec -- cargo test gateway --lib`) and the deployment
verification procedure in [`docs/hermes-gateway.md`](../docs/hermes-gateway.md).
Never remove an Infra convergence guard based on generic liveness.
