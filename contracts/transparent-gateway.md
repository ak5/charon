# Transparent secret-brokering gateway contract

Version: 1

This contract defines Charon's vendor-neutral transparent TLS gateway. It
complements the explicit [forward-proxy contract](forward-proxy.md). OpenAPI
describes only the origin-style runtime probes; it cannot describe intercepted
TCP, TLS, streaming bodies, or capability hydration.

## Capability references

The only public reference syntax is `{{charon.<capability>}}`. A capability name
is 1–128 ASCII letters, digits, dots, hyphens, or underscores. It cannot start
or end with a dot or contain consecutive dots. The complete reference is at
most 256 bytes. Nested, concatenated, partial, malformed, oversized, and unknown
references are denied before provider resolution.

A reference names local policy. It never names a provider, account, secret,
Vaultwarden item, environment variable, or credential. Policy binds the
capability to one realm persona, service, exact destination, methods, exact
paths, hydration sink, formatting rule, provider reference, response mode, and
resource limits.

## Workload identity and transport

Each transparent listener belongs to exactly one service with exactly one DNS
hostname. The realm belongs to exactly one protected workload. Infra routes
that workload's destination traffic to the listener without application proxy
settings, prevents other workloads from reaching the lane, and blocks direct
egress. A URL path, source IP, or capability reference is not workload identity.

Charon terminates TLS with the deployment CA, requires TLS SNI and HTTP
authority to equal the listener's exact hostname, validates upstream TLS, and
pins the first authorized IPv4 DNS result for the process lifetime. IPv6
listeners and resolved IPv6 addresses are denied. The binary has no HTTP/3
feature or UDP listener. Infra must reject or black-hole UDP/443 so QUIC cannot
bypass the TCP gateway.

Transparent identity is routing-bound and therefore weaker than the explicit
proxy's signed single-use manifest. Deploy one protected listener/realm per
workload. Shared listeners require a future cryptographic workload transport;
source addresses and URL paths are insufficient.

## Authorization and hydration

Charon parses and bounds framing, identifies the bound service, extracts one
reference only from the configured sink, resolves the exact capability, and
authorizes persona, service, destination, method, and path before resolving a
credential. Supported sinks are Authorization, an exact named API-key header,
Basic authentication, Git smart-HTTP Basic authentication, one path component,
one explicitly named query parameter, one RFC 6901 JSON string field, and one
URL-encoded form field.

JSON and form bodies are buffered only to the request limit because semantic
mutation cannot be performed safely on arbitrary chunks. Header, path, query,
Basic, Git, and opaque request bodies retain streaming and backpressure.
Caller-supplied Authorization is removed or denied when it is not the declared
sink. Routing, authority, framing, proxy authentication, and hop-by-hop fields
cannot be hydration sinks.

## Response modes

Every service selects one mode:

- `structured-stream`: parse one bounded SSE event or NDJSON record, remove
  exact forbidden JSON fields recursively, then pass it through rolling secret
  redaction before immediate delivery;
- `buffered-structured`: buffer one JSON document to its smaller declared
  limit, remove forbidden fields recursively, redact, and return it; overflow is
  denied and never changes mode;
- `text-stream`: retain only the overlap needed to recognize a protected value
  split across chunks, redact, and forward with bounded latency; or
- `opaque-stream`: strip sensitive headers and stream only an exact allowlisted
  media type, with rolling known-credential byte redaction but without claiming
  protocol-aware semantic body inspection.

All modes preserve backpressure and cancellation and enforce aggregate bytes,
total lifetime, idle time, and bounded memory. Authentication/session headers
and upstream Content-Length are removed before downstream headers. Known raw
and rendered credentials are held in secret types and registered with the
rolling redactor. A failure after partial output stops forwarding and records
an interrupted or sanitization-failed receipt; Charon does not append an
upstream error body.

Compression is explicit. `identity-only` asks upstream for identity encoding
and rejects encoded responses. `reject` rejects encoding without negotiation.
`opaque` is reserved and rejected by current policy validation: compressed
opaque bytes cannot be scanned without risking silent payload corruption. A
future bounded decompress, sanitize, and recompress implementation requires a
contract review. WebSocket upgrades are denied because `upgrade` is a forbidden
hop-by-hop field. A future WebSocket mode requires protocol-specific frame
policy and a new contract version.

## Redirects, errors, and receipts

Redirect following remains disabled. A 3xx response is sanitized and returned;
the caller must make a new request that independently passes destination and
capability authorization. Reflected protected values in retained headers cause
a fail-closed response. Cookies and authentication/session headers are removed.

The optional explicit-proxy journal and mandatory transparent-gateway journal
contain only the closed metadata shape in `data-plane-receipt.schema.json`.
They contain no headers, queries, request bodies, response bodies, arguments,
results, provider references, credentials, or memory content. The asynchronous
queue is bounded. An unhealthy or full queue denies a new request before
credential resolution; a queue failure after partial delivery is logged as
`receipt_lost` and cannot retract already delivered bytes.

The SHA-256 chain detects edits, deletion, and reordering only when an operator
retains a trusted checkpoint outside the journal. It is not a signature, does
not protect against a compromised Charon process, and does not prove the remote
service performed a semantic action. The journal is the recoverable source of
truth. Startup replays and validates every bounded entry, repairs a checkpoint
that matches an earlier verified entry, truncates only an incomplete tail whose
checkpoint matches the last complete entry, and rejects an invalid chain or an
unrecognized checkpoint. Each complete journal entry is synced before the
checkpoint is atomically replaced and its directory is synced.

## Ownership and correlation

Charon owns this generic broker, policy validation, provider calls, hydration,
response mediation, and data-plane receipts. An application integration owns
which capabilities a workload may reference. Infra owns isolated routing,
direct-egress denial, listener reachability, UDP/QUIC rejection, image pins, CA
deployment, provider mappings, filesystem ownership, and convergence. The
secret store owns private values.

For the Hermes deployment specifically, `hermes-config` owns the capability
references made available to Hermes; Infra owns routing, immutable image pins,
CA deployment, provider mappings, and host convergence; and Vaultwarden owns
the private values. None of that deployment data belongs in this repository.

Hermes tool admission, Hermes's dangerous-command human approval, Charon
gateway authorization, network isolation, and workload-manifest issuance are
separate controls. `charon-hermes` can supply semantic tool receipts, but an
unmodified `git`, `gh`, `curl`, or SDK cannot securely correlate its socket to a
specific tool call. Charon therefore authorizes transparent traffic
independently. Any operation identifier is descriptive correlation, never an
authorization input.

## Compatibility and migration

Contract version 1 requires an explicit typed hydration sink and response
mode. The former untyped service fields (`header`, `placeholder`, and a
top-level `value_template`) are removed rather than accepted as compatibility
aliases. Move formatting under `[services.hydration]`, select one sink type,
add `[services.response]`, and replace the old configured placeholder with the
canonical `{{charon.<capability>}}` reference. `charon policy validate` must
succeed against the exact candidate binary before routing is activated.

Unknown configuration fields, sink types, response modes, capabilities, and
contract versions fail closed. A future change that alters reference parsing,
authorization meaning, hydration behavior, or streaming semantics requires an
explicit contract-version review. Operators roll out a new binary together
with one complete validated policy; they do not mix schema generations.
