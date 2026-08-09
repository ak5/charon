# Tool admission and receipt contract

Version: 1

This contract connects a workload-specific tool adapter to a protected local
integration service. It is not part of Charon's forward-proxy protocol and does
not grant authority to select a capability, destination, provider, credential,
or secret reference.

## Messages

Each Unix-socket connection carries one UTF-8 JSON object followed by `LF` and
one response object followed by `LF`. A message is at most 64 KiB. Trailing
data, malformed JSON, unknown fields, and timeouts fail closed.

An admission request is:

```json
{
  "kind": "admit",
  "operation": {}
}
```

The operation conforms to `tool-operation.schema.json`. The service returns a
`tool-admission-decision.schema.json` object. An allow decision is short-lived,
single-use, and bound server-side to one operation ID. It is not a Charon
manifest.

A receipt request is:

```json
{
  "kind": "receipt",
  "receipt": {}
}
```

The receipt conforms to `tool-receipt.schema.json`. The service accepts it only
when its authorization ID and operation ID match one unconsumed admission.

## Canonical digests

Version 1 uses UTF-8 JSON with object keys sorted lexicographically, no
insignificant whitespace, and non-ASCII characters emitted directly. Numbers
must be finite. The digest is lowercase `sha256:` followed by 64 hexadecimal
characters.

Argument digests bind the complete hook argument object without transmitting
or retaining that object. Result digests are disabled by default because even a
digest can disclose a low-entropy result through comparison.

## Receipt journal

The local service wraps each receipt with `chain_previous` and `chain_digest`.
`chain_digest` covers the receipt and previous digest using the same canonical
JSON encoding. Readers must validate the complete chain before trusting its
continuity.

The chain is tamper-evident only relative to a trusted prior digest. It is not a
signature or proof against compromise of the journal host.

## Security behavior

- Admission service absence, ambiguity, invalid responses, and operation replay
  deny execution.
- Policies use exact tool names and explicit classifications. They reject
  wildcards.
- Raw arguments and raw tool output never cross the integration protocol.
- Receipt export is bounded and asynchronous; it cannot change the result of an
  already completed tool call.
- Charon continues to require a valid single-use manifest and independently
  enforce exact destination, method, and path policy.
