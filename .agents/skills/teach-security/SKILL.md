---
name: teach-security
description: Teach Charon credential flows, trust boundaries, and security review.
---

# Learn Charon security

Read `docs/threat-model.md` and `docs/integration-boundaries.md`. Trace a request
from signed manifest through capability policy, provider lookup, credential
injection, upstream transport, and redacted response handling.

Ask:

- Can the workload select a secret reference or destination?
- Does exact host, method, and path authorization fail closed?
- Could a redirect send credentials to another hop?
- Could logs, errors, serialization, snapshots, or fixtures expose a value?
- Does the data plane depend on an orchestrator or application database?
- Is each new trust boundary and credential flow documented and tested?

Use synthetic credentials. Require `mise run check` and a threat-model update
when the boundary changes.
