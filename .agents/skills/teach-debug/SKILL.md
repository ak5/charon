---
name: teach-debug
description: Teach safe, evidence-led debugging of Charon.
---

# Learn safe debugging

1. Reproduce with synthetic credentials and the smallest relevant test.
2. Separate observations, hypotheses, and conclusions.
3. Inspect configuration validation, manifest verification, capability
   matching, provider lookup, upstream handling, and redaction in order.
4. Never weaken deny-by-default checks to make a test pass.
5. Never print credential values; use sanitized metadata as evidence.
6. Add a regression test, update owned documentation, and run
   `mise run check`.
7. Recover by reverting the focused change or applying a corrective commit.
