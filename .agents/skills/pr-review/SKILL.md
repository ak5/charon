---
name: pr-review
description: Review a Charon PR for correctness, security, documentation, and policy.
---

# Review a pull request

1. Read `AGENTS.md`, `CONTRIBUTING.md`, and the pull request diff.
2. Verify the branch path with `.github/scripts/check-pr-path.sh`.
3. Prioritize credential exposure, authorization bypass, caller-selected
   references, wildcard destinations, redirects, unsafe logging, and
   orchestrator coupling.
4. Check tests for failure paths and synthetic credentials only.
5. Run `$doc-code-parity`; require a threat-model update for boundary changes.
6. Run `mise run check`.
7. Report findings in severity order with paths and evidence. State when no
   findings remain and identify residual test gaps.
