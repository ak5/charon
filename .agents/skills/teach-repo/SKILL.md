---
name: teach-repo
description: Orient a nontechnical operator to Charon and safe AI-assisted work.
---

# Learn the repository

Guide the operator through outcomes, not command memorization.

1. Explain Charon using `README.md`: workloads request approved capabilities;
   Charon injects credentials without returning them.
2. Use `docs/index.md` as the map. Show `src/`, `contracts/`, `docs/`,
   `examples/`, `deploy/`, and `tests/`.
3. Explain the fail-closed rules in `AGENTS.md`.
4. Demonstrate asking an agent for a small change, requesting evidence,
   inspecting the diff, and withholding approval when impact is unclear.
5. Explain that `mise run check` is the complete local quality gate.
6. Point to the other `$teach-*` skills for task-specific guidance.
