---
name: teach-dev
description: Teach safe setup, development, and verification for Charon.
---

# Learn local development

1. Explain that `mise install` installs pinned Rust and `cargo-deny`.
2. Use `mise run dev` with `examples/charon.dev.toml`.
3. Clarify that the environment provider is only for synthetic local values.
4. Make focused changes and name affected contracts and documentation.
5. Run focused Cargo tests while iterating, then `mise run check`.
6. Inspect the diff and test output before approving a commit or push.

Never place real credentials in environment files, examples, fixtures, logs,
or repository-root `tmp/`.
