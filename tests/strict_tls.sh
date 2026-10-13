#!/bin/sh
set -eu

# A separate interpreter preserves the Hermes admission package's tool pin.
# The venv holds test dependencies only; all synthetic TLS keys stay in the
# Rust fixture's disposable tempfile and are never emitted by this script.
strict_venv=$(mktemp -d "${TMPDIR:-/tmp}/charon-strict-python.XXXXXX")
trap 'rm -rf "$strict_venv"' EXIT HUP INT TERM
mise exec python@3.13.5 -- python -m venv "$strict_venv"
"$strict_venv/bin/python" -m pip --disable-pip-version-check install --quiet httpx==0.28.1
CHARON_STRICT_TLS_PYTHON="$strict_venv/bin/python" cargo test --lib \
    gateway::tests::python_313_strict_clients_accept_generated_chain -- --ignored --nocapture
