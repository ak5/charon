#!/bin/sh
set -eu
script="$(dirname "$0")/../.github/scripts/check-pr-path.sh"
"$script" main feat/example
"$script" main dependabot/cargo/update
if "$script" other feat/example; then exit 1; fi
if "$script" main main; then exit 1; fi
if "$script" main; then exit 1; fi
