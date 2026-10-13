#!/usr/bin/env bash
set -eu

base=${1:-}
head=${2:-}

if [ -z "$base" ] || [ -z "$head" ]; then
  printf 'error: usage: check-pr-path.sh <base-branch> <head-branch>\n' >&2
  exit 2
fi

if [ "$base" != main ]; then
  printf 'error: all pull requests must target main\n' >&2
  exit 1
fi
if [ "$head" = main ]; then
  printf 'error: pull requests must come from a feature branch\n' >&2
  exit 1
fi
printf 'valid pull request path: %s -> main\n' "$head"
