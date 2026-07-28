#!/usr/bin/env bash
set -eu

base=${1:-}
head=${2:-}

if [ -z "$base" ] || [ -z "$head" ]; then
  printf 'error: usage: check-pr-path.sh <base-branch> <head-branch>\n' >&2
  exit 2
fi

case "$base:$head" in
  main:dev)
    printf 'valid release path: dev -> main; use a merge commit\n'
    ;;
  main:hotfix/*)
    printf 'valid hotfix path: %s -> main; use a merge commit and then merge main -> dev\n' "$head"
    ;;
  main:*)
    printf 'error: main accepts only dev releases or hotfix/* emergency repairs\n' >&2
    exit 1
    ;;
  dev:main)
    printf 'valid hotfix reconciliation path: main -> dev; use a merge commit\n'
    ;;
  dev:*)
    printf 'valid integration path: %s -> dev; use squash or an approved rebase merge\n' "$head"
    ;;
  *)
    printf 'information: no staged-release path rule applies to %s -> %s\n' "$head" "$base"
    ;;
esac
