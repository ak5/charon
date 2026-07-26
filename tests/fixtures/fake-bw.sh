#!/bin/sh
set -eu

fixture_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

if [ -n "${HOME:-}" ] || [ -n "${AWS_SECRET_ACCESS_KEY:-}" ]; then
    : >"$fixture_dir/inherited-environment"
fi

if [ -f "$fixture_dir/outage" ]; then
    exit 70
fi

case "${1:-}" in
    status)
        expected_session=$(sed -n '1p' "$fixture_dir/expected-session")
        if [ "${BW_SESSION:-}" = "$expected_session" ]; then
            printf '%s\n' '{"serverUrl":"https://vault.example","lastSync":"2026-07-22T00:00:00.000Z","userEmail":"fixture@example.invalid","userId":"00000000-0000-4000-8000-000000000002","status":"unlocked"}'
        else
            printf '%s\n' '{"serverUrl":"https://vault.example","status":"locked"}'
        fi
        ;;
    sync)
        ;;
    get)
        if [ -f "$fixture_dir/deleted" ]; then
            exit 4
        fi
        sed -n '1p' "$fixture_dir/secret"
        ;;
    *)
        exit 64
        ;;
esac
