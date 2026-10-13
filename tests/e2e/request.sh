#!/bin/sh
# Workload input is public policy identity, never either KeePass password.
set -eu
name=${1:-}
case "$name" in first|second) ;; *) echo 'usage: request.sh first|second' >&2; exit 2;; esac
: "${CHARON_E2E_PROXY_URL:?set the fixture proxy URL}"
: "${CHARON_E2E_CA:?set the public fixture CA file}"
curl --silent --show-error --noproxy '' --max-time "${CHARON_E2E_TIMEOUT:-10}" \
  --proxy "$CHARON_E2E_PROXY_URL" --cacert "$CHARON_E2E_CA" \
  --request POST --header 'Content-Type: application/json' \
  --header "Authorization: Bearer {{charon.$name}}" \
  --data '{"operation":"synthetic-e2e"}' \
  --write-out '\n%{http_code}' "https://password.test/$name"
