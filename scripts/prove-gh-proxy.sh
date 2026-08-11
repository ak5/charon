#!/bin/sh
set -eu

: "${CHARON_PROXY_URL:?set the Charon HTTP proxy URL without credentials}"
: "${CHARON_WORKLOAD_MANIFEST:?set a fresh single-use workload manifest}"
: "${CHARON_CA_CERTIFICATE:?set the environment-specific public CA path}"

HTTPS_PROXY="http://charon:${CHARON_WORKLOAD_MANIFEST}@${CHARON_PROXY_URL#http://}" \
SSL_CERT_FILE="$CHARON_CA_CERTIFICATE" \
GH_TOKEN='{{charon.github-read-user}}' \
gh api user
