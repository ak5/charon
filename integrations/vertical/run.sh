#!/bin/sh
set -eu

fixture_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
workload_name=charon-vertical-workload
evidence_dir=${CHARON_EVIDENCE_DIRECTORY:-$fixture_dir/evidence}

compose() {
    docker compose --project-directory "$fixture_dir" --file "$fixture_dir/compose.yaml" "$@"
}

cleanup() {
    docker rm --force "$workload_name" >/dev/null 2>&1 || true
    compose down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

for name in \
    CHARON_IMAGE CHARON_FIXTURE_DIRECTORY CHARON_KDBX_PATH \
    CHARON_ADMIN_CERTIFICATE_PATH CHARON_ADMIN_PRIVATE_KEY_PATH CHARON_ADMIN_BIND_IP \
    CHARON_EGRESS_PROXY_PASSWORD_PATH; do
    eval "value=\${$name:-}"
    if [ -z "$value" ]; then
        printf 'missing required input: %s\n' "$name" >&2
        exit 2
    fi
done

export CHARON_CONFIG_PATH="$CHARON_FIXTURE_DIRECTORY/charon.toml"
export CHARON_CA_CERTIFICATE_PATH="$CHARON_FIXTURE_DIRECTORY/ca.pem"
export CHARON_CA_PRIVATE_KEY_PATH="$CHARON_FIXTURE_DIRECTORY/ca-key.pem"
export CHARON_ROOT_CA_CERTIFICATE_PATH="$CHARON_FIXTURE_DIRECTORY/root-ca.pem"
export CHARON_RECEIPT_STATE_PATH="$CHARON_FIXTURE_DIRECTORY/receipts"
export CHARON_LOCKED_RECEIPT_STATE_PATH="$CHARON_FIXTURE_DIRECTORY/locked-receipts"
export CHARON_ADMIN_STATE_PATH="$CHARON_FIXTURE_DIRECTORY/admin-state"
export CHARON_LOCKED_ADMIN_STATE_PATH="$CHARON_FIXTURE_DIRECTORY/locked-admin-state"
for path in "$CHARON_RECEIPT_STATE_PATH" "$CHARON_LOCKED_RECEIPT_STATE_PATH" "$CHARON_ADMIN_STATE_PATH" "$CHARON_LOCKED_ADMIN_STATE_PATH"; do
    mkdir -p "$path"
    chmod 700 "$path"
done
export CHARON_MANIFEST_DIRECTORY="$CHARON_FIXTURE_DIRECTORY/manifests"
export CHARON_RUNTIME_UID="${CHARON_RUNTIME_UID:-$(id -u)}"

compose build workload

mkdir -p "$evidence_dir"
compose up --detach --no-build --wait --wait-timeout 30 charon charon-locked
# Enrollment output is operator-console-only, never retained with evidence.
compose logs --no-color charon | sed -n '/Charon enrollment code (expires in five minutes): /p' >&2
printf 'Enroll and unlock at the configured HTTPS admin origin, then press Enter.
' >&2
read -r _
compose exec -T charon /usr/local/bin/charon healthcheck http://127.0.0.1:3129/readyz
if compose exec -T charon-locked /usr/local/bin/charon healthcheck http://127.0.0.1:3129/readyz >/dev/null 2>&1; then
    printf 'locked fixture unexpectedly ready\n' >&2
    exit 1
fi
cargo run --locked --quiet --example vertical_fixture -- issue "$CHARON_FIXTURE_DIRECTORY"
compose run --name "$workload_name" workload >"$evidence_dir/cases.jsonl"

docker inspect "$workload_name" >"$evidence_dir/workload-inspect.json"
docker inspect "$(compose ps --quiet charon)" "$(compose ps --quiet charon-locked)" \
    >"$evidence_dir/charon-inspect.json"
docker history --no-trunc "$(compose images --quiet workload)" \
    >"$evidence_dir/workload-image-history.txt"
compose logs --no-color charon charon-locked | sed '/Charon enrollment code (expires in five minutes): /d' >"$evidence_dir/charon.log"

if grep -Eiq \
    'github_pat_|ghp_|gho_|ghu_|ghs_|ghr_|CHARON_(KDBX|ADMIN_PRIVATE|CA_PRIVATE)|offline-root-key|BEGIN [A-Z ]*PRIVATE KEY' \
    "$evidence_dir/workload-inspect.json"; then
    printf 'credential-like material found in workload inspect output\n' >&2
    exit 1
fi

for manifest_file in "$CHARON_MANIFEST_DIRECTORY"/*; do
    manifest=$(tr -d '\r\n' < "$manifest_file")
    if [ -n "$manifest" ] && grep -Fq "$manifest" "$evidence_dir/charon.log"; then
        printf 'workload manifest leaked into Charon logs\n' >&2
        exit 1
    fi
done

if grep -Eiq 'github_pat_|ghp_|gho_|ghu_|ghs_|ghr_|fixture-secret|\{\{charon\.' \
    "$evidence_dir/charon.log"; then
    printf 'credential-like or placeholder material leaked into Charon logs\n' >&2
    exit 1
fi

test "$(wc -l < "$evidence_dir/cases.jsonl" | tr -d ' ')" = 6
grep -q '"case":"allowed","outcome":"allowed"' "$evidence_dir/cases.jsonl"
test "$(grep -c '"outcome":"denied"' "$evidence_dir/cases.jsonl")" = 5
grep -q '"outcome":"forwarded"' "$evidence_dir/charon.log"
grep -q '"outcome":"identity_denied"' "$evidence_dir/charon.log"
grep -q '"outcome":"tunneled_request_denied"' "$evidence_dir/charon.log"

printf 'vertical evidence: %s\n' "$evidence_dir"
