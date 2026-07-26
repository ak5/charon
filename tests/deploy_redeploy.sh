#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)"
test_root="$(mktemp -d)"
cleanup() { rm -rf "$test_root"; }
trap cleanup EXIT HUP INT TERM

deploy_dir="$test_root/deploy"
mock_bin="$test_root/bin"
mkdir -p "$deploy_dir" "$mock_bin"
printf '%s\n' 'CHARON_BIND_IP=127.0.0.1' 'CHARON_TEST_CREDENTIAL=disposable' >"$deploy_dir/runtime.env"
printf '%s\n' 'services: {}' >"$deploy_dir/compose.yaml.next"
printf '%s\n' '[server]' >"$deploy_dir/charon.toml.next"

cat >"$mock_bin/docker" <<'EOF'
#!/bin/sh
set -eu
if [ "${1:-}" = --config ]; then
  auth_dir="$2"
  shift 2
  case "${1:-}" in
    login)
      [ "$2" = ghcr.io ]
      [ "$3" = --username ]
      [ "$4" = example-owner ]
      [ "$5" = --password-stdin ]
      token="$(cat)"
      [ "$token" = test-token-not-secret ]
      printf '%s\n' '{"auths":{"ghcr.io":{}}}' >"$auth_dir/config.json"
      printf '%s\n' "$auth_dir" >"$TEST_ROOT/login-config"
      ;;
    logout) exit 0 ;;
    *) exit 90 ;;
  esac
  exit 0
fi
[ "${DOCKER_CONFIG:-}" = "$(cat "$TEST_ROOT/login-config")" ]
case "${1:-}" in
  compose)
    if [ "${FAIL_PULL:-0}" = 1 ] && [ "${4:-}" = pull ]; then
      exit 1
    fi
    ;;
  exec) exit 0 ;;
  inspect) printf '%s\n' "$TEST_REVISION" ;;
  *) exit 91 ;;
esac
EOF

cat >"$mock_bin/curl" <<'EOF'
#!/bin/sh
printf 401
EOF
chmod +x "$mock_bin/docker" "$mock_bin/curl"

revision=0123456789abcdef0123456789abcdef01234567
export PATH="$mock_bin:$PATH"
export TEST_ROOT="$test_root"
export TEST_REVISION="$revision"
export CHARON_DEPLOY_DIR="$deploy_dir"
export CHARON_EPHEMERAL_GHCR_AUTH=1

image_repository=ghcr.io/example-owner/charon
printf %s test-token-not-secret |
  "$repo_root/deploy/redeploy.sh" "$revision" "$image_repository" example-owner
[ ! -e "$(cat "$test_root/login-config")" ]
[ "$(sed -n 's/^CHARON_REVISION=//p' "$deploy_dir/.env")" = "$revision" ]
[ "$(sed -n 's/^CHARON_IMAGE=//p' "$deploy_dir/.env")" = "$image_repository:sha-$revision" ]

printf '%s\n' 'services: {}' >"$deploy_dir/compose.yaml.next"
printf '%s\n' '[server]' >"$deploy_dir/charon.toml.next"
export FAIL_PULL=1
if printf %s test-token-not-secret |
  "$repo_root/deploy/redeploy.sh" "$revision" "$image_repository" example-owner; then
  echo "expected failed pull to fail deployment" >&2
  exit 1
fi
[ ! -e "$(cat "$test_root/login-config")" ]

if "$repo_root/deploy/redeploy.sh" "$revision" ghcr.io/Example/charon example-owner; then
  echo "expected uppercase image path to fail" >&2
  exit 1
fi
if "$repo_root/deploy/redeploy.sh" "$revision" "$image_repository" 'bad user'; then
  echo "expected invalid registry username to fail" >&2
  exit 1
fi

echo "deployment auth contract passed"
