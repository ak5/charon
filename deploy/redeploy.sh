#!/bin/sh
set -eu

if [ -z "${DOCKER_HOST:-}" ] && [ "$(id -u)" -ne 0 ]; then
  deploy_uid="$(id -u)"
  DOCKER_HOST="unix:///run/user/$deploy_uid/docker.sock"
  export DOCKER_HOST
fi

readonly image_sha="${1:-}"
readonly image_repository="${2:-}"
readonly registry_username="${3:-}"
readonly deploy_dir="${CHARON_DEPLOY_DIR:-/opt/apps/charon}"
readonly env_file="$deploy_dir/.env"
readonly previous_env="$deploy_dir/.env.previous"
readonly compose_file="$deploy_dir/compose.yaml"
readonly config_file="$deploy_dir/charon.toml"
readonly next_compose="$deploy_dir/compose.yaml.next"
readonly next_config="$deploy_dir/charon.toml.next"
readonly ephemeral_registry_auth="${CHARON_EPHEMERAL_GHCR_AUTH:-0}"

case "$image_sha" in
  *[!0-9a-f]*|'')
    echo "usage: redeploy.sh <40-character lowercase commit SHA> <ghcr.io/owner/image> <registry username>" >&2
    exit 2
    ;;
esac
if [ "${#image_sha}" -ne 40 ]; then
  echo "usage: redeploy.sh <40-character lowercase commit SHA> <ghcr.io/owner/image> <registry username>" >&2
  exit 2
fi
case "$image_repository" in
  ghcr.io/*/*) ;;
  *)
    echo "image repository must be an explicit ghcr.io/owner/image path" >&2
    exit 2
    ;;
esac
case "${image_repository#ghcr.io/}" in
  *[!a-z0-9./_-]*|*..*|*/.|./*|*/|'')
    echo "image repository is invalid" >&2
    exit 2
    ;;
esac
case "$registry_username" in
  *[!A-Za-z0-9_-]*|'')
    echo "registry username is invalid" >&2
    exit 2
    ;;
esac

cd "$deploy_dir"
mkdir -p "$deploy_dir/receipts"
chmod 700 "$deploy_dir/receipts"
test -f runtime.env
test -f "$next_compose"
test -f "$next_config"

registry_auth_dir=""
candidate_env="$(mktemp "$deploy_dir/.env.candidate.XXXXXX")"
cleanup() {
  rm -f "$candidate_env"
  if [ -n "$registry_auth_dir" ]; then
    docker --config "$registry_auth_dir" logout ghcr.io >/dev/null 2>&1 || true
    rm -f "$registry_auth_dir/config.json"
    rmdir "$registry_auth_dir" 2>/dev/null || true
  fi
}
trap cleanup EXIT HUP INT TERM

case "$ephemeral_registry_auth" in
  0) ;;
  1)
    registry_auth_dir="$(mktemp -d "$deploy_dir/.docker-auth.XXXXXX")"
    chmod 700 "$registry_auth_dir"
    if ! docker --config "$registry_auth_dir" login ghcr.io \
      --username "$registry_username" --password-stdin >/dev/null; then
      echo "temporary registry authentication failed" >&2
      exit 1
    fi
    DOCKER_CONFIG="$registry_auth_dir"
    export DOCKER_CONFIG
    ;;
  *)
    echo "CHARON_EPHEMERAL_GHCR_AUTH must be 0 or 1" >&2
    exit 2
    ;;
esac

cat runtime.env >"$candidate_env"
printf '\nCHARON_IMAGE=%s:sha-%s\nCHARON_REVISION=%s\n' \
  "$image_repository" "$image_sha" "$image_sha" >>"$candidate_env"
chmod 600 "$candidate_env"

had_previous=false
if [ -f "$env_file" ]; then
  cp "$env_file" "$previous_env"
  chmod 600 "$previous_env"
  had_previous=true
fi
mv "$candidate_env" "$env_file"

had_previous_contract=false
if [ -f "$compose_file" ] && [ -f "$config_file" ]; then
  cp "$compose_file" "$compose_file.previous"
  cp "$config_file" "$config_file.previous"
  had_previous_contract=true
fi
mv "$next_compose" "$compose_file"
mv "$next_config" "$config_file"

restore_previous() {
  echo "deployment failed; restoring the last known-good image" >&2
  if [ "$had_previous" = true ]; then
    if [ "$had_previous_contract" = true ]; then
      mv "$compose_file.previous" "$compose_file"
      mv "$config_file.previous" "$config_file"
    fi
    mv "$previous_env" "$env_file"
    docker compose --env-file "$env_file" up -d --wait --remove-orphans
  else
    docker compose --env-file "$env_file" down
    rm -f "$env_file"
  fi
}

if ! docker compose --env-file "$env_file" pull charon ||
   ! docker compose --env-file "$env_file" up -d --wait --remove-orphans; then
  restore_previous
  exit 1
fi

health_code="$(docker exec charon /usr/local/bin/charon healthcheck \
  http://127.0.0.1:3129/healthz >/dev/null 2>&1 && printf 204 || true)"
bind_ip="$(sed -n 's/^CHARON_BIND_IP=//p' runtime.env)"
case "$bind_ip" in
  *[!0-9.]*|'')
    echo "runtime.env CHARON_BIND_IP must be an IPv4 address" >&2
    restore_previous
    exit 1
    ;;
esac
negative_code="$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --max-time 5 --proxy "http://$bind_ip:3129" http://api.github.com/ || true)"
running_revision="$(docker inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' charon)"

if [ "$health_code" != 204 ] || [ "$negative_code" != 401 ] || [ "$running_revision" != "$image_sha" ]; then
  echo "post-deploy verification failed (health=$health_code negative=$negative_code revision=$running_revision)" >&2
  restore_previous
  exit 1
fi

rm -f "$previous_env"
rm -f "$compose_file.previous" "$config_file.previous"
if [ -f "$deploy_dir/redeploy.next" ]; then
  mv "$deploy_dir/redeploy.next" "$deploy_dir/redeploy.sh"
fi
echo "deployed $image_repository:sha-$image_sha"
