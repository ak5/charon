#!/bin/sh
set -eu

version=2026.6.0
destination=${1:-}

if [ -z "$destination" ]; then
    printf 'usage: %s <destination-file>\n' "$0" >&2
    exit 2
fi

asset="bw-linux-$version.zip"
digest=392549496c712ab86bfbd6c27302df9fd2c431cfc7a47e26941ac3e3893f4d27

if [ -e "$destination" ]; then
    printf 'refusing to replace existing path: %s\n' "$destination" >&2
    exit 1
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/charon-bw.XXXXXX")
cleanup() {
    rm -rf "$temporary"
}
trap cleanup EXIT INT TERM

url="https://github.com/bitwarden/clients/releases/download/cli-v$version/$asset"
curl --fail --location --silent --show-error "$url" --output "$temporary/$asset"
actual=$(shasum -a 256 "$temporary/$asset" | awk '{print $1}')
if [ "$actual" != "$digest" ]; then
    printf 'Bitwarden CLI checksum mismatch\n' >&2
    exit 1
fi

mkdir -p "$(dirname "$destination")"
unzip -p "$temporary/$asset" bw >"$destination"
chmod 0555 "$destination"
printf 'installed checksum-verified Bitwarden CLI %s for Linux amd64\n' "$version"
