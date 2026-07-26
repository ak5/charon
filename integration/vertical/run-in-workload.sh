#!/bin/sh
set -eu

manifest() {
    tr -d '\r\n' < "/manifests/$1"
}

proxy() {
    printf 'http://charon:%s@%s:3129' "$(manifest "$1")" "$2"
}

result() {
    printf '{"case":"%s","outcome":"%s"}\n' "$1" "$2"
}

if GH_TOKEN=charon-placeholder \
    HTTPS_PROXY="$(proxy allowed charon)" \
    SSL_CERT_FILE=/etc/charon-ca/ca.pem \
    gh api user --jq .login >/tmp/allowed.out 2>/tmp/allowed.err; then
    result allowed allowed
else
    result allowed unexpected-deny
    exit 1
fi

if HTTPS_PROXY="$(proxy forbidden-host charon)" \
    SSL_CERT_FILE=/etc/charon-ca/ca.pem \
    curl --fail --silent --show-error https://example.com/ >/tmp/host.out 2>/tmp/host.err; then
    result forbidden-host unexpected-allow
    exit 1
else
    result forbidden-host denied
fi

if GH_TOKEN=charon-placeholder \
    HTTPS_PROXY="$(proxy forbidden-operation charon)" \
    SSL_CERT_FILE=/etc/charon-ca/ca.pem \
    gh api --method DELETE user >/tmp/operation.out 2>/tmp/operation.err; then
    result forbidden-operation unexpected-allow
    exit 1
else
    result forbidden-operation denied
fi

if GH_TOKEN=charon-placeholder \
    HTTPS_PROXY="$(proxy expired charon)" \
    SSL_CERT_FILE=/etc/charon-ca/ca.pem \
    gh api user >/tmp/expired.out 2>/tmp/expired.err; then
    result expired-identity unexpected-allow
    exit 1
else
    result expired-identity denied
fi

if GH_TOKEN=charon-placeholder \
    HTTPS_PROXY="$(proxy provider-failure charon-locked)" \
    SSL_CERT_FILE=/etc/charon-ca/ca.pem \
    gh api user >/tmp/provider.out 2>/tmp/provider.err; then
    result provider-failure unexpected-allow
    exit 1
else
    result provider-failure denied
fi

if HTTPS_PROXY='' HTTP_PROXY='' ALL_PROXY='' NO_PROXY='*' \
    curl --connect-timeout 3 --fail --silent https://api.github.com/user \
    >/tmp/bypass.out 2>/tmp/bypass.err; then
    result direct-bypass unexpected-allow
    exit 1
else
    result direct-bypass denied
fi
