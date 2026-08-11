# Non-production deployment

On a successful `CI` run for a push to `main`,
`.github/workflows/release.yml` checks out that exact commit and publishes
`ghcr.io/<repository-owner>/<repository>:sha-<40-character-commit>`. The image
name is derived from `github.repository`, lowercased for OCI compatibility, so
forks publish only to their own package namespace. Pull requests build without
publishing and receive neither package-write permission nor deploy credentials.

Publishing does not automatically make a GHCR package public. A repository
owner must set the package visibility to **Public** in the package settings if
anonymous pulls are desired.

The public workflows stop after publishing the image and do not access a
deployment host. Operators can use the project-owned files under `deploy/`
from their own trusted deployment system.

The operator provisions `/opt/apps/charon/runtime.env` (mode `0600`) with only:

```dotenv
CHARON_BIND_IP=<approved-internal-listener-ip>
CHARON_TEST_CREDENTIAL=<disposable-value-with-no-production-access>
```

The operator provisions a rootless Docker daemon for the deploy account,
ownership of only `/opt/apps/charon`, and `curl`. If registry authentication is
required, the trusted deployment system streams a short-lived package-read
token to `docker login` through the script's isolated temporary Docker config.
The token is never a command-line argument, Compose value, or permanent host
login. The deploy account has neither sudo nor access to a rootful Docker
socket shared by the secrets stack.

## Verification and failure behavior

Compose waits for `/healthz`. The deploy script then checks that an unauthenticated
proxy request is denied with `401` before credential resolution and that the running OCI revision label equals
the requested main commit. If pull, startup, health, denial, or revision checks
fail, the script restores `.env.previous` and recreates the last known-good image.
The Compose and policy files are staged and restored with the image, so a bad
configuration change cannot make the rollback use the candidate contract.
The currently selected revision is observable with:

```sh
docker inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' charon
```

## Rollback

Select a previously published full 40-character main commit SHA in the trusted
deployment system. It must pull the existing immutable image rather than
rebuild or retag it. The project-owned host command is:

```sh
/opt/apps/charon/redeploy.sh \
  <40-character-main-commit-sha> \
  ghcr.io/<owner>/<repository> \
  <registry-username>
```

## Removal

This removes the milestone-0 instance but retains its small deployment files for
audit and later redeployment:

```sh
cd /opt/apps/charon
docker compose --env-file .env down
```

After confirming the container and listener are gone, infra may remove the
project directory, deploy account/key, private-network policy, and workload
registry entry. No Vaultwarden state or production credential is part of this
deployment.

## Vaultwarden provider cutover

The durable provider uses Vaultwarden through a pinned native Bitwarden CLI,
which is compatible with the Vaultwarden client API. Infra, not a workload,
owns these three mounts:

- `/usr/local/bin/bw` is a read-only, checksum-verified CLI executable;
- `/var/lib/charon/bitwarden-cli` is a Charon-only directory containing the
  encrypted CLI vault and server selection;
- `/run/credentials/charon-vaultwarden-session` is a `0400`, memory-backed file
  containing the current unlock session.

The provider maps each opaque policy reference and exact persona to one exact
vault item UUID. Startup rejects any capability whose persona does not own its
service's mapping. It runs only `bw status`, `bw sync`, and
`bw get password <uuid>`. The session is
passed through the child environment, never an argument, response, or log. A
missing, empty, whitespace-containing, or non-unlocked session fails as locked.
Charon starts a fresh CLI process on a cache miss, zeroizes captured output, and
caches resolved values in `SecretString` for at most 300 seconds (30 seconds in
the example). A process restart starts with an empty value cache.

Provision the encrypted CLI state interactively under the dedicated Charon host
account, select the exact Vaultwarden server, log in with a least-privilege
persona vault account, and sync once. Materialize the unlock session only into
the memory-backed credential file immediately before starting Charon. Rotation
is: update the mapped item, sync, atomically replace the session file if the
vault was re-unlocked, wait one configured cache TTL or restart Charon, then
revoke the prior value. Never place the API key, master password, session, CLI
data, or resolved values in Compose environment, image layers, GitHub Actions,
or the workload.

Locked or missing sessions deny as `Vaultwarden provider is locked`; CLI/server
failure denies as `Vaultwarden provider is unavailable`; revoked or deleted
items deny as `Vaultwarden item is unavailable`. These messages are deliberately
value-free. Removing the session file locks future cache misses; restart Charon
when immediate invalidation of already-cached values is required.

## CONNECT interception CA

Infra keeps the root CA private key offline and outside every runtime host,
image, repository, backup, and container. A persona realm receives only its
root-signed intermediate private key, mounted read-only at
`/run/charon/realms/<realm>/ca/<generation>/intermediate-key.pem` with mode
`0400`, and the matching intermediate certificate. Charon serves that
intermediate in each leaf chain. Workspace images trust only the stable public
root certificate; adding or rotating a persona does not rebuild an image or
distribute a new trust anchor.

For a live non-production proof, issue a fresh single-use manifest and run
`scripts/prove-gh-proxy.sh`. It configures an unmodified `gh api user` through
`HTTPS_PROXY`, provides only the public CA and capability-reference GitHub token to the
workload, and relies on Charon to resolve the mapped value. The CA key,
Vaultwarden session, mapped item, and resolved value remain absent from the
workload.

Rotate a persona intermediate independently using the bounded overlap in the
realm contract: validate a second root-signed intermediate, select it for new
leaves, drain old tunnels, then destroy the retiring key. Workspace trust does
not change. A compromised intermediate requires immediate isolation of that
realm endpoint, key/session revocation, and realm rebuild; unrelated realms and
the offline root remain unchanged. Production credentials remain prohibited
until the explicit owner security review covers ADR 0002 and ADR 0003.

### CA commands and rotation

Charon refuses to overwrite CA files. Generate a deployment CA only in an
operator-owned protected directory:

```sh
charon ca generate "Charon deployment CA" /run/charon-ca/ca.pem /run/credentials/charon-ca-key.pem
charon ca validate /run/charon-ca/ca.pem /run/credentials/charon-ca-key.pem
charon ca fingerprint /run/charon-ca/ca.pem
charon ca export /run/charon-ca/ca.pem /tmp/charon-public-ca.pem
```

The private key is created as `0600`; mount it read-only for the Charon UID and
never install it in a workload. `validate` proves certificate/key identity and
prints the public SHA-256 fingerprint. Compare that fingerprint through a
separate trusted channel before installing the exported certificate.

For rotation, generate the new CA or intermediate in a new generation
directory, validate it, distribute and verify the new public trust anchor while
the old one remains trusted, then atomically select the new Charon config and
restart. Drain old connections before removing old trust and destroying the old
runtime key. Rollback selects the previous immutable image, complete policy,
certificate/key pair, and trust bundle together. Never mix certificate and key
generations.

## Containerized transparent gateway

[`examples/transparent-gateway.toml`](../examples/transparent-gateway.toml) is
the public contract consumed by downstream Infra. Run Charon as a dedicated
non-root UID/GID. That identity alone owns the provider session, CA private key,
receipt journal, and hash-chain state. Directories are `0700`; private files are
`0400` or `0600`; the public CA can be `0644`. Do not mount application state,
Hermes `/opt/data`, Git credential files, Docker sockets, or control-plane data.

Infra creates one network namespace and one transparent listener lane per
workload/service. It redirects only the exact destination's TCP/443 traffic to
the configured `transparent_listen`, prevents every other workload from
reaching that port, blocks direct workload egress, disables IPv6 or applies the
equivalent deny policy, and rejects UDP/443. Charon does not install routing,
iptables, nftables, Compose, or host policy.

The normal `listen` address remains the network-restricted control and explicit
proxy endpoint. `/healthz` proves the process is alive. `/readyz` checks the
provider and receipt writer without resolving a credential. A failed provider,
receipt state, CA, listener bind, policy validation, or DNS/TLS operation fails
closed. Restart policy should be `on-failure`; readiness failure removes the
gateway from service but must not open a bypass route.

At startup Charon replays the bounded receipt journal and verifies its chain.
The journal is the recovery source of truth: Charon repairs a checkpoint that
matches an earlier verified entry and discards only an incomplete tail whose
checkpoint still matches the last complete entry. An invalid chain or an
unrecognized checkpoint prevents startup. Back up the journal and checkpoint
together, and retain an independent trusted digest when external tamper
evidence is required.

Validate and inventory policy before activation:

```sh
charon policy validate /etc/charon/charon.toml
charon policy inventory /etc/charon/charon.toml
charon healthcheck http://127.0.0.1:3129/readyz
```

Safe rollout uses a synthetic credential and isolated upstream first. Prove an
exact read and mutation, each configured hydration sink in use, response
streaming/cancellation, an omitted capability denial before provider access,
service-loss denial, direct-egress denial, IPv6/QUIC denial, a metadata-only
receipt, and restart without credential artifacts. For Git, disable hooks,
credential helpers, recursive submodules, alternate object stores, and
caller-controlled URL rewrites in the workload policy; allow only the exact
smart-HTTP hostname and paths and select an opaque Git media type.

Rollback removes the transparent route before stopping Charon, restores the
previous immutable image plus its complete policy/CA/provider mapping, verifies
readiness, then restores the route. Application state remains on its independent
persistent volume. For Hermes that means `/opt/data` survives every Charon,
plugin, and image change; Charon neither mounts nor modifies it.
