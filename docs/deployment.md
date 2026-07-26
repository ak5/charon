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
`HTTPS_PROXY`, provides only the public CA and placeholder GitHub token to the
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
