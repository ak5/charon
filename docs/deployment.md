# Deployment

All changes, including dependency updates, merge through checked pull requests
to the protected default branch `main`. Each successful merged revision can be
published; deploying its immutable image remains an operator decision.

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

The operator provisions `/opt/apps/charon/runtime.env` with nonsecret Compose
listener settings only:

```dotenv
CHARON_BIND_IP=<approved-internal-listener-ip>
CHARON_ADMIN_BIND_IP=<owner-admin-listener-ip>
```

The deploy script adds the nonsecret image name and commit revision to `.env`.
Neither file contains application secrets. Store the optional bot token in a
dedicated protected KeePass Password entry, identified by
`keepass.telegram_bot_token_entry_id` and excluded from workload mappings. Telegram
starts only after owner unlock; no locked-boot notification is available. TLS
private keys are provisioned as separate private files so HTTPS can start locked.

The operator provisions a rootless Docker daemon for the deploy account,
ownership of only `/opt/apps/charon`, and `curl`. If registry authentication is
required, the trusted deployment system streams a short-lived package-read
token to `docker login` through the script's isolated temporary Docker config.
The token is never a command-line argument, Compose value, or permanent host
login. The deploy account has neither sudo nor access to a rootful Docker
socket shared by the secrets stack.

## Verification and failure behavior

Compose waits for `/healthz`. The deploy script then checks that an unauthenticated
absolute-form HTTPS-target proxy request is denied with `401` before credential resolution and that the running OCI revision label equals
the requested main commit. If pull, startup, health, denial, or revision checks
fail, the script restores `.env.previous` and recreates the last known-good image.
The Compose and policy files are staged and restored with the image, so a bad
configuration change cannot make the rollback use the candidate contract.
The smoke test uses curl's `--request-target https://api.github.com/user` over
the plaintext proxy connection to reach manifest validation without CONNECT or
a credential. Plaintext remote targets are rejected before identity validation
and are not a valid identity smoke test. Deployment success does not imply
unlocked readiness or Telegram delivery.

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

This removes the Charon instance but retains its small deployment files for
audit and later redeployment:

```sh
cd /opt/apps/charon
docker compose --env-file .env down
```

After confirming the container and listener are gone, infra may remove the
project directory, deploy account/key, private-network policy, and workload
registry entry. Remove encrypted databases, optional key files and public passkey state only
under the operator's retention and backup policy.

## KeePass and HTTPS admin setup

Provision the encrypted KDBX, exact UUID mappings, optional private key file,
browser-trusted admin certificate and independent TLS key. Create a mode-0700
admin-state directory writable by Charon. The supplied Compose mounts the KDBX
read-only and persists public passkey registrations separately from receipts.
The image runs as UID/GID 65532 by default. Set host file/directory ownership
for that identity (including the rootless daemon's UID mapping) or configure a
reviewed dedicated `user`. Private files must be accessible only to Charon's UID. Set `admin.origin` to the
stable HTTPS DNS origin your browser will actually use. The owner admin listener
is separate from workload ports; firewall it away from the workload network.
Publishing port 8444 only on an owner IP does not prevent access through a
container's workload-network address when `admin.listen` is `0.0.0.0`. Infra must
deny workload-to-admin traffic as well as restricting the host-published port.
When Telegram is enabled, allow Charon direct HTTPS/DNS egress to
`api.telegram.org`; the bot does not use the configured egress proxy.

First boot prints a five-minute console enrollment code. Retrieve it over SSH,
open the HTTPS admin origin, create a passkey, sign in and unlock with the KeePass
master password. Add a recovery passkey. Restart always requires another unlock;
rollback to another image also starts locked. Do not route credential traffic
until `/readyz` succeeds. Liveness can succeed while the vault is locked.

For rotation, update the encrypted database outside Charon, lock the store and
unlock again to load its current mapped values, then revoke the prior credential.
Changing policy mappings requires a validated configuration restart. Preserve
public passkey state across image replacement; changing the origin requires
new enrollment. Charon never writes a master-password file or modifies the KDBX.
See [owner operations](admin.md) for certificates, recovery and optional Telegram.

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
KeePass database, optional key file, mapped entry, and resolved value remain absent from the
workload.

Rotate a persona intermediate independently using the bounded overlap in the
realm contract: validate a second root-signed intermediate, select it for new
leaves, drain old tunnels, then destroy the retiring key. Workspace trust does
not change. A compromised intermediate requires immediate isolation of that
realm endpoint, key revocation and credential rotation, and realm rebuild; unrelated realms and
the offline root remain unchanged. Production credentials remain prohibited
until the explicit owner security review covers ADR 0002 and ADR 0003.

### CA commands and rotation

Generated deployment CAs include critical CA Basic Constraints and signing Key
Usage, with subject/authority identifiers. Intercepted server leaves include
the issuer authority identifier, non-CA constraints, digital-signature Key Usage
and server-authentication EKU. These extensions support strict Python 3.13 TLS
clients. Regenerate a CA missing required extensions and distribute its new
public trust before using the corrected gateway; an image update cannot alter
an existing CA certificate. Do not weaken client or upstream verification.

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
non-root UID/GID. That identity alone owns the KeePass database, admin state, TLS private keys,
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
KeePass store and receipt writer without resolving a credential. A locked store,
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
streaming/cancellation, an omitted capability denial before credential lookup,
service-loss denial, direct-egress denial, IPv6/QUIC denial, a metadata-only
receipt, and restart without credential artifacts. For Git, disable hooks,
credential helpers, recursive submodules, alternate object stores, and
caller-controlled URL rewrites in the workload policy; allow only the exact
smart-HTTP hostname and paths and select an opaque Git media type.

Rollback removes the transparent route before stopping Charon, restores the
previous immutable image plus its complete policy/CA/KeePass mapping, verifies
readiness, then restores the route. Application state remains on its independent
persistent volume. For Hermes that means `/opt/data` survives every Charon,
plugin, and image change; Charon neither mounts nor modifies it.

## Exclusive Hermes network gateway

The [exclusive workload gateway](../contracts/workload-gateway.md) provides a separate
`--gateway-config` mode for ordinary HTTP(S) proxy clients, including reusable
CONNECT tunnels. It binds one fixed isolated workload, supports secretless
forwarding and typed credential sinks, and requires its own validated schema.
Signed proxy authentication, transparent service lanes, and Hermes tool
admission remain independent controls. Infra owns isolation, trust and cutover.
