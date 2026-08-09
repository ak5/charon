# Secretless GitHub vertical fixture

This fixture runs an unmodified `gh api user` in a disposable workload that has
only `gh`, curl, a public Charon CA, public capability references, and fresh workload
manifests. It mounts no GitHub or Vaultwarden credential. Its only Docker network
is `internal`; Charon alone also joins the upstream network and is configured to
chain allowed requests through an operator-configured egress proxy. The example
uses the reserved name `egress.example.internal:8888`.

## Inputs

Prepare a disposable GitHub credential with read-only access sufficient for
`GET /user` and store it as the password of a dedicated Vaultwarden login item.
Do not put the value in this directory, Compose, an image, or an environment
variable. Initialize a fresh ignored runtime directory with the exact item UUID:

```sh
cargo run --locked --example vertical_fixture -- \
  init .vertical-runtime <vault-item-uuid>
```

This creates a fresh offline root, a root-signed persona intermediate,
workload-identity key, reviewed config, and manifest directory without printing
private material. The root private key remains in the operator-only fixture
directory and is never mounted into Charon or the workload. Initialization
refuses to replace an existing directory. Remove the directory after the proof.

Download the pinned Linux-native CLI matching the immutable image's `linux/amd64`
platform. The helper verifies the exact SHA-256 digest published in Bitwarden's
GitHub release metadata and refuses to replace an existing file:

```sh
integrations/vertical/prepare-linux-bw.sh \
  "$PWD/.vertical-runtime/bin/bw"
```

Provide absolute host paths and an immutable Charon image:

```sh
export CHARON_IMAGE=ghcr.io/<owner>/<repository>:sha-<40-character-main-commit>
export CHARON_FIXTURE_DIRECTORY="$PWD/.vertical-runtime"
export CHARON_BW_CLI_PATH="$PWD/.vertical-runtime/bin/bw"
export CHARON_BW_APPDATA_PATH=/protected/bitwarden-cli
export CHARON_BW_SESSION_PATH=/run/user/<uid>/charon-vaultwarden-session
export CHARON_EGRESS_PROXY_PASSWORD_PATH=/run/user/<uid>/charon-egress-password
```

The harness creates a private receipt-state directory inside the disposable
fixture directory and mounts it only into Charon. Receipts contain metadata,
not request/response bodies or credential values.

The native `bw` binary is pinned to 2026.6.0 and checksum-verified. The
appdata directory contains the encrypted vault and exact Vaultwarden server
selection. The session should be memory-backed. The appdata, session, generated
config, and CA/issuer private keys are owned by the invoking operator UID;
Charon runs as that UID so protected mode-`0400` mounts remain readable without
broadening host permissions. None of their parent directories is mounted into
the workload.

If the configured egress proxy requires authentication, provision a dedicated,
least-privilege password through the operator's secret-delivery process. Write
only the password value to `CHARON_EGRESS_PROXY_PASSWORD_PATH` with mode `0400`.
Charon reads it into a secret-holding value and configures proxy Basic auth; it
is not embedded in a URL, config, environment variable, command argument, or
log.

The workload trusts only `root-ca.pem`; Charon serves its persona intermediate
with each leaf. The harness builds the workload first, then issues five value-only manifest
files named `allowed`, `forbidden-host`, `forbidden-operation`, `expired`, and
`provider-failure` immediately before startup. They bind persona
`vertical-developer` and capability `github-read-user`, use unique random
nonces, target the integration issuer/audience, and expire within 50 seconds.
The issuer key remains outside Charon and every container.

Run immediately after issuance:

```sh
integrations/vertical/run.sh
```

## Assertions and evidence

The workload checks one allow and five denies: forbidden host, forbidden
operation, expired identity, locked provider, and direct bypass. The second
Charon instance intentionally lacks the session mount for the locked-provider
case. Both Charon instances have upstream access; the workload network itself
has no external route.

The harness preserves `cases.jsonl`, the stopped workload's Docker inspect, and
Charon's redacted logs under `integrations/vertical/evidence` (or
`CHARON_EVIDENCE_DIRECTORY`). It fails if inspect/log output contains known
GitHub token prefixes, provider/CA-private inputs, a manifest, the public
capability reference, or the fixture sentinel. It also checks that exactly one allow and
five denies were recorded. Review the Charon events to correlate realm, tenant,
persona, workspace, lease, workload, operation, generation, capability,
service, method, path, status, and outcome without bearer material.

The fixture must run only on an operator-controlled host with Docker and access
to the configured secret store and egress proxy, never on pull requests from
untrusted code. The owner review in
`docs/security-review-connect-interception.md` is complete.
