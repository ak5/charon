# GitHub vertical fixture

This operator-run fixture sends an unmodified `gh api user` through Charon. The
workload receives only public CA trust, capability references and fresh signed
manifests. It mounts no credential database, master password, admin state or
private key. Its Docker network is internal; Charon alone joins the upstream
network and chains through an operator-configured egress proxy.

Prepare a disposable read-only GitHub credential sufficient for `GET /user` in
a dedicated protected KeePass Password field. Keep its private KDBX outside this
repository. Initialize a fresh operator-owned directory with the entry UUID:

```sh
cargo run --locked --example vertical_fixture -- init /protected/vertical-runtime <keepass-entry-uuid>
```

Initialization creates an offline root, persona intermediate, identity issuer
key and config without printing private keys. The offline root key and issuer
key remain outside containers. Review the generated config, including egress
address and admin origin. Supply a browser-trusted certificate and independent
private TLS key matching that stable origin. No KDBX master password is written
to disk or passed as an environment variable.

Set absolute paths and an immutable Charon image:

```sh
export CHARON_IMAGE=ghcr.io/<owner>/<repository>:sha-<40-character-main-commit>
export CHARON_FIXTURE_DIRECTORY=/protected/vertical-runtime
export CHARON_KDBX_PATH=/protected/disposable.kdbx
export CHARON_ADMIN_CERTIFICATE_PATH=/protected/admin/fullchain.pem
export CHARON_ADMIN_PRIVATE_KEY_PATH=/protected/admin/privkey.pem
export CHARON_ADMIN_BIND_IP=<owner-only-listener-ip>
export CHARON_EGRESS_PROXY_PASSWORD_PATH=/protected/egress-password
integrations/vertical/run.sh
```

Provision all private inputs under the invoking operator UID with mode 0400 or
0600. Charon runs as that UID. The script creates separate private receipt and
public-registration directories for the primary and locked instances. The
workload receives none of those directories. Egress credentials are optional in
Charon generally; this specific fixture config uses protected Basic-auth egress.

The script starts both instances locked, prints only the primary enrollment
console line, and waits while you enroll a passkey and unlock through HTTPS.
It checks primary readiness and verifies the second instance is unready,
then issues fresh manifests, and immediately runs the
workload. The second instance remains locked and publishes no owner port. Its
public registration and receipt files are isolated from the primary instance.

The assertions cover one allow and five denials: unknown destination, forbidden
operation, expired identity, locked store and direct bypass. Manifests bind the
`vertical-developer` persona and `github-read-user` capability and expire within
50 seconds. The workload trusts only the generated root certificate.

Evidence includes outcome JSONL, container/image inspection and redacted Charon
logs. Enrollment-code lines are removed before writing evidence. Prefix and
manifest scans reject credential-like artifacts. Docker console logs themselves
are private operator material; do not export them into shared logging. The
script removes its containers on exit and leaves operator-owned fixture inputs
and evidence for review. Both containers listen on admin port 8444 internally;
Infra must deny workload-to-admin traffic on that port. Host publication alone
does not establish this isolation. Remove disposable credentials and keys under your own
retention policy after the proof.

Run only on an operator-controlled Docker host with approved upstream access.
The Rust suite independently exercises synthetic encrypted KDBX, passkeys,
authorization, TLS and callback rejection without requiring a live bot or token.
