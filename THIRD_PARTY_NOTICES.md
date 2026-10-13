# Third-party notices

Charon uses the unmodified `webauthn-rs` implementation by the Kanidm project for
passkey verification. Version 0.5.5 of these crates is licensed under MPL-2.0:

- `webauthn-rs`
- `webauthn-rs-core`
- `webauthn-rs-proto`
- `webauthn-attestation-ca`
- `base64urlsafedata`
- `webauthn-authenticator-rs` (test dependency only)

Original source, notices, and license text are available at
https://github.com/kanidm/webauthn-rs/tree/d2c10d53ca5ef033d37ee6462e936e9eb72ad98c and in the published source
packages at https://crates.io. Exact resolved packages are recorded in
`Cargo.lock`. Charon does not modify these dependency source files. Their license
notices remain part of the source packages. The container includes this notice
at `/usr/share/doc/charon/THIRD_PARTY_NOTICES.md`.

The WebAuthn dependency exceptions in `deny.toml` apply only to these exact
package versions. Other dependencies remain subject to the default license
policy and release SBOM.
