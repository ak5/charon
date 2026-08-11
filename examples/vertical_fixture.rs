//! Prepare non-secret CA/identity material and issue short-lived vertical manifests.

use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail, ensure};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use charon::identity::WorkloadClaims;
use ed25519_dalek::{Signer as _, SigningKey};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};

const ISSUER_KEY_FILE: &str = "issuer-key.bin";
const MANIFEST_DIRECTORY: &str = "manifests";

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next(), args.next(), args.next()) {
        (Some(command), Some(directory), Some(item_id), None) if command == "init" => {
            initialize(Path::new(&directory), &item_id.to_string_lossy())
        }
        (Some(command), Some(directory), None, None) if command == "issue" => {
            issue(Path::new(&directory))
        }
        _ => bail!(
            "usage: cargo run --example vertical_fixture -- init <directory> <vault-item-uuid> | issue <directory>"
        ),
    }
}

fn initialize(directory: &Path, item_id: &str) -> Result<()> {
    validate_item_id(item_id)?;
    fs::create_dir(directory).with_context(|| {
        format!(
            "failed to create fresh fixture directory {}",
            directory.display()
        )
    })?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;

    let issuer_key = random_bytes()?;
    let signing_key = SigningKey::from_bytes(&issuer_key);
    write_new(&directory.join(ISSUER_KEY_FILE), &issuer_key, 0o400)?;

    let root_key = KeyPair::generate()?;
    let root_key_pem = root_key.serialize_pem();
    let mut root_params = CertificateParams::new(Vec::<String>::new())?;
    root_params.distinguished_name = DistinguishedName::new();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "Charon Disposable Offline Root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let root = CertifiedIssuer::self_signed(root_params, root_key)?;
    write_new(
        &directory.join("offline-root-key.pem"),
        root_key_pem.as_bytes(),
        0o400,
    )?;
    write_new(&directory.join("root-ca.pem"), root.pem().as_bytes(), 0o444)?;

    let intermediate_key = KeyPair::generate()?;
    let intermediate_key_pem = intermediate_key.serialize_pem();
    let mut intermediate_params = CertificateParams::new(Vec::<String>::new())?;
    intermediate_params.distinguished_name = DistinguishedName::new();
    intermediate_params
        .distinguished_name
        .push(DnType::CommonName, "Charon Disposable Persona Intermediate");
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    intermediate_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let intermediate = CertifiedIssuer::signed_by(intermediate_params, intermediate_key, &root)?;
    write_new(
        &directory.join("ca-key.pem"),
        intermediate_key_pem.as_bytes(),
        0o400,
    )?;
    write_new(
        &directory.join("ca.pem"),
        intermediate.pem().as_bytes(),
        0o444,
    )?;

    let config = config(
        item_id,
        &STANDARD.encode(signing_key.verifying_key().to_bytes()),
    );
    write_new(&directory.join("charon.toml"), config.as_bytes(), 0o400)?;
    fs::create_dir(directory.join(MANIFEST_DIRECTORY))?;
    fs::set_permissions(
        directory.join(MANIFEST_DIRECTORY),
        fs::Permissions::from_mode(0o755),
    )?;
    println!("initialized fixture material in {}", directory.display());
    Ok(())
}

fn issue(directory: &Path) -> Result<()> {
    let key_bytes = fs::read(directory.join(ISSUER_KEY_FILE))?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("issuer key must contain exactly 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let manifests = [
        ("allowed", now, now, now + 50),
        ("forbidden-host", now, now, now + 50),
        ("forbidden-operation", now, now, now + 50),
        (
            "expired",
            now.saturating_sub(120),
            now.saturating_sub(120),
            now.saturating_sub(60),
        ),
        ("provider-failure", now, now, now + 50),
    ];
    let manifest_directory = directory.join(MANIFEST_DIRECTORY);
    for (name, iat, nbf, exp) in manifests {
        let claims = WorkloadClaims {
            iss: "fixture-control-plane".into(),
            aud: "charon-integration".into(),
            sub: "vertical-workload".into(),
            tenant: "vertical-tenant".into(),
            persona: "vertical-developer".into(),
            workspace: "vertical-workspace".into(),
            lease: "vertical-lease".into(),
            operation: format!("vertical-{name}"),
            capability: "github-read-user".into(),
            jti: URL_SAFE_NO_PAD.encode(random_bytes()?),
            iat,
            nbf,
            exp,
        };
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let signature = signing_key.sign(encoded.as_bytes());
        let manifest = format!(
            "{encoded}.{}\n",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        replace(&manifest_directory.join(name), manifest.as_bytes(), 0o444)?;
    }
    println!("issued five manifests valid for the next 50 seconds");
    Ok(())
}

fn random_bytes() -> Result<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn validate_item_id(item_id: &str) -> Result<()> {
    ensure!(
        item_id.len() == 36,
        "vault item UUID must contain 36 characters"
    );
    ensure!(
        item_id.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23) && byte == b'-'
                || !matches!(index, 8 | 13 | 18 | 23) && byte.is_ascii_hexdigit()
        }),
        "vault item UUID must use canonical hexadecimal UUID syntax"
    );
    Ok(())
}

fn write_new(path: &Path, value: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("refusing to replace {}", path.display()))?;
    file.write_all(value)?;
    file.sync_all()?;
    Ok(())
}

fn replace(path: &Path, value: &[u8], mode: u32) -> Result<()> {
    let temporary = PathBuf::from(format!("{}.next", path.display()));
    if temporary.exists() {
        fs::remove_file(&temporary)?;
    }
    write_new(&temporary, value, mode)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn config(item_id: &str, public_key: &str) -> String {
    format!(
        r#"listen = "0.0.0.0:3129"

[realm]
id = "realm-vertical-developer"
tenant = "vertical-tenant"
persona = "vertical-developer"
generation = 1

[upstream_proxy]
url = "http://egress.example.internal:8888"
username = "egress"
password_file = "/run/credentials/egress-proxy-password"

[provider]
kind = "vaultwarden"
cli_path = "/usr/local/bin/bw"
appdata_dir = "/var/lib/charon/bitwarden-cli"
session_file = "/run/credentials/charon-vaultwarden-session"
cache_ttl_seconds = 5

[[provider.items]]
secret_ref = "github/vertical-developer"
persona = "vertical-developer"
item_id = "{item_id}"

[tls]
ca_certificate = "/run/charon-ca/ca.pem"
ca_private_key = "/run/credentials/charon-ca-key.pem"

[identity]
issuer = "fixture-control-plane"
audience = "charon-integration"
public_key = "{public_key}"
max_ttl_seconds = 60
clock_skew_seconds = 2

[receipts]
journal_path = "/var/lib/charon/receipts/receipts.jsonl"
state_path = "/var/lib/charon/receipts/chain"
queue_capacity = 1024

[[capabilities]]
name = "github-read-user"
persona = "vertical-developer"
service = "github"
methods = ["GET"]
paths = ["/user"]

[[services]]
name = "github"
hosts = ["api.github.com"]
secret_ref = "github/vertical-developer"

[services.hydration]
kind = "authorization"
value_template = "token {{secret}}"

[services.response]
compression = "identity-only"
max_bytes = 16777216
max_duration_seconds = 60
idle_timeout_seconds = 15
max_secret_bytes = 4096

[services.response.body]
mode = "buffered-structured"
max_bytes = 1048576
forbidden_fields = ["access_token", "refresh_token", "token", "signed_url"]
"#
    )
}
