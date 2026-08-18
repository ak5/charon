//! Durable, channel-neutral human-approval broker primitives.

use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit as _, Nonce,
    aead::{Aead as _, Payload},
};
use ed25519_dalek::{Signer as _, SigningKey};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize as _;

const SCHEMA_VERSION: i64 = 1;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

/// Configuration for one approval broker state owner.
pub struct BrokerConfig {
    /// `SQLite` state path. Its parent directory must already be private.
    pub database: PathBuf,
    /// Protected 32-byte key used only to encrypt normalized requests at rest.
    pub state_key: PathBuf,
    /// Protected 32-byte Ed25519 seed dedicated to approval assertions.
    pub signing_key: PathBuf,
    /// Stable key identifier pinned by assertion consumers.
    pub signing_key_id: String,
    /// Assertion issuer value.
    pub issuer: String,
    /// Assertion lifetime, bounded by request expiry.
    pub assertion_ttl_seconds: u64,
    /// Required owner UID for the database, keys, and their directories.
    pub owner_uid: u32,
}

/// A schema-shaped normalized approval request.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEnvelope {
    /// Contract version.
    pub api_version: String,
    /// Normalized authorization input.
    pub request: NormalizedRequest,
    /// JCS SHA-256 digest of `request`.
    pub request_digest: String,
}

/// Authorization inputs bound into every decision.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedRequest {
    /// Unpredictable request nonce.
    pub request_id: String,
    /// Authenticated issuer identity.
    pub issuer: String,
    /// Tenant identity.
    pub tenant: String,
    /// Persona identity.
    pub persona: String,
    /// Workspace identity.
    pub workspace: String,
    /// Active lease identity.
    pub lease: String,
    /// Workload identity.
    pub workload: String,
    /// Operation correlation identity.
    pub operation: String,
    /// Named capability requested from the issuer.
    pub capability: String,
    /// Destination service classification.
    pub service: String,
    /// Exact structured resource.
    pub resource: Resource,
    /// Registry-owned action.
    pub action: String,
    /// Exact structured command.
    pub command: Command,
    /// Operator-owned risk classification.
    pub risk_tier: RiskTier,
    /// Active policy generation.
    pub policy_generation: u64,
    /// Requested Charon manifest lifetime.
    pub requested_manifest_ttl_seconds: u64,
    /// Creation time as Unix seconds.
    pub created_at: u64,
    /// Expiry time as Unix seconds.
    pub expires_at: u64,
}

/// Exact resource identity supported by the first registry version.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    /// Registry resource kind.
    pub kind: String,
    /// Resource owner.
    pub owner: String,
    /// Resource name.
    pub name: String,
}

/// Exact operation tokenization. Tokens must never contain secrets.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    /// Executable class.
    pub program: String,
    /// Ordered authorization-relevant arguments.
    pub arguments: Vec<String>,
}

/// Closed operator risk classification.
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    /// Routine reversible operation.
    Low,
    /// Operation requiring informed attention.
    Medium,
    /// Sensitive operation; reusable approval requires explicit registry policy.
    High,
    /// Non-reusable or unknown operation.
    Critical,
}

/// Terminal result of consuming an allow-once decision.
pub struct SignedApproval {
    /// Opaque decision identifier.
    pub decision_id: String,
    /// Compact JCS Ed25519 assertion.
    pub assertion: String,
}

/// Durable approval broker. It intentionally has no channel or provider client.
pub struct ApprovalBroker {
    connection: Mutex<Connection>,
    state_key: SecretKey,
    signing_key: SigningKey,
    issuer: String,
    assertion_ttl_seconds: u64,
}

struct SecretKey([u8; KEY_BYTES]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    sub: &'a str,
    request_id: &'a str,
    request_digest: &'a str,
    decision_id: &'a str,
    grant: &'static str,
    tenant: &'a str,
    persona: &'a str,
    workspace: &'a str,
    lease: &'a str,
    workload: &'a str,
    operation: &'a str,
    capability: &'a str,
    service: &'a str,
    resource_digest: String,
    action: &'a str,
    command_digest: String,
    policy_generation: u64,
    max_manifest_ttl_seconds: u64,
    jti: String,
    iat: u64,
    nbf: u64,
    exp: u64,
}

impl ApprovalEnvelope {
    /// Parse strictly, validate bounded fields, and verify the JCS request digest.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, unknown, out-of-bound, expired, or
    /// digest-mismatched input.
    pub fn parse(bytes: &[u8], now: u64) -> Result<Self> {
        let value: Value =
            serde_json::from_slice(bytes).context("invalid approval request JSON")?;
        let envelope: Self = serde_json::from_value(value).context("invalid approval request")?;
        envelope.validate(now)?;
        Ok(envelope)
    }

    fn validate(&self, now: u64) -> Result<()> {
        ensure!(
            self.api_version == "charon.approval/v1",
            "unsupported API version"
        );
        let request = &self.request;
        for (name, value) in [
            ("request_id", request.request_id.as_str()),
            ("tenant", request.tenant.as_str()),
            ("persona", request.persona.as_str()),
            ("workspace", request.workspace.as_str()),
            ("lease", request.lease.as_str()),
            ("workload", request.workload.as_str()),
            ("operation", request.operation.as_str()),
            ("capability", request.capability.as_str()),
            ("service", request.service.as_str()),
        ] {
            validate_identifier(name, value)?;
        }
        ensure!(
            !request.issuer.is_empty() && request.issuer.len() <= 256,
            "invalid issuer"
        );
        ensure!(
            request.resource.kind == "github_repository",
            "unknown resource kind"
        );
        validate_resource_identifier("resource owner", &request.resource.owner)?;
        validate_resource_identifier("resource name", &request.resource.name)?;
        validate_action(&request.action)?;
        ensure!(
            !request.command.program.is_empty() && request.command.program.len() <= 64,
            "invalid program"
        );
        ensure!(
            request.command.arguments.len() <= 32,
            "too many command arguments"
        );
        for argument in &request.command.arguments {
            ensure!(
                !argument.is_empty() && argument.len() <= 512,
                "invalid command argument"
            );
            ensure!(
                !argument.chars().any(char::is_control),
                "command argument contains control characters"
            );
        }
        ensure!(
            (1..=300).contains(&request.requested_manifest_ttl_seconds),
            "invalid manifest TTL"
        );
        ensure!(request.policy_generation > 0, "invalid policy generation");
        ensure!(
            request.created_at <= now,
            "request was created in the future"
        );
        ensure!(request.expires_at > now, "request is expired");
        ensure!(
            request.expires_at > request.created_at,
            "invalid request window"
        );
        let digest = digest_jcs(&request)?;
        ensure!(
            constant_time_equal(self.request_digest.as_bytes(), digest.as_bytes()),
            "request digest mismatch"
        );
        Ok(())
    }
}

impl ApprovalBroker {
    /// Open protected state, validate keys, migrate schema, and expire ambiguous requests.
    ///
    /// # Errors
    ///
    /// Returns an error when configuration, ownership, permissions, keys,
    /// database state, or schema validation fails.
    pub fn open(config: &BrokerConfig, now: u64) -> Result<Self> {
        ensure!(
            (1..=300).contains(&config.assertion_ttl_seconds),
            "invalid assertion TTL"
        );
        validate_identifier("signing key ID", &config.signing_key_id)?;
        ensure!(
            !config.issuer.is_empty() && config.issuer.len() <= 256,
            "invalid broker issuer"
        );
        let state_key = SecretKey(read_protected_key(&config.state_key, config.owner_uid)?);
        let signing_key =
            SigningKey::from_bytes(&read_protected_key(&config.signing_key, config.owner_uid)?);
        let connection = open_database(&config.database, config.owner_uid)?;
        migrate(&connection)?;
        bind_signing_key_id(&connection, &config.signing_key_id)?;
        connection.execute(
            "UPDATE requests SET state = 'timed_out', terminal_at = ?1 WHERE state = 'pending'",
            params![to_i64(now)?],
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
            state_key,
            signing_key,
            issuer: config.issuer.clone(),
            assertion_ttl_seconds: config.assertion_ttl_seconds,
        })
    }

    /// Persist a validated request. Repeated identical request IDs are idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid requests, conflicting request IDs,
    /// encryption failure, or durable-state failure.
    pub fn submit(&self, envelope: &ApprovalEnvelope, now: u64) -> Result<()> {
        envelope.validate(now)?;
        let plaintext = serde_jcs::to_vec(&envelope.request)?;
        let encrypted = encrypt(
            &self.state_key.0,
            envelope.request_digest.as_bytes(),
            &plaintext,
        )?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("approval state lock poisoned"))?;
        let existing: Option<String> = connection
            .query_row(
                "SELECT request_digest FROM requests WHERE request_id = ?1",
                params![envelope.request.request_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            ensure!(
                constant_time_equal(existing.as_bytes(), envelope.request_digest.as_bytes()),
                "request ID is already bound to different content"
            );
            return Ok(());
        }
        connection.execute(
            "INSERT INTO requests (request_id, request_digest, issuer, tenant, encrypted_request, created_at, expires_at, state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending')",
            params![
                envelope.request.request_id,
                envelope.request_digest,
                envelope.request.issuer,
                envelope.request.tenant,
                encrypted,
                to_i64(envelope.request.created_at)?,
                to_i64(envelope.request.expires_at)?,
            ],
        )?;
        Ok(())
    }

    /// Atomically allow one pending request and issue one short-lived assertion.
    ///
    /// # Errors
    ///
    /// Returns an error unless the request is current, pending, digest-bound,
    /// emergency issuance is enabled, and the state transition commits.
    pub fn allow_once(
        &self,
        request_id: &str,
        request_digest: &str,
        audience: &str,
        now: u64,
    ) -> Result<SignedApproval> {
        validate_identifier("request ID", request_id)?;
        ensure!(
            !audience.is_empty() && audience.len() <= 256,
            "invalid assertion audience"
        );
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("approval state lock poisoned"))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure!(
            !emergency_disabled(&transaction)?,
            "approval issuance is disabled"
        );
        let stored = transaction.query_row(
            "SELECT request_digest, encrypted_request, expires_at, state FROM requests WHERE request_id = ?1",
            params![request_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?, row.get::<_, String>(3)?)),
        ).optional()?.context("approval request not found")?;
        ensure!(
            stored.3 == "pending",
            "approval request is already terminal"
        );
        ensure!(
            constant_time_equal(stored.0.as_bytes(), request_digest.as_bytes()),
            "request digest mismatch"
        );
        ensure!(stored.2 > to_i64(now)?, "approval request is expired");
        let plaintext = decrypt(&self.state_key.0, stored.0.as_bytes(), &stored.1)?;
        let request: NormalizedRequest =
            serde_json::from_slice(&plaintext).context("stored approval request is invalid")?;
        let decision_id = random_id()?;
        let jti = random_id()?;
        let exp = now
            .saturating_add(self.assertion_ttl_seconds)
            .min(request.expires_at);
        ensure!(exp > now, "approval assertion has no valid lifetime");
        let claims = AssertionClaims {
            iss: &self.issuer,
            aud: audience,
            sub: &request.workload,
            request_id: &request.request_id,
            request_digest,
            decision_id: &decision_id,
            grant: "once",
            tenant: &request.tenant,
            persona: &request.persona,
            workspace: &request.workspace,
            lease: &request.lease,
            workload: &request.workload,
            operation: &request.operation,
            capability: &request.capability,
            service: &request.service,
            resource_digest: digest_jcs(&request.resource)?,
            action: &request.action,
            command_digest: digest_jcs(&request.command)?,
            policy_generation: request.policy_generation,
            max_manifest_ttl_seconds: request.requested_manifest_ttl_seconds,
            jti,
            iat: now,
            nbf: now,
            exp,
        };
        let assertion = self.sign_assertion(&claims)?;
        let changed = transaction.execute(
            "UPDATE requests SET state = 'allowed', terminal_at = ?1, decision_id = ?2, assertion_jti = ?3 WHERE request_id = ?4 AND state = 'pending'",
            params![to_i64(now)?, decision_id, claims.jti, request_id],
        )?;
        ensure!(changed == 1, "approval request lost terminal decision race");
        transaction.commit()?;
        Ok(SignedApproval {
            decision_id,
            assertion,
        })
    }

    /// Atomically deny one pending request without creating authorization state.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is absent, expired, terminal, or cannot
    /// be durably transitioned.
    pub fn deny(&self, request_id: &str, now: u64) -> Result<()> {
        validate_identifier("request ID", request_id)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("approval state lock poisoned"))?;
        let changed = connection.execute(
            "UPDATE requests SET state = 'denied', terminal_at = ?1, decision_id = ?2 WHERE request_id = ?3 AND state = 'pending' AND expires_at > ?1",
            params![to_i64(now)?, random_id()?, request_id],
        )?;
        ensure!(
            changed == 1,
            "approval request is absent, expired, or terminal"
        );
        Ok(())
    }

    /// Set the monotonic emergency-disable state transactionally.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero or stale generation or a storage failure.
    pub fn set_emergency_disable(&self, disabled: bool, generation: u64) -> Result<()> {
        ensure!(generation > 0, "invalid emergency generation");
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("approval state lock poisoned"))?;
        let changed = connection.execute(
            "UPDATE emergency SET disabled = ?1, generation = ?2 WHERE singleton = 1 AND generation < ?2",
            params![i64::from(disabled), to_i64(generation)?],
        )?;
        ensure!(changed == 1, "emergency generation is stale");
        Ok(())
    }

    fn sign_assertion<T: Serialize>(&self, claims: &T) -> Result<String> {
        let payload = serde_jcs::to_vec(claims)?;
        let encoded = URL_SAFE_NO_PAD.encode(&payload);
        let signature = self.signing_key.sign(encoded.as_bytes());
        Ok(format!(
            "{encoded}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }
}

fn open_database(path: &Path, owner_uid: u32) -> Result<Connection> {
    ensure_private_parent(path, owner_uid)?;
    let existed = path.exists();
    let connection = Connection::open(path).context("failed to open approval state")?;
    if !existed {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    validate_private_regular_file(path, owner_uid)?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    Ok(connection)
}

fn migrate(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "BEGIN IMMEDIATE;
         CREATE TABLE IF NOT EXISTS metadata (schema_version INTEGER NOT NULL);
         INSERT INTO metadata(schema_version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM metadata);
         CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS requests (
           request_id TEXT PRIMARY KEY,
           request_digest TEXT NOT NULL UNIQUE,
           issuer TEXT NOT NULL,
           tenant TEXT NOT NULL,
           encrypted_request BLOB NOT NULL,
           created_at INTEGER NOT NULL,
           expires_at INTEGER NOT NULL,
           state TEXT NOT NULL CHECK(state IN ('pending','allowed','denied','timed_out','cancelled')),
           terminal_at INTEGER,
           decision_id TEXT UNIQUE,
           assertion_jti TEXT UNIQUE
         );
         CREATE TABLE IF NOT EXISTS emergency (
           singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
           disabled INTEGER NOT NULL CHECK(disabled IN (0,1)),
           generation INTEGER NOT NULL
         );
         INSERT OR IGNORE INTO emergency(singleton, disabled, generation) VALUES(1, 1, 1);
         COMMIT;",
    )?;
    let version: i64 =
        connection.query_row("SELECT schema_version FROM metadata", [], |row| row.get(0))?;
    ensure!(
        version == SCHEMA_VERSION,
        "unsupported approval database schema"
    );
    Ok(())
}

fn bind_signing_key_id(connection: &Connection, key_id: &str) -> Result<()> {
    let existing: Option<String> = connection
        .query_row(
            "SELECT value FROM settings WHERE name = 'signing_key_id'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        ensure!(
            constant_time_equal(existing.as_bytes(), key_id.as_bytes()),
            "configured signing key ID does not match durable state"
        );
    } else {
        connection.execute(
            "INSERT INTO settings(name, value) VALUES('signing_key_id', ?1)",
            params![key_id],
        )?;
    }
    Ok(())
}

fn emergency_disabled(transaction: &rusqlite::Transaction<'_>) -> Result<bool> {
    let value: i64 = transaction.query_row(
        "SELECT disabled FROM emergency WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    Ok(value != 0)
}

fn encrypt(key: &[u8; KEY_BYTES], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).context("secure randomness unavailable")?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("request encryption failed"))?;
    let mut result = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt(key: &[u8; KEY_BYTES], aad: &[u8], encrypted: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        encrypted.len() > NONCE_BYTES,
        "stored encrypted request is invalid"
    );
    let (nonce, ciphertext) = encrypted.split_at(NONCE_BYTES);
    ChaCha20Poly1305::new(key.into())
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("stored approval request authentication failed"))
}

fn digest_jcs<T: Serialize>(value: &T) -> Result<String> {
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_jcs::to_vec(value)?)
    ))
}

fn random_id() -> Result<String> {
    let mut bytes = [0_u8; 24];
    getrandom::fill(&mut bytes).context("secure randomness unavailable")?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn read_protected_key(path: &Path, owner_uid: u32) -> Result<[u8; KEY_BYTES]> {
    validate_private_regular_file(path, owner_uid)?;
    let mut file = fs::File::open(path).context("failed to open protected key")?;
    let mut key = [0_u8; KEY_BYTES];
    file.read_exact(&mut key)
        .context("protected key must contain exactly 32 bytes")?;
    let mut extra = [0_u8; 1];
    ensure!(
        file.read(&mut extra)? == 0,
        "protected key must contain exactly 32 bytes"
    );
    Ok(key)
}

fn validate_private_regular_file(path: &Path, owner_uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("protected file is unavailable")?;
    ensure!(
        metadata.file_type().is_file(),
        "protected path must be a regular file"
    );
    ensure!(
        metadata.uid() == owner_uid,
        "protected file has the wrong owner"
    );
    ensure!(
        metadata.mode().trailing_zeros() >= 6,
        "protected file must not grant group or other access"
    );
    Ok(())
}

fn ensure_private_parent(path: &Path, owner_uid: u32) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    let metadata = fs::symlink_metadata(parent).context("state parent is unavailable")?;
    ensure!(metadata.is_dir(), "state parent must be a directory");
    ensure!(
        metadata.uid() == owner_uid,
        "state parent has the wrong owner"
    );
    ensure!(
        metadata.mode().trailing_zeros() >= 6,
        "state parent must not grant group or other access"
    );
    Ok(())
}

fn validate_identifier(name: &str, value: &str) -> Result<()> {
    ensure!((1..=128).contains(&value.len()), "invalid {name}");
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "invalid {name}"
    );
    Ok(())
}

fn validate_resource_identifier(name: &str, value: &str) -> Result<()> {
    ensure!(value.len() <= 100, "invalid {name}");
    validate_identifier(name, value)
}

fn validate_action(value: &str) -> Result<()> {
    ensure!(
        (1..=128).contains(&value.len()) && value.contains('.'),
        "invalid action"
    );
    ensure!(
        value.bytes().all(|byte| byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'_' | b'-')),
        "invalid action"
    );
    ensure!(
        value.as_bytes().first().is_some_and(u8::is_ascii_lowercase),
        "invalid action"
    );
    for segment in value.split('.') {
        ensure!(
            !segment.is_empty() && segment.as_bytes()[0].is_ascii_lowercase(),
            "invalid action"
        );
    }
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).context("timestamp exceeds storage range")
}

/// Create a protected binary key file without overwriting an existing key.
///
/// # Errors
///
/// Returns an error if the parent is not private, randomness is unavailable,
/// the path exists, or the durable write fails.
pub fn create_key(path: &Path, owner_uid: u32) -> Result<()> {
    ensure_private_parent(path, owner_uid)?;
    let mut key = [0_u8; KEY_BYTES];
    getrandom::fill(&mut key).context("secure randomness unavailable")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .context("failed to create protected key")?;
    file.write_all(&key)?;
    file.sync_all()?;
    key.zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture(now: u64) -> Result<(TempDir, ApprovalBroker, ApprovalEnvelope)> {
        let directory = TempDir::new()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let owner_uid = fs::metadata(directory.path())?.uid();
        let state_key = directory.path().join("state.key");
        let signing_key = directory.path().join("signing.key");
        create_key(&state_key, owner_uid)?;
        create_key(&signing_key, owner_uid)?;
        let request = NormalizedRequest {
            request_id: "request_123456789".into(),
            issuer: "issuer.example".into(),
            tenant: "tenant-1".into(),
            persona: "persona-1".into(),
            workspace: "workspace-1".into(),
            lease: "lease-1".into(),
            workload: "workload-1".into(),
            operation: "operation-123456".into(),
            capability: "github-api".into(),
            service: "github".into(),
            resource: Resource {
                kind: "github_repository".into(),
                owner: "example".into(),
                name: "repo".into(),
            },
            action: "github.issue.create".into(),
            command: Command {
                program: "gh".into(),
                arguments: vec!["issue".into(), "create".into()],
            },
            risk_tier: RiskTier::Medium,
            policy_generation: 7,
            requested_manifest_ttl_seconds: 60,
            created_at: now,
            expires_at: now + 120,
        };
        let envelope = ApprovalEnvelope {
            api_version: "charon.approval/v1".into(),
            request_digest: digest_jcs(&request)?,
            request,
        };
        let broker = ApprovalBroker::open(
            &BrokerConfig {
                database: directory.path().join("state.db"),
                state_key,
                signing_key,
                signing_key_id: "approval-key-1".into(),
                issuer: "approval.example".into(),
                assertion_ttl_seconds: 30,
                owner_uid,
            },
            now,
        )?;
        broker.set_emergency_disable(false, 2)?;
        Ok((directory, broker, envelope))
    }

    #[test]
    fn allow_once_is_atomic_and_replay_fails() -> Result<()> {
        let now = 1_800_000_000;
        let (_directory, broker, envelope) = fixture(now)?;
        broker.submit(&envelope, now)?;
        let signed = broker.allow_once(
            &envelope.request.request_id,
            &envelope.request_digest,
            "issuer.example",
            now + 1,
        )?;
        assert_eq!(signed.assertion.split('.').count(), 2);
        assert!(
            broker
                .allow_once(
                    &envelope.request.request_id,
                    &envelope.request_digest,
                    "issuer.example",
                    now + 2
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn restart_expires_pending_requests() -> Result<()> {
        let now = 1_800_000_000;
        let (directory, broker, envelope) = fixture(now)?;
        broker.submit(&envelope, now)?;
        drop(broker);
        let reopened = ApprovalBroker::open(
            &BrokerConfig {
                database: directory.path().join("state.db"),
                state_key: directory.path().join("state.key"),
                signing_key: directory.path().join("signing.key"),
                signing_key_id: "approval-key-1".into(),
                issuer: "approval.example".into(),
                assertion_ttl_seconds: 30,
                owner_uid: fs::metadata(directory.path())?.uid(),
            },
            now + 1,
        )?;
        assert!(
            reopened
                .allow_once(
                    &envelope.request.request_id,
                    &envelope.request_digest,
                    "issuer.example",
                    now + 1
                )
                .is_err()
        );
        Ok(())
    }
}
