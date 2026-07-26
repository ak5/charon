//! Secret-provider boundary and locked-by-default Vaultwarden implementation.

use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use tokio::{process::Command, time::timeout};
use zeroize::Zeroize;

use crate::config::{ProviderConfig, VaultwardenConfig};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

/// An opaque, policy-selected provider reference.
///
/// It is not secret material, but provider errors and audit events must not
/// disclose it because backend identifiers can reveal operational metadata.
pub struct SecretRef<'a>(&'a str);

impl<'a> SecretRef<'a> {
    /// Borrow an already validated reference from trusted Charon policy.
    #[must_use]
    pub const fn from_policy(value: &'a str) -> Self {
        Self(value)
    }

    /// Expose the reference to a provider adapter.
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

/// Resolves an opaque policy reference to secret material.
///
/// Implementations are in-process members of Charon's trusted computing base.
/// They must fail closed, return values only in secret-holding types, avoid
/// logging references or values, and perform no caller-selected routing.
#[async_trait]
pub trait SecretProvider: Send + Sync {
    /// Check provider readiness without resolving a credential.
    async fn health(&self) -> Result<()> {
        Ok(())
    }

    /// Resolve one secret. Implementations must never log the result.
    async fn resolve(&self, secret_ref: &SecretRef<'_>) -> Result<SecretString>;
}

/// Construct the configured, compile-time registered provider adapter.
///
/// # Errors
///
/// Returns an error when the selected adapter cannot validate its protected
/// runtime inputs. Charon does not load dynamic provider code.
pub fn build(config: &ProviderConfig) -> Result<Arc<dyn SecretProvider>> {
    match config {
        ProviderConfig::Environment => Ok(Arc::new(EnvironmentProvider)),
        ProviderConfig::Vaultwarden(provider) => {
            Ok(Arc::new(VaultwardenProvider::new(provider.clone())?))
        }
    }
}

/// Prototype provider that reads secrets from Charon's own process environment.
///
/// This proves that the workload can remain secretless. It is not the final
/// storage design; the self-hosted milestone replaces it with Vaultwarden.
#[derive(Debug, Default)]
pub struct EnvironmentProvider;

#[async_trait]
impl SecretProvider for EnvironmentProvider {
    async fn resolve(&self, secret_ref: &SecretRef<'_>) -> Result<SecretString> {
        std::env::var(secret_ref.as_str())
            .map(SecretString::from)
            .map_err(|_| anyhow::anyhow!("environment provider value is unavailable"))
    }
}

struct CachedSecret {
    value: SecretString,
    expires_at: Instant,
}

/// Resolves exact item UUIDs through a short-lived, non-interactive `bw` CLI.
///
/// The encrypted CLI vault may persist on the Charon host. The unlock session
/// is read from a protected file for each cache miss and exists only in Charon
/// and its short-lived child process, never in a developer workload.
pub struct VaultwardenProvider {
    config: VaultwardenConfig,
    items: HashMap<String, String>,
    cache: Mutex<HashMap<String, CachedSecret>>,
}

impl VaultwardenProvider {
    /// Construct a provider from already validated configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the CLI is not an executable file or an item mapping
    /// is ambiguous.
    pub fn new(config: VaultwardenConfig) -> Result<Self> {
        ensure_executable(&config.cli_path)?;
        ensure_private_directory(&config.appdata_dir)?;
        if config.session_file.try_exists().unwrap_or(false) {
            ensure_private_file(&config.session_file, "Vaultwarden session")?;
        }
        let mut items = HashMap::new();
        for mapping in &config.items {
            if items
                .insert(mapping.secret_ref.clone(), mapping.item_id.clone())
                .is_some()
            {
                bail!("Vaultwarden item mapping is ambiguous");
            }
        }
        Ok(Self {
            config,
            items,
            cache: Mutex::new(HashMap::new()),
        })
    }

    fn cached(&self, secret_ref: &str) -> Result<Option<SecretString>> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| anyhow::anyhow!("Vaultwarden cache is unavailable"))?;
        cache.retain(|_, entry| entry.expires_at > Instant::now());
        Ok(cache.get(secret_ref).map(|entry| entry.value.clone()))
    }

    fn session(&self) -> Result<SecretString> {
        ensure_private_file(&self.config.session_file, "Vaultwarden session")
            .map_err(|_| anyhow::anyhow!("Vaultwarden provider is locked"))?;
        let session = std::fs::read_to_string(&self.config.session_file)
            .map_err(|_| anyhow::anyhow!("Vaultwarden provider is locked"))?;
        if session.is_empty() || session.chars().any(char::is_whitespace) {
            bail!("Vaultwarden provider is locked");
        }
        Ok(SecretString::from(session))
    }

    async fn command(&self, session: &SecretString, args: &[&str]) -> Result<std::process::Output> {
        let mut command = Command::new(&self.config.cli_path);
        command
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("BW_SESSION", session.expose_secret())
            .env("BITWARDENCLI_APPDATA_DIR", &self.config.appdata_dir)
            .kill_on_drop(true);
        timeout(COMMAND_TIMEOUT, command.output())
            .await
            .map_err(|_| anyhow::anyhow!("Vaultwarden provider is unavailable"))?
            .map_err(|_| anyhow::anyhow!("Vaultwarden provider is unavailable"))
    }

    async fn ensure_unlocked(&self, session: &SecretString) -> Result<()> {
        let mut output = self.command(session, &["status"]).await?;
        if !output.status.success() {
            output.stdout.zeroize();
            output.stderr.zeroize();
            bail!("Vaultwarden provider is unavailable");
        }
        let status: VaultStatus = match serde_json::from_slice(&output.stdout) {
            Ok(status) => status,
            Err(error) => {
                tracing::warn!(
                    outcome = "vaultwarden_status_invalid",
                    command_success = output.status.success(),
                    stdout_bytes = output.stdout.len(),
                    stderr_bytes = output.stderr.len(),
                    json_error_line = error.line(),
                    json_error_column = error.column(),
                    "Vaultwarden CLI returned an invalid status shape"
                );
                output.stdout.zeroize();
                output.stderr.zeroize();
                bail!("Vaultwarden provider returned an invalid status");
            }
        };
        output.stdout.zeroize();
        output.stderr.zeroize();
        if status.status != "unlocked" {
            bail!("Vaultwarden provider is locked");
        }
        Ok(())
    }

    async fn refresh(&self, session: &SecretString) -> Result<()> {
        let mut output = self.command(session, &["sync"]).await?;
        let success = output.status.success();
        output.stdout.zeroize();
        output.stderr.zeroize();
        if !success {
            bail!("Vaultwarden provider is unavailable");
        }
        Ok(())
    }

    async fn item_password(&self, session: &SecretString, item_id: &str) -> Result<SecretString> {
        let mut output = self.command(session, &["get", "password", item_id]).await?;
        output.stderr.zeroize();
        if !output.status.success() {
            output.stdout.zeroize();
            bail!("Vaultwarden item is unavailable");
        }
        let mut value = match String::from_utf8(std::mem::take(&mut output.stdout)) {
            Ok(value) => value,
            Err(error) => {
                let mut bytes = error.into_bytes();
                bytes.zeroize();
                bail!("Vaultwarden item is invalid");
            }
        };
        while value.ends_with(['\n', '\r']) {
            value.pop();
        }
        if value.is_empty() {
            value.zeroize();
            bail!("Vaultwarden item is unavailable");
        }
        Ok(SecretString::from(value))
    }
}

#[cfg(unix)]
pub(crate) fn ensure_private_file(path: &Path, description: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata =
        std::fs::symlink_metadata(path).with_context(|| format!("{description} is unavailable"))?;
    if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
        bail!("{description} must be a private regular file");
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn ensure_private_file(path: &Path, description: &str) -> Result<()> {
    if !path.is_file() {
        bail!("{description} must be a private regular file");
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = std::fs::symlink_metadata(path)
        .context("Vaultwarden encrypted vault state is unavailable")?;
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        bail!("Vaultwarden encrypted vault state must be a private directory");
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_directory(path: &Path) -> Result<()> {
    if !path.is_dir() {
        bail!("Vaultwarden encrypted vault state must be a private directory");
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = std::fs::symlink_metadata(path).context("Vaultwarden CLI is unavailable")?;
    let mode = metadata.permissions().mode();
    if !metadata.file_type().is_file() || mode & 0o100 == 0 || mode & 0o022 != 0 {
        bail!("Vaultwarden CLI must be a non-writable executable file");
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_executable(path: &Path) -> Result<()> {
    if !path.is_file() {
        bail!("Vaultwarden CLI must be an executable file");
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct VaultStatus {
    status: String,
}

#[async_trait]
impl SecretProvider for VaultwardenProvider {
    async fn health(&self) -> Result<()> {
        let session = self.session()?;
        self.ensure_unlocked(&session).await
    }

    async fn resolve(&self, secret_ref: &SecretRef<'_>) -> Result<SecretString> {
        let secret_ref = secret_ref.as_str();
        let item_id = self
            .items
            .get(secret_ref)
            .context("credential reference is not mapped")?;
        if let Some(value) = self.cached(secret_ref)? {
            return Ok(value);
        }
        let session = self.session()?;
        self.ensure_unlocked(&session).await?;
        self.refresh(&session).await?;
        let value = self.item_password(&session, item_id).await?;
        self.cache
            .lock()
            .map_err(|_| anyhow::anyhow!("Vaultwarden cache is unavailable"))?
            .insert(
                secret_ref.to_owned(),
                CachedSecret {
                    value: value.clone(),
                    expires_at: Instant::now() + Duration::from_secs(self.config.cache_ttl_seconds),
                },
            );
        Ok(value)
    }
}
