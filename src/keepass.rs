//! Concrete, locked-on-boot, read-only `KeePass` credential store.

use crate::config::KeePassConfig;
use anyhow::{Context, Result, bail};
use keepass::{
    Database, DatabaseKey,
    db::{EntryId, fields},
};
use secrecy::{ExposeSecret as _, SecretString};
use std::{
    collections::HashMap,
    io::{Cursor, Read as _},
    path::Path,
    sync::{
        Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
};
use zeroize::Zeroizing;

/// Data-free failures that cannot disclose database content or entry identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreError {
    /// No decrypted credentials are held in this process.
    Locked,
    /// A private input or the store state is unavailable.
    Unavailable,
    /// The policy reference is not mapped.
    ReferenceNotMapped,
    /// A mapped password is absent, unprotected, empty, or oversized.
    SecretUnavailable,
    /// The password/key cannot open the database, or its format is invalid.
    UnlockFailed,
}
impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Locked => "KeePass store is locked",
            Self::Unavailable => "KeePass store is unavailable",
            Self::ReferenceNotMapped => "secret reference is not mapped",
            Self::SecretUnavailable => "mapped password is unavailable",
            Self::UnlockFailed => "KeePass unlock failed",
        })
    }
}
impl std::error::Error for StoreError {}
/// Result with a closed, non-disclosing error shape.
pub type StoreResult<T> = std::result::Result<T, StoreError>;

/// A reference selected by validated local policy, never by a workload.
pub struct SecretRef<'a>(&'a str);
impl<'a> SecretRef<'a> {
    /// Borrow a policy reference.
    #[must_use]
    pub const fn from_policy(value: &'a str) -> Self {
        Self(value)
    }
}

/// One realm's concrete `KeePass` store. No decrypted database or password is persisted.
pub struct KeePassStore {
    config: KeePassConfig,
    values: Mutex<Option<Snapshot>>,
    changes: tokio::sync::watch::Sender<u64>,
    generation: AtomicU64,
    lookups: AtomicUsize,
    unlock_gate: Mutex<()>,
}
struct Snapshot {
    values: HashMap<String, SecretString>,
    telegram: Option<SecretString>,
}
impl KeePassStore {
    /// Construct a locked store. Database presence is checked on unlock, not startup.
    ///
    /// # Errors
    /// Rejects ambiguous or invalid configuration.
    pub fn new(config: KeePassConfig) -> Result<Self> {
        let persona = config.items.first().map_or("", |i| i.persona.as_str());
        config.validate(persona)?;
        Ok(Self {
            config,
            values: Mutex::new(None),
            changes: tokio::sync::watch::channel(0).0,
            generation: AtomicU64::new(0),
            lookups: AtomicUsize::new(0),
            unlock_gate: Mutex::new(()),
        })
    }
    /// Decrypt on a blocking thread, retain only mapped Password fields, and discard the key.
    /// Call this only from the authenticated admin boundary.
    ///
    /// # Errors
    /// Fails closed for invalid keys, inputs, or mapped passwords. A concurrent lock cancels it.
    pub fn unlock(&self, password: SecretString) -> StoreResult<()> {
        let _gate = self
            .unlock_gate
            .try_lock()
            .map_err(|_| StoreError::Unavailable)?;
        let generation = self.generation.load(Ordering::SeqCst);
        if password.expose_secret().is_empty() || password.expose_secret().len() > 4096 {
            return Err(StoreError::UnlockFailed);
        }
        let bytes = private_bytes(&self.config.database, 64 * 1024 * 1024)?;
        // Restrict to KDBX; legacy KDB and unencrypted XML are not credential sources.
        if bytes.get(..8) != Some(&[0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5]) {
            return Err(StoreError::UnlockFailed);
        }
        let mut key = DatabaseKey::new().with_password(password.expose_secret());
        drop(password);
        if let Some(path) = &self.config.key_file {
            let key_bytes = private_bytes(path, 1024 * 1024)?;
            key = key
                .with_keyfile(&mut Cursor::new(key_bytes.as_slice()))
                .map_err(|_| StoreError::UnlockFailed)?;
        }
        let database = Database::open(&mut Cursor::new(bytes.as_slice()), key)
            .map_err(|_| StoreError::UnlockFailed)?;
        let mut values = HashMap::new();
        for mapping in &self.config.items {
            let id = uuid::Uuid::parse_str(&mapping.entry_id)
                .map_err(|_| StoreError::ReferenceNotMapped)?;
            let entry = database
                .entry(EntryId::from_uuid(id))
                .ok_or(StoreError::SecretUnavailable)?;
            let value = entry
                .fields
                .get(fields::PASSWORD)
                .ok_or(StoreError::SecretUnavailable)?;
            // Protected fields use zeroizing secret-holding memory in the parser as well.
            if !value.is_protected() || value.get().is_empty() || value.get().len() > 16384 {
                return Err(StoreError::SecretUnavailable);
            }
            values.insert(
                mapping.secret_ref.clone(),
                SecretString::from(value.get().clone()),
            );
        }
        let telegram = self
            .config
            .telegram_bot_token_entry_id
            .as_ref()
            .map(|id| {
                let id = uuid::Uuid::parse_str(id).map_err(|_| StoreError::SecretUnavailable)?;
                let entry = database
                    .entry(EntryId::from_uuid(id))
                    .ok_or(StoreError::SecretUnavailable)?;
                let value = entry
                    .fields
                    .get(fields::PASSWORD)
                    .ok_or(StoreError::SecretUnavailable)?;
                if !value.is_protected() || !crate::telegram::valid_token(value.get()) {
                    return Err(StoreError::SecretUnavailable);
                }
                Ok(SecretString::from(value.get().clone()))
            })
            .transpose()?;
        drop(database);
        let mut current = self.values.lock().map_err(|_| StoreError::Unavailable)?;
        if generation != self.generation.load(Ordering::SeqCst) {
            return Err(StoreError::Locked);
        }
        *current = Some(Snapshot { values, telegram });
        self.changes
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        Ok(())
    }
    /// Drop retained credentials and prevent an in-flight unlock from committing.
    ///
    /// # Errors
    /// Reports unavailable state without disclosing values.
    pub fn lock(&self) -> StoreResult<()> {
        let mut values = self.values.lock().map_err(|_| StoreError::Unavailable)?;
        self.generation.fetch_add(1, Ordering::SeqCst);
        *values = None;
        self.changes
            .send_modify(|epoch| *epoch = epoch.wrapping_add(1));
        Ok(())
    }
    /// Check unlocked state without accessing any entry.
    ///
    /// # Errors
    /// Reports locked or unavailable state.
    pub fn health(&self) -> StoreResult<()> {
        if self
            .values
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .is_some()
        {
            Ok(())
        } else {
            Err(StoreError::Locked)
        }
    }
    /// Resolve only a mapped reference from the unlocked in-memory snapshot.
    ///
    /// # Errors
    /// Denies locked or unmapped access.
    pub fn resolve(&self, reference: &SecretRef<'_>) -> StoreResult<SecretString> {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        let state = self.values.lock().map_err(|_| StoreError::Unavailable)?;
        state
            .as_ref()
            .ok_or(StoreError::Locked)?
            .values
            .get(reference.0)
            .cloned()
            .ok_or(StoreError::ReferenceNotMapped)
    }
    pub(crate) fn has_telegram_entry(&self) -> bool {
        self.config.telegram_bot_token_entry_id.is_some()
    }
    pub(crate) fn telegram_token(&self) -> StoreResult<SecretString> {
        let state = self.values.lock().map_err(|_| StoreError::Unavailable)?;
        state
            .as_ref()
            .ok_or(StoreError::Locked)?
            .telegram
            .clone()
            .ok_or(StoreError::SecretUnavailable)
    }
    pub(crate) fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
    /// Aggregate resolution attempts, containing no credential or reference data.
    #[must_use]
    pub fn lookup_count(&self) -> usize {
        self.lookups.load(Ordering::Relaxed)
    }
}

/// Read one bounded private regular file without accepting symlinks or an inode swap.
fn private_bytes(path: &Path, limit: u64) -> StoreResult<Zeroizing<Vec<u8>>> {
    ensure_private_file(path, "KeePass input").map_err(|_| StoreError::Unavailable)?;
    let before = std::fs::symlink_metadata(path).map_err(|_| StoreError::Unavailable)?;
    let file = std::fs::File::open(path).map_err(|_| StoreError::Unavailable)?;
    let after = file.metadata().map_err(|_| StoreError::Unavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.ino() != after.ino() || before.dev() != after.dev() {
            return Err(StoreError::Unavailable);
        }
    }
    if !after.is_file() || after.len() > limit {
        return Err(StoreError::Unavailable);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StoreError::Unavailable)?;
    if bytes.len() as u64 > limit {
        return Err(StoreError::Unavailable);
    }
    Ok(bytes)
}

pub(crate) fn ensure_private_file(path: &Path, description: &str) -> Result<()> {
    let metadata =
        std::fs::symlink_metadata(path).with_context(|| format!("{description} is unavailable"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("{description} must be private");
        }
    }
    if !metadata.file_type().is_file() {
        bail!("{description} must be a regular file");
    }
    Ok(())
}
