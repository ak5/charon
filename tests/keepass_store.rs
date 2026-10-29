//! Real encrypted synthetic KDBX coverage for the concrete store.
#![cfg(unix)]
mod common;
use anyhow::Result;
use charon::{
    config::KeePassConfig,
    keepass::{KeePassStore, SecretRef, StoreError},
};
use keepass::{
    Database, DatabaseKey,
    db::{EntryId, fields},
};
use secrecy::{ExposeSecret as _, SecretString};
use std::{
    collections::HashMap,
    fs::{File, Permissions},
    os::unix::fs::{PermissionsExt as _, symlink},
};

struct Fixture {
    directory: tempfile::TempDir,
    config: KeePassConfig,
}

#[test]
fn keepass_chacha_key_state_is_zeroized_on_drop() {
    fn requires_zeroize<T: zeroize::ZeroizeOnDrop>() {}
    requires_zeroize::<chacha20::ChaChaCore<chacha20::R20, chacha20::variants::Ietf>>();
}
impl Fixture {
    fn new(protected: bool, key_file: bool) -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let mut config = common::config("developer");
        config.items.truncate(1);
        config.database = directory.path().join("synthetic.kdbx");
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry_with_id(EntryId::from_uuid(uuid::Uuid::parse_str(
                &config.items[0].entry_id,
            )?))?;
            if protected {
                entry.set_protected(fields::PASSWORD, "synthetic-entry-value");
            } else {
                entry.set_unprotected(fields::PASSWORD, "synthetic-entry-value");
            }
        }
        let mut key = DatabaseKey::new().with_password("synthetic-master");
        if key_file {
            let path = directory.path().join("synthetic.key");
            std::fs::write(&path, b"synthetic-key-file-material-only")?;
            std::fs::set_permissions(&path, Permissions::from_mode(0o600))?;
            key = key.with_keyfile(&mut File::open(&path)?)?;
            config.key_file = Some(path);
        }
        db.save(&mut File::create(&config.database)?, key)?;
        std::fs::set_permissions(&config.database, Permissions::from_mode(0o600))?;
        Ok(Self { directory, config })
    }
}
#[test]
fn boot_locked_wrong_key_rejected_unlock_maps_only_and_lock_discards() -> Result<()> {
    let fixture = Fixture::new(true, false)?;
    let store = KeePassStore::new(fixture.config.clone())?;
    assert_eq!(store.health(), Err(StoreError::Locked));
    assert_eq!(
        store.unlock(SecretString::from("wrong-synthetic-master")),
        Err(StoreError::UnlockFailed)
    );
    assert_eq!(store.health(), Err(StoreError::Locked));
    store.unlock(SecretString::from("synthetic-master"))?;
    let value = store.resolve(&SecretRef::from_policy(common::REFERENCES[0]))?;
    assert_eq!(value.expose_secret(), "synthetic-entry-value");
    assert!(matches!(
        store.resolve(&SecretRef::from_policy("caller-selected")),
        Err(StoreError::ReferenceNotMapped)
    ));
    store.lock()?;
    assert!(matches!(
        store.resolve(&SecretRef::from_policy(common::REFERENCES[0])),
        Err(StoreError::Locked)
    ));
    assert_eq!(
        KeePassStore::new(fixture.config)?.health(),
        Err(StoreError::Locked)
    );
    Ok(())
}
#[test]
fn optional_key_file_is_required_and_database_remains_read_only() -> Result<()> {
    let fixture = Fixture::new(true, true)?;
    let before = std::fs::read(&fixture.config.database)?;
    let store = KeePassStore::new(fixture.config.clone())?;
    store.unlock(SecretString::from("synthetic-master"))?;
    assert_eq!(before, std::fs::read(&fixture.config.database)?);
    let mut no_key = fixture.config.clone();
    no_key.key_file = None;
    assert_eq!(
        KeePassStore::new(no_key)?.unlock(SecretString::from("synthetic-master")),
        Err(StoreError::UnlockFailed)
    );
    if let Some(path) = fixture.config.key_file {
        std::fs::write(path, b"different-synthetic-key")?;
    }
    assert_eq!(
        store.unlock(SecretString::from("synthetic-master")),
        Err(StoreError::UnlockFailed)
    );
    Ok(())
}
#[test]
fn unsafe_files_unprotected_or_missing_mappings_and_xml_fail_closed() -> Result<()> {
    let fixture = Fixture::new(false, false)?;
    assert_eq!(
        KeePassStore::new(fixture.config)?.unlock(SecretString::from("synthetic-master")),
        Err(StoreError::SecretUnavailable)
    );
    let fixture = Fixture::new(true, false)?;
    let mut missing = fixture.config.clone();
    missing.items[0].entry_id = uuid::Uuid::from_u128(999).to_string();
    assert_eq!(
        KeePassStore::new(missing)?.unlock(SecretString::from("synthetic-master")),
        Err(StoreError::SecretUnavailable)
    );
    std::fs::set_permissions(&fixture.config.database, Permissions::from_mode(0o644))?;
    assert_eq!(
        KeePassStore::new(fixture.config.clone())?.unlock(SecretString::from("synthetic-master")),
        Err(StoreError::Unavailable)
    );
    std::fs::set_permissions(&fixture.config.database, Permissions::from_mode(0o600))?;
    let path = fixture.directory.path().join("link.kdbx");
    symlink(&fixture.config.database, &path)?;
    let mut linked = fixture.config.clone();
    linked.database = path;
    assert_eq!(
        KeePassStore::new(linked)?.unlock(SecretString::from("synthetic-master")),
        Err(StoreError::Unavailable)
    );
    std::fs::write(&fixture.config.database, b"<KeePassFile/>")?;
    assert_eq!(
        KeePassStore::new(fixture.config)?.unlock(SecretString::from("synthetic-master")),
        Err(StoreError::UnlockFailed)
    );
    Ok(())
}
#[test]
fn transport_fixture_holds_only_a_decrypted_snapshot() -> Result<()> {
    let store = common::store(HashMap::from([(
        common::REFERENCES[0].into(),
        "synthetic".into(),
    )]))?;
    store.health()?;
    store.lock()?;
    assert!(
        store
            .unlock(SecretString::from("synthetic-unlock-only"))
            .is_err()
    );
    Ok(())
}

#[test]
fn telegram_entry_is_operator_only_and_required_protected_on_unlock() -> Result<()> {
    let fixture = Fixture::new(true, false)?;
    let mut config = fixture.config.clone();
    let id = config.items[0].entry_id.clone();
    config.telegram_bot_token_entry_id = Some(id.clone());
    assert!(
        KeePassStore::new(config.clone()).is_err(),
        "bot entry reachable by workload"
    );
    config.items.clear();
    let store = KeePassStore::new(config.clone())?;
    store.unlock(SecretString::from("synthetic-master"))?;
    assert!(matches!(
        store.resolve(&SecretRef::from_policy(&id)),
        Err(StoreError::ReferenceNotMapped)
    ));
    store.lock()?;
    config.telegram_bot_token_entry_id = Some(uuid::Uuid::from_u128(999).to_string());
    let missing = KeePassStore::new(config)?;
    assert_eq!(
        missing.unlock(SecretString::from("synthetic-master")),
        Err(StoreError::SecretUnavailable)
    );
    assert_eq!(missing.health(), Err(StoreError::Locked));
    let fixture = Fixture::new(true, false)?;
    let mut invalid = fixture.config.clone();
    invalid.telegram_bot_token_entry_id = Some(invalid.items[0].entry_id.clone());
    invalid.items.clear();
    let mut database = Database::open(
        &mut File::open(&invalid.database)?,
        DatabaseKey::new().with_password("synthetic-master"),
    )?;
    database
        .entry_mut(EntryId::from_uuid(uuid::Uuid::parse_str(
            invalid
                .telegram_bot_token_entry_id
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("missing bot ID"))?,
        )?))
        .ok_or_else(|| anyhow::anyhow!("missing bot entry"))?
        .set_protected(fields::PASSWORD, "invalid token / with spaces");
    database.save(
        &mut File::create(&invalid.database)?,
        DatabaseKey::new().with_password("synthetic-master"),
    )?;
    assert_eq!(
        KeePassStore::new(invalid)?.unlock(SecretString::from("synthetic-master")),
        Err(StoreError::SecretUnavailable)
    );
    let mut fixture = Fixture::new(false, false)?;
    fixture.config.telegram_bot_token_entry_id = Some(fixture.config.items[0].entry_id.clone());
    fixture.config.items.clear();
    assert_eq!(
        KeePassStore::new(fixture.config)?.unlock(SecretString::from("synthetic-master")),
        Err(StoreError::SecretUnavailable)
    );
    Ok(())
}
