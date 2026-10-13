//! Synthetic KDBX fixtures shared by transport tests; never real credentials.
#![allow(dead_code)]
use anyhow::Result;
use keepass::{
    Database, DatabaseKey,
    db::{EntryId, fields},
};
use secrecy::SecretString;
use std::{
    collections::HashMap,
    fs::{File, Permissions},
    os::unix::fs::PermissionsExt as _,
};

use charon::{
    config::{KeePassConfig, KeePassItemMapping},
    keepass::KeePassStore,
};

pub const REFERENCES: &[&str] = &[
    "CHARON_GITHUB_TOKEN",
    "CHARON_SYNTHETIC_TEST",
    "CHARON_TEST",
    "CHARON_ALLOWED_TOKEN",
    "CHARON_MOCK_TOKEN",
    "CHARON_REDIRECT_TOKEN",
    "CHARON_STREAM_TOKEN",
    "CHARON_TOKEN",
    "fixture/whoami",
    "CHARON_FIXTURE_ALICE",
    "CHARON_FIXTURE_BOB",
];
pub fn config(persona: &str) -> KeePassConfig {
    KeePassConfig {
        database: "/synthetic/test.kdbx".into(),
        key_file: None,
        telegram_bot_token_entry_id: None,
        items: REFERENCES
            .iter()
            .enumerate()
            .map(|(i, r)| KeePassItemMapping {
                secret_ref: (*r).into(),
                persona: persona.into(),
                entry_id: uuid::Uuid::from_u128(i as u128 + 1).to_string(),
            })
            .collect(),
    }
}
pub fn store(mut values: HashMap<String, String>) -> Result<KeePassStore> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("synthetic.kdbx");
    let mut config = config("developer");
    config.database.clone_from(&path);
    config.items.retain(|i| values.contains_key(&i.secret_ref));
    let mut db = Database::new();
    for mapping in &config.items {
        let mut root = db.root_mut();
        let mut entry = root.add_entry_with_id(EntryId::from_uuid(uuid::Uuid::parse_str(
            &mapping.entry_id,
        )?))?;
        entry.set_protected(
            fields::PASSWORD,
            values
                .remove(&mapping.secret_ref)
                .ok_or_else(|| anyhow::anyhow!("missing synthetic value"))?,
        );
    }
    db.save(
        &mut File::create(&path)?,
        DatabaseKey::new().with_password("synthetic-unlock-only"),
    )?;
    std::fs::set_permissions(&path, Permissions::from_mode(0o600))?;
    let store = KeePassStore::new(config)?;
    store.unlock(SecretString::from("synthetic-unlock-only"))?;
    Ok(store)
}
