//! Disposable Vaultwarden-CLI compatibility fixture tests.

#![cfg(unix)]

use std::{os::unix::fs::PermissionsExt as _, path::Path, time::Duration};

use anyhow::Result;
use charon::{
    config::{VaultItemMapping, VaultwardenConfig},
    provider::{ProviderError, SecretProvider, SecretRef, VaultwardenProvider},
};
use secrecy::ExposeSecret as _;
use tempfile::TempDir;

const ITEM_ID: &str = "00000000-0000-4000-8000-000000000001";

fn write(path: &Path, value: &str) -> Result<()> {
    std::fs::write(path, value)?;
    Ok(())
}

fn fixture() -> Result<(TempDir, VaultwardenConfig)> {
    let directory = tempfile::tempdir()?;
    let cli = directory.path().join("bw");
    std::fs::copy("tests/fixtures/fake-bw.sh", &cli)?;
    let mut permissions = std::fs::metadata(&cli)?.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&cli, permissions)?;
    write(
        &directory.path().join("expected-session"),
        "fixture-session\n",
    )?;
    write(&directory.path().join("session"), "fixture-session")?;
    write(&directory.path().join("secret"), "first-secret\n")?;
    std::fs::create_dir(directory.path().join("appdata"))?;
    for path in [
        directory.path().join("session"),
        directory.path().join("appdata"),
    ] {
        let mut permissions = std::fs::metadata(&path)?.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions)?;
    }
    let config = VaultwardenConfig {
        cli_path: cli,
        appdata_dir: directory.path().join("appdata"),
        session_file: directory.path().join("session"),
        cache_ttl_seconds: 1,
        items: vec![VaultItemMapping {
            secret_ref: "github/developer".into(),
            persona: "developer".into(),
            item_id: ITEM_ID.into(),
        }],
    };
    Ok((directory, config))
}

#[tokio::test]
async fn cache_is_bounded_and_restart_observes_rotation() -> Result<()> {
    let (fixture, config) = fixture()?;
    let provider = VaultwardenProvider::new(config.clone())?;
    let reference = SecretRef::from_policy("github/developer");
    let first = provider.resolve(&reference).await?;
    assert_eq!(first.expose_secret(), "first-secret");
    assert!(!fixture.path().join("inherited-environment").exists());

    write(&fixture.path().join("secret"), "rotated-secret\n")?;
    let cached = provider.resolve(&reference).await?;
    assert_eq!(cached.expose_secret(), "first-secret");

    let restarted = VaultwardenProvider::new(config)?;
    let after_restart = restarted.resolve(&reference).await?;
    assert_eq!(after_restart.expose_secret(), "rotated-secret");

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let after_expiry = provider.resolve(&reference).await?;
    assert_eq!(after_expiry.expose_secret(), "rotated-secret");
    Ok(())
}

#[tokio::test]
async fn satisfies_the_secret_provider_contract() -> Result<()> {
    let (_fixture, config) = fixture()?;
    let provider = VaultwardenProvider::new(config)?;

    provider.health().await?;
    let value = provider
        .resolve(&SecretRef::from_policy("github/developer"))
        .await?;
    assert_eq!(value.expose_secret(), "first-secret");

    let Err(error) = provider
        .resolve(&SecretRef::from_policy(
            "policy/reference-that-is-not-mapped",
        ))
        .await
    else {
        panic!("an unmapped trusted-policy reference must fail closed");
    };
    assert_eq!(error, ProviderError::ReferenceNotMapped);
    assert!(!error.to_string().contains("policy"));
    assert!(!error.to_string().contains("github"));
    Ok(())
}

#[test]
fn rejects_over_permissive_session_and_vault_state() -> Result<()> {
    let (_fixture, config) = fixture()?;
    let mut permissions = std::fs::metadata(&config.session_file)?.permissions();
    permissions.set_mode(0o644);
    std::fs::set_permissions(&config.session_file, permissions)?;
    assert!(VaultwardenProvider::new(config.clone()).is_err());

    let mut permissions = std::fs::metadata(&config.session_file)?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(&config.session_file, permissions)?;
    let mut permissions = std::fs::metadata(&config.appdata_dir)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&config.appdata_dir, permissions)?;
    assert!(VaultwardenProvider::new(config).is_err());
    Ok(())
}

#[tokio::test]
async fn lock_outage_and_deleted_item_fail_without_leaking_values() -> Result<()> {
    let (fixture, config) = fixture()?;
    write(&fixture.path().join("outage"), "")?;
    assert!(
        VaultwardenProvider::new(config.clone())?
            .health()
            .await
            .is_err()
    );
    let Err(error) = VaultwardenProvider::new(config.clone())?
        .resolve(&SecretRef::from_policy("github/developer"))
        .await
    else {
        panic!("fixture outage must fail");
    };
    assert_eq!(error, ProviderError::Unavailable);
    assert!(!error.to_string().contains("first-secret"));

    std::fs::remove_file(fixture.path().join("outage"))?;
    write(&fixture.path().join("deleted"), "")?;
    let Err(error) = VaultwardenProvider::new(config.clone())?
        .resolve(&SecretRef::from_policy("github/developer"))
        .await
    else {
        panic!("deleted fixture item must fail");
    };
    assert_eq!(error, ProviderError::SecretUnavailable);

    std::fs::remove_file(fixture.path().join("deleted"))?;
    std::fs::remove_file(fixture.path().join("session"))?;
    let health_provider = VaultwardenProvider::new(config.clone())?;
    let Err(error) = health_provider.health().await else {
        panic!("missing session must fail readiness");
    };
    assert_eq!(error, ProviderError::Locked);
    let Err(error) = VaultwardenProvider::new(config)?
        .resolve(&SecretRef::from_policy("github/developer"))
        .await
    else {
        panic!("missing session must stay locked");
    };
    assert_eq!(error, ProviderError::Locked);
    Ok(())
}
