//! Disposable two-persona realm isolation fixture.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use async_trait::async_trait;
use axum::{Router, http::HeaderMap, routing::any};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use charon::{
    config::{
        CapabilityPolicy, Config, IdentityConfig, ProviderConfig, RealmConfig, ServicePolicy,
    },
    identity::WorkloadClaims,
    provider::{ProviderError, ProviderResult, SecretProvider, SecretRef},
    proxy::{AppState, app},
};
use ed25519_dalek::{Signer as _, SigningKey};
use secrecy::SecretString;
use serde_json::Value;
use tokio::net::TcpListener;

struct DisposableProvider {
    value: SecretString,
    unavailable: AtomicBool,
}

impl DisposableProvider {
    fn new(value: &str) -> Self {
        Self {
            value: SecretString::from(value),
            unavailable: AtomicBool::new(false),
        }
    }

    fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, Ordering::SeqCst);
    }
}

#[async_trait]
impl SecretProvider for DisposableProvider {
    async fn health(&self) -> ProviderResult<()> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(ProviderError::Unavailable);
        }
        Ok(())
    }

    async fn resolve(&self, _secret_ref: &SecretRef<'_>) -> ProviderResult<SecretString> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(ProviderError::Unavailable);
        }
        Ok(self.value.clone())
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[31_u8; 32])
}

#[derive(Clone, Copy)]
struct Grant<'a> {
    tenant: &'a str,
    persona: &'a str,
    workspace: &'a str,
    lease: &'a str,
    nonce: &'a str,
    issued_at: u64,
    expires_at: u64,
}

fn token(grant: Grant<'_>) -> Result<String> {
    let claims = WorkloadClaims {
        iss: "fixture-control-plane".into(),
        aud: "charon-fixture".into(),
        sub: format!("workload-{}", grant.workspace),
        tenant: grant.tenant.into(),
        persona: grant.persona.into(),
        workspace: grant.workspace.into(),
        lease: grant.lease.into(),
        operation: format!("operation-{}", grant.nonce),
        capability: "fixture-whoami".into(),
        jti: grant.nonce.into(),
        iat: grant.issued_at,
        nbf: grant.issued_at,
        exp: grant.expires_at,
    };
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let signature = signing_key().sign(encoded.as_bytes());
    Ok(format!(
        "{encoded}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn realm_config(address: std::net::SocketAddr, realm: &str, tenant: &str, persona: &str) -> Config {
    Config {
        realm: RealmConfig {
            id: realm.into(),
            tenant: tenant.into(),
            persona: persona.into(),
            generation: 1,
        },
        listen: address,
        upstream_proxy: None,
        provider: ProviderConfig::Environment,
        tls: None,
        identity: IdentityConfig {
            issuer: "fixture-control-plane".into(),
            audience: "charon-fixture".into(),
            public_key: base64::engine::general_purpose::STANDARD
                .encode(signing_key().verifying_key().to_bytes()),
            max_ttl_seconds: 60,
            clock_skew_seconds: 0,
        },
        receipts: None,
        capabilities: vec![CapabilityPolicy {
            name: "fixture-whoami".into(),
            persona: persona.into(),
            service: "fixture".into(),
            methods: vec!["GET".into()],
            paths: vec!["/whoami".into()],
        }],
        services: vec![ServicePolicy {
            name: "fixture".into(),
            hosts: vec!["127.0.0.1".into()],
            hydration: charon::config::HydrationPolicy {
                sink: charon::broker::HydrationSink::Authorization,
                value_template: "Bearer {secret}".into(),
            },
            secret_ref: format!("CHARON_FIXTURE_{}", persona.to_ascii_uppercase()),
            response: charon::config::ResponsePolicy::text_stream(16 * 1024 * 1024, 30, 10, 4096),
            transparent_listen: None,
        }],
    }
}

async fn spawn_realm(
    realm: &str,
    tenant: &str,
    persona: &str,
    provider: Arc<DisposableProvider>,
) -> Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let config = realm_config(address, realm, tenant, persona);
    let state = Arc::new(AppState::new(config, provider)?);
    tokio::spawn(async move { axum::serve(listener, app(state)).await });
    Ok(address)
}

async fn use_realm(
    proxy_address: std::net::SocketAddr,
    upstream_address: std::net::SocketAddr,
    manifest: &str,
) -> Result<reqwest::Response> {
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_address}"))?)
        .build()?;
    client
        .get(format!("http://{upstream_address}/whoami"))
        .header("proxy-authorization", format!("Charon {manifest}"))
        .header("authorization", "Bearer {{charon.fixture-whoami}}")
        .send()
        .await
        .map_err(Into::into)
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn two_persona_realms_fail_closed_and_fail_independently() -> Result<()> {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_address = upstream_listener.local_addr()?;
    let upstream = Router::new().fallback(any(|headers: HeaderMap| async move {
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("missing")
            .to_owned()
    }));
    tokio::spawn(async move { axum::serve(upstream_listener, upstream).await });

    let alice_provider = Arc::new(DisposableProvider::new("alice-fixture-value"));
    let bob_provider = Arc::new(DisposableProvider::new("bob-fixture-value"));
    let alice = spawn_realm(
        "realm-alice",
        "tenant-fixture",
        "alice",
        Arc::clone(&alice_provider),
    )
    .await?;
    let bob = spawn_realm(
        "realm-bob",
        "tenant-fixture",
        "bob",
        Arc::clone(&bob_provider),
    )
    .await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    for (workspace, nonce) in [
        ("alice-workspace-one", "alice-workspace-one-nonce"),
        ("alice-workspace-two", "alice-workspace-two-nonce"),
    ] {
        let manifest = token(Grant {
            tenant: "tenant-fixture",
            persona: "alice",
            workspace,
            lease: "alice-active-lease",
            nonce,
            issued_at: now,
            expires_at: now + 30,
        })?;
        let response = use_realm(alice, upstream_address, &manifest).await?;
        assert!(response.status().is_success());
        assert_eq!(response.text().await?, "Bearer [REDACTED]");
    }

    let cross_persona = token(Grant {
        tenant: "tenant-fixture",
        persona: "alice",
        workspace: "alice-workspace-three",
        lease: "alice-active-lease",
        nonce: "alice-wrong-endpoint-nonce",
        issued_at: now,
        expires_at: now + 30,
    })?;
    assert!(
        !use_realm(bob, upstream_address, &cross_persona)
            .await?
            .status()
            .is_success()
    );

    let replay = token(Grant {
        tenant: "tenant-fixture",
        persona: "bob",
        workspace: "bob-workspace",
        lease: "bob-active-lease",
        nonce: "bob-replay-manifest-nonce",
        issued_at: now,
        expires_at: now + 30,
    })?;
    assert!(
        use_realm(bob, upstream_address, &replay)
            .await?
            .status()
            .is_success()
    );
    assert!(
        !use_realm(bob, upstream_address, &replay)
            .await?
            .status()
            .is_success()
    );

    let expired = token(Grant {
        tenant: "tenant-fixture",
        persona: "bob",
        workspace: "bob-workspace",
        lease: "bob-active-lease",
        nonce: "bob-expired-manifest-nonce",
        issued_at: now - 30,
        expires_at: now - 1,
    })?;
    assert!(
        !use_realm(bob, upstream_address, &expired)
            .await?
            .status()
            .is_success()
    );

    alice_provider.set_unavailable(true);
    assert_eq!(
        reqwest::get(format!("http://{alice}/readyz"))
            .await?
            .status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    let alice_failed = token(Grant {
        tenant: "tenant-fixture",
        persona: "alice",
        workspace: "alice-workspace-one",
        lease: "alice-active-lease",
        nonce: "alice-provider-failure-nonce",
        issued_at: now,
        expires_at: now + 30,
    })?;
    assert!(
        !use_realm(alice, upstream_address, &alice_failed)
            .await?
            .status()
            .is_success()
    );

    let bob_independent = token(Grant {
        tenant: "tenant-fixture",
        persona: "bob",
        workspace: "bob-workspace",
        lease: "bob-active-lease",
        nonce: "bob-independent-realm-nonce",
        issued_at: now,
        expires_at: now + 30,
    })?;
    let response = use_realm(bob, upstream_address, &bob_independent).await?;
    assert!(response.status().is_success());
    assert_eq!(response.text().await?, "Bearer [REDACTED]");

    let readiness_bytes = reqwest::get(format!("http://{bob}/readyz"))
        .await?
        .bytes()
        .await?;
    let readiness: Value = serde_json::from_slice(&readiness_bytes)?;
    assert_eq!(readiness["status"], "ready");
    assert_eq!(readiness["realm"], "realm-bob");
    assert_eq!(readiness["tenant"], "tenant-fixture");
    assert_eq!(readiness["persona"], "bob");
    assert_eq!(readiness["generation"], 1);

    Ok(())
}
