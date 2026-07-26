//! CONNECT interception and hostname-confusion negative tests.

#![cfg(unix)]

use std::{
    collections::HashMap,
    os::unix::fs::PermissionsExt as _,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use charon::{
    config::{
        CapabilityPolicy, Config, IdentityConfig, ProviderConfig, RealmConfig, ServicePolicy,
        TlsConfig,
    },
    identity::WorkloadClaims,
    provider::{SecretProvider, SecretRef},
    proxy::{AppState, app},
};
use ed25519_dalek::{Signer as _, SigningKey};
use http::StatusCode;
use http_body_util::{BodyExt as _, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use secrecy::SecretString;
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsConnector, client::TlsStream};

#[derive(Debug)]
struct StaticProvider(HashMap<String, String>);

#[async_trait]
impl SecretProvider for StaticProvider {
    async fn resolve(&self, secret_ref: &SecretRef<'_>) -> Result<SecretString> {
        self.0
            .get(secret_ref.as_str())
            .cloned()
            .map(SecretString::from)
            .context("missing fixture secret")
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[21_u8; 32])
}

fn realm() -> RealmConfig {
    RealmConfig {
        id: "realm-developer".into(),
        tenant: "tenant-test".into(),
        persona: "developer".into(),
        generation: 1,
    }
}

fn token(nonce: &str) -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let claims = WorkloadClaims {
        iss: "connect-test".into(),
        aud: "charon-test".into(),
        sub: "test-workload".into(),
        tenant: "tenant-test".into(),
        persona: "developer".into(),
        workspace: "workspace-test".into(),
        lease: "lease-test".into(),
        operation: "operation-test".into(),
        capability: "allowed-user".into(),
        jti: nonce.into(),
        iat: now,
        nbf: now,
        exp: now + 30,
    };
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let signature = signing_key().sign(encoded.as_bytes());
    Ok(format!(
        "{encoded}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn ca_fixture() -> Result<(TempDir, TlsConfig, RootCertStore)> {
    let directory = tempfile::tempdir()?;
    let root_key = KeyPair::generate()?;
    let mut root_params = CertificateParams::new(Vec::<String>::new())?;
    root_params.distinguished_name = DistinguishedName::new();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "Charon Test Root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let root = CertifiedIssuer::self_signed(root_params, root_key)?;

    let intermediate_key = KeyPair::generate()?;
    let intermediate_key_pem = intermediate_key.serialize_pem();
    let mut intermediate_params = CertificateParams::new(Vec::<String>::new())?;
    intermediate_params.distinguished_name = DistinguishedName::new();
    intermediate_params
        .distinguished_name
        .push(DnType::CommonName, "Charon Test Intermediate");
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    intermediate_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let intermediate = CertifiedIssuer::signed_by(intermediate_params, intermediate_key, &root)?;
    let certificate_path = directory.path().join("ca.pem");
    let key_path = directory.path().join("ca-key.pem");
    std::fs::write(&certificate_path, intermediate.pem())?;
    std::fs::write(&key_path, intermediate_key_pem)?;
    let mut permissions = std::fs::metadata(&key_path)?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(&key_path, permissions)?;
    let mut roots = RootCertStore::empty();
    roots.add(root.der().clone())?;
    Ok((
        directory,
        TlsConfig {
            ca_certificate: certificate_path,
            ca_private_key: key_path,
        },
        roots,
    ))
}

fn ca_rotation_fixture() -> Result<(TempDir, [TlsConfig; 2], RootCertStore)> {
    let directory = tempfile::tempdir()?;
    let root_key = KeyPair::generate()?;
    let mut root_params = CertificateParams::new(Vec::<String>::new())?;
    root_params.distinguished_name = DistinguishedName::new();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "Charon Rotation Test Root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let root = CertifiedIssuer::self_signed(root_params, root_key)?;
    let mut configurations = Vec::new();
    for generation in ["old", "new"] {
        let key = KeyPair::generate()?;
        let key_pem = key.serialize_pem();
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(
            DnType::CommonName,
            format!("Charon Rotation {generation} Intermediate"),
        );
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let intermediate = CertifiedIssuer::signed_by(params, key, &root)?;
        let certificate_path = directory.path().join(format!("{generation}-ca.pem"));
        let key_path = directory.path().join(format!("{generation}-ca-key.pem"));
        std::fs::write(&certificate_path, intermediate.pem())?;
        std::fs::write(&key_path, key_pem)?;
        let mut permissions = std::fs::metadata(&key_path)?.permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&key_path, permissions)?;
        configurations.push(TlsConfig {
            ca_certificate: certificate_path,
            ca_private_key: key_path,
        });
    }
    let configurations: [TlsConfig; 2] = configurations
        .try_into()
        .map_err(|_| anyhow::anyhow!("rotation fixture must contain two intermediates"))?;
    let mut roots = RootCertStore::empty();
    roots.add(root.der().clone())?;
    Ok((directory, configurations, roots))
}

async fn proxy(tls: TlsConfig) -> Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let config = Config {
        realm: realm(),
        listen: address,
        upstream_proxy: None,
        provider: ProviderConfig::Environment,
        tls: Some(tls),
        identity: IdentityConfig {
            issuer: "connect-test".into(),
            audience: "charon-test".into(),
            public_key: base64::engine::general_purpose::STANDARD
                .encode(signing_key().verifying_key().to_bytes()),
            max_ttl_seconds: 60,
            clock_skew_seconds: 2,
        },
        capabilities: vec![CapabilityPolicy {
            name: "allowed-user".into(),
            persona: "developer".into(),
            service: "allowed".into(),
            methods: vec!["GET".into()],
            paths: vec!["/user".into()],
        }],
        services: vec![ServicePolicy {
            name: "allowed".into(),
            hosts: vec!["allowed.test".into()],
            header: "authorization".into(),
            placeholder: "Bearer charon-placeholder".into(),
            value_template: "Bearer {secret}".into(),
            secret_ref: "allowed-token".into(),
        }],
    };
    let provider = StaticProvider(HashMap::from([(
        "allowed-token".into(),
        "fixture-secret".into(),
    )]));
    let state = Arc::new(AppState::new(config, Arc::new(provider))?);
    tokio::spawn(async move { axum::serve(listener, app(state)).await });
    Ok(address)
}

async fn connect(
    proxy: std::net::SocketAddr,
    authority: &str,
    authorization: &str,
) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;
    stream
        .write_all(
            format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: {authorization}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") && response.len() < 4096 {
        let mut byte = [0_u8; 1];
        if stream.read(&mut byte).await? == 0 {
            break;
        }
        response.push(byte[0]);
    }
    if !response.starts_with(b"HTTP/1.1 200") {
        bail!("CONNECT failed: {}", String::from_utf8_lossy(&response));
    }
    Ok(stream)
}

async fn tls_connect(
    stream: TcpStream,
    roots: RootCertStore,
    server_name: &str,
) -> Result<TlsStream<TcpStream>> {
    tls_connect_with_alpn(stream, roots, server_name, Vec::new()).await
}

async fn tls_connect_with_alpn(
    stream: TcpStream,
    roots: RootCertStore,
    server_name: &str,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsStream<TcpStream>> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = alpn_protocols;
    let name = ServerName::try_from(server_name.to_owned())?;
    Ok(TlsConnector::from(Arc::new(config))
        .connect(name, stream)
        .await?)
}

#[tokio::test]
async fn negotiates_http2_and_reauthorizes_pseudo_authority() -> Result<()> {
    let (_fixture, tls_config, roots) = ca_fixture()?;
    let address = proxy(tls_config).await?;
    let stream = connect(
        address,
        "allowed.test:443",
        &format!("Charon {}", token("connect-http2-allowed-1")?),
    )
    .await?;
    let tls = tls_connect_with_alpn(stream, roots, "allowed.test", vec![b"h2".to_vec()]).await?;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls)).await?;
    tokio::spawn(connection);
    let response = sender
        .send_request(
            hyper::Request::builder()
                .uri("https://allowed.test/user")
                .body(Empty::<axum::body::Bytes>::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.into_body().collect().await?.to_bytes(),
        "credential placeholder is missing"
    );
    let response = sender
        .send_request(
            hyper::Request::builder()
                .uri("https://allowed.test/user")
                .body(Empty::<axum::body::Bytes>::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.into_body().collect().await?.to_bytes(),
        "one request is allowed per CONNECT"
    );

    let (_fixture, tls_config, roots) = ca_fixture()?;
    let address = proxy(tls_config).await?;
    let stream = connect(
        address,
        "allowed.test:443",
        &format!("Charon {}", token("connect-http2-confused-1")?),
    )
    .await?;
    let tls = tls_connect_with_alpn(stream, roots, "allowed.test", vec![b"h2".to_vec()]).await?;
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls)).await?;
    tokio::spawn(connection);
    let response = sender
        .send_request(
            hyper::Request::builder()
                .uri("https://denied.test/user")
                .body(Empty::<axum::body::Bytes>::new())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
    Ok(())
}

#[tokio::test]
async fn rejects_unlisted_connect_before_tls() -> Result<()> {
    let (_fixture, tls_config, _roots) = ca_fixture()?;
    let address = proxy(tls_config).await?;
    let mut stream = TcpStream::connect(address).await?;
    stream
        .write_all(b"CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test:443\r\n\r\n")
        .await?;
    let mut response = [0_u8; 256];
    let read = stream.read(&mut response).await?;
    assert!(response[..read].starts_with(b"HTTP/1.1 403"));
    Ok(())
}

#[tokio::test]
async fn rotates_intermediate_without_changing_workspace_root_trust() -> Result<()> {
    let (_fixture, [old_intermediate, new_intermediate], roots) = ca_rotation_fixture()?;
    let old_address = proxy(old_intermediate).await?;
    let new_address = proxy(new_intermediate).await?;

    let old_stream = connect(
        old_address,
        "allowed.test:443",
        &format!("Charon {}", token("connect-old-intermediate")?),
    )
    .await?;
    tls_connect(old_stream, roots.clone(), "allowed.test").await?;

    let new_stream = connect(
        new_address,
        "allowed.test:443",
        &format!("Charon {}", token("connect-new-intermediate")?),
    )
    .await?;
    tls_connect(new_stream, roots, "allowed.test").await?;
    Ok(())
}

#[tokio::test]
async fn rejects_sni_and_decrypted_authority_confusion() -> Result<()> {
    let (_fixture, tls_config, roots) = ca_fixture()?;
    let address = proxy(tls_config).await?;
    let manifest = token("connect-negative-1234")?;
    let basic = base64::engine::general_purpose::STANDARD.encode(format!("charon:{manifest}"));
    let stream = connect(address, "allowed.test:443", &format!("Basic {basic}")).await?;
    let mut tls = tls_connect(stream, roots, "allowed.test").await?;
    tls.write_all(
        b"GET /user HTTP/1.1\r\nHost: denied.test\r\nAuthorization: Bearer charon-placeholder\r\nConnection: close\r\n\r\n",
    )
    .await?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    assert!(response.starts_with(b"HTTP/1.1 421"));

    let (_fixture, tls_config, roots) = ca_fixture()?;
    let address = proxy(tls_config).await?;
    let stream = connect(
        address,
        "allowed.test:443",
        &format!("Charon {}", token("connect-wrong-sni-1")?),
    )
    .await?;
    assert!(tls_connect(stream, roots, "denied.test").await.is_err());
    Ok(())
}

#[tokio::test]
async fn rejects_malformed_decrypted_headers_and_untrusted_ca() -> Result<()> {
    let (_fixture, tls_config, roots) = ca_fixture()?;
    let address = proxy(tls_config).await?;
    let stream = connect(
        address,
        "allowed.test:443",
        &format!("Charon {}", token("connect-malformed-1")?),
    )
    .await?;
    let mut tls = tls_connect(stream, roots, "allowed.test").await?;
    tls.write_all(b"GET /user HTTP/1.1\r\nBad Header\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    assert!(response.starts_with(b"HTTP/1.1 400"));

    let (_other_fixture, _other_config, unrelated_roots) = ca_fixture()?;
    let stream = connect(
        address,
        "allowed.test:443",
        &format!("Charon {}", token("connect-wrong-ca-1")?),
    )
    .await?;
    assert!(
        tls_connect(stream, unrelated_roots, "allowed.test")
            .await
            .is_err()
    );
    Ok(())
}
