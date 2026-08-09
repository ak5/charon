//! End-to-end tests for the milestone-0 HTTP forward proxy.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Redirect,
    routing::{any, get},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use charon::{
    config::{
        CapabilityPolicy, Config, IdentityConfig, ProviderConfig, RealmConfig, ServicePolicy,
        UpstreamProxyConfig,
    },
    identity::WorkloadClaims,
    provider::{ProviderError, ProviderResult, SecretProvider, SecretRef},
    proxy::{AppState, app},
};
use ed25519_dalek::{Signer as _, SigningKey};
use futures_util::{StreamExt as _, stream};
use secrecy::SecretString;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
    sync::{Mutex, mpsc, oneshot},
    time::{Duration, timeout},
};

#[derive(Debug)]
struct StaticProvider(HashMap<String, String>);

#[async_trait]
impl SecretProvider for StaticProvider {
    async fn resolve(&self, secret_ref: &SecretRef<'_>) -> ProviderResult<SecretString> {
        self.0
            .get(secret_ref.as_str())
            .cloned()
            .map(SecretString::from)
            .ok_or(ProviderError::SecretUnavailable)
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[11_u8; 32])
}

fn identity_config() -> IdentityConfig {
    IdentityConfig {
        issuer: "test-issuer".into(),
        audience: "charon-test".into(),
        public_key: base64::engine::general_purpose::STANDARD
            .encode(signing_key().verifying_key().to_bytes()),
        max_ttl_seconds: 60,
        clock_skew_seconds: 2,
    }
}

fn realm() -> RealmConfig {
    RealmConfig {
        id: "realm-developer".into(),
        tenant: "tenant-test".into(),
        persona: "developer".into(),
        generation: 1,
    }
}

fn token(capability: &str, nonce: &str) -> Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let claims = WorkloadClaims {
        iss: "test-issuer".into(),
        aud: "charon-test".into(),
        sub: "test-workload".into(),
        tenant: "tenant-test".into(),
        persona: "developer".into(),
        workspace: "workspace-test".into(),
        lease: "lease-test".into(),
        operation: "operation-test".into(),
        capability: capability.into(),
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

#[tokio::test]
async fn hydrates_capability_reference_without_exposing_secret_to_client() -> Result<()> {
    let receipt_directory = tempfile::tempdir()?;
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

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_address = proxy_listener.local_addr()?;
    let config = Config {
        realm: realm(),
        listen: proxy_address,
        upstream_proxy: None,
        provider: ProviderConfig::Environment,
        tls: None,
        identity: identity_config(),
        receipts: Some(charon::config::ReceiptConfig {
            journal_path: receipt_directory.path().join("receipts.jsonl"),
            state_path: receipt_directory.path().join("chain"),
            queue_capacity: 8,
        }),
        capabilities: vec![CapabilityPolicy {
            name: "mock-whoami".into(),
            persona: "developer".into(),
            service: "mock".into(),
            methods: vec!["GET".into()],
            paths: vec!["/whoami".into()],
        }],
        services: vec![ServicePolicy {
            name: "mock".into(),
            hosts: vec!["127.0.0.1".into()],
            hydration: charon::config::HydrationPolicy {
                sink: charon::broker::HydrationSink::Authorization,
                value_template: "Bearer {secret}".into(),
            },
            secret_ref: "CHARON_MOCK_TOKEN".into(),
            response: charon::config::ResponsePolicy::text_stream(16 * 1024 * 1024, 30, 10, 4096),
            transparent_listen: None,
        }],
    };
    // Tests use an IP destination; production configuration intentionally
    // rejects hosts containing ports, while URI matching receives host only.
    let secrets = StaticProvider(HashMap::from([(
        "CHARON_MOCK_TOKEN".into(),
        "real-secret".into(),
    )]));
    let state = Arc::new(AppState::new(config, Arc::new(secrets))?);
    tokio::spawn(async move { axum::serve(proxy_listener, app(state)).await });

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_address}"))?)
        .build()?;
    let response = client
        .get(format!("http://{upstream_address}/whoami"))
        .header(
            "proxy-authorization",
            format!("Charon {}", token("mock-whoami", "nonce-whoami-1234")?),
        )
        .header("authorization", "Bearer {{charon.mock-whoami}}")
        .send()
        .await?;

    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: Bytes = response.bytes().await?;
    assert_eq!(&body[..], b"Bearer [REDACTED]");
    let journal_path = receipt_directory.path().join("receipts.jsonl");
    let mut journal = String::new();
    for _ in 0..20 {
        journal = std::fs::read_to_string(&journal_path).unwrap_or_default();
        if journal.contains("\"outcome\":\"completed\"") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(journal.contains("\"capability\":\"mock-whoami\""));
    assert!(journal.contains("\"delivered_bytes\":17"));
    assert!(!journal.contains("real-secret"));
    assert!(!journal.contains("authorization"));
    Ok(())
}

#[tokio::test]
async fn authenticates_to_upstream_proxy_from_a_protected_file() -> Result<()> {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_address = upstream_listener.local_addr()?;
    let (observed_tx, observed_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await?;
        let mut input = vec![0_u8; 4096];
        let read = stream.read(&mut input).await?;
        let request = String::from_utf8_lossy(&input[..read]);
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("egress:synthetic-password")
        );
        let authenticated = request.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("proxy-authorization") && value.trim() == expected
            })
        });
        let _ = observed_tx.send(authenticated);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await?;
        Result::<()>::Ok(())
    });

    let directory = tempfile::tempdir()?;
    let password_file = directory.path().join("egress-password");
    std::fs::write(&password_file, "synthetic-password")?;
    #[cfg(unix)]
    {
        let mut permissions = std::fs::metadata(&password_file)?.permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&password_file, permissions)?;
    }
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_address = proxy_listener.local_addr()?;
    let config = Config {
        realm: realm(),
        listen: proxy_address,
        upstream_proxy: Some(UpstreamProxyConfig {
            url: format!("http://{upstream_address}"),
            username: Some("egress".into()),
            password_file: Some(password_file),
        }),
        provider: ProviderConfig::Environment,
        tls: None,
        identity: identity_config(),
        receipts: None,
        capabilities: vec![CapabilityPolicy {
            name: "proxied-read".into(),
            persona: "developer".into(),
            service: "upstream".into(),
            methods: vec!["GET".into()],
            paths: vec!["/resource".into()],
        }],
        services: vec![ServicePolicy {
            name: "upstream".into(),
            hosts: vec!["127.0.0.1".into()],
            hydration: charon::config::HydrationPolicy {
                sink: charon::broker::HydrationSink::Authorization,
                value_template: "Bearer {secret}".into(),
            },
            secret_ref: "CHARON_TOKEN".into(),
            response: charon::config::ResponsePolicy::text_stream(16 * 1024 * 1024, 30, 10, 4096),
            transparent_listen: None,
        }],
    };
    let secrets = StaticProvider(HashMap::from([(
        "CHARON_TOKEN".into(),
        "synthetic-token".into(),
    )]));
    let state = Arc::new(AppState::new(config, Arc::new(secrets))?);
    tokio::spawn(async move { axum::serve(proxy_listener, app(state)).await });

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_address}"))?)
        .build()?;
    let response = client
        .get("http://127.0.0.1/resource")
        .header(
            "proxy-authorization",
            format!("Charon {}", token("proxied-read", "nonce-proxied-1234")?),
        )
        .header("authorization", "Bearer {{charon.proxied-read}}")
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(observed_rx.await?);
    Ok(())
}

#[tokio::test]
async fn denies_unlisted_destinations() -> Result<()> {
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_address = proxy_listener.local_addr()?;
    let config = Config {
        realm: realm(),
        listen: proxy_address,
        upstream_proxy: None,
        provider: ProviderConfig::Environment,
        tls: None,
        identity: identity_config(),
        receipts: None,
        capabilities: vec![CapabilityPolicy {
            name: "allowed-read".into(),
            persona: "developer".into(),
            service: "allowed".into(),
            methods: vec!["GET".into()],
            paths: vec!["/resource".into()],
        }],
        services: vec![ServicePolicy {
            name: "allowed".into(),
            hosts: vec!["allowed.invalid".into()],
            hydration: charon::config::HydrationPolicy {
                sink: charon::broker::HydrationSink::Authorization,
                value_template: "Bearer {secret}".into(),
            },
            secret_ref: "CHARON_TOKEN".into(),
            response: charon::config::ResponsePolicy::text_stream(16 * 1024 * 1024, 30, 10, 4096),
            transparent_listen: None,
        }],
    };
    let secrets = StaticProvider(HashMap::from([("CHARON_TOKEN".into(), "secret".into())]));
    let state = Arc::new(AppState::new(config, Arc::new(secrets))?);
    tokio::spawn(async move { axum::serve(proxy_listener, app(state)).await });

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_address}"))?)
        .build()?;
    let response = client
        .get("http://127.0.0.2/resource")
        .header("authorization", "Bearer {{charon.allowed-read}}")
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    Ok(())
}

#[derive(Debug)]
struct CountingProvider {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl SecretProvider for CountingProvider {
    async fn resolve(&self, _secret_ref: &SecretRef<'_>) -> ProviderResult<SecretString> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(SecretString::from("must-not-be-read"))
    }
}

#[tokio::test]
async fn rejects_identity_before_resolving_a_credential() -> Result<()> {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_address = upstream_listener.local_addr()?;
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_address = proxy_listener.local_addr()?;
    let config = Config {
        realm: realm(),
        listen: proxy_address,
        upstream_proxy: None,
        provider: ProviderConfig::Environment,
        tls: None,
        identity: identity_config(),
        receipts: None,
        capabilities: vec![CapabilityPolicy {
            name: "protected".into(),
            persona: "developer".into(),
            service: "mock".into(),
            methods: vec!["GET".into()],
            paths: vec!["/protected".into()],
        }],
        services: vec![ServicePolicy {
            name: "mock".into(),
            hosts: vec!["127.0.0.1".into()],
            hydration: charon::config::HydrationPolicy {
                sink: charon::broker::HydrationSink::Authorization,
                value_template: "Bearer {secret}".into(),
            },
            secret_ref: "CHARON_MOCK_TOKEN".into(),
            response: charon::config::ResponsePolicy::text_stream(16 * 1024 * 1024, 30, 10, 4096),
            transparent_listen: None,
        }],
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = CountingProvider {
        calls: calls.clone(),
    };
    let state = Arc::new(AppState::new(config, Arc::new(provider))?);
    tokio::spawn(async move { axum::serve(proxy_listener, app(state)).await });

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_address}"))?)
        .build()?;
    let response = client
        .get(format!("http://{upstream_address}/protected"))
        .header("authorization", "Bearer {{charon.protected}}")
        .send()
        .await?;

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn rejects_declared_oversize_before_credential_resolution() -> Result<()> {
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_address = proxy_listener.local_addr()?;
    let config = Config {
        realm: realm(),
        listen: proxy_address,
        upstream_proxy: None,
        provider: ProviderConfig::Environment,
        tls: None,
        identity: identity_config(),
        receipts: None,
        capabilities: vec![CapabilityPolicy {
            name: "upload".into(),
            persona: "developer".into(),
            service: "mock".into(),
            methods: vec!["POST".into()],
            paths: vec!["/upload".into()],
        }],
        services: vec![ServicePolicy {
            name: "mock".into(),
            hosts: vec!["127.0.0.1".into()],
            hydration: charon::config::HydrationPolicy {
                sink: charon::broker::HydrationSink::Authorization,
                value_template: "Bearer {secret}".into(),
            },
            secret_ref: "CHARON_MOCK_TOKEN".into(),
            response: charon::config::ResponsePolicy::text_stream(16 * 1024 * 1024, 30, 10, 4096),
            transparent_listen: None,
        }],
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = CountingProvider {
        calls: Arc::clone(&calls),
    };
    let state = Arc::new(AppState::new(config, Arc::new(provider))?);
    tokio::spawn(async move { axum::serve(proxy_listener, app(state)).await });

    let manifest = token("upload", "nonce-oversize-1234")?;
    let mut stream = tokio::net::TcpStream::connect(proxy_address).await?;
    stream
        .write_all(
            format!(
                "POST http://127.0.0.1:9/upload HTTP/1.1\r\nHost: 127.0.0.1:9\r\nProxy-Authorization: Charon {manifest}\r\nAuthorization: Bearer {{{{charon.upload}}}}\r\nContent-Length: 16777217\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await??;
    assert!(response.starts_with(b"HTTP/1.1 413"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn never_follows_upstream_redirects_with_an_injected_credential() -> Result<()> {
    let final_calls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&final_calls);
    let upstream = Router::new()
        .route("/start", get(|| async { Redirect::temporary("/final") }))
        .route(
            "/final",
            get(move || {
                let calls = Arc::clone(&calls);
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }
            }),
        );
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_address = upstream_listener.local_addr()?;
    tokio::spawn(async move { axum::serve(upstream_listener, upstream).await });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_address = proxy_listener.local_addr()?;
    let config = Config {
        realm: realm(),
        listen: proxy_address,
        upstream_proxy: None,
        provider: ProviderConfig::Environment,
        tls: None,
        identity: identity_config(),
        receipts: None,
        capabilities: vec![CapabilityPolicy {
            name: "redirect-start".into(),
            persona: "developer".into(),
            service: "redirect-test".into(),
            methods: vec!["GET".into()],
            paths: vec!["/start".into()],
        }],
        services: vec![ServicePolicy {
            name: "redirect-test".into(),
            hosts: vec!["127.0.0.1".into()],
            hydration: charon::config::HydrationPolicy {
                sink: charon::broker::HydrationSink::Authorization,
                value_template: "Bearer {secret}".into(),
            },
            secret_ref: "CHARON_REDIRECT_TOKEN".into(),
            response: charon::config::ResponsePolicy::text_stream(16 * 1024 * 1024, 30, 10, 4096),
            transparent_listen: None,
        }],
    };
    let secrets = StaticProvider(HashMap::from([(
        "CHARON_REDIRECT_TOKEN".into(),
        "fixture-secret".into(),
    )]));
    let state = Arc::new(AppState::new(config, Arc::new(secrets))?);
    tokio::spawn(async move { axum::serve(proxy_listener, app(state)).await });

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .proxy(reqwest::Proxy::http(format!("http://{proxy_address}"))?)
        .build()?;
    let response = client
        .get(format!("http://{upstream_address}/start"))
        .header(
            "proxy-authorization",
            format!("Charon {}", token("redirect-start", "nonce-redirect-1234")?),
        )
        .header("authorization", "Bearer {{charon.redirect-start}}")
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(final_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

struct StreamingUpstream {
    request_seen: Mutex<Option<oneshot::Sender<()>>>,
    response: Mutex<Option<mpsc::Receiver<std::io::Result<Bytes>>>>,
}

async fn streaming_upstream(State(state): State<Arc<StreamingUpstream>>, body: Body) -> Body {
    let mut request = body.into_data_stream();
    if request.next().await.is_some()
        && let Some(signal) = state.request_seen.lock().await.take()
    {
        let _ = signal.send(());
    }
    while request.next().await.is_some() {}
    let Some(response) = state.response.lock().await.take() else {
        return Body::empty();
    };
    Body::from_stream(stream::unfold(response, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    }))
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn streams_request_and_response_without_full_body_buffering() -> Result<()> {
    let (request_seen_tx, request_seen_rx) = oneshot::channel();
    let (response_tx, response_rx) = mpsc::channel(2);
    response_tx
        .send(Ok(Bytes::from_static(
            b"response-first-padding-longer-than-any-protected-value",
        )))
        .await
        .map_err(|_| anyhow!("response fixture closed"))?;
    let upstream_state = Arc::new(StreamingUpstream {
        request_seen: Mutex::new(Some(request_seen_tx)),
        response: Mutex::new(Some(response_rx)),
    });
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_address = upstream_listener.local_addr()?;
    let upstream = Router::new()
        .route("/stream", any(streaming_upstream))
        .with_state(upstream_state);
    tokio::spawn(async move { axum::serve(upstream_listener, upstream).await });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_address = proxy_listener.local_addr()?;
    let config = Config {
        realm: realm(),
        listen: proxy_address,
        upstream_proxy: None,
        provider: ProviderConfig::Environment,
        tls: None,
        identity: identity_config(),
        receipts: None,
        capabilities: vec![CapabilityPolicy {
            name: "stream".into(),
            persona: "developer".into(),
            service: "mock".into(),
            methods: vec!["POST".into()],
            paths: vec!["/stream".into()],
        }],
        services: vec![ServicePolicy {
            name: "mock".into(),
            hosts: vec!["127.0.0.1".into()],
            hydration: charon::config::HydrationPolicy {
                sink: charon::broker::HydrationSink::Authorization,
                value_template: "Bearer {secret}".into(),
            },
            secret_ref: "CHARON_STREAM_TOKEN".into(),
            response: charon::config::ResponsePolicy::text_stream(16 * 1024 * 1024, 30, 10, 4096),
            transparent_listen: None,
        }],
    };
    let secrets = StaticProvider(HashMap::from([(
        "CHARON_STREAM_TOKEN".into(),
        "fixture-secret".into(),
    )]));
    let state = Arc::new(AppState::new(config, Arc::new(secrets))?);
    tokio::spawn(async move { axum::serve(proxy_listener, app(state)).await });

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy_address}"))?)
        .build()?;
    let (request_tx, request_rx) = mpsc::channel(2);
    let request_stream = stream::unfold(request_rx, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    });
    let request = tokio::spawn(async move {
        client
            .post(format!("http://{upstream_address}/stream"))
            .header(
                "proxy-authorization",
                format!("Charon {}", token("stream", "nonce-streaming-1234")?),
            )
            .header("authorization", "Bearer {{charon.stream}}")
            .body(reqwest::Body::wrap_stream(request_stream))
            .send()
            .await
            .map_err(anyhow::Error::from)
    });

    request_tx
        .send(Ok::<_, std::io::Error>(Bytes::from_static(
            b"request-first",
        )))
        .await
        .map_err(|_| anyhow!("request fixture closed"))?;
    timeout(Duration::from_secs(2), request_seen_rx).await??;
    request_tx
        .send(Ok(Bytes::from_static(b"request-second")))
        .await
        .map_err(|_| anyhow!("request fixture closed"))?;
    drop(request_tx);

    let mut response = timeout(Duration::from_secs(2), request).await???;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let first = response
        .chunk()
        .await?
        .ok_or_else(|| anyhow!("stream ended before the first mediated bytes"))?;
    assert!(!first.is_empty());
    response_tx
        .send(Ok(Bytes::from_static(b"response-second")))
        .await
        .map_err(|_| anyhow!("response fixture closed"))?;
    drop(response_tx);
    let mut delivered = first.to_vec();
    while let Some(chunk) = response.chunk().await? {
        delivered.extend_from_slice(&chunk);
    }
    assert_eq!(
        delivered,
        b"response-first-padding-longer-than-any-protected-valueresponse-second"
    );
    assert!(response.chunk().await?.is_none());
    Ok(())
}
