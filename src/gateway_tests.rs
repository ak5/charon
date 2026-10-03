//! Real local TLS fixtures for the exclusive workload gateway.
use super::*;
use crate::provider::{ProviderError, ProviderResult};
use async_trait::async_trait;
use http_body_util::BodyExt as _;
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

const SENTINEL: &str = "FAKE_SENTINEL_CREDENTIAL_0123456789";
struct FakeProvider(AtomicUsize);
struct PublicFixtureResolver;
impl reqwest::dns::Resolve for PublicFixtureResolver {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async {
            Ok(
                Box::new(vec![SocketAddr::from(([8, 8, 8, 8], 443))].into_iter())
                    as reqwest::dns::Addrs,
            )
        })
    }
}
#[async_trait]
impl SecretProvider for FakeProvider {
    async fn resolve(&self, _: &SecretRef<'_>) -> ProviderResult<SecretString> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(SecretString::from(SENTINEL))
    }
    async fn health(&self) -> ProviderResult<()> {
        Err(ProviderError::Unavailable)
    }
}
fn route(name: &str, path: &str, mediation: Mediation) -> Route {
    Route {
        name: name.into(),
        host: "allowed.test".into(),
        scheme: "https".into(),
        methods: vec!["GET".into(), "POST".into()],
        paths: vec![path.into()],
        path_prefix: None,
        allow_query: true,
        caller_headers: vec!["cookie".into()],
        session_response_headers: vec!["set-cookie".into()],
        mediation,
        max_request_bytes: 1024 * 1024,
        max_response_bytes: 1024 * 1024,
        max_duration_seconds: 10,
        idle_timeout_seconds: 3,
    }
}
struct Fixture {
    directory: tempfile::TempDir,
    gateway: Arc<Gateway>,
    provider: Arc<FakeProvider>,
    address: SocketAddr,
    upstream_address: SocketAddr,
    ca: reqwest::Certificate,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
#[allow(clippy::too_many_lines)]
async fn fixture() -> Result<Fixture> {
    let directory = tempfile::tempdir()?;
    let cert = directory.path().join("ca.pem");
    let key = directory.path().join("key.pem");
    crate::ca::generate("Synthetic Test CA", &cert, &key)?;
    let ca = reqwest::Certificate::from_pem(&std::fs::read(&cert)?)?;
    let tls_config = TlsConfig {
        ca_certificate: cert,
        ca_private_key: key,
    };
    let authority = TlsAuthority::load(&tls_config)?;
    let mut server = authority.server_config("allowed.test")?;
    Arc::make_mut(&mut server).alpn_protocols = vec![b"http/1.1".to_vec()];
    let upstream = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream.local_addr()?;
    // Fixture-only HTTP CONNECT intermediary routes to a real local TLS origin.
    let upstream_task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = upstream.accept().await {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") && headers.len() < 4096 {
                    let mut byte = [0];
                    if socket.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    headers.push(byte[0]);
                }
                if socket
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let Ok(tls) = TlsAcceptor::from(server).accept(socket).await else {
                    return;
                };
                let service = hyper::service::service_fn(
                    |request: hyper::Request<hyper::body::Incoming>| async move {
                        let path = request.uri().path().to_owned();
                        let auth = request
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned();
                        let cookie = request.headers().get("cookie").cloned();
                        let upload = request.into_body().collect().await;
                        let mut response = Response::builder()
                            .header("content-type", "text/event-stream")
                            .header("set-cookie", "session=synthetic; Secure");
                        if let Some(value) = cookie {
                            response = response.header("x-cookie-preserved", value);
                        }
                        if path == "/redirect" {
                            response = response
                                .status(302)
                                .header("location", "https://denied.test/next");
                        }
                        if path == "/header-echo" {
                            response = response.header("x-echo", SENTINEL);
                        }
                        if path == "/compressed" || path == "/compressed-hop" {
                            response = response.header("content-encoding", "gzip");
                            if path == "/compressed-hop" {
                                response = response.header("connection", "content-encoding");
                            }
                        }
                        let body = if path == "/upload" {
                            Body::from(
                                upload
                                    .map(http_body_util::Collected::to_bytes)
                                    .unwrap_or_default(),
                            )
                        } else if path == "/stream" {
                            Body::from_stream(futures_util::stream::unfold(
                                0_u8,
                                |index| async move {
                                    if index == 2 {
                                        return None;
                                    }
                                    if index == 1 {
                                        tokio::time::sleep(Duration::from_millis(800)).await;
                                    }
                                    Some((
                                        Ok::<_, std::io::Error>(axum::body::Bytes::from_static(
                                            b"data: streaming\n\n",
                                        )),
                                        index + 1,
                                    ))
                                },
                            ))
                        } else {
                            let chunks = vec![
                                Ok::<_, std::io::Error>(axum::body::Bytes::from(format!(
                                    "data: {path}\n\n"
                                ))),
                                Ok(axum::body::Bytes::from(format!("data: {auth}\n\n"))),
                            ];
                            Body::from_stream(futures_util::stream::iter(chunks))
                        };
                        Ok::<_, Infallible>(response.body(body).unwrap_or_else(|_| denied()))
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let credential = || Mediation::Header {
        secret_ref: "CHARON_SYNTHETIC_TEST".into(),
        name: "authorization".into(),
        value_template: "Bearer {secret}".into(),
    };
    let config = GatewayConfig {
        version: 1,
        realm: RealmConfig {
            id: "realm-test".into(),
            tenant: "tenant-test".into(),
            persona: "persona-test".into(),
            generation: 1,
        },
        workload: "hermes-test".into(),
        listen: address,
        exclusive_network: true,
        tls: tls_config,
        provider: ProviderConfig::Environment,
        receipts: ReceiptConfig {
            journal_path: directory.path().join("receipts.jsonl"),
            state_path: directory.path().join("checkpoint"),
            queue_capacity: 64,
        },
        routes: vec![
            route("stream", "/stream", Mediation::Forward),
            route("plain", "/plain", Mediation::Forward),
            route("credential", "/credential", credential()),
            route(
                "gh-user",
                "/api/v3/user",
                Mediation::Header {
                    secret_ref: "CHARON_SYNTHETIC_TEST".into(),
                    name: "authorization".into(),
                    value_template: "token {secret}".into(),
                },
            ),
            route(
                "basic",
                "/basic",
                Mediation::Basic {
                    secret_ref: "CHARON_SYNTHETIC_TEST".into(),
                    username: "fixed-user".into(),
                },
            ),
            route("redirect", "/redirect", Mediation::Forward),
            route("upload", "/upload", Mediation::Forward),
            route("header", "/header-echo", credential()),
            route("compressed", "/compressed", Mediation::Forward),
            route("compressed-hop", "/compressed-hop", Mediation::Forward),
        ],
    };
    let provider = Arc::new(FakeProvider(AtomicUsize::new(0)));
    let mut gateway = Gateway::new(config, provider.clone())?;
    gateway.resolver = Arc::new(PublicFixtureResolver);
    gateway.client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .proxy(reqwest::Proxy::all(format!("http://{upstream_addr}"))?)
        .add_root_certificate(ca.clone())
        .build()?;
    let gateway = Arc::new(gateway);
    let router = Arc::clone(&gateway).router();
    let gateway_task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(Fixture {
        directory,
        gateway,
        provider,
        address,
        upstream_address: upstream_addr,
        ca,
        tasks: vec![upstream_task, gateway_task],
    })
}
fn client(f: &Fixture) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .http1_only()
        .no_proxy()
        .proxy(reqwest::Proxy::all(format!("http://{}", f.address))?)
        .add_root_certificate(f.ca.clone())
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}
#[tokio::test]
async fn ordinary_clients_forward_stream_upload_and_keep_sessions_without_lookup() -> Result<()> {
    let f = fixture().await?;
    let client = client(&f)?;
    for _ in 0..2 {
        let response = client
            .get("https://allowed.test/plain?token=synthetic-query")
            .header("cookie", "session=synthetic")
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("set-cookie"));
        assert_eq!(
            response.headers()["x-cookie-preserved"],
            "session=synthetic"
        );
        assert!(response.text().await?.contains("data: /plain"));
    }
    let response = client
        .post("https://allowed.test/upload")
        .body("synthetic upload")
        .send()
        .await?;
    assert_eq!(response.text().await?, "synthetic upload");
    let response = client.get("https://allowed.test/redirect").send().await?;
    assert_eq!(response.status(), 302);
    assert!(client.get("https://denied.test/next").send().await.is_err());
    let response = client
        .get("https://allowed.test/denied")
        .header("authorization", SENTINEL)
        .send()
        .await?;
    assert_eq!(response.status(), 403);
    assert!(!response.text().await?.contains(SENTINEL));
    assert_eq!(f.provider.0.load(Ordering::SeqCst), 0);
    Ok(())
}
#[tokio::test]
async fn hydration_is_typed_and_sentinel_never_reaches_errors_or_journal() -> Result<()> {
    let f = fixture().await?;
    let client = client(&f)?;
    for value in [
        SENTINEL,
        "Bearer {{charon.plain}}",
        "Bearer {{charon.CHARON_SYNTHETIC_TEST}}",
    ] {
        let response = client
            .get("https://allowed.test/credential")
            .header("authorization", value)
            .send()
            .await?;
        assert_eq!(response.status(), 403);
        assert!(!response.text().await?.contains(SENTINEL));
    }
    assert_eq!(f.provider.0.load(Ordering::SeqCst), 0);
    let response = client
        .get("https://allowed.test/credential")
        .header("authorization", "Bearer {{charon.credential}}")
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    let text = response.text().await?;
    assert!(!text.contains(SENTINEL));
    assert!(text.contains("[REDACTED]"));
    let response = client
        .get("https://allowed.test/header-echo")
        .header("authorization", "Bearer {{charon.header}}")
        .send()
        .await?;
    assert_eq!(response.status(), 403);
    assert!(!response.text().await?.contains(SENTINEL));
    assert_eq!(f.provider.0.load(Ordering::SeqCst), 2);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let journal = std::fs::read_to_string(&f.gateway.config.receipts.journal_path)?;
    assert!(!journal.contains(SENTINEL));
    assert!(!journal.contains("synthetic-query"));
    assert!(!journal.contains("CHARON_SYNTHETIC_TEST"));
    Ok(())
}
#[tokio::test]
async fn reusable_tls_connection_reauthorizes_each_request_and_authority() -> Result<()> {
    let f = fixture().await?;
    let mut socket = TcpStream::connect(f.address).await?;
    socket
        .write_all(b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
        .await?;
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        socket.read_exact(&mut byte).await?;
        headers.push(byte[0]);
    }
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from_pem_slice(
        &std::fs::read(&f.gateway.config.tls.ca_certificate)?,
    )?)?;
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("allowed.test")?,
            socket,
        )
        .await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    let task = tokio::spawn(connection);
    for (path, host, status) in [
        ("/plain", "allowed.test", 200),
        ("/denied", "allowed.test", 403),
        ("/plain", "wrong.test", 421),
        ("/plain", "allowed.test", 200),
    ] {
        let response = sender
            .send_request(
                hyper::Request::builder()
                    .uri(path)
                    .header("host", host)
                    .body(http_body_util::Empty::<axum::body::Bytes>::new())?,
            )
            .await?;
        assert_eq!(response.status().as_u16(), status);
        response.into_body().collect().await?;
    }
    assert_eq!(f.provider.0.load(Ordering::SeqCst), 0);
    task.abort();
    Ok(())
}
#[tokio::test]
async fn unsupported_protocols_and_compression_fail_closed() -> Result<()> {
    let f = fixture().await?;
    let client = client(&f)?;
    for path in ["compressed", "compressed-hop"] {
        let response = client
            .get(format!("https://allowed.test/{path}"))
            .send()
            .await?;
        assert_eq!(response.status(), 403);
    }
    let tls = tunnel(&f, "allowed.test", vec![b"http/1.1".to_vec()]).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
    let task = tokio::spawn(connection);
    for (name, value) in [
        ("upgrade", "websocket"),
        ("proxy-authorization", "caller-override"),
        ("content-encoding", "gzip"),
    ] {
        let response = sender
            .send_request(
                hyper::Request::builder()
                    .uri("/plain")
                    .header("host", "allowed.test")
                    .header(name, value)
                    .body(http_body_util::Empty::<axum::body::Bytes>::new())?,
            )
            .await?;
        assert_eq!(response.status(), 403);
        response.into_body().collect().await?;
    }
    task.abort();
    assert_eq!(f.provider.0.load(Ordering::SeqCst), 0);
    Ok(())
}
#[test]
fn schema_rejects_shared_and_ambiguous_policy() -> Result<()> {
    let config = GatewayConfig::load(Path::new("examples/hermes-gateway.toml"))?;
    let mut invalid = config.clone();
    invalid.exclusive_network = false;
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.routes.push(invalid.routes[0].clone());
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.routes[0].host = "*.example.com".into();
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.routes[0].host = "127.0.0.1".into();
    assert!(invalid.validate().is_err());
    let mut invalid = config;
    invalid.routes[0].mediation = Mediation::Header {
        secret_ref: "CHARON_TEST".into(),
        name: "host".into(),
        value_template: "{secret}".into(),
    };
    assert!(invalid.validate().is_err());
    Ok(())
}

#[tokio::test]
async fn streaming_delivers_before_completion_and_basic_is_a_typed_sink() -> Result<()> {
    let f = fixture().await?;
    let client = client(&f)?;
    let mut response = client.get("https://allowed.test/stream").send().await?;
    assert_eq!(response.status(), 200);
    let first = timeout(Duration::from_millis(400), response.chunk()).await??;
    assert!(first.is_some());
    let rest = response.text().await?;
    assert!(rest.contains("streaming"));
    assert_eq!(f.provider.0.load(Ordering::SeqCst), 0);
    let response = client
        .get("https://allowed.test/basic")
        .basic_auth("fixed-user", Some("{{charon.basic}}"))
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    let body = response.text().await?;
    assert!(!body.contains(SENTINEL));
    assert!(body.contains("[REDACTED]"));
    assert_eq!(f.provider.0.load(Ordering::SeqCst), 1);
    Ok(())
}

async fn tunnel(
    f: &Fixture,
    sni: &str,
    alpn: Vec<Vec<u8>>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut socket = TcpStream::connect(f.address).await?;
    socket
        .write_all(b"CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
        .await?;
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") && headers.len() < 4096 {
        let mut byte = [0];
        socket.read_exact(&mut byte).await?;
        headers.push(byte[0]);
    }
    ensure!(
        headers.starts_with(b"HTTP/1.1 200"),
        "synthetic CONNECT failed"
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from_pem_slice(
        &std::fs::read(&f.gateway.config.tls.ca_certificate)?,
    )?)?;
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = alpn;
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from(sni.to_owned())?,
            socket,
        )
        .await?)
}
#[tokio::test]
async fn http2_reuse_reauthorizes_authority_and_sni_is_required() -> Result<()> {
    let f = fixture().await?;
    let tls = tunnel(&f, "allowed.test", vec![b"h2".to_vec()]).await?;
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        TokioIo::new(tls),
    )
    .await?;
    let task = tokio::spawn(connection);
    for (uri, status) in [
        ("https://allowed.test/plain", 200),
        ("https://allowed.test/no-grant", 403),
        ("https://wrong.test/plain", 421),
        ("https://allowed.test:444/plain", 421),
        ("http://allowed.test/plain", 421),
        ("https://user@allowed.test/plain", 421),
        ("https://allowed.test/plain", 200),
    ] {
        let response = sender
            .send_request(
                hyper::Request::builder()
                    .uri(uri)
                    .body(http_body_util::Empty::<axum::body::Bytes>::new())?,
            )
            .await?;
        assert_eq!(response.status().as_u16(), status);
        response.into_body().collect().await?;
    }
    task.abort();
    assert!(tunnel(&f, "wrong.test", Vec::new()).await.is_err());
    assert_eq!(f.provider.0.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn rejects_private_dns_before_provider_and_invalid_upstream_tls() -> Result<()> {
    let f = fixture().await?;
    let mut config = f.gateway.config.clone();
    config.receipts.journal_path = f.directory.path().join("private-receipts.jsonl");
    config.receipts.state_path = f.directory.path().join("private-chain");
    config.routes.retain(|r| r.name == "credential");
    config.routes[0].host = "localhost".into();
    let gateway = Gateway::new(config, f.provider.clone())?;
    let response = handle(
        &gateway,
        Request::builder()
            .uri("https://localhost/credential")
            .header("authorization", "Bearer {{charon.credential}}")
            .body(Body::empty())?,
    )
    .await;
    assert_eq!(response.status(), 403);
    assert_eq!(f.provider.0.load(Ordering::SeqCst), 0);
    let no_trust = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(format!("http://{}", f.address))?)
        .build()?;
    assert!(
        no_trust
            .get("https://allowed.test/plain")
            .send()
            .await
            .is_err()
    );
    let mut config = f.gateway.config.clone();
    config.receipts.journal_path = f.directory.path().join("untrusted-receipts.jsonl");
    config.receipts.state_path = f.directory.path().join("untrusted-chain");
    let mut gateway = Gateway::new(config, f.provider.clone())?;
    gateway.resolver = Arc::new(PublicFixtureResolver);
    gateway.client = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(format!(
            "http://{}",
            f.upstream_address
        ))?)
        .build()?;
    let response = handle(
        &gateway,
        Request::builder()
            .uri("https://allowed.test/plain")
            .body(Body::empty())?,
    )
    .await;
    assert_eq!(response.status(), 403);
    assert_eq!(f.provider.0.load(Ordering::SeqCst), 0);
    Ok(())
}

#[derive(Clone)]
struct LogWriter(Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("log fixture unavailable"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[tokio::test]
async fn secret_bearing_upstream_error_is_redacted_in_logs_and_receipts() -> Result<()> {
    let f = fixture().await?;
    let logs = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&logs);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || LogWriter(Arc::clone(&sink)))
        .finish();
    // Keep callsites enabled throughout concurrent tests; a scoped subscriber
    // can race with the global no-subscriber maximum-level cache.
    tracing::subscriber::set_global_default(subscriber)?;
    let request = Request::builder()
        .uri(format!("https://allowed.test/header-echo?token={SENTINEL}"))
        .header("authorization", "Bearer {{charon.header}}")
        .body(Body::from("synthetic private prompt"))?;
    let response = handle(&f.gateway, request).await;
    assert_eq!(response.status(), 403);
    let body = axum::body::to_bytes(response.into_body(), 1024).await?;
    assert_eq!(body, "gateway request denied");
    let log = String::from_utf8(
        logs.lock()
            .map_err(|_| anyhow::anyhow!("log fixture unavailable"))?
            .clone(),
    )?;
    assert!(log.contains("gateway_request_denied"));
    for forbidden in [
        SENTINEL,
        "synthetic private prompt",
        "header-echo",
        "CHARON_SYNTHETIC_TEST",
    ] {
        assert!(!log.contains(forbidden));
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let journal = std::fs::read_to_string(&f.gateway.config.receipts.journal_path)?;
    assert!(journal.contains("denied"));
    for forbidden in [
        SENTINEL,
        "synthetic private prompt",
        "header-echo",
        "CHARON_SYNTHETIC_TEST",
    ] {
        assert!(!journal.contains(forbidden));
    }
    Ok(())
}

#[tokio::test]
async fn configured_upload_and_download_bounds_are_enforced() -> Result<()> {
    let f = fixture().await?;
    let mut config = f.gateway.config.clone();
    config.receipts.journal_path = f.directory.path().join("bounded-receipts.jsonl");
    config.receipts.state_path = f.directory.path().join("bounded-chain");
    for route in &mut config.routes {
        route.max_request_bytes = 16;
        route.max_response_bytes = 16;
    }
    let mut gateway = Gateway::new(config, f.provider.clone())?;
    gateway.resolver = Arc::new(PublicFixtureResolver);
    gateway.client = f.gateway.client.clone();
    let response = handle(
        &gateway,
        Request::builder()
            .uri("https://allowed.test/credential")
            .header("authorization", "Bearer {{charon.credential}}")
            .header("content-length", "32")
            .body(Body::from("synthetic oversized upload"))?,
    )
    .await;
    assert_eq!(response.status(), 403);
    assert_eq!(f.provider.0.load(Ordering::SeqCst), 0);
    let response = handle(
        &gateway,
        Request::builder()
            .uri("https://allowed.test/stream")
            .body(Body::empty())?,
    )
    .await;
    assert_eq!(response.status(), 200);
    assert!(
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .is_err()
    );
    assert_eq!(f.provider.0.load(Ordering::SeqCst), 0);
    Ok(())
}

fn executable(name: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|p| p.is_file())
    })
}
#[tokio::test]
async fn unmodified_curl_and_gh_use_standard_proxy_and_credential_settings() -> Result<()> {
    let curl = executable("curl").context("curl required for ordinary client proof")?;
    let f = fixture().await?;
    let proxy = format!("http://{}", f.address);
    let curl_output = tokio::process::Command::new(curl)
        .env_clear()
        .arg("--silent")
        .arg("--show-error")
        .arg("--noproxy")
        .arg("")
        .arg("--proxy")
        .arg(&proxy)
        .arg("--cacert")
        .arg(&f.gateway.config.tls.ca_certificate)
        .arg("--max-time")
        .arg("10")
        .arg("https://allowed.test/plain")
        .output()
        .await?;
    ensure!(curl_output.status.success(), "synthetic curl proof failed");
    assert!(String::from_utf8(curl_output.stdout)?.contains("data: /plain"));
    assert_eq!(f.provider.0.load(Ordering::SeqCst), 0);
    // Go's macOS certificate verifier in existing gh builds uses Keychain,
    // not SSL_CERT_FILE. Exercise gh in Linux CI without installing a test CA
    // into the operator's system trust or disabling certificate verification.
    if cfg!(target_os = "macos") {
        return Ok(());
    }
    let gh = executable("gh").context("gh required for ordinary client proof")?;
    // Clear all ambient authentication/config: these are fake credentials and a
    // loopback TLS origin, never the operator's signed-in GitHub session.
    let gh_output = tokio::time::timeout(
        Duration::from_secs(20),
        tokio::process::Command::new(gh)
            .kill_on_drop(true)
            .env_clear()
            .env("HOME", f.directory.path())
            .env("GH_CONFIG_DIR", f.directory.path().join("gh"))
            .env("GH_HOST", "allowed.test")
            .env("GH_ENTERPRISE_TOKEN", "{{charon.gh-user}}")
            .env("HTTPS_PROXY", &proxy)
            .env("SSL_CERT_FILE", &f.gateway.config.tls.ca_certificate)
            .arg("api")
            .arg("user")
            .output(),
    )
    .await??;
    ensure!(gh_output.status.success(), "synthetic gh proof failed");
    let body = String::from_utf8(gh_output.stdout)?;
    assert!(!body.contains(SENTINEL));
    assert!(body.contains("[REDACTED]"));
    assert_eq!(f.provider.0.load(Ordering::SeqCst), 1);
    Ok(())
}
