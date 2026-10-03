//! Exclusive-workload explicit proxy: independent of signed-manifest listeners.

use crate::{
    config::{ProviderConfig, RealmConfig, ReceiptConfig, TlsConfig},
    dns::PinnedResolver,
    provider::{SecretProvider, SecretRef},
    receipt::{DataPlaneReceipt, ReceiptJournal, ReceiptOutcome, receipt_stream},
    response::{guard_stream, redact_text_stream},
    tls::TlsAuthority,
};
use anyhow::{Context, Result, bail, ensure};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use std::{
    collections::HashSet, convert::Infallible, net::SocketAddr, path::Path, sync::Arc,
    time::Duration,
};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

/// A complete policy for a separate, network-authenticated process/listener.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Schema generation, currently 1.
    pub version: u32,
    /// Fixed ownership context; never supplied by the client.
    pub realm: RealmConfig,
    /// Fixed protected workload identifier.
    pub workload: String,
    /// IPv4 address reachable exclusively by this workload.
    pub listen: SocketAddr,
    /// Explicit acknowledgement of the network identity boundary.
    pub exclusive_network: bool,
    /// Interception CA; there is no splice mode.
    pub tls: TlsConfig,
    /// Provider instantiated only for policy-owned credential mediation.
    pub provider: ProviderConfig,
    /// Required durable metadata journal.
    pub receipts: ReceiptConfig,
    /// Exact-host operation grants, evaluated for every request.
    pub routes: Vec<Route>,
}

/// One fixed-workload capability grant. Hostname wildcards are forbidden.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// Safe identifier used in receipts instead of request paths.
    pub name: String,
    /// One exact lowercase DNS name.
    pub host: String,
    /// HTTPS or secretless HTTP.
    pub scheme: String,
    /// Exact methods.
    pub methods: Vec<String>,
    /// Exact paths, excluding query strings.
    #[serde(default)]
    pub paths: Vec<String>,
    /// Optional literal path prefix, terminated with slash (no glob syntax).
    pub path_prefix: Option<String>,
    /// Whether query strings may be forwarded, never recorded.
    pub allow_query: bool,
    /// Credential/session request headers permitted to remain caller-owned.
    pub caller_headers: Vec<String>,
    /// Session/authentication response headers permitted to remain caller-owned.
    pub session_response_headers: Vec<String>,
    /// Closed secretless/credential mode.
    pub mediation: Mediation,
    /// Aggregate streamed upload bound.
    pub max_request_bytes: usize,
    /// Aggregate streamed download bound.
    pub max_response_bytes: usize,
    /// Total request lifetime, including upstream headers and upload.
    pub max_duration_seconds: u64,
    /// Idle body interval.
    pub idle_timeout_seconds: u64,
}

/// Policy-owned typed credential sinks; no caller-selected provider reference.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Mediation {
    /// Forward without any provider lookup.
    Forward,
    /// Inject only into Authorization or one named API-key header.
    Header {
        /// Policy-owned opaque provider identifier.
        secret_ref: String,
        /// Exact capability reference required in this header.
        name: String,
        /// One `{secret}` marker, applied only to this declared header value.
        value_template: String,
    },
    /// Standard Basic-auth capability for ordinary Git/curl clients.
    Basic {
        /// Policy-owned opaque provider identifier.
        secret_ref: String,
        /// Fixed upstream username.
        username: String,
    },
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn sensitive(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization"
            | "cookie"
            | "x-api-key"
            | "api-key"
            | "x-goog-api-key"
            | "x-auth-token"
            | "x-session-token"
    )
}
fn session(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "set-cookie" | "www-authenticate" | "authentication-info" | "x-session-token"
    )
}

impl GatewayConfig {
    /// Load the exclusive listener schema, with data-free parse errors.
    /// # Errors
    /// Invalid or unavailable policy fails closed.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).context("gateway policy unavailable")?;
        let policy: Self =
            toml::from_str(&raw).map_err(|_| anyhow::anyhow!("gateway policy is invalid"))?;
        policy.validate()?;
        Ok(policy)
    }
    /// Reject ambiguous grants and unsupported transport before opening sockets.
    /// # Errors
    /// Returns fixed, non-secret configuration diagnostics.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.exclusive_network && self.listen.is_ipv4(),
            "exclusive IPv4 workload gateway required"
        );
        ensure!(
            [
                &self.workload,
                &self.realm.id,
                &self.realm.tenant,
                &self.realm.persona
            ]
            .iter()
            .all(|v| identifier(v))
                && self.realm.generation > 0,
            "invalid fixed workload realm"
        );
        ensure!(
            self.tls.ca_certificate.is_absolute() && self.tls.ca_private_key.is_absolute(),
            "absolute CA paths required"
        );
        ensure!(
            self.receipts.journal_path.is_absolute()
                && self.receipts.state_path.is_absolute()
                && self.receipts.journal_path != self.receipts.state_path
                && (1..=65536).contains(&self.receipts.queue_capacity),
            "invalid receipt configuration"
        );
        ensure!(!self.routes.is_empty(), "gateway requires routes");
        let mut names = HashSet::new();
        for route in &self.routes {
            ensure!(
                identifier(&route.name) && names.insert(&route.name),
                "invalid or duplicate capability"
            );
            crate::broker::CapabilityReference::parse(&format!("{{{{charon.{}}}}}", route.name))?;
            ensure!(
                crate::config::is_exact_host(&route.host)
                    && route.host == route.host.to_ascii_lowercase()
                    && route.host.parse::<std::net::IpAddr>().is_err(),
                "exact DNS destination required"
            );
            ensure!(
                matches!(route.scheme.as_str(), "https" | "http"),
                "unsupported route scheme"
            );
            ensure!(
                !route.methods.is_empty()
                    && route.methods.iter().all(|m| matches!(
                        m.as_str(),
                        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
                    )),
                "unsupported route method"
            );
            let valid_path = |p: &str| {
                p.starts_with('/')
                    && !p.contains(['?', '#', '*', '\\', '%'])
                    && !p.split('/').any(|s| matches!(s, "." | ".."))
            };
            ensure!(
                !route.paths.is_empty() || route.path_prefix.is_some(),
                "route requires path policy"
            );
            ensure!(
                route.paths.iter().all(|p| valid_path(p))
                    && route
                        .path_prefix
                        .as_deref()
                        .is_none_or(|p| valid_path(p) && p.ends_with('/')),
                "invalid path policy"
            );
            ensure!(
                (1..=1024 * 1024 * 1024).contains(&route.max_request_bytes)
                    && (1..=1024 * 1024 * 1024).contains(&route.max_response_bytes)
                    && (1..=3600).contains(&route.max_duration_seconds)
                    && (1..=300).contains(&route.idle_timeout_seconds),
                "invalid stream limits"
            );
            for name in &route.caller_headers {
                ensure!(
                    name.parse::<HeaderName>().is_ok_and(|n| sensitive(&n)),
                    "unsupported caller credential header"
                );
            }
            for name in &route.session_response_headers {
                ensure!(
                    name.parse::<HeaderName>().is_ok_and(|n| session(&n)),
                    "unsupported session response header"
                );
            }
            let secret_ref = match &route.mediation {
                Mediation::Forward => None,
                Mediation::Header {
                    secret_ref,
                    name,
                    value_template,
                } => {
                    let header: HeaderName = name.parse().context("invalid mediation header")?;
                    ensure!(
                        sensitive(&header) && header != http::header::COOKIE,
                        "unsupported typed credential sink"
                    );
                    ensure!(
                        value_template.matches("{secret}").count() == 1
                            && value_template.len() <= 1024
                            && !value_template.contains(['\r', '\n']),
                        "invalid header template"
                    );
                    ensure!(
                        !route
                            .caller_headers
                            .iter()
                            .any(|n| n.eq_ignore_ascii_case(name)),
                        "sink cannot be caller-owned"
                    );
                    Some(secret_ref)
                }
                Mediation::Basic {
                    secret_ref,
                    username,
                } => {
                    ensure!(
                        identifier(username)
                            && !route
                                .caller_headers
                                .iter()
                                .any(|n| n.eq_ignore_ascii_case("authorization")),
                        "invalid Basic policy"
                    );
                    Some(secret_ref)
                }
            };
            if let Some(reference) = secret_ref {
                ensure!(
                    route.scheme == "https" && !reference.is_empty() && reference.len() <= 256,
                    "invalid credential route"
                );
                match &self.provider {
                    ProviderConfig::Environment => ensure!(
                        reference.starts_with("CHARON_")
                            && reference
                                .bytes()
                                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                        "invalid environment reference"
                    ),
                    ProviderConfig::Vaultwarden(vault) => ensure!(
                        vault
                            .items
                            .iter()
                            .any(|i| &i.secret_ref == reference && i.persona == self.realm.persona),
                        "unmapped realm credential"
                    ),
                }
            }
        }
        // Overlap must not let grant order change which credential is selected.
        for (index, left) in self.routes.iter().enumerate() {
            for right in &self.routes[index + 1..] {
                if left.host == right.host
                    && left.scheme == right.scheme
                    && left.methods.iter().any(|m| right.methods.contains(m))
                {
                    let overlaps = left.paths.iter().any(|p| right.matches_path(p))
                        || right.paths.iter().any(|p| left.matches_path(p))
                        || left
                            .path_prefix
                            .as_ref()
                            .zip(right.path_prefix.as_ref())
                            .is_some_and(|(a, b)| a.starts_with(b) || b.starts_with(a));
                    ensure!(!overlaps, "overlapping operation grants");
                }
            }
        }
        Ok(())
    }
}
impl Route {
    fn matches_path(&self, path: &str) -> bool {
        self.paths.iter().any(|p| p == path)
            || self
                .path_prefix
                .as_deref()
                .is_some_and(|p| path.starts_with(p))
    }
}

/// Runtime for exactly one isolated workload. Contains secret-bearing objects.
pub struct Gateway {
    config: GatewayConfig,
    client: reqwest::Client,
    resolver: Arc<dyn reqwest::dns::Resolve>,
    secrets: Arc<dyn SecretProvider>,
    tls: Arc<TlsAuthority>,
    receipts: ReceiptJournal,
}
impl Gateway {
    /// Build with verified upstream TLS, no ambient proxy, and public-only DNS.
    /// # Errors
    /// Invalid policy, CA, journal, or client construction fails startup.
    pub fn new(config: GatewayConfig, secrets: Arc<dyn SecretProvider>) -> Result<Self> {
        config.validate()?;
        let hosts = config.routes.iter().map(|r| r.host.clone()).collect();
        let resolver: Arc<dyn reqwest::dns::Resolve> =
            Arc::new(PinnedResolver::new(hosts, HashSet::new()));
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .dns_resolver(Arc::clone(&resolver))
            .build()?;
        let tls = Arc::new(TlsAuthority::load(&config.tls)?);
        let receipts = ReceiptJournal::start(&config.receipts)?;
        Ok(Self {
            config,
            client,
            resolver,
            secrets,
            tls,
            receipts,
        })
    }
    /// Build a router for this exclusive listener only.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route(
                "/healthz",
                axum::routing::get(|| async { StatusCode::NO_CONTENT }),
            )
            .route(
                "/readyz",
                axum::routing::get(|State(state): State<Arc<Gateway>>| async move {
                    if state.receipts.is_healthy() {
                        StatusCode::NO_CONTENT
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                }),
            )
            .fallback(entry)
            .with_state(self)
    }
}

async fn entry(State(state): State<Arc<Gateway>>, mut request: Request) -> Response {
    if request.method() == Method::CONNECT {
        match prepare_connect(&state, &request) {
            Ok((host, config)) => {
                let upgrade = hyper::upgrade::on(&mut request);
                tokio::spawn(async move {
                    if intercept(state, upgrade, host, config).await.is_err() {
                        tracing::warn!(outcome = "gateway_tunnel_closed", "gateway tunnel closed");
                    }
                });
                StatusCode::OK.into_response()
            }
            Err(_) => denied(),
        }
    } else {
        // Only explicit plaintext HTTP is accepted outside CONNECT.
        if request.uri().scheme_str() != Some("http") {
            return denied();
        }
        handle(&state, request).await
    }
}
fn denied() -> Response {
    (StatusCode::FORBIDDEN, "gateway request denied").into_response()
}
fn prepare_connect(
    state: &Gateway,
    request: &Request,
) -> Result<(String, Arc<rustls::ServerConfig>)> {
    ensure!(
        !request
            .headers()
            .contains_key(http::header::PROXY_AUTHORIZATION),
        "workload listener does not accept identity overrides"
    );
    let authority = request
        .uri()
        .authority()
        .context("CONNECT authority required")?;
    ensure!(authority.port_u16() == Some(443), "CONNECT port denied");
    ensure!(
        !authority.as_str().contains('@'),
        "CONNECT user information denied"
    );
    let host = authority.host().to_ascii_lowercase();
    ensure!(
        state
            .config
            .routes
            .iter()
            .any(|r| r.host == host && r.scheme == "https"),
        "CONNECT host denied"
    );
    crate::proxy::validate_request_authority(
        request.headers(),
        &reqwest::Url::parse(&format!("https://{authority}/"))?,
    )?;
    Ok((host.clone(), state.tls.server_config(&host)?))
}
async fn intercept(
    state: Arc<Gateway>,
    upgrade: hyper::upgrade::OnUpgrade,
    host: String,
    config: Arc<rustls::ServerConfig>,
) -> Result<()> {
    use hyper::{
        server::conn::{http1, http2},
        service::service_fn,
    };
    use hyper_util::rt::{TokioExecutor, TokioIo};
    let upgraded = timeout(Duration::from_secs(10), upgrade).await??;
    let tls = timeout(
        Duration::from_secs(10),
        TlsAcceptor::from(config).accept(TokioIo::new(upgraded)),
    )
    .await??;
    ensure!(
        tls.get_ref()
            .1
            .server_name()
            .is_some_and(|s| s.eq_ignore_ascii_case(&host)),
        "SNI authority mismatch"
    );
    let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let lifetime = Duration::from_hours(1);
    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
        let state = Arc::clone(&state);
        let host = host.clone();
        async move {
            let response = if request
                .headers()
                .contains_key(http::header::PROXY_AUTHORIZATION)
            {
                denied()
            } else {
                match crate::proxy::prepare_tunneled_request(request, &host, None) {
                    Ok(request) => handle(&state, request).await,
                    Err(response) => *response,
                }
            };
            Ok::<_, Infallible>(response)
        }
    });
    match alpn.as_deref() {
        Some(b"h2") => {
            timeout(
                lifetime,
                http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service),
            )
            .await??;
        }
        Some(b"http/1.1") | None => {
            timeout(
                lifetime,
                http1::Builder::new().serve_connection(TokioIo::new(tls), service),
            )
            .await??;
        }
        _ => bail!("unsupported TLS application protocol"),
    }
    Ok(())
}
async fn handle(state: &Gateway, request: Request) -> Response {
    if let Ok(response) = forward(state, request).await {
        response
    } else {
        tracing::warn!(outcome = "gateway_request_denied", "gateway request denied");
        denied()
    }
}

#[allow(clippy::too_many_lines)]
async fn forward(state: &Gateway, request: Request) -> Result<Response> {
    let started = std::time::Instant::now();
    let permit = state.receipts.reserve()?;
    let mut attempt = Attempt {
        permit: Some(permit),
        started,
        receipt: DataPlaneReceipt {
            realm: state.config.realm.id.clone(),
            workload: state.config.workload.clone(),
            capability: "denied".into(),
            service: "denied".into(),
            destination: "denied.invalid".into(),
            method: "DENIED".into(),
            path: "/denied".into(),
            status: Some(403),
            delivered_bytes: 0,
            elapsed_ms: 0,
            outcome: ReceiptOutcome::Denied,
        },
    };
    let (parts, body) = request.into_parts();
    ensure!(
        !parts.headers.contains_key(http::header::UPGRADE)
            && parts.method != Method::CONNECT
            && !parts
                .headers
                .contains_key(http::header::PROXY_AUTHORIZATION),
        "unsupported protocol or identity override"
    );
    let target = reqwest::Url::parse(&parts.uri.to_string())
        .map_err(|_| anyhow::anyhow!("invalid target"))?;
    let host = target.host_str().context("missing destination")?;
    ensure!(
        target.username().is_empty() && target.password().is_none() && target.fragment().is_none(),
        "target userinfo denied"
    );
    ensure!(
        matches!(
            (target.scheme(), target.port_or_known_default()),
            ("https", Some(443)) | ("http", Some(80))
        ),
        "transport denied"
    );
    crate::proxy::validate_request_authority(&parts.headers, &target)?;
    // Reject encoded separators/dot segments rather than disagreeing with upstream routing.
    let path = parts.uri.path();
    ensure!(
        path == target.path()
            && !path.contains('\\')
            && !path.split('/').any(|s| matches!(s, "." | "..")),
        "ambiguous path denied"
    );
    let route = state
        .config
        .routes
        .iter()
        .find(|r| {
            r.host == host
                && r.scheme == target.scheme()
                && r.methods.iter().any(|m| m == parts.method.as_str())
                && r.matches_path(path)
                && (r.allow_query || target.query().is_none())
        })
        .context("operation denied")?;
    for segment in path.split('/') {
        let decoded = percent_encoding::percent_decode_str(segment)
            .decode_utf8()
            .map_err(|_| anyhow::anyhow!("invalid path encoding"))?;
        ensure!(
            !decoded.contains(['/', '\\'])
                && !decoded.chars().any(char::is_control)
                && !matches!(decoded.as_ref(), "." | ".."),
            "ambiguous encoded path denied"
        );
    }
    attempt.receipt.capability.clone_from(&route.name);
    attempt.receipt.service.clone_from(&route.name);
    attempt.receipt.destination.clone_from(&route.host);
    attempt.receipt.method = parts.method.to_string();
    attempt.receipt.path = format!("/capability/{}", route.name);
    crate::proxy::enforce_content_length(&parts.headers, route.max_request_bytes, "request")?;
    let mut headers = HeaderMap::new();
    for (name, value) in crate::proxy::filtered_headers(&parts.headers)? {
        if sensitive(&name) {
            let sink = match &route.mediation {
                Mediation::Header { name: sink, .. } => name.as_str().eq_ignore_ascii_case(sink),
                Mediation::Basic { .. } => name == http::header::AUTHORIZATION,
                Mediation::Forward => false,
            };
            ensure!(
                sink || route
                    .caller_headers
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(name.as_str())),
                "caller credential header denied"
            );
        }
        headers.append(name, value);
    }
    ensure!(
        !parts.headers.contains_key(http::header::CONTENT_ENCODING),
        "encoded uploads unsupported"
    );
    headers.insert(
        http::header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    let mut addresses = timeout(
        Duration::from_secs(10)
            .min(Duration::from_secs(route.max_duration_seconds).saturating_sub(started.elapsed())),
        state.resolver.resolve(host.parse()?),
    )
    .await
    .map_err(|_| anyhow::anyhow!("DNS authorization timed out"))?
    .map_err(|_| anyhow::anyhow!("destination address denied"))?;
    ensure!(addresses.next().is_some(), "destination address denied");
    let mut protected = Vec::new();
    match &route.mediation {
        Mediation::Forward => {}
        Mediation::Header {
            secret_ref,
            name,
            value_template,
        } => {
            let reference = format!("{{{{charon.{}}}}}", route.name);
            let expected = value_template.replace("{secret}", &reference);
            ensure!(
                parts.headers.get(name).and_then(|v| v.to_str().ok()) == Some(expected.as_str())
                    && headers.contains_key(name),
                "typed capability reference required"
            );
            let secret = timeout(
                Duration::from_secs(route.max_duration_seconds).saturating_sub(started.elapsed()),
                state.secrets.resolve(&SecretRef::from_policy(secret_ref)),
            )
            .await
            .map_err(|_| anyhow::anyhow!("credential mediation timed out"))??;
            ensure!(
                (8..=16384).contains(&secret.expose_secret().len()),
                "credential bound violated"
            );
            let rendered = crate::broker::render_secret(value_template, &secret)?;
            headers.insert(
                name.parse::<HeaderName>()?,
                HeaderValue::from_str(rendered.expose_secret())
                    .map_err(|_| anyhow::anyhow!("invalid credential header"))?,
            );
            protected.extend([secret, rendered]);
        }
        Mediation::Basic {
            secret_ref,
            username,
        } => {
            let reference = format!("{{{{charon.{}}}}}", route.name);
            let expected = format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{reference}"))
            );
            ensure!(
                parts
                    .headers
                    .get(http::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    == Some(expected.as_str())
                    && headers.contains_key(http::header::AUTHORIZATION),
                "typed Basic capability required"
            );
            let secret = timeout(
                Duration::from_secs(route.max_duration_seconds).saturating_sub(started.elapsed()),
                state.secrets.resolve(&SecretRef::from_policy(secret_ref)),
            )
            .await
            .map_err(|_| anyhow::anyhow!("credential mediation timed out"))??;
            ensure!(
                (8..=16384).contains(&secret.expose_secret().len()),
                "credential bound violated"
            );
            let plain = SecretString::from(format!("{username}:{}", secret.expose_secret()));
            let rendered = SecretString::from(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(plain.expose_secret())
            ));
            headers.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_str(rendered.expose_secret())
                    .map_err(|_| anyhow::anyhow!("invalid credential header"))?,
            );
            protected.extend([secret, plain, rendered]);
        }
    }
    if !protected.is_empty() {
        for (name, value) in &mut headers {
            if sensitive(name) {
                value.set_sensitive(true);
            }
        }
    }
    let encodings = protected
        .iter()
        .flat_map(|v| {
            let raw = v.expose_secret();
            [
                SecretString::from(
                    url::form_urlencoded::byte_serialize(raw.as_bytes()).collect::<String>(),
                ),
                SecretString::from(base64::engine::general_purpose::STANDARD.encode(raw)),
                SecretString::from(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)),
            ]
        })
        .collect::<Vec<_>>();
    protected.extend(encodings);
    let upload = guard_stream(
        body.into_data_stream(),
        route.max_request_bytes,
        Duration::from_secs(route.max_duration_seconds),
        Duration::from_secs(route.idle_timeout_seconds),
    );
    let remaining =
        Duration::from_secs(route.max_duration_seconds).saturating_sub(started.elapsed());
    let response = timeout(
        remaining,
        state
            .client
            .request(parts.method.clone(), target)
            .headers(headers)
            .body(reqwest::Body::wrap_stream(upload))
            .send(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("request timed out"))?
    .map_err(|_| anyhow::anyhow!("upstream unavailable"))?;
    ensure!(
        response.status() != StatusCode::SWITCHING_PROTOCOLS,
        "upstream upgrade denied"
    );
    crate::proxy::enforce_content_length(response.headers(), route.max_response_bytes, "response")?;
    for encoding in response.headers().get_all(http::header::CONTENT_ENCODING) {
        ensure!(
            encoding
                .to_str()
                .is_ok_and(|v| v.eq_ignore_ascii_case("identity")),
            "compressed response denied"
        );
    }
    let mut downstream = Response::builder().status(response.status());
    for (name, value) in crate::proxy::filtered_headers(response.headers())? {
        if session(&name)
            && !route
                .session_response_headers
                .iter()
                .any(|n| n.eq_ignore_ascii_case(name.as_str()))
        {
            continue;
        }
        ensure!(
            !protected.iter().any(|s| value
                .as_bytes()
                .windows(s.expose_secret().len())
                .any(|w| w == s.expose_secret().as_bytes())),
            "protected response header denied"
        );
        downstream = downstream.header(name, value);
    }
    let status = response.status().as_u16();
    let remaining =
        Duration::from_secs(route.max_duration_seconds).saturating_sub(started.elapsed());
    let guarded = guard_stream(
        response.bytes_stream(),
        route.max_response_bytes,
        remaining,
        Duration::from_secs(route.idle_timeout_seconds),
    );
    let sanitized = redact_text_stream(guarded, protected, route.max_response_bytes);
    // Path is a policy identifier, never an untrusted URL or token-bearing path.
    let receipt = DataPlaneReceipt {
        realm: state.config.realm.id.clone(),
        workload: state.config.workload.clone(),
        capability: route.name.clone(),
        service: route.name.clone(),
        destination: route.host.clone(),
        method: parts.method.to_string(),
        path: format!("/capability/{}", route.name),
        status: Some(status),
        delivered_bytes: 0,
        elapsed_ms: 0,
        outcome: ReceiptOutcome::Interrupted,
    };
    Ok(downstream.body(Body::from_stream(receipt_stream(
        sanitized,
        attempt.permit.take().context("receipt reservation lost")?,
        receipt,
        started,
    )))?)
}

struct Attempt {
    permit: Option<crate::receipt::ReceiptPermit>,
    receipt: DataPlaneReceipt,
    started: std::time::Instant,
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            self.receipt.elapsed_ms =
                u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
            permit.record(self.receipt.clone());
        }
    }
}

#[cfg(test)]
#[path = "gateway_tests.rs"]
mod tests;
