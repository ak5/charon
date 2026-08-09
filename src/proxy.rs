//! Fail-closed HTTP credential injection data plane.

use std::{collections::HashSet, convert::Infallible, net::IpAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::Engine as _;
use futures_util::{Stream, StreamExt as _};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    broker::{CapabilityReference, CompressionPolicy, HydrationSink, ResponseMode, render_secret},
    config::{Config, ServicePolicy},
    dns::PinnedResolver,
    identity::{AuthorizedWorkload, IDENTITY_HEADER, IdentityVerifier},
    provider::{SecretProvider, SecretRef, ensure_private_file},
    receipt::{DataPlaneReceipt, ReceiptJournal, ReceiptOutcome, receipt_stream},
    response::{
        guard_stream, redact_text_stream, sanitize_headers, sanitize_json_document,
        sanitize_structured_stream,
    },
    tls::TlsAuthority,
};

const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HOP_BY_HOP_HEADERS: [&str; 10] = [
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Shared, immutable proxy state.
pub struct AppState {
    config: Config,
    client: Client,
    secrets: Arc<dyn SecretProvider>,
    identities: IdentityVerifier,
    tls: Option<Arc<TlsAuthority>>,
    receipts: Option<ReceiptJournal>,
}

impl AppState {
    /// Construct validated runtime state.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid policy, upstream-proxy configuration, or
    /// HTTP client construction failure.
    pub fn new(config: Config, secrets: Arc<dyn SecretProvider>) -> Result<Self> {
        config.validate()?;
        let service_hosts = config
            .services
            .iter()
            .flat_map(|service| service.hosts.iter())
            .map(|host| host.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        let mut infrastructure_hosts = HashSet::new();
        if let Some(proxy) = &config.upstream_proxy
            && let Some(host) = reqwest::Url::parse(&proxy.url)?.host_str()
        {
            infrastructure_hosts.insert(host.to_ascii_lowercase());
        }
        let mut builder = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .dns_resolver(PinnedResolver::new(service_hosts, infrastructure_hosts));
        if let Some(proxy) = &config.upstream_proxy {
            let mut reqwest_proxy =
                reqwest::Proxy::all(&proxy.url).context("invalid upstream proxy")?;
            if let (Some(username), Some(password_file)) = (&proxy.username, &proxy.password_file) {
                ensure_private_file(password_file, "upstream proxy credential")?;
                let password = std::fs::read_to_string(password_file)
                    .context("upstream proxy credential is unavailable")?;
                if password.is_empty() || password.chars().any(char::is_whitespace) {
                    anyhow::bail!("upstream proxy credential is invalid");
                }
                let password = SecretString::from(password);
                reqwest_proxy = reqwest_proxy.basic_auth(username, password.expose_secret());
            }
            builder = builder.proxy(reqwest_proxy);
        }
        let client = builder
            .build()
            .context("failed to build upstream HTTP client")?;
        let identities = IdentityVerifier::new(&config)?;
        let tls = config
            .tls
            .as_ref()
            .map(TlsAuthority::load)
            .transpose()?
            .map(Arc::new);
        let receipts = config
            .receipts
            .as_ref()
            .map(ReceiptJournal::start)
            .transpose()?;
        Ok(Self {
            config,
            client,
            secrets,
            identities,
            tls,
            receipts,
        })
    }
}

/// Build the HTTP application.
pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/readyz", get(readiness))
        .fallback(forward)
        .with_state(state)
}

/// Serve one policy-bound transparent TLS listener.
///
/// Network routing must ensure that only the configured workload can reach the
/// listener and that direct egress is unavailable. The listener itself binds
/// one exact service before accepting TLS and rechecks SNI plus HTTP authority.
///
/// # Errors
///
/// Returns when the listener fails or the service/TLS policy is unavailable.
pub async fn serve_transparent(
    listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    service_name: String,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let service = state
        .config
        .services
        .iter()
        .find(|service| service.name == service_name)
        .context("transparent listener names an unknown service")?;
    let host = service
        .hosts
        .first()
        .context("transparent service has no exact hostname")?
        .clone();
    if service.hosts.len() != 1 {
        anyhow::bail!("transparent listeners require exactly one destination hostname");
    }
    let tls = state
        .tls
        .as_ref()
        .context("transparent interception requires a configured CA")?;
    let server_config = tls.server_config(&host)?;
    let connection_lifetime = Duration::from_secs(service.response.max_duration_seconds);

    let mut connections = tokio::task::JoinSet::new();
    loop {
        let accepted = tokio::select! {
            result = listener.accept() => Some(result.context("transparent accept failed")?),
            result = shutdown.changed() => {
                result.context("transparent shutdown channel closed")?;
                None
            }
        };
        let Some((stream, _)) = accepted else { break };
        let state = Arc::clone(&state);
        let host = host.clone();
        let server_config = Arc::clone(&server_config);
        connections.spawn(async move {
            if transparent_connection(stream, state, host, server_config, connection_lifetime)
                .await
                .is_err()
            {
                warn!(
                    outcome = "transparent_connection_closed",
                    "transparent connection closed"
                );
            }
        });
    }
    let drain = async { while connections.join_next().await.is_some() {} };
    if timeout(Duration::from_secs(10), drain).await.is_err() {
        connections.abort_all();
    }
    Ok(())
}

async fn transparent_connection(
    stream: tokio::net::TcpStream,
    state: Arc<AppState>,
    host: String,
    server_config: Arc<rustls::ServerConfig>,
    lifetime: Duration,
) -> Result<()> {
    use hyper::{
        server::conn::{http1, http2},
        service::service_fn,
    };
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let tls = timeout(
        TLS_HANDSHAKE_TIMEOUT,
        TlsAcceptor::from(server_config).accept(stream),
    )
    .await
    .context("transparent TLS handshake timed out")?
    .context("transparent TLS handshake failed")?;
    let connection = tls.get_ref().1;
    if !connection
        .server_name()
        .is_some_and(|name| name.eq_ignore_ascii_case(&host))
    {
        anyhow::bail!("transparent TLS SNI does not match the bound destination");
    }
    let alpn = connection.alpn_protocol().map(<[u8]>::to_vec);
    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
        let state = Arc::clone(&state);
        let host = host.clone();
        async move { Ok::<_, Infallible>(transparent_request(&state, request, &host).await) }
    });
    match alpn.as_deref() {
        Some(b"h2") => timeout(
            lifetime,
            http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), service),
        )
        .await
        .context("transparent HTTP/2 lifetime exceeded")?
        .context("transparent HTTP/2 connection failed")?,
        Some(b"http/1.1") | None => timeout(
            lifetime,
            http1::Builder::new().serve_connection(TokioIo::new(tls), service),
        )
        .await
        .context("transparent HTTP/1.1 lifetime exceeded")?
        .context("transparent HTTP/1.1 connection failed")?,
        Some(_) => anyhow::bail!("transparent TLS negotiated an unsupported protocol"),
    }
    Ok(())
}

async fn transparent_request(
    state: &AppState,
    request: hyper::Request<hyper::body::Incoming>,
    host: &str,
) -> Response {
    if let Ok(response) = transparent_request_inner(state, request, host).await {
        response
    } else {
        warn!(outcome = "transparent_request_denied", "request denied");
        (StatusCode::FORBIDDEN, "request denied").into_response()
    }
}

async fn transparent_request_inner(
    state: &AppState,
    request: hyper::Request<hyper::body::Incoming>,
    host: &str,
) -> Result<Response> {
    let authority = request
        .uri()
        .authority()
        .map(|value| value.host().to_owned())
        .or_else(|| {
            request
                .headers()
                .get(http::header::HOST)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<http::uri::Authority>().ok())
                .map(|value| value.host().to_owned())
        })
        .context("transparent request has no valid authority")?;
    if !authority.eq_ignore_ascii_case(host) {
        anyhow::bail!("transparent request authority disagrees with its listener");
    }
    if request.headers().contains_key(IDENTITY_HEADER) {
        anyhow::bail!("transparent clients must not supply proxy identity");
    }
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let absolute: Uri = format!("https://{host}{path}").parse()?;
    let method = request.method().clone();
    let (mut parts, incoming) = request.into_parts();
    parts.uri = absolute;
    let mut body = Body::new(incoming);
    let policy = state
        .config
        .service_for_host(host)
        .context("transparent destination policy disappeared")?;
    let capability_name = extract_capability(policy, &parts.headers, &parts.uri, &mut body).await?;
    let capability = state
        .config
        .capability(&capability_name)
        .context("capability reference is unknown")?;
    let target = absolute_target(&parts.uri)?;
    let authorized_path = authorization_path(policy, &target)?;
    if capability.service != policy.name
        || capability.persona != state.config.realm.persona
        || !capability
            .methods
            .iter()
            .any(|item| item == method.as_str())
        || !capability.paths.iter().any(|item| item == &authorized_path)
    {
        anyhow::bail!("transparent capability does not authorize this request");
    }
    let identity = AuthorizedWorkload {
        workload: state.config.realm.id.clone(),
        tenant: state.config.realm.tenant.clone(),
        persona: state.config.realm.persona.clone(),
        workspace: state.config.realm.id.clone(),
        lease: format!("generation-{}", state.config.realm.generation),
        operation: "transparent-independent".into(),
        capability: capability_name,
    };
    forward_inner_as(state, Request::from_parts(parts, body), Some(identity)).await
}

fn authorization_path(policy: &ServicePolicy, target: &reqwest::Url) -> Result<String> {
    let HydrationSink::PathComponent { index } = &policy.hydration.sink else {
        return Ok(target.path().to_owned());
    };
    let mut segments = target
        .path_segments()
        .context("target URL has no path segments")?
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let segment = segments
        .get_mut(*index)
        .context("configured path component is absent")?;
    let decoded = percent_encoding::percent_decode_str(segment)
        .decode_utf8()
        .context("path component is not UTF-8")?;
    if decoded.contains(['/', '\0']) {
        anyhow::bail!("decoded path component is ambiguous");
    }
    *segment = decoded.into_owned();
    Ok(format!("/{}", segments.join("/")))
}

#[derive(Serialize)]
struct Readiness {
    status: &'static str,
    realm: String,
    tenant: String,
    persona: String,
    generation: u64,
}

async fn readiness(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let readiness = Readiness {
        status: "ready",
        realm: state.config.realm.id.clone(),
        tenant: state.config.realm.tenant.clone(),
        persona: state.config.realm.persona.clone(),
        generation: state.config.realm.generation,
    };
    if state.secrets.health().await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(Readiness {
                status: "unavailable",
                ..readiness
            }),
        );
    }
    if state
        .receipts
        .as_ref()
        .is_some_and(|journal| !journal.is_healthy())
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(Readiness {
                status: "unavailable",
                ..readiness
            }),
        );
    }
    (StatusCode::OK, axum::Json(readiness))
}

async fn forward(State(state): State<Arc<AppState>>, mut request: Request) -> Response {
    if request.method() == Method::CONNECT {
        return connect(state, &mut request);
    }
    if let Ok(response) = forward_inner(&state, request).await {
        response
    } else {
        warn!(outcome = "proxy_error", "request denied");
        (StatusCode::BAD_GATEWAY, "request denied").into_response()
    }
}

async fn forward_inner(state: &AppState, request: Request) -> Result<Response> {
    forward_inner_as(state, request, None).await
}

#[allow(clippy::too_many_lines)]
async fn forward_inner_as(
    state: &AppState,
    request: Request,
    authorized: Option<AuthorizedWorkload>,
) -> Result<Response> {
    let started = std::time::Instant::now();
    let receipt_permit = state
        .receipts
        .as_ref()
        .map(ReceiptJournal::reserve)
        .transpose()?;
    let (parts, mut body) = request.into_parts();
    let mut target = absolute_target(&parts.uri)?;
    validate_request_authority(&parts.headers, &target)?;
    if parts.headers.contains_key(http::header::UPGRADE) {
        return Ok((StatusCode::FORBIDDEN, "protocol upgrades are not enabled").into_response());
    }
    let host = target
        .host_str()
        .context("absolute target has no hostname")?
        .to_owned();
    let Some(policy) = state.config.service_for_host(&host) else {
        warn!(host, method = %parts.method, outcome = "host_denied", "request denied");
        return Ok((StatusCode::FORBIDDEN, "destination is not allowed").into_response());
    };
    if target.query().is_some()
        && !matches!(policy.hydration.sink, HydrationSink::QueryParameter { .. })
    {
        return Ok((
            StatusCode::FORBIDDEN,
            "query parameters are not enabled by the capability model",
        )
            .into_response());
    }
    if let HydrationSink::QueryParameter { name } = &policy.hydration.sink {
        let pairs = target.query_pairs().collect::<Vec<_>>();
        if pairs.len() != 1 || pairs[0].0 != name.as_str() {
            return Ok(
                (StatusCode::FORBIDDEN, "query request shape is not allowed").into_response(),
            );
        }
    }
    if let Some(response) = request_size_denial(&parts.headers, policy, &host, &parts.method) {
        return Ok(response);
    }

    let public_path = authorization_path(policy, &target)?;
    let identity = match authorized {
        Some(identity) => identity,
        None => match authorize_workload(
            state,
            policy,
            &parts.headers,
            &parts.method,
            &target,
            &public_path,
        ) {
            Ok(identity) => identity,
            Err(response) => return Ok(*response),
        },
    };

    let injection_header: Option<HeaderName> = match &policy.hydration.sink {
        HydrationSink::Authorization
        | HydrationSink::Basic { .. }
        | HydrationSink::GitSmartHttp { .. } => Some(http::header::AUTHORIZATION),
        HydrationSink::Header { name } => Some(
            name.parse()
                .context("configured injection header is invalid")?,
        ),
        HydrationSink::PathComponent { .. }
        | HydrationSink::QueryParameter { .. }
        | HydrationSink::JsonField { .. }
        | HydrationSink::FormField { .. } => None,
    };
    let reference = format!("{{{{charon.{}}}}}", identity.capability);
    CapabilityReference::parse(&reference)?;
    if !reference_is_present(policy, &parts.headers, &target, &mut body, &reference).await? {
        warn!(
            service = policy.name,
            host,
            method = %parts.method,
            outcome = "capability_reference_denied",
            "request denied"
        );
        return Ok((StatusCode::FORBIDDEN, "capability reference is missing").into_response());
    }

    let secret = state
        .secrets
        .resolve(&SecretRef::from_policy(&policy.secret_ref))
        .await?;
    if secret.expose_secret().len() > policy.response.max_secret_bytes {
        anyhow::bail!("resolved credential exceeds the configured bound");
    }
    let rendered = render_secret(&policy.hydration.value_template, &secret)?;
    let hydrated = hydrate_request(
        policy,
        &parts.headers,
        &mut target,
        &mut body,
        &reference,
        &rendered,
    )
    .await?;
    let injected_protected = hydrated
        .as_ref()
        .and_then(|(_, value)| value.to_str().ok())
        .map(|value| SecretString::from(value.to_owned()));

    let mut upstream = state
        .client
        .request(parts.method.clone(), target.to_string());
    for (name, value) in filtered_headers(&parts.headers)? {
        if injection_header.as_ref() != Some(&name) {
            if name == http::header::AUTHORIZATION {
                anyhow::bail!("caller-supplied Authorization is forbidden for this sink");
            }
            upstream = upstream.header(name, value);
        }
    }
    let request_body = reqwest::Body::wrap_stream(limited_stream(
        body.into_data_stream(),
        MAX_REQUEST_BODY_BYTES,
        "request body exceeds the configured limit",
    ));
    if matches!(
        policy.response.compression,
        CompressionPolicy::IdentityOnly | CompressionPolicy::Reject
    ) {
        upstream = upstream.header(http::header::ACCEPT_ENCODING, "identity");
    }
    if let Some((name, value)) = hydrated {
        upstream = upstream.header(name, value);
    }
    upstream = upstream
        .body(request_body)
        .timeout(Duration::from_secs(policy.response.max_duration_seconds));

    let response = upstream.send().await.context("upstream request failed")?;
    let status = response.status();
    let opaque = matches!(policy.response.body, ResponseMode::OpaqueStream { .. });
    let mut protected = vec![secret.clone(), rendered.clone()];
    if let Some(value) = injected_protected {
        protected.push(value);
    }
    let encoded = protected
        .iter()
        .flat_map(|value| {
            let raw = value.expose_secret();
            [
                SecretString::from(
                    url::form_urlencoded::byte_serialize(raw.as_bytes()).collect::<String>(),
                ),
                SecretString::from(base64::engine::general_purpose::STANDARD.encode(raw)),
                SecretString::from(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)),
            ]
        })
        .collect::<Vec<_>>();
    protected.extend(encoded);
    let response_headers = sanitize_headers(
        response.headers(),
        &protected,
        policy.response.compression,
        opaque,
    )?;
    enforce_content_length(&response_headers, policy.response.max_bytes, "response")?;
    if let ResponseMode::OpaqueStream { content_types } = &policy.response.body {
        let media_type = response_headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if !media_type.is_some_and(|value| content_types.iter().any(|item| item == value)) {
            anyhow::bail!("upstream content type is not allowed for opaque streaming");
        }
    }
    let guarded = guard_stream(
        response.bytes_stream(),
        policy.response.max_bytes,
        Duration::from_secs(policy.response.max_duration_seconds),
        Duration::from_secs(policy.response.idle_timeout_seconds),
    );
    let mut response_body = match &policy.response.body {
        ResponseMode::OpaqueStream { .. } | ResponseMode::TextStream => Body::from_stream(
            redact_text_stream(guarded, protected, policy.response.max_bytes),
        ),
        ResponseMode::StructuredStream {
            format,
            max_record_bytes,
            forbidden_fields,
        } => {
            let structured = sanitize_structured_stream(
                guarded,
                *format,
                *max_record_bytes,
                forbidden_fields.clone(),
            );
            Body::from_stream(redact_text_stream(
                structured,
                protected,
                policy.response.max_bytes,
            ))
        }
        ResponseMode::BufferedStructured {
            max_bytes,
            forbidden_fields,
        } => {
            let chunks = guarded.collect::<Vec<_>>().await;
            let mut complete = Vec::new();
            for chunk in chunks {
                complete.extend_from_slice(&chunk?);
            }
            if complete.len() > *max_bytes {
                complete.zeroize();
                anyhow::bail!("buffered structured response exceeds its configured limit");
            }
            let sanitized = sanitize_json_document(&complete, forbidden_fields)?;
            complete.zeroize();
            Body::from_stream(redact_text_stream(
                futures_util::stream::once(async move {
                    Ok::<_, std::io::Error>(Bytes::from(sanitized))
                }),
                protected,
                *max_bytes,
            ))
        }
    };

    if let Some(permit) = receipt_permit {
        let receipt = DataPlaneReceipt {
            realm: state.config.realm.id.clone(),
            workload: identity.workload.clone(),
            capability: identity.capability.clone(),
            service: policy.name.clone(),
            destination: host.clone(),
            method: parts.method.to_string(),
            path: public_path.clone(),
            status: Some(status.as_u16()),
            delivered_bytes: 0,
            elapsed_ms: 0,
            outcome: ReceiptOutcome::Interrupted,
        };
        response_body = Body::from_stream(receipt_stream(
            response_body.into_data_stream(),
            permit,
            receipt,
            started,
        ));
    }

    audit_forwarded(
        state,
        &identity,
        policy,
        &host,
        &parts.method,
        &public_path,
        status,
    );

    downstream_response(status, &response_headers, response_body)
}

fn request_size_denial(
    headers: &HeaderMap,
    policy: &ServicePolicy,
    host: &str,
    method: &Method,
) -> Option<Response> {
    enforce_content_length(headers, MAX_REQUEST_BODY_BYTES, "request").err()?;
    warn!(
        service = policy.name,
        host,
        method = %method,
        outcome = "request_size_denied",
        "request denied"
    );
    Some((StatusCode::PAYLOAD_TOO_LARGE, "request body is too large").into_response())
}

async fn reference_is_present(
    policy: &ServicePolicy,
    headers: &HeaderMap,
    target: &reqwest::Url,
    body: &mut Body,
    reference: &str,
) -> Result<bool> {
    require_hydration_content_type(policy, headers)?;
    let present = match &policy.hydration.sink {
        HydrationSink::Authorization | HydrationSink::Header { .. } => {
            let name = match &policy.hydration.sink {
                HydrationSink::Authorization => http::header::AUTHORIZATION,
                HydrationSink::Header { name } => name.parse()?,
                _ => unreachable!(),
            };
            let expected = policy
                .hydration
                .value_template
                .replace("{secret}", reference);
            headers.get(name).and_then(|value| value.to_str().ok()) == Some(expected.as_str())
        }
        HydrationSink::Basic { username } | HydrationSink::GitSmartHttp { username } => {
            basic_password(headers, username).as_deref() == Some(reference)
        }
        HydrationSink::PathComponent { index } => {
            target
                .path_segments()
                .and_then(|segments| segments.into_iter().nth(*index))
                .and_then(|value| {
                    percent_encoding::percent_decode_str(value)
                        .decode_utf8()
                        .ok()
                })
                .as_deref()
                == Some(reference)
        }
        HydrationSink::QueryParameter { name } => {
            let matches = target
                .query_pairs()
                .filter(|(candidate, value)| candidate == name && value == reference)
                .count();
            matches == 1
        }
        HydrationSink::JsonField { pointer } => {
            let bytes = take_bounded_body(body).await?;
            let value: serde_json::Value = serde_json::from_slice(&bytes)?;
            let present =
                value.pointer(pointer).and_then(serde_json::Value::as_str) == Some(reference);
            *body = Body::from(bytes);
            present
        }
        HydrationSink::FormField { name } => {
            let bytes = take_bounded_body(body).await?;
            let matches = url::form_urlencoded::parse(&bytes)
                .filter(|(candidate, value)| candidate == name && value == reference)
                .count();
            *body = Body::from(bytes);
            matches == 1
        }
    };
    Ok(present)
}

async fn extract_capability(
    policy: &ServicePolicy,
    headers: &HeaderMap,
    uri: &Uri,
    body: &mut Body,
) -> Result<String> {
    let target = absolute_target(uri)?;
    let candidate = match &policy.hydration.sink {
        HydrationSink::Authorization | HydrationSink::Header { .. } => {
            let name = match &policy.hydration.sink {
                HydrationSink::Authorization => http::header::AUTHORIZATION,
                HydrationSink::Header { name } => name.parse()?,
                _ => unreachable!(),
            };
            let supplied = headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .context("capability reference header is absent")?;
            extract_template_value(&policy.hydration.value_template, supplied)?
        }
        HydrationSink::Basic { username } | HydrationSink::GitSmartHttp { username } => {
            basic_password(headers, username).context("Basic capability reference is absent")?
        }
        HydrationSink::PathComponent { index } => {
            let segment = target
                .path_segments()
                .and_then(|segments| segments.into_iter().nth(*index))
                .context("path capability reference is absent")?;
            percent_encoding::percent_decode_str(segment)
                .decode_utf8()
                .context("path capability reference is not UTF-8")?
                .into_owned()
        }
        HydrationSink::QueryParameter { name } => {
            let values = target
                .query_pairs()
                .filter(|(candidate, _)| candidate == name)
                .map(|(_, value)| value.into_owned())
                .collect::<Vec<_>>();
            if values.len() != 1 {
                anyhow::bail!("query capability reference is ambiguous");
            }
            values[0].clone()
        }
        HydrationSink::JsonField { pointer } => {
            let bytes = take_bounded_body(body).await?;
            let value: serde_json::Value = serde_json::from_slice(&bytes)?;
            let candidate = value
                .pointer(pointer)
                .and_then(serde_json::Value::as_str)
                .context("JSON capability reference is absent")?
                .to_owned();
            *body = Body::from(bytes);
            candidate
        }
        HydrationSink::FormField { name } => {
            let bytes = take_bounded_body(body).await?;
            let values = url::form_urlencoded::parse(&bytes)
                .filter(|(candidate, _)| candidate == name)
                .map(|(_, value)| value.into_owned())
                .collect::<Vec<_>>();
            *body = Body::from(bytes);
            if values.len() != 1 {
                anyhow::bail!("form capability reference is ambiguous");
            }
            values[0].clone()
        }
    };
    let reference = CapabilityReference::parse(&candidate)?;
    Ok(reference.capability().to_owned())
}

fn extract_template_value(template: &str, supplied: &str) -> Result<String> {
    let (prefix, suffix) = template
        .split_once("{secret}")
        .context("credential template has no secret marker")?;
    let value = supplied
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .context("credential field does not match its formatting rule")?;
    Ok(value.to_owned())
}

#[allow(clippy::too_many_lines)]
async fn hydrate_request(
    policy: &ServicePolicy,
    headers: &HeaderMap,
    target: &mut reqwest::Url,
    body: &mut Body,
    reference: &str,
    rendered: &SecretString,
) -> Result<Option<(HeaderName, HeaderValue)>> {
    require_hydration_content_type(policy, headers)?;
    match &policy.hydration.sink {
        HydrationSink::Authorization => Ok(Some((
            http::header::AUTHORIZATION,
            HeaderValue::from_str(rendered.expose_secret())?,
        ))),
        HydrationSink::Header { name } => Ok(Some((
            name.parse()?,
            HeaderValue::from_str(rendered.expose_secret())?,
        ))),
        HydrationSink::Basic { username } | HydrationSink::GitSmartHttp { username } => {
            let password = rendered.expose_secret();
            let credentials = Zeroizing::new(format!("{username}:{password}"));
            let encoded = Zeroizing::new(
                base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes()),
            );
            let header = Zeroizing::new(format!("Basic {}", encoded.as_str()));
            Ok(Some((
                http::header::AUTHORIZATION,
                HeaderValue::from_str(header.as_str())?,
            )))
        }
        HydrationSink::PathComponent { index } => {
            let segments = target
                .path_segments()
                .context("target URL cannot contain path segments")?
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if segments
                .get(*index)
                .and_then(|value| {
                    percent_encoding::percent_decode_str(value)
                        .decode_utf8()
                        .ok()
                })
                .as_deref()
                != Some(reference)
            {
                anyhow::bail!("path capability reference changed during hydration");
            }
            let mut updated = segments;
            rendered.expose_secret().clone_into(&mut updated[*index]);
            target
                .path_segments_mut()
                .map_err(|()| anyhow::anyhow!("target URL cannot be hydrated"))?
                .clear()
                .extend(updated);
            Ok(None)
        }
        HydrationSink::QueryParameter { name } => {
            let pairs = target
                .query_pairs()
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<Vec<_>>();
            target.set_query(None);
            let mut serializer = target.query_pairs_mut();
            for (key, value) in pairs {
                if key == *name && value == reference {
                    serializer.append_pair(&key, rendered.expose_secret());
                } else {
                    serializer.append_pair(&key, &value);
                }
            }
            drop(serializer);
            Ok(None)
        }
        HydrationSink::JsonField { pointer } => {
            let mut bytes = take_bounded_body(body).await?.to_vec();
            let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
            bytes.zeroize();
            let field = value
                .pointer_mut(pointer)
                .context("configured JSON field is absent")?;
            *field = serde_json::Value::String(rendered.expose_secret().to_owned());
            let encoded = serde_json::to_vec(&value)?;
            zeroize_json_strings(&mut value);
            *body = Body::from(encoded);
            Ok(None)
        }
        HydrationSink::FormField { name } => {
            let mut bytes = take_bounded_body(body).await?.to_vec();
            let pairs = url::form_urlencoded::parse(&bytes)
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect::<Vec<_>>();
            bytes.zeroize();
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (key, value) in pairs {
                if key == *name && value == reference {
                    serializer.append_pair(&key, rendered.expose_secret());
                } else {
                    serializer.append_pair(&key, &value);
                }
            }
            let mut encoded = serializer.finish();
            *body = Body::from(encoded.as_bytes().to_vec());
            encoded.zeroize();
            Ok(None)
        }
    }
}

fn require_hydration_content_type(policy: &ServicePolicy, headers: &HeaderMap) -> Result<()> {
    let expected = match policy.hydration.sink {
        HydrationSink::JsonField { .. } => Some("application/json"),
        HydrationSink::FormField { .. } => Some("application/x-www-form-urlencoded"),
        _ => None,
    };
    let Some(expected) = expected else {
        return Ok(());
    };
    let actual = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    anyhow::ensure!(
        actual == Some(expected),
        "request content type is not allowed"
    );
    Ok(())
}

fn zeroize_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(value) => value.zeroize(),
        serde_json::Value::Array(values) => values.iter_mut().for_each(zeroize_json_strings),
        serde_json::Value::Object(values) => values.values_mut().for_each(zeroize_json_strings),
        _ => {}
    }
}

fn basic_password(headers: &HeaderMap, expected_username: &str) -> Option<String> {
    let encoded = headers
        .get(http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;
    let mut decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let separator = decoded.iter().position(|byte| *byte == b':')?;
    let username = std::str::from_utf8(&decoded[..separator]).ok()?;
    if username != expected_username {
        decoded.zeroize();
        return None;
    }
    let password = String::from_utf8(decoded[separator + 1..].to_vec()).ok();
    decoded.zeroize();
    password
}

async fn take_bounded_body(body: &mut Body) -> Result<Bytes> {
    let taken = std::mem::replace(body, Body::empty());
    to_bytes(taken, MAX_REQUEST_BODY_BYTES)
        .await
        .context("structured request body exceeds its configured limit")
}

fn audit_forwarded(
    state: &AppState,
    identity: &AuthorizedWorkload,
    policy: &ServicePolicy,
    host: &str,
    method: &Method,
    path: &str,
    status: StatusCode,
) {
    info!(
        workload = identity.workload,
        tenant = identity.tenant,
        persona = identity.persona,
        workspace = identity.workspace,
        lease = identity.lease,
        operation = identity.operation,
        realm = state.config.realm.id,
        generation = state.config.realm.generation,
        capability = identity.capability,
        service = policy.name,
        host,
        method = %method,
        path,
        status = status.as_u16(),
        outcome = "forwarded",
        "request forwarded"
    );
}

fn downstream_response(status: StatusCode, headers: &HeaderMap, body: Body) -> Result<Response> {
    let mut output = Response::builder().status(status);
    for (name, value) in filtered_headers(headers)? {
        output = output.header(name, value);
    }
    output
        .body(body)
        .context("failed to construct downstream response")
}

fn limited_stream<S, E>(
    stream: S,
    limit: usize,
    limit_message: &'static str,
) -> impl Stream<Item = std::io::Result<Bytes>>
where
    S: Stream<Item = std::result::Result<Bytes, E>>,
    E: std::fmt::Display,
{
    let mut received = 0_usize;
    stream.map(move |item| {
        let chunk = item.map_err(|_error| {
            warn!(outcome = "body_stream_error", "stream terminated");
            std::io::Error::other("body stream failed")
        })?;
        received = received
            .checked_add(chunk.len())
            .ok_or_else(|| std::io::Error::other(limit_message))?;
        if received > limit {
            warn!(outcome = "body_limit_exceeded", "stream terminated");
            return Err(std::io::Error::other(limit_message));
        }
        Ok(chunk)
    })
}

fn enforce_content_length(headers: &HeaderMap, limit: usize, kind: &str) -> Result<()> {
    let Some(value) = headers.get(http::header::CONTENT_LENGTH) else {
        return Ok(());
    };
    let length = value
        .to_str()
        .context("content-length is not valid text")?
        .parse::<u64>()
        .context("content-length is invalid")?;
    if length > limit as u64 {
        anyhow::bail!("{kind} body exceeds the configured limit");
    }
    Ok(())
}

fn connect(state: Arc<AppState>, request: &mut Request) -> Response {
    match prepare_connect(&state, request) {
        Ok(prepared) => {
            let upgrade = hyper::upgrade::on(request);
            tokio::spawn(async move {
                if intercept(upgrade, state, prepared).await.is_err() {
                    warn!(outcome = "connect_closed", "CONNECT tunnel closed");
                }
            });
            StatusCode::OK.into_response()
        }
        Err(response) => {
            warn!(
                status = response.status().as_u16(),
                outcome = "connect_denied",
                "CONNECT denied"
            );
            *response
        }
    }
}

struct PreparedConnect {
    host: String,
    token: SecretString,
    server_config: Arc<rustls::ServerConfig>,
    lifetime: Duration,
}

fn prepare_connect(
    state: &AppState,
    request: &Request,
) -> std::result::Result<PreparedConnect, Box<Response>> {
    let Some(authority) = request.uri().authority() else {
        return Err(Box::new(
            (StatusCode::BAD_REQUEST, "CONNECT authority is required").into_response(),
        ));
    };
    if let Some(host) = request
        .headers()
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<http::uri::Authority>().ok())
        && !same_tls_authority(authority, &host)
    {
        return Err(Box::new(
            (
                StatusCode::MISDIRECTED_REQUEST,
                "CONNECT authority mismatch",
            )
                .into_response(),
        ));
    }
    if authority.port_u16() != Some(443) {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "CONNECT requires explicit port 443").into_response(),
        ));
    }
    let host = authority.host().to_ascii_lowercase();
    let Some(service) = state.config.service_for_host(&host) else {
        warn!(host, outcome = "connect_host_denied", "CONNECT denied");
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "CONNECT destination is not allowed").into_response(),
        ));
    };
    let token = identity_token(request.headers()).ok_or_else(|| {
        Box::new((StatusCode::UNAUTHORIZED, "workload identity is required").into_response())
    })?;
    let tls = state.tls.as_ref().ok_or_else(|| {
        Box::new(
            (
                StatusCode::NOT_IMPLEMENTED,
                "CONNECT interception is not configured",
            )
                .into_response(),
        )
    })?;
    let server_config = tls.server_config(&host).map_err(|_| {
        Box::new(
            (
                StatusCode::BAD_GATEWAY,
                "CONNECT certificate issuance failed",
            )
                .into_response(),
        )
    })?;
    Ok(PreparedConnect {
        host,
        token,
        server_config,
        lifetime: Duration::from_secs(service.response.max_duration_seconds),
    })
}

async fn intercept(
    upgrade: hyper::upgrade::OnUpgrade,
    state: Arc<AppState>,
    prepared: PreparedConnect,
) -> Result<()> {
    use hyper::{
        server::conn::{http1, http2},
        service::service_fn,
    };
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let upgraded = timeout(TLS_HANDSHAKE_TIMEOUT, upgrade)
        .await
        .context("CONNECT upgrade timed out")?
        .context("CONNECT upgrade failed")?;
    let tls = timeout(
        TLS_HANDSHAKE_TIMEOUT,
        TlsAcceptor::from(prepared.server_config).accept(TokioIo::new(upgraded)),
    )
    .await
    .context("TLS handshake timed out")?
    .context("TLS handshake failed")?;
    let connection = tls.get_ref().1;
    let sni = connection.server_name().unwrap_or_default();
    if !sni.eq_ignore_ascii_case(&prepared.host) {
        anyhow::bail!("TLS SNI does not match CONNECT authority");
    }
    let alpn = connection.alpn_protocol().map(<[u8]>::to_vec);

    let used = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let host = prepared.host;
    let lifetime = prepared.lifetime;
    let token = Arc::new(prepared.token);
    let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
        let state = Arc::clone(&state);
        let host = host.clone();
        let token = Arc::clone(&token);
        let used = Arc::clone(&used);
        async move {
            let response = if used.swap(true, std::sync::atomic::Ordering::AcqRel) {
                (StatusCode::FORBIDDEN, "one request is allowed per CONNECT").into_response()
            } else {
                tunneled_request(&state, request, &host, token.expose_secret()).await
            };
            Ok::<_, Infallible>(response)
        }
    });
    match alpn.as_deref() {
        Some(b"h2") => timeout(
            lifetime,
            http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), service),
        )
        .await
        .context("CONNECT HTTP/2 request timed out")?
        .context("decrypted HTTP/2 request failed")?,
        Some(b"http/1.1") | None => timeout(
            lifetime,
            http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(tls), service),
        )
        .await
        .context("CONNECT HTTP/1.1 request timed out")?
        .context("decrypted HTTP/1.1 request failed")?,
        Some(_) => anyhow::bail!("TLS negotiated an unsupported application protocol"),
    }
    Ok(())
}

async fn tunneled_request(
    state: &AppState,
    request: hyper::Request<hyper::body::Incoming>,
    connect_host: &str,
    token: &str,
) -> Response {
    match prepare_tunneled_request(request, connect_host, token) {
        Ok(request) => {
            if let Ok(response) = forward_inner(state, request).await {
                response
            } else {
                warn!(outcome = "tunneled_request_denied", "request denied");
                (StatusCode::BAD_GATEWAY, "request denied").into_response()
            }
        }
        Err(response) => *response,
    }
}

fn prepare_tunneled_request(
    request: hyper::Request<hyper::body::Incoming>,
    connect_host: &str,
    token: &str,
) -> std::result::Result<Request, Box<Response>> {
    if request
        .uri()
        .scheme_str()
        .is_some_and(|scheme| scheme != "https")
    {
        return Err(Box::new(
            (StatusCode::MISDIRECTED_REQUEST, "TLS scheme mismatch").into_response(),
        ));
    }
    let uri_authority = request.uri().authority().cloned();
    let host_authority = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<http::uri::Authority>().ok());
    if let (Some(uri), Some(host)) = (&uri_authority, &host_authority)
        && !same_tls_authority(uri, host)
    {
        return Err(Box::new(
            (StatusCode::MISDIRECTED_REQUEST, "TLS authority mismatch").into_response(),
        ));
    }
    let authority = uri_authority.or(host_authority).ok_or_else(|| {
        Box::new((StatusCode::BAD_REQUEST, "valid TLS authority is required").into_response())
    })?;
    if !authority.host().eq_ignore_ascii_case(connect_host)
        || authority.port_u16().is_some_and(|port| port != 443)
    {
        return Err(Box::new(
            (StatusCode::MISDIRECTED_REQUEST, "TLS authority mismatch").into_response(),
        ));
    }
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let absolute = format!("https://{connect_host}{path}");
    let (mut parts, body) = request.into_parts();
    parts.uri = absolute.parse().map_err(|_| {
        Box::new((StatusCode::BAD_REQUEST, "request target is invalid").into_response())
    })?;
    let identity = HeaderValue::from_str(&format!("Charon {token}")).map_err(|_| {
        Box::new((StatusCode::UNAUTHORIZED, "workload identity is invalid").into_response())
    })?;
    parts.headers.insert(IDENTITY_HEADER, identity);
    Ok(Request::from_parts(parts, Body::new(body)))
}

fn same_tls_authority(left: &http::uri::Authority, right: &http::uri::Authority) -> bool {
    left.host().eq_ignore_ascii_case(right.host())
        && left.port_u16().unwrap_or(443) == right.port_u16().unwrap_or(443)
}

fn identity_token(headers: &HeaderMap) -> Option<SecretString> {
    let value = headers.get(IDENTITY_HEADER)?.to_str().ok()?;
    if let Some(token) = value.strip_prefix("Charon ") {
        return Some(SecretString::from(token.to_owned()));
    }
    let encoded = value.strip_prefix("Basic ")?;
    let mut decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let mut decoded_text = match String::from_utf8(std::mem::take(&mut decoded)) {
        Ok(value) => value,
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            return None;
        }
    };
    if !decoded_text.starts_with("charon:") {
        decoded_text.zeroize();
        return None;
    }
    let mut token = decoded_text.split_off("charon:".len());
    decoded_text.zeroize();
    if token.is_empty() {
        token.zeroize();
        return None;
    }
    Some(SecretString::from(token))
}

fn authorize_workload(
    state: &AppState,
    policy: &ServicePolicy,
    headers: &HeaderMap,
    method: &Method,
    target: &reqwest::Url,
    authorized_path: &str,
) -> std::result::Result<AuthorizedWorkload, Box<Response>> {
    let host = target.host_str().unwrap_or("invalid-host");
    let Some(token) = headers
        .get(IDENTITY_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Charon "))
    else {
        warn!(
            service = policy.name,
            host,
            method = %method,
            outcome = "identity_missing",
            "request denied"
        );
        return Err(Box::new(
            (StatusCode::UNAUTHORIZED, "workload identity is required").into_response(),
        ));
    };

    state
        .identities
        .authorize(token, &state.config, &policy.name, method, authorized_path)
        .map_err(|_error| {
            warn!(
                service = policy.name,
                host,
                method = %method,
                outcome = "identity_denied",
                "request denied"
            );
            Box::new(
                (
                    StatusCode::UNAUTHORIZED,
                    "workload identity is not authorized",
                )
                    .into_response(),
            )
        })
}

fn absolute_target(uri: &Uri) -> Result<reqwest::Url> {
    if uri.scheme().is_none() || uri.host().is_none() {
        anyhow::bail!("forward-proxy requests must use an absolute URI");
    }
    let target = reqwest::Url::parse(&uri.to_string()).context("invalid absolute target URI")?;
    if !target.username().is_empty() || target.password().is_some() {
        anyhow::bail!("target user information is forbidden");
    }
    let host = target
        .host_str()
        .context("absolute target has no hostname")?;
    let loopback_http = target.scheme() == "http"
        && host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if target.scheme() != "https" && !loopback_http {
        anyhow::bail!("credential-bearing targets require HTTPS");
    }
    if target.scheme() == "https" && target.port_or_known_default() != Some(443) {
        anyhow::bail!("HTTPS targets require port 443");
    }
    Ok(target)
}

fn validate_request_authority(headers: &HeaderMap, target: &reqwest::Url) -> Result<()> {
    let Some(value) = headers.get(http::header::HOST) else {
        return Ok(());
    };
    let authority: http::uri::Authority = value
        .to_str()
        .context("Host header is invalid")?
        .parse()
        .context("Host header authority is invalid")?;
    let target_host = target.host_str().context("target hostname is missing")?;
    let target_port = target.port_or_known_default();
    let authority_port = authority
        .port_u16()
        .or_else(|| (target.scheme() == "https").then_some(443))
        .or_else(|| (target.scheme() == "http").then_some(80));
    if !authority.host().eq_ignore_ascii_case(target_host) || authority_port != target_port {
        anyhow::bail!("Host header does not match the request target");
    }
    Ok(())
}

fn filtered_headers(headers: &HeaderMap) -> Result<Vec<(HeaderName, HeaderValue)>> {
    let mut blocked = HOP_BY_HOP_HEADERS
        .iter()
        .map(|name| HeaderName::from_static(name))
        .collect::<HashSet<_>>();
    for value in headers.get_all(http::header::CONNECTION) {
        for token in value
            .to_str()
            .context("Connection header is invalid")?
            .split(',')
        {
            let name: HeaderName = token
                .trim()
                .parse()
                .context("Connection header names an invalid field")?;
            blocked.insert(name);
        }
    }
    let mut filtered = Vec::new();
    for (name, value) in headers {
        if !blocked.contains(name) {
            filtered.push((name.clone(), value.clone()));
        }
    }
    Ok(filtered)
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, Bytes, to_bytes};
    use futures_util::{StreamExt as _, stream};
    use http::{HeaderMap, HeaderValue, Uri};

    use secrecy::{ExposeSecret as _, SecretString};

    use super::{
        absolute_target, filtered_headers, hydrate_request, limited_stream, reference_is_present,
        validate_request_authority,
    };
    use crate::{
        broker::HydrationSink,
        config::{HydrationPolicy, ResponsePolicy, ServicePolicy},
    };

    fn service(sink: HydrationSink) -> ServicePolicy {
        ServicePolicy {
            name: "fixture".into(),
            hosts: vec!["api.example.test".into()],
            hydration: HydrationPolicy {
                sink,
                value_template: "{secret}".into(),
            },
            secret_ref: "fixture/ref".into(),
            response: ResponsePolicy::text_stream(4096, 30, 5, 1024),
            transparent_listen: None,
        }
    }

    #[tokio::test]
    async fn counted_stream_allows_the_limit_and_errors_above_it() {
        let allowed = limited_stream(
            stream::iter([
                Ok::<_, std::io::Error>(Bytes::from_static(b"ab")),
                Ok(Bytes::from_static(b"cd")),
            ]),
            4,
            "limit",
        )
        .collect::<Vec<_>>()
        .await;
        assert!(allowed.iter().all(Result::is_ok));

        let denied = limited_stream(
            stream::iter([
                Ok::<_, std::io::Error>(Bytes::from_static(b"ab")),
                Ok(Bytes::from_static(b"cde")),
            ]),
            4,
            "limit",
        )
        .collect::<Vec<_>>()
        .await;
        assert!(denied[0].is_ok());
        assert!(denied[1].is_err());
    }

    #[test]
    fn remote_targets_require_https_on_the_default_port_without_userinfo() {
        let plaintext: Uri = "http://api.github.com/user"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(absolute_target(&plaintext).is_err());

        let alternate_port: Uri = "https://api.github.com:8443/user"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(absolute_target(&alternate_port).is_err());

        let userinfo: Uri = "https://user@api.github.com/user"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(absolute_target(&userinfo).is_err());

        let allowed: Uri = "https://api.github.com/user"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(absolute_target(&allowed).is_ok());

        let loopback: Uri = "http://127.0.0.1:8080/test"
            .parse()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(absolute_target(&loopback).is_ok());
    }

    #[test]
    fn conflicting_authority_and_connection_nominated_headers_are_removed() {
        let target = reqwest::Url::parse("https://api.github.com/user")
            .unwrap_or_else(|error| panic!("{error}"));
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("evil.example"));
        assert!(validate_request_authority(&headers, &target).is_err());

        headers.insert("host", HeaderValue::from_static("api.github.com"));
        headers.insert("connection", HeaderValue::from_static("x-remove"));
        headers.insert("x-remove", HeaderValue::from_static("attacker-controlled"));
        headers.insert("x-keep", HeaderValue::from_static("safe"));
        let filtered = filtered_headers(&headers).unwrap_or_else(|error| panic!("{error}"));
        assert!(
            filtered
                .iter()
                .all(|(name, _)| name != "host" && name != "connection" && name != "x-remove")
        );
        assert!(filtered.iter().any(|(name, _)| name == "x-keep"));
    }

    #[tokio::test]
    async fn hydrates_json_and_form_only_at_the_declared_field() {
        let reference = "{{charon.fixture}}";
        let rendered = SecretString::from("synthetic-value");
        let secret = SecretString::from("synthetic-value");
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        let mut target = reqwest::Url::parse("https://api.example.test/v1")
            .unwrap_or_else(|error| panic!("{error}"));

        let json = service(HydrationSink::JsonField {
            pointer: "/auth/token".into(),
        });
        let mut body = Body::from(r#"{"auth":{"token":"{{charon.fixture}}"},"keep":1}"#);
        assert!(
            reference_is_present(&json, &headers, &target, &mut body, reference)
                .await
                .unwrap_or(false)
        );
        hydrate_request(
            &json,
            &headers,
            &mut target,
            &mut body,
            reference,
            &rendered,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let output = to_bytes(body, 4096)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output)
                .unwrap_or_else(|error| panic!("{error}"))["auth"]["token"],
            secret.expose_secret()
        );

        let form = service(HydrationSink::FormField {
            name: "token".into(),
        });
        headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let mut form_body = Body::from("keep=1&token=%7B%7Bcharon.fixture%7D%7D");
        assert!(
            reference_is_present(&form, &headers, &target, &mut form_body, reference)
                .await
                .unwrap_or(false)
        );
        hydrate_request(
            &form,
            &headers,
            &mut target,
            &mut form_body,
            reference,
            &rendered,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        let output = to_bytes(form_body, 4096)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(&output[..], b"keep=1&token=synthetic-value");
    }

    #[tokio::test]
    async fn hydrates_basic_path_and_query_without_ambiguous_replacement() {
        use base64::Engine as _;

        let reference = "{{charon.fixture}}";
        let rendered = SecretString::from("synthetic-value");

        let basic = service(HydrationSink::Basic {
            username: "agent".into(),
        });
        let mut basic_headers = HeaderMap::new();
        basic_headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!("agent:{reference}"))
            ))
            .unwrap_or_else(|error| panic!("{error}")),
        );
        let mut target = reqwest::Url::parse("https://api.example.test/v1")
            .unwrap_or_else(|error| panic!("{error}"));
        let mut body = Body::empty();
        assert!(
            reference_is_present(&basic, &basic_headers, &target, &mut body, reference)
                .await
                .unwrap_or(false)
        );
        let (_, value) = hydrate_request(
            &basic,
            &basic_headers,
            &mut target,
            &mut body,
            reference,
            &rendered,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_or_else(|| panic!("Basic hydration must produce a header"));
        let encoded = value
            .to_str()
            .unwrap_or_else(|error| panic!("{error}"))
            .strip_prefix("Basic ")
            .unwrap_or_else(|| panic!("Basic prefix is missing"));
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap_or_else(|error| panic!("{error}")),
            b"agent:synthetic-value"
        );

        let path = service(HydrationSink::PathComponent { index: 1 });
        let mut path_target =
            reqwest::Url::parse("https://api.example.test/items/%7B%7Bcharon.fixture%7D%7D")
                .unwrap_or_else(|error| panic!("{error}"));
        let mut path_body = Body::empty();
        assert!(
            reference_is_present(
                &path,
                &HeaderMap::new(),
                &path_target,
                &mut path_body,
                reference
            )
            .await
            .unwrap_or(false)
        );
        hydrate_request(
            &path,
            &HeaderMap::new(),
            &mut path_target,
            &mut path_body,
            reference,
            &rendered,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(path_target.path(), "/items/synthetic-value");

        let query = service(HydrationSink::QueryParameter { name: "key".into() });
        let mut query_target =
            reqwest::Url::parse("https://api.example.test/v1?key=%7B%7Bcharon.fixture%7D%7D")
                .unwrap_or_else(|error| panic!("{error}"));
        let mut query_body = Body::empty();
        assert!(
            reference_is_present(
                &query,
                &HeaderMap::new(),
                &query_target,
                &mut query_body,
                reference,
            )
            .await
            .unwrap_or(false)
        );
        hydrate_request(
            &query,
            &HeaderMap::new(),
            &mut query_target,
            &mut query_body,
            reference,
            &rendered,
        )
        .await
        .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(query_target.query(), Some("key=synthetic-value"));
    }
}
