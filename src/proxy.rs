//! Fail-closed HTTP credential injection data plane.

use std::{convert::Infallible, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use axum::{
    Router,
    body::{Body, Bytes},
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
use zeroize::Zeroize;

use crate::{
    config::{Config, ServicePolicy},
    identity::{AuthorizedWorkload, IDENTITY_HEADER, IdentityVerifier},
    provider::{SecretProvider, SecretRef},
    tls::TlsAuthority,
};

const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_TIMEOUT: Duration = Duration::from_mins(1);
const HOP_BY_HOP_HEADERS: [&str; 8] = [
    "connection",
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
        let mut builder = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30));
        if let Some(proxy) = &config.upstream_proxy {
            let mut reqwest_proxy =
                reqwest::Proxy::all(&proxy.url).context("invalid upstream proxy")?;
            if let (Some(username), Some(password_file)) = (&proxy.username, &proxy.password_file) {
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
        Ok(Self {
            config,
            client,
            secrets,
            identities,
            tls,
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
    (StatusCode::OK, axum::Json(readiness))
}

async fn forward(State(state): State<Arc<AppState>>, mut request: Request) -> Response {
    if request.method() == Method::CONNECT {
        return connect(state, &mut request);
    }
    match forward_inner(&state, request).await {
        Ok(response) => response,
        Err(error) => {
            warn!(error = %error, outcome = "proxy_error", "request denied");
            (StatusCode::BAD_GATEWAY, "request denied").into_response()
        }
    }
}

async fn forward_inner(state: &AppState, request: Request) -> Result<Response> {
    let (parts, body) = request.into_parts();
    let target = absolute_target(&parts.uri)?;
    if target.query().is_some() {
        warn!(
            method = %parts.method,
            outcome = "query_denied",
            "request denied"
        );
        return Ok((
            StatusCode::FORBIDDEN,
            "query parameters are not enabled by the capability model",
        )
            .into_response());
    }
    let host = target
        .host_str()
        .context("absolute target has no hostname")?;
    let Some(policy) = state.config.service_for_host(host) else {
        warn!(host, method = %parts.method, outcome = "host_denied", "request denied");
        return Ok((StatusCode::FORBIDDEN, "destination is not allowed").into_response());
    };
    if let Err(error) = enforce_content_length(&parts.headers, MAX_REQUEST_BODY_BYTES, "request") {
        warn!(
            service = policy.name,
            host,
            method = %parts.method,
            reason = %error,
            outcome = "request_size_denied",
            "request denied"
        );
        return Ok((StatusCode::PAYLOAD_TOO_LARGE, "request body is too large").into_response());
    }

    let identity = match authorize_workload(state, policy, &parts.headers, &parts.method, &target) {
        Ok(identity) => identity,
        Err(response) => return Ok(*response),
    };

    let injection_header: HeaderName = policy
        .header
        .parse()
        .context("configured injection header is invalid")?;
    let supplied = parts
        .headers
        .get(&injection_header)
        .and_then(|value| value.to_str().ok());
    if supplied != Some(policy.placeholder.as_str()) {
        warn!(
            service = policy.name,
            host,
            method = %parts.method,
            outcome = "placeholder_denied",
            "request denied"
        );
        return Ok((StatusCode::FORBIDDEN, "credential placeholder is missing").into_response());
    }

    let secret = state
        .secrets
        .resolve(&SecretRef::from_policy(&policy.secret_ref))
        .await?;
    let rendered = policy
        .value_template
        .replace("{secret}", secret.expose_secret());
    let injected =
        HeaderValue::from_str(&rendered).context("rendered credential is not a header")?;

    let mut upstream = state
        .client
        .request(parts.method.clone(), target.to_string());
    for (name, value) in filtered_headers(&parts.headers) {
        if name != injection_header {
            upstream = upstream.header(name, value);
        }
    }
    let request_body = reqwest::Body::wrap_stream(limited_stream(
        body.into_data_stream(),
        MAX_REQUEST_BODY_BYTES,
        "request body exceeds the configured limit",
    ));
    upstream = upstream
        .header(injection_header, injected)
        .body(request_body);

    let response = upstream.send().await.context("upstream request failed")?;
    let status = response.status();
    let response_headers = response.headers().clone();
    enforce_content_length(&response_headers, MAX_RESPONSE_BODY_BYTES, "response")?;
    let response_body = Body::from_stream(limited_stream(
        response.bytes_stream(),
        MAX_RESPONSE_BODY_BYTES,
        "upstream response exceeds the configured limit",
    ));

    audit_forwarded(
        state,
        &identity,
        policy,
        host,
        &parts.method,
        target.path(),
        status,
    );

    downstream_response(status, &response_headers, response_body)
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
    for (name, value) in filtered_headers(headers) {
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
                if let Err(error) = intercept(upgrade, state, prepared).await {
                    warn!(error = %error, outcome = "connect_closed", "CONNECT tunnel closed");
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
    if authority.port_u16() != Some(443) {
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "CONNECT requires explicit port 443").into_response(),
        ));
    }
    let host = authority.host().to_ascii_lowercase();
    if state.config.service_for_host(&host).is_none() {
        warn!(host, outcome = "connect_host_denied", "CONNECT denied");
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "CONNECT destination is not allowed").into_response(),
        ));
    }
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
            TUNNEL_TIMEOUT,
            http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), service),
        )
        .await
        .context("CONNECT HTTP/2 request timed out")?
        .context("decrypted HTTP/2 request failed")?,
        Some(b"http/1.1") | None => timeout(
            TUNNEL_TIMEOUT,
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
        Ok(request) => match forward_inner(state, request).await {
            Ok(response) => response,
            Err(error) => {
                warn!(error = %error, outcome = "tunneled_request_denied", "request denied");
                (StatusCode::BAD_GATEWAY, "request denied").into_response()
            }
        },
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
        .authorize(token, &state.config, &policy.name, method, target.path())
        .map_err(|error| {
            warn!(
                service = policy.name,
                host,
                method = %method,
                outcome = "identity_denied",
                reason = %error,
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
    if !matches!(target.scheme(), "http" | "https") {
        anyhow::bail!("only HTTP and HTTPS targets are supported");
    }
    Ok(target)
}

fn filtered_headers(headers: &HeaderMap) -> impl Iterator<Item = (&HeaderName, &HeaderValue)> {
    headers.iter().filter(|(name, _)| {
        !HOP_BY_HOP_HEADERS
            .iter()
            .any(|blocked| name.as_str().eq_ignore_ascii_case(blocked))
    })
}

#[cfg(test)]
mod tests {
    use axum::body::Bytes;
    use futures_util::{StreamExt as _, stream};

    use super::limited_stream;

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
}
