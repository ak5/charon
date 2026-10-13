//! HTTPS-only single-owner passkey enrollment, authentication, and vault unlock.
use crate::keepass::{KeePassStore, ensure_private_file};
use anyhow::{Result, ensure};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write as _,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use webauthn_rs::prelude::*;
use zeroize::Zeroize as _;

const TTL: Duration = Duration::from_secs(300);
const SESSION_TTL: Duration = Duration::from_secs(600);
const COOKIE: &str = "__Host-charon-admin";

/// Independent HTTPS admin listener; never reuse the interception CA key.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// HTTPS listener, separate from workload listeners.
    pub listen: SocketAddr,
    /// Exact stable HTTPS origin, including any nonstandard port.
    pub origin: String,
    /// Browser-trusted server certificate chain in PEM format.
    pub certificate: PathBuf,
    /// Private HTTPS server key, accessible only to Charon.
    pub private_key: PathBuf,
    /// Private file containing only public passkey registration data.
    pub passkeys_file: PathBuf,
    /// Optional private Telegram notifications and per-request approval prompts.
    pub telegram: Option<crate::telegram::TelegramConfig>,
}
impl AdminConfig {
    /// Validate a strict HTTPS origin and absolute storage paths.
    ///
    /// # Errors
    /// Rejects plaintext, user information, URL paths, or missing DNS origin.
    pub fn validate(&self) -> Result<()> {
        let origin = Url::parse(&self.origin)?;
        ensure!(
            origin.scheme() == "https"
                && origin.username().is_empty()
                && origin.password().is_none()
                && origin.query().is_none()
                && origin.fragment().is_none()
                && origin.path() == "/"
                && origin.host_str().is_some_and(crate::config::is_exact_host)
                && origin
                    .host_str()
                    .is_some_and(|h| h.parse::<std::net::IpAddr>().is_err()),
            "admin requires an exact HTTPS DNS origin"
        );
        ensure!(
            self.origin == origin.origin().ascii_serialization(),
            "admin origin must be canonical without a trailing slash"
        );
        ensure!(
            self.certificate.is_absolute()
                && self.private_key.is_absolute()
                && self.passkeys_file.is_absolute(),
            "admin paths must be absolute"
        );
        if let Some(telegram) = &self.telegram {
            telegram.validate()?;
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registrations {
    origin: String,
    owner: Uuid,
    keys: Vec<Passkey>,
}
enum Ceremony {
    Registration(PasskeyRegistration, Option<[u8; 32]>),
    Authentication(PasskeyAuthentication),
}
struct Pending {
    deadline: Instant,
    ceremony: Ceremony,
}
struct Runtime {
    registrations: Registrations,
    enrollment: Option<([u8; 32], Instant)>,
    pending: HashMap<String, Pending>,
    sessions: HashMap<[u8; 32], Instant>,
    rate_started: Instant,
    rate_count: u32,
}
/// Trusted admin state holds `WebAuthn` challenges server-side, never in browser tokens.
pub struct Admin {
    config: AdminConfig,
    webauthn: Webauthn,
    runtime: Mutex<Runtime>,
    store: Arc<KeePassStore>,
    telegram: Option<Arc<crate::telegram::Telegram>>,
}
impl Admin {
    /// Load public registrations or create one console-only, expiring setup code.
    ///
    /// # Errors
    /// Rejects invalid public state, insecure permissions, and mismatched origins.
    pub fn new(
        config: AdminConfig,
        store: Arc<KeePassStore>,
    ) -> Result<(Arc<Self>, Option<SecretString>)> {
        config.validate()?;
        let telegram = config
            .telegram
            .as_ref()
            .map(|t| crate::telegram::Telegram::new(t, &config.origin, store.clone()))
            .transpose()?;
        Self::load(config, store, telegram)
    }
    #[cfg(test)]
    pub(crate) fn new_for_e2e(
        config: AdminConfig,
        store: Arc<KeePassStore>,
        telegram: Arc<crate::telegram::Telegram>,
    ) -> Result<(Arc<Self>, Option<SecretString>)> {
        config.validate()?;
        Self::load(config, store, Some(telegram))
    }
    fn load(
        config: AdminConfig,
        store: Arc<KeePassStore>,
        telegram: Option<Arc<crate::telegram::Telegram>>,
    ) -> Result<(Arc<Self>, Option<SecretString>)> {
        let origin = Url::parse(&config.origin)?;
        let webauthn = WebauthnBuilder::new(
            origin
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("admin origin has no host"))?,
            &origin,
        )?
        .rp_name("Charon")
        .timeout(TTL)
        .build()?;
        let parent = config
            .passkeys_file
            .parent()
            .ok_or_else(|| anyhow::anyhow!("passkey directory missing"))?;
        let metadata = fs::symlink_metadata(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            ensure!(
                metadata.permissions().mode().trailing_zeros() >= 6,
                "passkey directory must be private"
            );
        }
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "passkey directory must be a real directory"
        );
        let registrations = match fs::symlink_metadata(&config.passkeys_file) {
            Ok(_) => {
                ensure_private_file(&config.passkeys_file, "passkey state")?;
                let bytes = fs::read(&config.passkeys_file)?;
                ensure!(bytes.len() <= 65536, "passkey state too large");
                let value: Registrations = serde_json::from_slice(&bytes)?;
                ensure!(
                    value.origin == config.origin
                        && !value.keys.is_empty()
                        && value.keys.len() <= 8,
                    "invalid passkey state"
                );
                value
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Registrations {
                origin: config.origin.clone(),
                owner: Uuid::new_v4(),
                keys: vec![],
            },
            Err(error) => return Err(error.into()),
        };
        let code = if registrations.keys.is_empty() {
            Some(SecretString::from(random_token()?))
        } else {
            None
        };
        let enrollment = code
            .as_ref()
            .map(|c| (digest(c.expose_secret()), Instant::now() + TTL));
        Ok((
            Arc::new(Self {
                config,
                webauthn,
                store,
                telegram,
                runtime: Mutex::new(Runtime {
                    registrations,
                    enrollment,
                    pending: HashMap::new(),
                    sessions: HashMap::new(),
                    rate_started: Instant::now(),
                    rate_count: 0,
                }),
            }),
            code,
        ))
    }
    /// Admin-only routes. Serve this router directly over TLS, separately from the proxy.
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new()
            .route(
                "/",
                get(|| async { Html(include_str!("admin/index.html")) }),
            )
            .route(
                "/admin.js",
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, "text/javascript")],
                        include_str!("admin/admin.js"),
                    )
                }),
            )
            .route(
                "/admin.css",
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, "text/css")],
                        include_str!("admin/admin.css"),
                    )
                }),
            )
            .route("/api/status", get(status))
            .route("/api/register/start", post(register_start))
            .route("/api/register/finish", post(register_finish))
            .route("/api/login/start", post(login_start))
            .route("/api/login/finish", post(login_finish))
            .route("/api/unlock", post(unlock))
            .route("/api/lock", post(lock))
            .route("/api/logout", post(logout))
            .layer(axum::extract::DefaultBodyLimit::max(16384))
            .layer(middleware::from_fn_with_state(self.clone(), protect))
            .with_state(self.clone())
    }
    /// Run the independent TLS listener with graceful shutdown.
    ///
    /// # Errors
    /// Rejects invalid TLS inputs and bind/server failures.
    pub async fn serve(self: Arc<Self>, handle: axum_server::Handle<SocketAddr>) -> Result<()> {
        ensure_private_file(&self.config.private_key, "admin TLS key")?;
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &self.config.certificate,
            &self.config.private_key,
        )
        .await?;
        let server = axum_server::bind_rustls(self.config.listen, tls)
            .handle(handle)
            .serve(self.router().into_make_service());
        if let Some(telegram) = &self.telegram {
            tokio::select! { result = server => result?, result = telegram.clone().run() => {result?; anyhow::bail!("Telegram channel stopped");} }
        } else {
            server.await?;
        }
        Ok(())
    }
    /// Shared local decision coordinator; no credential-store authority.
    pub fn approvals(&self) -> Option<Arc<crate::telegram::Telegram>> {
        self.telegram.clone()
    }
    fn session(&self, headers: &HeaderMap) -> Option<[u8; 32]> {
        let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
        let mut tokens = cookie
            .split(';')
            .filter_map(|v| v.trim().strip_prefix(&format!("{COOKIE}=")));
        let value = tokens.next()?;
        if tokens.next().is_some() {
            return None;
        }
        let hash = digest(value);
        let runtime = self.runtime.lock().ok()?;
        runtime
            .sessions
            .get(&hash)
            .filter(|expiry| **expiry > Instant::now())
            .map(|_| hash)
    }
    fn persist(&self, registrations: &Registrations) -> Result<()> {
        let path = &self.config.passkeys_file;
        let temporary = path.with_extension(format!("{}.new", random_token()?));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let result = (|| -> Result<()> {
            let mut file = options.open(&temporary)?;
            file.write_all(&serde_json::to_vec(registrations)?)?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            fs::File::open(
                path.parent()
                    .ok_or_else(|| anyhow::anyhow!("missing state directory"))?,
            )?
            .sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}
fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
fn random_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("randomness unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn denied() -> Response {
    (StatusCode::FORBIDDEN, "Request denied").into_response()
}
fn failed() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, "Operation unavailable").into_response()
}
fn cookie(token: &str) -> String {
    format!("{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=600")
}
fn secret_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<SecretString, D::Error> {
    String::deserialize(deserializer).map(SecretString::from)
}
async fn body<T: DeserializeOwned>(request: Request) -> Result<T> {
    ensure!(
        request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v == "application/json"),
        "JSON required"
    );
    let bytes = to_bytes(request.into_body(), 16384).await?;
    // Network frames can share Hyper's read buffer; do not reject valid requests.
    // Our owned parsing copy is zeroized, independently of transport buffers.
    let mut owned = zeroize::Zeroizing::new(bytes.to_vec());
    drop(bytes);
    let result = serde_json::from_slice(&owned);
    owned.zeroize();
    Ok(result?)
}
async fn protect(State(admin): State<Arc<Admin>>, request: Request, next: Next) -> Response {
    if request.method() != http::Method::GET {
        if request
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            != Some(admin.config.origin.as_str())
        {
            return secure_response(denied());
        }
        let Ok(mut runtime) = admin.runtime.lock() else {
            return secure_response(failed());
        };
        if runtime.rate_started.elapsed() >= Duration::from_secs(60) {
            runtime.rate_started = Instant::now();
            runtime.rate_count = 0;
        }
        runtime.rate_count += 1;
        if runtime.rate_count > 30 {
            return secure_response(
                (StatusCode::TOO_MANY_REQUESTS, "Try again later").into_response(),
            );
        }
    }
    secure_response(next.run(request).await)
}
fn secure_response(mut response: Response) -> Response {
    let headers = response.headers_mut();
    for (name, value) in [
        ("cache-control", "no-store"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("strict-transport-security", "max-age=31536000"),
        (
            "permissions-policy",
            "publickey-credentials-get=(self), publickey-credentials-create=(self)",
        ),
    ] {
        headers.insert(
            http::HeaderName::from_static(name),
            http::HeaderValue::from_static(value),
        );
    }
    response
}
async fn status(State(admin): State<Arc<Admin>>, headers: HeaderMap) -> Response {
    let enrolled = match admin.runtime.lock() {
        Ok(r) => !r.registrations.keys.is_empty(),
        Err(_) => return failed(),
    };
    let authenticated = admin.session(&headers).is_some();
    Json(serde_json::json!({"enrolled":enrolled,"authenticated":authenticated,"unlocked": authenticated && admin.store.health().is_ok()})).into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    #[serde(deserialize_with = "secret_string")]
    code: SecretString,
}
async fn register_start(State(admin): State<Arc<Admin>>, request: Request) -> Response {
    let session = admin.session(request.headers());
    let Ok(setup) = body::<Setup>(request).await else {
        return denied();
    };
    let Ok(mut r) = admin.runtime.lock() else {
        return failed();
    };
    r.pending.retain(|_, p| p.deadline > Instant::now());
    let initial = r.registrations.keys.is_empty();
    if initial {
        let Some((expected, deadline)) = r.enrollment else {
            return denied();
        };
        let actual = digest(setup.code.expose_secret());
        if deadline <= Instant::now()
            || expected
                .iter()
                .zip(actual)
                .fold(0u8, |a, (b, c)| a | (b ^ c))
                != 0
        {
            return denied();
        }
        if r.pending
            .values()
            .any(|p| matches!(p.ceremony, Ceremony::Registration(_, None)))
        {
            return denied();
        }
    } else if session.is_none() || r.registrations.keys.len() >= 8 {
        return denied();
    }
    if r.pending.len() >= 32 {
        return failed();
    }
    let excluded = Some(
        r.registrations
            .keys
            .iter()
            .map(|k| k.cred_id().clone())
            .collect(),
    );
    let Ok((challenge, state)) = admin.webauthn.start_passkey_registration(
        r.registrations.owner,
        "owner",
        "Charon owner",
        excluded,
    ) else {
        return failed();
    };
    let Ok(id) = random_token() else {
        return failed();
    };
    r.pending.insert(
        id.clone(),
        Pending {
            deadline: Instant::now() + TTL,
            ceremony: Ceremony::Registration(state, session),
        },
    );
    Json(serde_json::json!({"id":id,"options":challenge})).into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    id: String,
    credential: RegisterPublicKeyCredential,
}
async fn register_finish(State(admin): State<Arc<Admin>>, request: Request) -> Response {
    let session = admin.session(request.headers());
    let Ok(input) = body::<Registration>(request).await else {
        return denied();
    };
    let Ok(mut r) = admin.runtime.lock() else {
        return failed();
    };
    let Some(pending) = r.pending.remove(&input.id) else {
        return denied();
    };
    let Ceremony::Registration(state, bound_session) = pending.ceremony else {
        return denied();
    };
    if pending.deadline <= Instant::now()
        || r.registrations.keys.len() >= 8
        || bound_session != session
        || (bound_session.is_none() && !r.registrations.keys.is_empty())
    {
        return denied();
    }
    if bound_session.is_none()
        && r.enrollment
            .is_none_or(|(_, deadline)| deadline <= Instant::now())
    {
        return denied();
    }
    let Ok(key) = admin
        .webauthn
        .finish_passkey_registration(&input.credential, &state)
    else {
        return denied();
    };
    let mut updated = Registrations {
        origin: r.registrations.origin.clone(),
        owner: r.registrations.owner,
        keys: r.registrations.keys.clone(),
    };
    if updated.keys.iter().any(|k| k.cred_id() == key.cred_id()) {
        return denied();
    }
    updated.keys.push(key);
    if admin.persist(&updated).is_err() {
        return failed();
    }
    r.registrations = updated;
    r.enrollment = None;
    StatusCode::NO_CONTENT.into_response()
}
async fn login_start(State(admin): State<Arc<Admin>>) -> Response {
    let Ok(mut r) = admin.runtime.lock() else {
        return failed();
    };
    r.pending.retain(|_, p| p.deadline > Instant::now());
    r.sessions.retain(|_, e| *e > Instant::now());
    if r.registrations.keys.is_empty() || r.pending.len() >= 32 || r.sessions.len() >= 32 {
        return denied();
    }
    let Ok((challenge, state)) = admin
        .webauthn
        .start_passkey_authentication(&r.registrations.keys)
    else {
        return failed();
    };
    let Ok(id) = random_token() else {
        return failed();
    };
    r.pending.insert(
        id.clone(),
        Pending {
            deadline: Instant::now() + TTL,
            ceremony: Ceremony::Authentication(state),
        },
    );
    Json(serde_json::json!({"id":id,"options":challenge})).into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authentication {
    id: String,
    credential: PublicKeyCredential,
}
async fn login_finish(State(admin): State<Arc<Admin>>, request: Request) -> Response {
    let Ok(input) = body::<Authentication>(request).await else {
        return denied();
    };
    let Ok(mut r) = admin.runtime.lock() else {
        return failed();
    };
    let Some(pending) = r.pending.remove(&input.id) else {
        return denied();
    };
    let Ceremony::Authentication(state) = pending.ceremony else {
        return denied();
    };
    r.sessions.retain(|_, expiry| *expiry > Instant::now());
    if pending.deadline <= Instant::now() || r.sessions.len() >= 32 {
        return denied();
    }
    let Ok(result) = admin
        .webauthn
        .finish_passkey_authentication(&input.credential, &state)
    else {
        return denied();
    };
    let mut keys = r.registrations.keys.clone();
    for key in &mut keys {
        key.update_credential(&result);
    }
    let updated = Registrations {
        origin: r.registrations.origin.clone(),
        owner: r.registrations.owner,
        keys,
    };
    if admin.persist(&updated).is_err() {
        return failed();
    }
    let Ok(token) = random_token() else {
        return failed();
    };
    r.registrations = updated;
    r.sessions
        .insert(digest(&token), Instant::now() + SESSION_TTL);
    (
        [(header::SET_COOKIE, cookie(&token))],
        StatusCode::NO_CONTENT,
    )
        .into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Unlock {
    #[serde(deserialize_with = "secret_string")]
    password: SecretString,
}
async fn unlock(State(admin): State<Arc<Admin>>, request: Request) -> Response {
    if admin.session(request.headers()).is_none() {
        return denied();
    }
    let Ok(input) = body::<Unlock>(request).await else {
        return denied();
    };
    let password = input.password;
    let store = admin.store.clone();
    match tokio::task::spawn_blocking(move || store.unlock(password)).await {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        _ => (StatusCode::FORBIDDEN, "Unable to unlock vault").into_response(),
    }
}
async fn lock(State(admin): State<Arc<Admin>>, headers: HeaderMap) -> Response {
    if admin.session(&headers).is_none() {
        return denied();
    }
    if admin.store.lock().is_err() {
        return failed();
    }
    StatusCode::NO_CONTENT.into_response()
}
async fn logout(State(admin): State<Arc<Admin>>, headers: HeaderMap) -> Response {
    if let Some(session) = admin.session(&headers)
        && let Ok(mut r) = admin.runtime.lock()
    {
        r.sessions.remove(&session);
    }
    (
        [(
            header::SET_COOKIE,
            format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"),
        )],
        StatusCode::NO_CONTENT,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use keepass::{
        Database, DatabaseKey,
        db::{EntryId, fields},
    };
    use serde_json::{Value, json};
    use tower::ServiceExt as _;
    use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
    struct Fixture {
        directory: tempfile::TempDir,
        admin: Arc<Admin>,
        code: SecretString,
    }
    impl Fixture {
        fn new() -> Result<Self> {
            let directory = tempfile::tempdir()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
            }
            let mut config = crate::test_support::config("developer");
            config.items.truncate(1);
            config.database = directory.path().join("synthetic.kdbx");
            let mut db = Database::new();
            {
                let mut root = db.root_mut();
                let mut entry = root.add_entry_with_id(EntryId::from_uuid(Uuid::parse_str(
                    &config.items[0].entry_id,
                )?))?;
                entry.set_protected(fields::PASSWORD, "synthetic-entry-value");
            }
            db.save(
                &mut fs::File::create(&config.database)?,
                DatabaseKey::new().with_password("synthetic-master"),
            )?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&config.database, fs::Permissions::from_mode(0o600))?;
            }
            let config = AdminConfig {
                listen: "127.0.0.1:8444".parse()?,
                origin: "https://charon.example.test".into(),
                certificate: directory.path().join("cert.pem"),
                private_key: directory.path().join("key.pem"),
                passkeys_file: directory.path().join("passkeys.json"),
                telegram: None,
            };
            let (admin, code) = Admin::new(
                config,
                Arc::new(KeePassStore::new(config_for_store(&directory))?),
            )?;
            Ok(Self {
                directory,
                admin,
                code: code.ok_or_else(|| anyhow::anyhow!("missing setup code"))?,
            })
        }
    }
    fn config_for_store(directory: &tempfile::TempDir) -> crate::config::KeePassConfig {
        let mut config = crate::test_support::config("developer");
        config.items.truncate(1);
        config.database = directory.path().join("synthetic.kdbx");
        config
    }
    async fn post(
        admin: &Arc<Admin>,
        path: &str,
        value: Value,
        session: Option<&str>,
        origin: Option<&str>,
    ) -> Result<Response> {
        let mut request = http::Request::builder()
            .method("POST")
            .uri(format!("/api/{path}"))
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        if let Some(session) = session {
            request = request.header(header::COOKIE, session);
        }
        Ok(admin
            .router()
            .oneshot(request.body(Body::from(serde_json::to_vec(&value)?))?)
            .await?)
    }
    async fn value(response: Response) -> Result<Value> {
        Ok(serde_json::from_slice(
            &to_bytes(response.into_body(), 16384).await?,
        )?)
    }
    async fn enroll(
        admin: &Arc<Admin>,
        auth: &mut WebauthnAuthenticator<SoftPasskey>,
        code: &str,
        session: Option<&str>,
    ) -> Result<Value> {
        let start = post(
            admin,
            "register/start",
            json!({"code":code}),
            session,
            Some(&admin.config.origin),
        )
        .await?;
        assert_eq!(start.status(), StatusCode::OK);
        let start = value(start).await?;
        let credential = auth.do_registration(
            Url::parse(&admin.config.origin)?,
            serde_json::from_value(start["options"].clone())?,
        )?;
        let finish = json!({"id":start["id"],"credential":credential});
        let response = post(
            admin,
            "register/finish",
            finish.clone(),
            session,
            Some(&admin.config.origin),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        Ok(finish)
    }
    async fn login(
        admin: &Arc<Admin>,
        auth: &mut WebauthnAuthenticator<SoftPasskey>,
    ) -> Result<String> {
        let start = value(
            post(
                admin,
                "login/start",
                json!({}),
                None,
                Some(&admin.config.origin),
            )
            .await?,
        )
        .await?;
        let credential = auth.do_authentication(
            Url::parse(&admin.config.origin)?,
            serde_json::from_value(start["options"].clone())?,
        )?;
        let finish = json!({"id":start["id"],"credential":credential});
        let response = post(
            admin,
            "login/finish",
            finish.clone(),
            None,
            Some(&admin.config.origin),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .ok_or_else(|| anyhow::anyhow!("missing cookie"))?
            .to_str()?
            .to_owned();
        assert!(cookie.contains("Secure; HttpOnly; SameSite=Strict"));
        assert_eq!(
            post(
                admin,
                "login/finish",
                finish,
                None,
                Some(&admin.config.origin)
            )
            .await?
            .status(),
            StatusCode::FORBIDDEN
        );
        Ok(cookie
            .split(';')
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty cookie"))?
            .into())
    }
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn passkey_enrollment_login_unlock_recovery_and_restart() -> Result<()> {
        let fixture = Fixture::new()?;
        let admin = &fixture.admin;
        let mut auth = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let replay = enroll(admin, &mut auth, fixture.code.expose_secret(), None).await?;
        assert_eq!(
            post(
                admin,
                "register/finish",
                replay,
                None,
                Some(&admin.config.origin)
            )
            .await?
            .status(),
            StatusCode::FORBIDDEN
        );
        let session = login(admin, &mut auth).await?;
        assert_eq!(
            post(
                admin,
                "unlock",
                json!({"password":"synthetic-master"}),
                None,
                Some(&admin.config.origin)
            )
            .await?
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(
                admin,
                "unlock",
                json!({"password":"synthetic-master"}),
                Some(&session),
                Some("https://other.example.test")
            )
            .await?
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(
                admin,
                "unlock",
                json!({"password":"wrong-synthetic"}),
                Some(&session),
                Some(&admin.config.origin)
            )
            .await?
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            post(
                admin,
                "unlock",
                json!({"password":"synthetic-master"}),
                Some(&session),
                Some(&admin.config.origin)
            )
            .await?
            .status(),
            StatusCode::NO_CONTENT
        );
        admin.store.health()?;
        let mut recovery = WebauthnAuthenticator::new(SoftPasskey::new(true));
        enroll(admin, &mut recovery, "", Some(&session)).await?;
        let recovery_session = login(admin, &mut recovery).await?;
        assert_eq!(
            post(
                admin,
                "lock",
                json!({}),
                Some(&recovery_session),
                Some(&admin.config.origin)
            )
            .await?
            .status(),
            StatusCode::NO_CONTENT
        );
        assert!(admin.store.health().is_err());
        assert_eq!(
            post(
                admin,
                "logout",
                json!({}),
                Some(&session),
                Some(&admin.config.origin)
            )
            .await?
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            post(
                admin,
                "lock",
                json!({}),
                Some(&session),
                Some(&admin.config.origin)
            )
            .await?
            .status(),
            StatusCode::FORBIDDEN
        );
        let persisted = fs::read_to_string(&admin.config.passkeys_file)?;
        assert!(!persisted.contains("synthetic-master"));
        assert!(!persisted.contains("synthetic-entry-value"));
        assert!(!persisted.contains(fixture.code.expose_secret()));
        let (restarted, code) = Admin::new(
            admin.config.clone(),
            Arc::new(KeePassStore::new(config_for_store(&fixture.directory))?),
        )?;
        assert!(code.is_none());
        assert!(restarted.store.health().is_err());
        login(&restarted, &mut recovery).await?;
        Ok(())
    }
    #[tokio::test]
    async fn setup_code_origin_and_expiry_are_enforced() -> Result<()> {
        let fixture = Fixture::new()?;
        let admin = &fixture.admin;
        for origin in [None, Some("https://other.example.test")] {
            let response = post(
                admin,
                "register/start",
                json!({"code":fixture.code.expose_secret()}),
                None,
                origin,
            )
            .await?;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                response
                    .headers()
                    .get(header::CACHE_CONTROL)
                    .and_then(|v| v.to_str().ok()),
                Some("no-store")
            );
        }
        assert_eq!(
            post(
                admin,
                "register/start",
                json!({"code":"wrong"}),
                None,
                Some(&admin.config.origin)
            )
            .await?
            .status(),
            StatusCode::FORBIDDEN
        );
        let start = value(
            post(
                admin,
                "register/start",
                json!({"code":fixture.code.expose_secret()}),
                None,
                Some(&admin.config.origin),
            )
            .await?,
        )
        .await?;
        let mut auth = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let credential = auth.do_registration(
            Url::parse(&admin.config.origin)?,
            serde_json::from_value(start["options"].clone())?,
        )?;
        {
            let mut runtime = admin
                .runtime
                .lock()
                .map_err(|_| anyhow::anyhow!("test mutex"))?;
            runtime.enrollment = Some((
                digest(fixture.code.expose_secret()),
                Instant::now()
                    .checked_sub(Duration::from_secs(1))
                    .ok_or_else(|| anyhow::anyhow!("test clock underflow"))?,
            ));
        }
        assert_eq!(
            post(
                admin,
                "register/finish",
                json!({"id":start["id"],"credential":credential}),
                None,
                Some(&admin.config.origin)
            )
            .await?
            .status(),
            StatusCode::FORBIDDEN
        );
        assert!(!admin.config.passkeys_file.exists());
        assert_eq!(
            post(
                admin,
                "register/start",
                json!({"code":fixture.code.expose_secret()}),
                None,
                Some(&admin.config.origin)
            )
            .await?
            .status(),
            StatusCode::FORBIDDEN
        );
        Ok(())
    }
    #[tokio::test]
    async fn independent_https_listener_serves_ui_and_rejects_untrusted_tls() -> Result<()> {
        let fixture = Fixture::new()?;
        let mut config = fixture.admin.config.clone();
        config.listen = "127.0.0.1:0".parse()?;
        let key = rcgen::KeyPair::generate()?;
        let mut params = rcgen::CertificateParams::new(vec!["charon.example.test".into()])?;
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = params.self_signed(&key)?;
        fs::write(&config.certificate, certificate.pem())?;
        fs::write(&config.private_key, key.serialize_pem())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&config.private_key, fs::Permissions::from_mode(0o600))?;
        }
        let (admin, enrollment) = Admin::new(config, fixture.admin.store.clone())?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        let task = tokio::spawn(async move { admin.serve(server_handle).await });
        let address = tokio::time::timeout(Duration::from_secs(5), handle.listening())
            .await?
            .ok_or_else(|| anyhow::anyhow!("admin did not bind"))?;
        let result = async {
            let client = reqwest::Client::builder()
                .no_proxy()
                .resolve("charon.example.test", address)
                .add_root_certificate(reqwest::Certificate::from_pem(
                    certificate.pem().as_bytes(),
                )?)
                .build()?;
            let response = client.get("https://charon.example.test/").send().await?;
            assert!(response.status().is_success());
            assert!(response.headers().contains_key("strict-transport-security"));
            assert!(response.text().await?.contains("Create passkey"));
            let setup = enrollment
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing enrollment code"))?;
            let response = client
                .post("https://charon.example.test/api/register/start")
                .header(header::ORIGIN, "https://charon.example.test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(&json!({"code":setup.expose_secret()}))?)
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            let untrusted = reqwest::Client::builder()
                .no_proxy()
                .resolve("charon.example.test", address)
                .build()?;
            assert!(
                untrusted
                    .get("https://charon.example.test/")
                    .send()
                    .await
                    .is_err()
            );
            let response = client
                .post("https://charon.example.test/api/unlock")
                .header(header::ORIGIN, "https://charon.example.test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(r#"{"password":"synthetic-master"}"#)
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            Ok::<_, anyhow::Error>(())
        }
        .await;
        handle.graceful_shutdown(Some(Duration::from_secs(1)));
        task.await??;
        result
    }
    #[tokio::test]
    #[ignore = "requires Chrome and Node 22+; run mise run browser-admin-check"]
    #[allow(clippy::too_many_lines)]
    async fn chrome_passkey_ui() -> Result<()> {
        use tokio::io::AsyncWriteExt as _;
        let fixture = Fixture::new()?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        drop(listener);
        let mut config = fixture.admin.config.clone();
        config.listen = address;
        config.origin = format!("https://charon.example.test:{}", address.port());
        let certificate = rcgen::generate_simple_self_signed(vec!["charon.example.test".into()])?;
        fs::write(&config.certificate, certificate.cert.pem())?;
        fs::write(&config.private_key, certificate.signing_key.serialize_pem())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&config.private_key, fs::Permissions::from_mode(0o600))?;
        }
        let origin = config.origin.clone();
        let (admin, code) = Admin::new(config, fixture.admin.store.clone())?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        let server = tokio::spawn(async move { admin.serve(server_handle).await });
        ensure!(
            tokio::time::timeout(Duration::from_secs(5), handle.listening())
                .await?
                .is_some(),
            "admin did not bind"
        );
        let profile = tempfile::tempdir()?;
        let chrome = std::env::var("CHARON_TEST_CHROME").unwrap_or_else(|_| {
            if cfg!(target_os = "macos") {
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into()
            } else {
                "google-chrome".into()
            }
        });
        // Fresh synthetic profile, ephemeral debug port, and one test-only DNS mapping.
        // Certificate trust is independently verified by the HTTPS listener test.
        let mut chrome = tokio::process::Command::new(chrome)
            .args([
                "--headless=new",
                "--no-first-run",
                "--no-default-browser-check",
                "--remote-debugging-port=0",
                "--ignore-certificate-errors",
                "--host-resolver-rules=MAP charon.example.test 127.0.0.1",
                "--no-proxy-server",
            ])
            .arg(format!("--user-data-dir={}", profile.path().display()))
            .arg("about:blank")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let result=async {
            let port_file=profile.path().join("DevToolsActivePort");
            let details=tokio::time::timeout(Duration::from_secs(15),async {
                loop {if let Ok(details)=fs::read_to_string(&port_file){break details;}tokio::time::sleep(Duration::from_millis(100)).await;}
            }).await?;
            let mut lines=details.lines();let port=lines.next().ok_or_else(||anyhow::anyhow!("missing debug port"))?;
            let path=lines.next().ok_or_else(||anyhow::anyhow!("missing debug path"))?;
            let input=json!({"devtools":format!("ws://127.0.0.1:{port}{path}"),"origin":origin,"code":code.as_ref().ok_or_else(||anyhow::anyhow!("missing setup code"))?.expose_secret(),"password":"synthetic-master","screenshot":std::env::var("CHARON_TEST_ADMIN_SCREENSHOT").ok()});
            let mut node=tokio::process::Command::new("node").arg("tests/admin_browser.mjs").stdin(std::process::Stdio::piped()).kill_on_drop(true).spawn()?;
            let mut stdin=node.stdin.take().ok_or_else(||anyhow::anyhow!("missing node stdin"))?;
            stdin.write_all(&serde_json::to_vec(&input)?).await?;stdin.shutdown().await?;drop(stdin);
            ensure!(tokio::time::timeout(Duration::from_secs(60),node.wait()).await??.success(),"Chrome UI proof failed");
            Ok::<_,anyhow::Error>(())
        }.await;
        let _ = chrome.kill().await;
        handle.graceful_shutdown(Some(Duration::from_secs(1)));
        server.await??;
        result
    }
    #[tokio::test]
    async fn overlapping_registrations_cannot_exceed_eight_passkeys() -> Result<()> {
        let fixture = Fixture::new()?;
        let admin = &fixture.admin;
        let mut owner = WebauthnAuthenticator::new(SoftPasskey::new(true));
        enroll(admin, &mut owner, fixture.code.expose_secret(), None).await?;
        let session = login(admin, &mut owner).await?;
        for _ in 0..6 {
            let mut key = WebauthnAuthenticator::new(SoftPasskey::new(true));
            enroll(admin, &mut key, "", Some(&session)).await?;
        }
        let mut finishes = Vec::new();
        for _ in 0..2 {
            let start = value(
                post(
                    admin,
                    "register/start",
                    json!({"code":""}),
                    Some(&session),
                    Some(&admin.config.origin),
                )
                .await?,
            )
            .await?;
            let mut key = WebauthnAuthenticator::new(SoftPasskey::new(true));
            let credential = key.do_registration(
                Url::parse(&admin.config.origin)?,
                serde_json::from_value(start["options"].clone())?,
            )?;
            finishes.push(json!({"id":start["id"],"credential":credential}));
        }
        for (index, finish) in finishes.into_iter().enumerate() {
            let response = post(
                admin,
                "register/finish",
                finish,
                Some(&session),
                Some(&admin.config.origin),
            )
            .await?;
            assert_eq!(
                response.status(),
                if index == 0 {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::FORBIDDEN
                }
            );
        }
        let persisted: Registrations =
            serde_json::from_slice(&fs::read(&admin.config.passkeys_file)?)?;
        assert_eq!(persisted.keys.len(), 8);
        let (_, code) = Admin::new(admin.config.clone(), admin.store.clone())?;
        assert!(code.is_none());
        Ok(())
    }
    #[tokio::test]
    async fn overlapping_logins_cannot_exceed_session_capacity() -> Result<()> {
        let fixture = Fixture::new()?;
        let admin = &fixture.admin;
        let mut owner = WebauthnAuthenticator::new(SoftPasskey::new(true));
        enroll(admin, &mut owner, fixture.code.expose_secret(), None).await?;
        login(admin, &mut owner).await?;
        let mut finishes = Vec::new();
        for _ in 0..2 {
            let start = value(
                post(
                    admin,
                    "login/start",
                    json!({}),
                    None,
                    Some(&admin.config.origin),
                )
                .await?,
            )
            .await?;
            let credential = owner.do_authentication(
                Url::parse(&admin.config.origin)?,
                serde_json::from_value(start["options"].clone())?,
            )?;
            finishes.push(json!({"id":start["id"],"credential":credential}));
        }
        {
            let mut runtime = admin
                .runtime
                .lock()
                .map_err(|_| anyhow::anyhow!("test mutex"))?;
            for index in 0..30 {
                runtime.sessions.insert(
                    digest(&format!("synthetic-session-{index}")),
                    Instant::now() + SESSION_TTL,
                );
            }
        }
        for (index, finish) in finishes.into_iter().enumerate() {
            let response = post(
                admin,
                "login/finish",
                finish,
                None,
                Some(&admin.config.origin),
            )
            .await?;
            assert_eq!(
                response.status(),
                if index == 0 {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::FORBIDDEN
                }
            );
        }
        assert_eq!(
            admin
                .runtime
                .lock()
                .map_err(|_| anyhow::anyhow!("test mutex"))?
                .sessions
                .len(),
            32
        );
        Ok(())
    }
}
