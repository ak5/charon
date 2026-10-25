//! Two-entry KDBX and actual HTTPS admin/gateway fixtures. Inputs are synthetic.
use super::{password_api, telegram_api::Bot};
use crate::{
    admin::{Admin, AdminConfig},
    config::{KeePassConfig, KeePassItemMapping, RealmConfig, ReceiptConfig, TlsConfig},
    gateway::{Gateway, GatewayConfig, Mediation, Route},
    keepass::KeePassStore,
    tls::TlsAuthority,
};
use anyhow::{Result, ensure};
use keepass::{
    Database, DatabaseKey,
    db::{EntryId, fields},
};
use secrecy::{ExposeSecret as _, SecretString};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    net::SocketAddr,
    path::Path,
    sync::{Arc, atomic::AtomicUsize},
};
use tokio::net::TcpListener;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
pub const MASTER: &str = "synthetic-master-e2e-only";
pub const PASSWORDS: [&str; 2] = [
    "synthetic-first-password-e2e",
    "synthetic-second-password-e2e",
];
pub const BOT_TOKEN: &str = "synthetic:token";
pub const BOT_ENTRY: &str = "00000000-0000-0000-0000-000000000003";
const ORIGIN: &str = "https://admin.charon.test";
struct PublicResolver;
impl reqwest::dns::Resolve for PublicResolver {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async {
            Ok(
                Box::new(vec![SocketAddr::from(([8, 8, 8, 8], 443))].into_iter())
                    as reqwest::dns::Addrs,
            )
        })
    }
}
fn private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
fn database(directory: &Path) -> Result<KeePassConfig> {
    let mut database = Database::new();
    let mut items = Vec::new();
    for (index, (name, password)) in ["first", "second"].into_iter().zip(PASSWORDS).enumerate() {
        let id = uuid::Uuid::from_u128(index as u128 + 1);
        let mut root = database.root_mut();
        let mut entry = root.add_entry_with_id(EntryId::from_uuid(id))?;
        entry.set_unprotected(fields::TITLE, format!("E2E {name}"));
        entry.set_protected(fields::PASSWORD, password);
        items.push(KeePassItemMapping {
            secret_ref: format!("e2e/{name}"),
            persona: "e2e-owner".into(),
            entry_id: id.to_string(),
        });
    }
    {
        let mut root = database.root_mut();
        let mut entry =
            root.add_entry_with_id(EntryId::from_uuid(uuid::Uuid::parse_str(BOT_ENTRY)?))?;
        entry.set_unprotected(fields::TITLE, "Operator Telegram bot");
        entry.set_protected(fields::PASSWORD, BOT_TOKEN);
    }
    let path = directory.join("two-passwords.kdbx");
    database.save(
        &mut File::create(&path)?,
        DatabaseKey::new().with_password(MASTER),
    )?;
    private(&path)?;
    // Reopen the encrypted file to establish that the fixture really contains both entries.
    let reopened = Database::open(
        &mut File::open(&path)?,
        DatabaseKey::new().with_password(MASTER),
    )?;
    for (index, item) in items.iter().enumerate() {
        let entry = reopened
            .entry(EntryId::from_uuid(uuid::Uuid::parse_str(&item.entry_id)?))
            .ok_or_else(|| anyhow::anyhow!("fixture entry absent"))?;
        let password = entry
            .fields
            .get(fields::PASSWORD)
            .ok_or_else(|| anyhow::anyhow!("fixture password absent"))?;
        ensure!(
            password.is_protected() && password.get() == PASSWORDS[index],
            "fixture password invalid"
        );
    }
    Ok(KeePassConfig {
        database: path,
        key_file: None,
        telegram_bot_token_entry_id: Some(BOT_ENTRY.into()),
        items,
    })
}
fn route(name: &str) -> Route {
    Route {
        name: name.into(),
        host: "password.test".into(),
        scheme: "https".into(),
        methods: vec!["POST".into()],
        paths: vec![format!("/{name}")],
        path_prefix: None,
        allow_query: false,
        caller_headers: vec![],
        session_response_headers: vec![],
        mediation: Mediation::Header {
            secret_ref: format!("e2e/{name}"),
            name: "authorization".into(),
            value_template: "Bearer {secret}".into(),
        },
        max_request_bytes: 4096,
        max_response_bytes: 4096,
        max_duration_seconds: 2,
        idle_timeout_seconds: 1,
    }
}
pub struct Fixture {
    pub directory: tempfile::TempDir,
    pub store: Arc<KeePassStore>,
    pub calls: Arc<AtomicUsize>,
    pub bot: Bot,
    pub proxy: SocketAddr,
    pub admin_client: reqwest::Client,
    pub admin_config: AdminConfig,
    pub code: Option<SecretString>,
    pub auth: WebauthnAuthenticator<SoftPasskey>,
    pub session: Option<String>,
    admin_handle: axum_server::Handle<SocketAddr>,
    admin_task: tokio::task::JoinHandle<Result<()>>,
    gateway_task: tokio::task::JoinHandle<()>,
    website_task: tokio::task::JoinHandle<()>,
    website: SocketAddr,
    config: GatewayConfig,
    live: bool,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.admin_handle.shutdown();
        self.admin_task.abort();
        self.gateway_task.abort();
        self.website_task.abort();
        self.bot.task.abort();
    }
}
impl Fixture {
    pub async fn new() -> Result<Self> {
        Self::start(None).await
    }
    pub async fn live(user_id: i64) -> Result<Self> {
        Self::start(Some(user_id)).await
    }
    #[allow(clippy::too_many_lines)]
    async fn start(live_user: Option<i64>) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        }
        let keepass = if live_user.is_some() {
            // The operator owns this encrypted input. Never write real tokens into fixtures.
            KeePassConfig {
                database: std::path::PathBuf::from(std::env::var("CHARON_E2E_KDBX")?),
                key_file: None,
                telegram_bot_token_entry_id: Some(std::env::var("CHARON_E2E_BOT_ENTRY")?),
                items: ["first", "second"]
                    .into_iter()
                    .enumerate()
                    .map(|(index, name)| KeePassItemMapping {
                        secret_ref: format!("e2e/{name}"),
                        persona: "e2e-owner".into(),
                        entry_id: std::env::var(if index == 0 {
                            "CHARON_E2E_FIRST_ENTRY"
                        } else {
                            "CHARON_E2E_SECOND_ENTRY"
                        })
                        .unwrap_or_default(),
                    })
                    .collect(),
            }
        } else {
            database(directory.path())?
        };
        let store = Arc::new(KeePassStore::new(keepass.clone())?);
        let certificate = rcgen::generate_simple_self_signed(vec!["admin.charon.test".into()])?;
        let certificate_path = directory.path().join("admin-cert.pem");
        let key_path = directory.path().join("admin-key.pem");
        fs::write(&certificate_path, certificate.cert.pem())?;
        fs::write(&key_path, certificate.signing_key.serialize_pem())?;
        private(&key_path)?;
        let mut admin_config = AdminConfig {
            listen: "127.0.0.1:0".parse()?,
            origin: ORIGIN.into(),
            certificate: certificate_path,
            private_key: key_path,
            passkeys_file: directory.path().join("passkeys.json"),
            telegram: Some(Bot::config()),
        };
        let mut bot = Bot::start(ORIGIN, store.clone()).await?;
        if let Some(user_id) = live_user {
            let mut policy = Bot::config();
            policy.user_id = user_id;
            bot.channel = crate::telegram::Telegram::test_live(&policy, ORIGIN, store.clone())?;
            admin_config.telegram = Some(policy);
        }
        let (admin, code) =
            Admin::new_for_e2e(admin_config.clone(), store.clone(), bot.channel.clone())?;
        let handle = axum_server::Handle::new();
        let task_handle = handle.clone();
        let admin_task = tokio::spawn(async move { admin.serve(task_handle).await });
        let admin_address =
            tokio::time::timeout(std::time::Duration::from_secs(5), handle.listening())
                .await?
                .ok_or_else(|| anyhow::anyhow!("admin bind failed"))?;
        let admin_client = admin_client(&admin_config, admin_address)?;
        let tls = TlsConfig {
            ca_certificate: directory.path().join("public-ca.pem"),
            ca_private_key: directory.path().join("ca-key.pem"),
        };
        crate::ca::generate("Synthetic E2E CA", &tls.ca_certificate, &tls.ca_private_key)?;
        let authority = TlsAuthority::load(&tls)?;
        let calls = Arc::new(AtomicUsize::new(0));
        let (website, website_task) =
            password_api::start(&authority, PASSWORDS.map(SecretString::from), calls.clone())
                .await?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let proxy = listener.local_addr()?;
        let mut config = GatewayConfig {
            version: 1,
            realm: RealmConfig {
                id: "e2e-realm".into(),
                tenant: "e2e-tenant".into(),
                persona: "e2e-owner".into(),
                generation: 1,
            },
            workload: "e2e-workload".into(),
            listen: proxy,
            exclusive_network: true,
            tls: tls.clone(),
            keepass,
            admin: Some(admin_config.clone()),
            receipts: ReceiptConfig {
                journal_path: directory.path().join("receipts.jsonl"),
                state_path: directory.path().join("receipts.chain"),
                queue_capacity: 64,
            },
            routes: vec![route("first"), route("second")],
        };
        if live_user.is_some() {
            for route in &mut config.routes {
                route.max_duration_seconds = 180;
            }
        }
        let mut gateway =
            Gateway::new(config.clone(), store.clone())?.with_approvals(Some(bot.channel.clone()));
        gateway.resolver = Arc::new(PublicResolver);
        gateway.client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .proxy(reqwest::Proxy::all(format!("http://{website}"))?)
            .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(
                &tls.ca_certificate,
            )?)?)
            .build()?;
        let gateway = Arc::new(gateway);
        let gateway_task = tokio::spawn(async move {
            let _ = axum::serve(listener, gateway.router()).await;
        });
        Ok(Self {
            directory,
            store,
            calls,
            bot,
            proxy,
            admin_client,
            admin_config,
            code,
            auth: WebauthnAuthenticator::new(SoftPasskey::new(true)),
            session: None,
            admin_handle: handle,
            admin_task,
            gateway_task,
            website_task,
            website,
            config,
            live: live_user.is_some(),
        })
    }
    pub async fn verify_password_api(&self) -> Result<()> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .proxy(reqwest::Proxy::all(format!("http://{}", self.website))?)
            .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(
                &self.config.tls.ca_certificate,
            )?)?)
            .build()?;
        let response = client
            .post("https://password.test/first")
            .header(
                http::header::AUTHORIZATION,
                "Bearer wrong-synthetic-password",
            )
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(r#"{"operation":"synthetic-e2e"}"#)
            .send()
            .await?;
        ensure!(
            response.status() == 401,
            "password API accepted an invalid password"
        );
        let body: Value = serde_json::from_str(&response.text().await?)?;
        ensure!(
            body == json!({"ok":false,"endpoint":"first"}),
            "password API returned unexpected denial JSON"
        );
        ensure!(
            self.calls.load(std::sync::atomic::Ordering::SeqCst) == 1,
            "API negative control was not observed"
        );
        self.calls.store(0, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    pub async fn post(
        &self,
        path: &str,
        body: Value,
        authenticated: bool,
    ) -> Result<reqwest::Response> {
        let mut request = self
            .admin_client
            .post(format!("{ORIGIN}/api/{path}"))
            .header(http::header::ORIGIN, ORIGIN)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&body)?);
        if authenticated {
            request = request.header(
                http::header::COOKIE,
                self.session
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("session missing"))?,
            );
        }
        Ok(request.send().await?)
    }
    pub async fn enroll(&mut self) -> Result<()> {
        let code = self
            .code
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("code missing"))?;
        let start = self
            .post(
                "register/start",
                json!({"code":code.expose_secret()}),
                false,
            )
            .await?;
        ensure!(start.status().is_success(), "enrollment start failed");
        let start: Value = serde_json::from_str(&start.text().await?)?;
        let credential = self.auth.do_registration(
            url::Url::parse(ORIGIN)?,
            serde_json::from_value(start["options"].clone())?,
        )?;
        ensure!(
            self.post(
                "register/finish",
                json!({"id":start["id"],"credential":credential}),
                false
            )
            .await?
            .status()
                == 204,
            "enrollment finish failed"
        );
        self.code = None;
        self.login().await
    }
    pub async fn login(&mut self) -> Result<()> {
        let start = self.post("login/start", json!({}), false).await?;
        ensure!(start.status().is_success(), "login start failed");
        let start: Value = serde_json::from_str(&start.text().await?)?;
        let credential = self.auth.do_authentication(
            url::Url::parse(ORIGIN)?,
            serde_json::from_value(start["options"].clone())?,
        )?;
        let response = self
            .post(
                "login/finish",
                json!({"id":start["id"],"credential":credential}),
                false,
            )
            .await?;
        ensure!(response.status() == 204, "login finish failed");
        self.session = Some(
            response
                .headers()
                .get(http::header::SET_COOKIE)
                .ok_or_else(|| anyhow::anyhow!("cookie missing"))?
                .to_str()?
                .split(';')
                .next()
                .ok_or_else(|| anyhow::anyhow!("cookie empty"))?
                .into(),
        );
        Ok(())
    }
    pub fn request(&self, name: &str) -> tokio::task::JoinHandle<Result<(u16, String)>> {
        let proxy = format!("http://{}", self.proxy);
        let certificate = self.config.tls.ca_certificate.clone();
        let name = name.to_owned();
        let timeout = if self.live { "130" } else { "10" };
        tokio::spawn(async move {
            let output = tokio::process::Command::new("sh")
                .arg("tests/e2e/request.sh")
                .arg(name)
                .env("CHARON_E2E_PROXY_URL", proxy)
                .env("CHARON_E2E_CA", certificate)
                .env("CHARON_E2E_TIMEOUT", timeout)
                .kill_on_drop(true)
                .output()
                .await?;
            ensure!(output.status.success(), "curl transport failed");
            let output = String::from_utf8(output.stdout)?;
            let (body, status) = output
                .rsplit_once('\n')
                .ok_or_else(|| anyhow::anyhow!("HTTP status missing"))?;
            Ok((status.parse()?, body.to_owned()))
        })
    }
    pub async fn restart(&mut self) -> Result<()> {
        self.admin_handle.shutdown();
        (&mut self.admin_task).await??;
        let store = Arc::new(KeePassStore::new(self.config.keepass.clone())?);
        ensure!(
            self.store.health().is_err(),
            "old store must be locked before restart"
        );
        self.store = store;
        self.bot.channel = crate::telegram::Telegram::test_api(
            &Bot::config(),
            ORIGIN,
            &self.bot.endpoint,
            self.store.clone(),
        )?;
        let (admin, code) = Admin::new_for_e2e(
            self.admin_config.clone(),
            self.store.clone(),
            self.bot.channel.clone(),
        )?;
        ensure!(code.is_none(), "restart unexpectedly requested enrollment");
        let handle = axum_server::Handle::new();
        let task_handle = handle.clone();
        self.admin_task = tokio::spawn(async move { admin.serve(task_handle).await });
        let address = tokio::time::timeout(std::time::Duration::from_secs(5), handle.listening())
            .await?
            .ok_or_else(|| anyhow::anyhow!("restarted admin bind failed"))?;
        self.admin_client = admin_client(&self.admin_config, address)?;
        self.admin_handle = handle;
        self.session = None;
        self.gateway_task.abort();
        let _ = (&mut self.gateway_task).await;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        self.proxy = listener.local_addr()?;
        self.config.listen = self.proxy;
        let mut gateway = Gateway::new(self.config.clone(), self.store.clone())?
            .with_approvals(Some(self.bot.channel.clone()));
        gateway.resolver = Arc::new(PublicResolver);
        gateway.client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .proxy(reqwest::Proxy::all(format!("http://{}", self.website))?)
            .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(
                &self.config.tls.ca_certificate,
            )?)?)
            .build()?;
        let gateway = Arc::new(gateway);
        self.gateway_task = tokio::spawn(async move {
            let _ = axum::serve(listener, gateway.router()).await;
        });
        Ok(())
    }
}
fn admin_client(config: &AdminConfig, address: SocketAddr) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .resolve("admin.charon.test", address)
        .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(
            &config.certificate,
        )?)?)
        .build()?)
}
