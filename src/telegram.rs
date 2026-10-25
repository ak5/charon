//! Optional private Telegram allow-once/deny prompts. No vault password enters this channel.
use anyhow::{Result, ensure};
use axum::body::{Body, to_bytes};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
const MAX_REQUEST_PREVIEW_BYTES: usize = 3500;
const APPROVAL_TTL: Duration = Duration::from_secs(120);
const PROMPT_WINDOW: Duration = Duration::from_secs(60);
const PROMPTS_PER_WINDOW: usize = 10;

/// Trusted operator settings. The bot token comes only from the unlocked `KeePass` store.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramConfig {
    /// One immutable positive numeric private user/chat ID.
    pub user_id: i64,
    /// Exact capability/route names requiring a fresh human decision for each request.
    pub approval_capabilities: Vec<String>,
    /// Public, operator-written authority descriptions; exactly one per gated name.
    #[serde(default)]
    pub approval_descriptions: HashMap<String, String>,
}
impl TelegramConfig {
    /// Validate the private recipient and exact approval policy names.
    ///
    /// # Errors
    /// Rejects invalid recipients, names, and duplicates.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.user_id > 0,
            "Telegram requires one positive private user ID"
        );
        let mut names = HashSet::new();
        for name in &self.approval_capabilities {
            ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
                    && names.insert(name),
                "invalid Telegram approval capability"
            );
        }
        ensure!(
            self.approval_descriptions.len() == names.len()
                && names
                    .iter()
                    .all(|name| self
                        .approval_descriptions
                        .get(*name)
                        .is_some_and(|description| !description.trim().is_empty()
                            && description.len() <= 240
                            && description.bytes().all(|b| matches!(b, b' '..=b'~')))),
            "Telegram requires one public printable ASCII description (1-240 bytes) per gated capability"
        );
        Ok(())
    }
    /// Reject approval rules that do not name a configured capability or route.
    ///
    /// # Errors
    /// Rejects unknown policy names.
    pub fn validate_inventory<'a>(&self, names: impl Iterator<Item = &'a str>) -> Result<()> {
        self.validate()?;
        let names: HashSet<_> = names.collect();
        ensure!(
            self.approval_capabilities
                .iter()
                .all(|name| names.contains(name.as_str())),
            "Telegram approval policy names an unknown capability"
        );
        Ok(())
    }
}
#[derive(Clone)]
struct RequestPreview {
    action: String,
    summary: String,
    request: String,
}
struct Pending {
    expires: Instant,
    message: Option<i64>,
    reply: oneshot::Sender<bool>,
    preview: RequestPreview,
}
struct Prompt {
    token: SecretString,
    #[cfg(test)]
    capability: String,
    preview: RequestPreview,
}
enum CallbackAction {
    View {
        request: String,
        message: i64,
        token: SecretString,
    },
    Decide {
        pending: Pending,
        allow: bool,
        message: i64,
    },
}
/// Local approval coordinator, with bounded pending state and single-use callbacks.
pub struct Telegram {
    user: i64,
    capabilities: HashMap<String, String>,
    store: Option<Arc<crate::keepass::KeePassStore>>,
    #[cfg(test)]
    token: Option<SecretString>,
    client: reqwest::Client,
    pending: Mutex<HashMap<[u8; 32], Pending>>,
    recent_prompts: Mutex<VecDeque<Instant>>,
    send: mpsc::Sender<Prompt>,
    receive: tokio::sync::Mutex<mpsc::Receiver<Prompt>>,
    origin: Option<String>,
    #[cfg(test)]
    api_origin: Option<String>,
}
impl Telegram {
    /// Construct a locked channel backed by the operator-only `KeePass` token entry.
    ///
    /// # Errors
    /// Rejects missing entry configuration or invalid approval policy.
    pub fn new(
        config: &TelegramConfig,
        origin: &str,
        store: Arc<crate::keepass::KeePassStore>,
    ) -> Result<Arc<Self>> {
        ensure!(
            store.has_telegram_entry(),
            "Telegram KeePass token entry missing"
        );
        let mut channel = Self::build(config, origin)?;
        Arc::get_mut(&mut channel)
            .ok_or_else(|| anyhow::anyhow!("Telegram unavailable"))?
            .store = Some(store);
        Ok(channel)
    }
    #[cfg(test)]
    fn with_token(config: &TelegramConfig, origin: &str, token: SecretString) -> Result<Arc<Self>> {
        ensure!(valid_token(token.expose_secret()), "invalid Telegram token");
        let mut channel = Self::build(config, origin)?;
        Arc::get_mut(&mut channel)
            .ok_or_else(|| anyhow::anyhow!("Telegram unavailable"))?
            .token = Some(token);
        Ok(channel)
    }
    fn build(config: &TelegramConfig, origin: &str) -> Result<Arc<Self>> {
        config.validate()?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()?;
        let (send, receive) = mpsc::channel(32);
        Ok(Arc::new(Self {
            user: config.user_id,
            capabilities: config.approval_descriptions.clone(),
            store: None,
            #[cfg(test)]
            token: None,
            client,
            pending: Mutex::new(HashMap::new()),
            recent_prompts: Mutex::new(VecDeque::new()),
            send,
            receive: tokio::sync::Mutex::new(receive),
            origin: Some(origin.into()),
            #[cfg(test)]
            api_origin: None,
        }))
    }
    #[cfg(test)]
    pub(crate) fn test_coordinator(names: Vec<String>) -> Result<Arc<Self>> {
        Self::with_token(
            &TelegramConfig {
                user_id: 123,
                approval_descriptions: names
                    .iter()
                    .map(|name| (name.clone(), format!("Use test capability {name}")))
                    .collect(),
                approval_capabilities: names,
            },
            "https://charon.example",
            SecretString::from("synthetic:token"),
        )
    }
    #[cfg(test)]
    pub(crate) fn test_api(
        config: &TelegramConfig,
        origin: &str,
        endpoint: &str,
        store: Arc<crate::keepass::KeePassStore>,
    ) -> Result<Arc<Self>> {
        config.validate()?;
        let mut telegram = Self::new(config, origin, store)?;
        Arc::get_mut(&mut telegram)
            .ok_or_else(|| anyhow::anyhow!("test coordinator shared"))?
            .api_origin = Some(endpoint.into());
        Ok(telegram)
    }
    #[cfg(test)]
    pub(crate) fn test_live(
        config: &TelegramConfig,
        origin: &str,
        store: Arc<crate::keepass::KeePassStore>,
    ) -> Result<Arc<Self>> {
        let mut telegram = Self::new(config, origin, store)?;
        Arc::get_mut(&mut telegram)
            .ok_or_else(|| anyhow::anyhow!("test coordinator shared"))?
            .origin = None;
        Ok(telegram)
    }
    #[cfg(test)]
    pub(crate) fn test_pending_count(&self) -> Result<usize> {
        Ok(self
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("test mutex"))?
            .len())
    }
    #[cfg(test)]
    pub(crate) async fn test_decide_next(&self, allow: bool) -> Result<String> {
        let prompt = tokio::time::timeout(Duration::from_secs(5), self.receive.lock().await.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("no prompt"))?;
        let hash: [u8; 32] = Sha256::digest(prompt.token.expose_secret().as_bytes()).into();
        let pending = self
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("test mutex"))?
            .remove(&hash)
            .ok_or_else(|| anyhow::anyhow!("no pending decision"))?;
        pending
            .reply
            .send(allow)
            .map_err(|_| anyhow::anyhow!("request canceled"))?;
        Ok(prompt.capability)
    }
    /// Approve a redacted preview of this exact, policy-authorized request before lookup.
    ///
    /// # Errors
    /// Denies unsupported/oversized previews, timeout, cancellation, or human denial.
    pub async fn authorize_request(
        &self,
        capability: &str,
        parts: &http::request::Parts,
        target: &url::Url,
        body: &mut Body,
        body_limit: usize,
        credential_sink: Option<&crate::broker::HydrationSink>,
    ) -> Result<()> {
        let Some(description) = self.capabilities.get(capability) else {
            return Ok(());
        };
        if let Some(store) = &self.store {
            store.health()?;
        }
        let preview = request_preview(parts, target, body, body_limit, credential_sink).await?;
        let line = preview
            .lines()
            .next()
            .ok_or_else(|| anyhow::anyhow!("approval preview unavailable"))?;
        self.authorize_preview(
            capability,
            RequestPreview {
                action: format!(
                    "send {}{} request to {}{}",
                    if credential_sink.is_some() {
                        "authenticated "
                    } else {
                        ""
                    },
                    parts.method,
                    target.origin().ascii_serialization(),
                    target.path(),
                ),
                summary: format!("{description}\n\n{line}\n\nPermission: {capability}"),
                request: preview,
            },
        )
        .await
    }
    /// Require an allow-once decision for a synthetic test request.
    ///
    /// # Errors
    /// Denies timeout, cancellation, queue saturation, channel failure, or a human denial.
    #[cfg(test)]
    pub async fn authorize(&self, capability: &str, method: &str) -> Result<()> {
        let Some(description) = self.capabilities.get(capability) else {
            return Ok(());
        };
        self.authorize_preview(
            capability,
            RequestPreview {
                action: format!(
                    "send authenticated {method} request to https://example.test/write"
                ),
                summary: format!("{description}\n\nPermission: {capability}\nMethod: {method}"),
                request: format!("{method} https://example.test/write\n\n[body hidden]"),
            },
        )
        .await
    }
    async fn authorize_preview(&self, capability: &str, preview: RequestPreview) -> Result<()> {
        ensure!(
            self.capabilities.contains_key(capability)
                && preview.summary.len() <= 3000
                && preview.request.len() <= MAX_REQUEST_PREVIEW_BYTES,
            "approval preview unavailable"
        );
        let mut epoch = self.store.as_ref().map(|store| store.changes());
        if let Some(store) = &self.store {
            store.health()?;
        }
        let generation = epoch.as_ref().map(|epoch| *epoch.borrow());
        let mut bytes = [0u8; 24];
        getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("approval unavailable"))?;
        let token = SecretString::from(URL_SAFE_NO_PAD.encode(bytes));
        let hash: [u8; 32] = Sha256::digest(token.expose_secret().as_bytes()).into();
        let (reply, receive) = oneshot::channel();
        {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| anyhow::anyhow!("approval unavailable"))?;
            pending.retain(|_, p| p.expires > Instant::now() && !p.reply.is_closed());
            ensure!(pending.len() < 32, "approval capacity unavailable");
            let now = Instant::now();
            let mut recent = self
                .recent_prompts
                .lock()
                .map_err(|_| anyhow::anyhow!("approval unavailable"))?;
            recent.retain(|at| now.duration_since(*at) < PROMPT_WINDOW);
            ensure!(
                recent.len() < PROMPTS_PER_WINDOW,
                "approval rate unavailable"
            );
            recent.push_back(now);
            pending.insert(
                hash,
                Pending {
                    expires: Instant::now() + APPROVAL_TTL,
                    message: None,
                    reply,
                    preview: preview.clone(),
                },
            );
        }
        let sent = self
            .send
            .try_send(Prompt {
                token,
                #[cfg(test)]
                capability: capability.into(),
                preview,
            })
            .is_ok();
        let result = if sent {
            if let Some(epoch) = epoch.as_mut() {
                tokio::select! {
                    result = tokio::time::timeout(APPROVAL_TTL, receive) => matches!(result, Ok(Ok(true))),
                    _changed = epoch.changed() => false,
                }
            } else {
                matches!(
                    tokio::time::timeout(APPROVAL_TTL, receive).await,
                    Ok(Ok(true))
                )
            }
        } else {
            false
        };
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&hash);
        }
        ensure!(result, "human approval denied");
        if let Some(store) = &self.store {
            store.health()?;
            ensure!(
                generation == Some(*store.changes().borrow()),
                "approval expired with vault state"
            );
        }
        Ok(())
    }
    /// Run outbound notifications and authenticated callback polling.
    ///
    /// # Errors
    /// Retries channel failures without exposing HTTP errors or bot URLs.
    /// Returns only when store-state notifications are unavailable.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let Some(store) = &self.store else {
            return self.run_active().await;
        };
        let mut changes = store.changes();
        loop {
            changes.borrow_and_update();
            if store.health().is_ok() {
                tokio::select! {
                    result = self.clone().run_active() => {
                        if result.is_err() { tracing::warn!("Telegram channel unavailable"); }
                        self.clear_pending();
                        tokio::select! { () = tokio::time::sleep(Duration::from_secs(2)) => {}, result = changes.changed() => { result?; } }
                    }
                    result = changes.changed() => { result?; self.clear_pending(); }
                }
            } else {
                self.clear_pending();
                changes.changed().await?;
            }
        }
    }
    fn clear_pending(&self) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.clear();
        }
    }
    async fn run_active(self: Arc<Self>) -> Result<()> {
        let text = self.origin.as_ref().map_or_else(
            || "Charon live test is ready.\nAllow the first test request, then deny the second.".into(),
            |origin| format!("Charon is unlocked.\nApproval requests will appear here.\nManage vault: {origin}"),
        );
        self.call(
            "sendMessage",
            json!({"chat_id":self.user,"text":text,"link_preview_options":{"is_disabled":true}}),
        )
        .await?;
        let mut receiver = self.receive.lock().await;
        let mut offset = 0i64;
        // Keep one long poll alive while delivering prompts; cancellation leaves
        // a server-side poll behind and can make the next poll conflict with it.
        let mut poll = Box::pin(self.call(
            "getUpdates",
            json!({"offset":offset,"timeout":10,"allowed_updates":["callback_query"]}),
        ));
        loop {
            tokio::select! {
                prompt=receiver.recv()=>{
                    let Some(prompt)=prompt else{return Ok(());};
                    let hash: [u8;32]=Sha256::digest(prompt.token.expose_secret().as_bytes()).into();
                    let live=self.pending.lock().is_ok_and(|p|p.get(&hash).is_some_and(|p|p.expires>Instant::now()&&!p.reply.is_closed()));
                    if !live{continue;}
                    let sent=self.call("sendMessage",json!({"chat_id":self.user,"text":format!("Allow this request?\n\n{}\n\nChoose within 2 minutes; the request may expire sooner.",prompt.preview.summary),"reply_markup":{"inline_keyboard":[[{"text":"Allow once","callback_data":format!("a:{}",prompt.token.expose_secret())},{"text":"Deny","callback_data":format!("d:{}",prompt.token.expose_secret())}],[{"text":"Show request details","callback_data":format!("v:{}",prompt.token.expose_secret())}]]}})).await;
                    if let Ok(mut pending)=self.pending.lock(){
                        match sent.ok().and_then(|v|v.get("message_id").and_then(Value::as_i64)) {
                            Some(id)=>if let Some(p)=pending.get_mut(&hash){p.message=Some(id);},
                            None=>{pending.remove(&hash);}
                        }
                    }
                }
                updates=&mut poll=>{
                    match updates {
                        Ok(Value::Array(updates))=>for update in updates {
                            if let Some(id)=update.get("update_id").and_then(Value::as_i64){offset=offset.max(id.saturating_add(1));}
                            if let Some(callback)=update.get("callback_query"){
                                self.finish_callback(callback).await;
                            }
                        },
                        _=>{tokio::time::sleep(Duration::from_secs(2)).await;}
                    }
                    poll = Box::pin(self.call("getUpdates", json!({"offset":offset,"timeout":10,"allowed_updates":["callback_query"]})));
                }
            }
        }
    }
    async fn finish_callback(&self, callback: &Value) {
        let (reply, answer) = match self.take_callback(callback) {
            Some(CallbackAction::View {
                request,
                message,
                token,
            }) => {
                let mut body = request_message("Request details (secrets hidden)", &request);
                body["reply_markup"] = json!({"inline_keyboard":[[
                    {"text":"Allow once","callback_data":format!("a:{}",token.expose_secret())},
                    {"text":"Deny","callback_data":format!("d:{}",token.expose_secret())}
                ]]});
                let displayed = self.edit_callback_message(message, body).await;
                (
                    None,
                    if displayed {
                        "Request details shown"
                    } else {
                        "Details unavailable. Try again."
                    },
                )
            }
            Some(CallbackAction::Decide {
                pending,
                allow,
                message,
            }) => {
                let body = json!({
                    "text": format!("{}: {}", if allow { "Allowed once" } else { "Denied" }, pending.preview.action),
                    "entities": [],
                    "reply_markup": {"inline_keyboard": []},
                    "link_preview_options": {"is_disabled": true}
                });
                // Finish feedback before releasing a request that may stop its worker.
                self.edit_callback_message(message, body).await;
                (Some((pending.reply, allow)), "Choice saved")
            }
            None => (None, "This request is no longer waiting"),
        };
        if let Some(id) = callback.get("id").and_then(Value::as_str) {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                self.call(
                    "answerCallbackQuery",
                    json!({
                        "callback_query_id": id, "text": answer
                    }),
                ),
            )
            .await;
        }
        if let Some((reply, allow)) = reply {
            let _ = reply.send(allow);
        }
    }
    async fn edit_callback_message(&self, message: i64, mut body: Value) -> bool {
        body["chat_id"] = json!(self.user);
        body["message_id"] = json!(message);
        let edited =
            tokio::time::timeout(Duration::from_secs(2), self.call("editMessageText", body)).await;
        let displayed = matches!(edited, Ok(Ok(_)));
        if !displayed {
            tracing::warn!("Telegram request display unavailable");
        }
        displayed
    }
    #[cfg(test)]
    fn callback(&self, callback: &Value) -> bool {
        match self.take_callback(callback) {
            Some(CallbackAction::Decide { pending, allow, .. }) => {
                pending.reply.send(allow).is_ok()
            }
            _ => false,
        }
    }
    fn take_callback(&self, callback: &Value) -> Option<CallbackAction> {
        if callback.pointer("/from/id").and_then(Value::as_i64) != Some(self.user)
            || callback.pointer("/message/chat/id").and_then(Value::as_i64) != Some(self.user)
            || callback
                .pointer("/message/chat/type")
                .and_then(Value::as_str)
                != Some("private")
        {
            return None;
        }
        let data = callback.get("data").and_then(Value::as_str)?;
        let (decision, token) = data.split_once(':')?;
        if !matches!(decision, "a" | "d" | "v") || token.len() != 32 {
            return None;
        }
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut pending = self.pending.lock().ok()?;
        let p = pending.get(&hash)?;
        let message = callback
            .pointer("/message/message_id")
            .and_then(Value::as_i64)
            .filter(|id| *id > 0)?;
        if p.expires <= Instant::now() || p.reply.is_closed() || p.message != Some(message) {
            return None;
        }
        if decision == "v" {
            return Some(CallbackAction::View {
                request: p.preview.request.clone(),
                message,
                token: SecretString::from(token.to_owned()),
            });
        }
        let p = pending.remove(&hash)?;
        Some(CallbackAction::Decide {
            pending: p,
            allow: decision == "a",
            message,
        })
    }
    async fn call(&self, method: &str, body: Value) -> Result<Value> {
        // Never return/log reqwest errors: Telegram URLs contain the bot token.
        let origin = "https://api.telegram.org";
        #[cfg(test)]
        let origin = self.api_origin.as_deref().unwrap_or(origin);
        let token = if let Some(store) = &self.store {
            store.telegram_token()?
        } else {
            #[cfg(test)]
            {
                self.token
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("Telegram unavailable"))?
            }
            #[cfg(not(test))]
            {
                anyhow::bail!("Telegram unavailable");
            }
        };
        let mut response = self
            .client
            .post(format!("{origin}/bot{}/{method}", token.expose_secret()))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&body).map_err(|_| anyhow::anyhow!("Telegram unavailable"))?)
            .send()
            .await
            .map_err(|error| {
                tracing::warn!(
                    method,
                    timeout = error.is_timeout(),
                    connect = error.is_connect(),
                    "Telegram transport unavailable"
                );
                anyhow::anyhow!("Telegram unavailable")
            })?;
        if !response.status().is_success() {
            tracing::warn!(
                method,
                status = response.status().as_u16(),
                "Telegram API request rejected"
            );
            anyhow::bail!("Telegram unavailable");
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("Telegram unavailable"))?
        {
            ensure!(
                bytes.len().saturating_add(chunk.len()) <= 262_144,
                "Telegram response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("Telegram unavailable"))?;
        if value.get("ok").and_then(Value::as_bool) != Some(true) {
            tracing::warn!(method, "Telegram API response rejected");
            anyhow::bail!("Telegram unavailable");
        }
        Ok(value.get("result").cloned().unwrap_or(Value::Null))
    }
}

fn request_message(heading: &str, request: &str) -> Value {
    let prefix = format!("{heading}\n\n");
    json!({
        "text": format!("{prefix}{request}"),
        "entities": [{"type":"pre", "offset":prefix.encode_utf16().count(),
            "length":request.encode_utf16().count(), "language":"http"}],
        "link_preview_options": {"is_disabled":true}
    })
}

async fn request_preview(
    parts: &http::request::Parts,
    target: &url::Url,
    body: &mut Body,
    body_limit: usize,
    credential_sink: Option<&crate::broker::HydrationSink>,
) -> Result<String> {
    use crate::broker::CapabilityReference;
    use std::fmt::Write as _;
    ensure!(
        matches!(target.scheme(), "http" | "https")
            && target.has_host()
            && target.username().is_empty()
            && target.password().is_none()
            && target.fragment().is_none(),
        "approval destination unavailable"
    );
    // References are public; resolving a credential must happen only after approval.
    let path = target
        .path_segments()
        .ok_or_else(|| anyhow::anyhow!("approval path unavailable"))?
        .map(|segment| {
            let decoded = percent_encoding::percent_decode_str(segment).decode_utf8();
            match decoded {
                Ok(value) if CapabilityReference::parse(&value).is_ok() => value.into_owned(),
                _ => segment.to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    let mut preview = format!(
        "{} {}/{}",
        parts.method,
        target.origin().ascii_serialization(),
        path
    );
    if let Some(query) = target.query() {
        preview.push('?');
        preview.push_str(query);
    }
    preview.push('\n');
    writeln!(
        preview,
        "host: {}",
        &target[url::Position::BeforeHost..url::Position::AfterPort]
    )?;
    for (name, value) in &parts.headers {
        if name == http::header::HOST {
            continue;
        }
        writeln!(
            preview,
            "{name}: {}",
            preview_header(name, value, credential_sink)?
        )?;
    }
    let taken = std::mem::replace(body, Body::empty());
    let bytes = tokio::time::timeout(
        Duration::from_secs(10),
        to_bytes(taken, body_limit.min(65_536)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("approval body timed out"))?
    .map_err(|_| anyhow::anyhow!("approval body exceeds its limit"))?;
    *body = Body::from(bytes.clone());
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("approval body is not UTF-8 text"))?;
    preview.push('\n');
    preview.push_str(&display_text(text));
    ensure!(
        preview.len() <= MAX_REQUEST_PREVIEW_BYTES,
        "approval preview exceeds its display limit"
    );
    Ok(preview)
}

fn preview_header(
    name: &http::HeaderName,
    value: &http::HeaderValue,
    credential_sink: Option<&crate::broker::HydrationSink>,
) -> Result<String> {
    use crate::broker::HydrationSink;
    let sensitive = value.is_sensitive();
    let value = value
        .to_str()
        .map_err(|_| anyhow::anyhow!("approval header is not displayable"))?;
    let injection = match credential_sink {
        Some(
            HydrationSink::Authorization
            | HydrationSink::Basic { .. }
            | HydrationSink::GitSmartHttp { .. },
        ) => name == http::header::AUTHORIZATION,
        Some(HydrationSink::Header { name: sink }) => name.as_str().eq_ignore_ascii_case(sink),
        _ => false,
    };
    let shown = if injection {
        if matches!(
            credential_sink,
            Some(HydrationSink::Basic { .. } | HydrationSink::GitSmartHttp { .. })
        ) {
            let decoded = value
                .strip_prefix("Basic ")
                .and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok())
                .and_then(|v| String::from_utf8(v).ok())
                .ok_or_else(|| anyhow::anyhow!("approval Basic reference unavailable"))?;
            format!("Basic base64({decoded})")
        } else {
            value.to_owned()
        }
    } else if name == crate::identity::IDENTITY_HEADER
        || value.starts_with("Charon ")
        || sensitive
        || matches!(
            name.as_str(),
            "authorization"
                | "proxy-authorization"
                | "cookie"
                | "x-api-key"
                | "api-key"
                | "x-goog-api-key"
                | "x-auth-token"
                | "x-session-token"
        )
    {
        "[redacted caller credential]".into()
    } else {
        value.to_owned()
    };
    Ok(display_text(&shown))
}

fn display_text(text: &str) -> String {
    use std::fmt::Write as _;
    let mut escaped = String::new();
    for character in text.chars() {
        if character == '\n' || (character.is_ascii() && !character.is_ascii_control()) {
            escaped.push(character);
        } else {
            let mut units = [0u16; 2];
            for unit in character.encode_utf16(&mut units) {
                let _ = write!(escaped, "\\u{unit:04x}");
            }
        }
    }
    escaped
}

pub(crate) fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 256
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn http_code_blocks_use_utf16_entities_and_never_parse_payload_markup() {
        let request = "POST https://example.test/write\n\n{\"text\":\"`<not markup>\"}";
        let message = request_message("🔎 Request details (secrets hidden)", request);
        assert_eq!(
            message["entities"][0]["offset"],
            json!(
                "🔎 Request details (secrets hidden)\n\n"
                    .encode_utf16()
                    .count()
            )
        );
        assert_eq!(
            message["entities"][0]["length"],
            json!(request.encode_utf16().count())
        );
        assert_eq!(message["entities"][0]["language"], json!("http"));
        assert!(
            message["text"]
                .as_str()
                .is_some_and(|text| text.contains(request))
        );
        assert!(message.get("parse_mode").is_none());
    }
    #[tokio::test]
    async fn viewing_request_requires_owner_message_and_preserves_the_decision() -> Result<()> {
        let t = coordinator()?;
        let token = "abcdefghijklmnopqrstuvwxyz012345";
        let expires = Instant::now() + APPROVAL_TTL;
        let mut receive = pending(&t, token, Some(456), expires)?;
        let mut view = callback(token);
        view["data"] = json!(format!("v:{token}"));
        for pointer in ["/from/id", "/message/chat/id", "/message/message_id"] {
            let mut wrong = view.clone();
            *wrong
                .pointer_mut(pointer)
                .ok_or_else(|| anyhow::anyhow!("fixture field"))? = json!(999);
            assert!(t.take_callback(&wrong).is_none());
        }
        assert!(matches!(
            t.take_callback(&view),
            Some(CallbackAction::View { .. })
        ));
        assert!(matches!(
            receive.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        assert!(
            t.pending
                .lock()
                .is_ok_and(|p| p.len() == 1 && p.get(&hash).is_some_and(|p| p.expires == expires))
        );
        assert!(t.callback(&callback(token)));
        assert!(receive.await?);
        assert!(t.take_callback(&view).is_none());
        Ok(())
    }
    #[tokio::test]
    async fn full_http_preview_preserves_references_and_body_bytes() -> Result<()> {
        let bytes = br#"{"operation":"close","token":"{{charon.write}}","nested":{"items":[1,0.1]},"text":"public body"}"#;
        let request = http::Request::builder()
            .method("PATCH")
            .uri("https://api.example.test/issues/456?state=closed&key=%7B%7Bcharon.write%7D%7D")
            .header("content-type", "application/json")
            .header("x-request-id", "public-header")
            .header("x-repeat", "first")
            .header("x-repeat", "second")
            .header("cookie", "synthetic-private-cookie")
            .header(
                crate::identity::IDENTITY_HEADER,
                "Charon synthetic-identity",
            )
            .header("authorization", "Bearer {{charon.write}}")
            .body(Body::from(bytes.as_slice()))?;
        let (parts, mut body) = request.into_parts();
        let target = url::Url::parse(&parts.uri.to_string())?;
        let preview = request_preview(
            &parts,
            &target,
            &mut body,
            4096,
            Some(&crate::broker::HydrationSink::Authorization),
        )
        .await?;
        assert!(preview.contains("?state=closed&key=%7B%7Bcharon.write%7D%7D"));
        assert!(preview.contains("authorization: Bearer {{charon.write}}"));
        assert!(preview.contains("x-request-id: public-header"));
        assert!(preview.contains("x-repeat: first\nx-repeat: second"));
        assert!(preview.contains(std::str::from_utf8(bytes)?));
        assert!(!preview.contains("synthetic-private-cookie"));
        assert!(!preview.contains("synthetic-identity"));
        assert_eq!(to_bytes(body, 4096).await?.as_ref(), bytes);
        assert_eq!(display_text("text\r\u{202e}"), "text\\u000d\\u202e");
        Ok(())
    }
    #[tokio::test]
    async fn preview_supports_text_form_path_and_basic_references() -> Result<()> {
        let request = http::Request::builder()
            .method("POST")
            .uri("https://api.example.test/bot/%7B%7Bcharon.write%7D%7D/send")
            .header(
                "authorization",
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode("user:{{charon.write}}")
                ),
            )
            .body(Body::from("key=%7B%7Bcharon.write%7D%7D&operation=send"))?;
        let (parts, mut body) = request.into_parts();
        let target = url::Url::parse(&parts.uri.to_string())?;
        let preview = request_preview(
            &parts,
            &target,
            &mut body,
            4096,
            Some(&crate::broker::HydrationSink::Basic {
                username: "user".into(),
            }),
        )
        .await?;
        assert!(preview.contains("/bot/{{charon.write}}/send"));
        assert!(preview.contains("authorization: Basic base64(user:{{charon.write}})"));
        assert!(preview.contains("key=%7B%7Bcharon.write%7D%7D&operation=send"));
        Ok(())
    }
    #[tokio::test]
    async fn undisplayable_previews_fail_before_a_prompt() -> Result<()> {
        let t = coordinator()?;
        for (bytes, limit) in [
            (vec![b'x'; 3501], 4096),
            (vec![0xff], 4096),
            (vec![b'x'; 9], 8),
        ] {
            let request = http::Request::builder()
                .method("POST")
                .uri("https://api.example.test/first")
                .body(Body::from(bytes))?;
            let (parts, mut body) = request.into_parts();
            let target = url::Url::parse(&parts.uri.to_string())?;
            assert!(
                t.authorize_request("write", &parts, &target, &mut body, limit, None)
                    .await
                    .is_err()
            );
            assert_eq!(t.test_pending_count()?, 0);
            assert!(t.receive.lock().await.try_recv().is_err());
        }
        Ok(())
    }
    fn coordinator() -> Result<Arc<Telegram>> {
        Telegram::with_token(
            &TelegramConfig {
                user_id: 123,
                approval_capabilities: vec!["write".into()],
                approval_descriptions: HashMap::from([(
                    "write".into(),
                    "Write using the configured test policy".into(),
                )]),
            },
            "https://charon.example",
            SecretString::from("synthetic:token"),
        )
    }
    #[test]
    fn descriptions_are_complete_public_and_bounded() -> Result<()> {
        let valid = TelegramConfig {
            user_id: 123,
            approval_capabilities: vec!["write".into()],
            approval_descriptions: HashMap::from([("write".into(), "Write test data".into())]),
        };
        valid.validate_inventory(["write"].into_iter())?;
        for description in [
            String::new(),
            " ".into(),
            "x".repeat(241),
            "line\nbreak".into(),
            "hidden\u{202e}text".into(),
        ] {
            let mut config = valid.clone();
            config
                .approval_descriptions
                .insert("write".into(), description);
            assert!(config.validate().is_err());
        }
        let mut missing = valid.clone();
        missing.approval_descriptions.clear();
        assert!(missing.validate().is_err());
        let mut extra = valid;
        extra
            .approval_descriptions
            .insert("other".into(), "Other authority".into());
        assert!(extra.validate().is_err());
        Ok(())
    }
    #[tokio::test]
    async fn prompt_rate_is_bounded_even_after_decisions_and_recovers_after_window() -> Result<()> {
        let t = coordinator()?;
        for _ in 0..PROMPTS_PER_WINDOW {
            let gate = t.clone();
            let request = tokio::spawn(async move { gate.authorize("write", "POST").await });
            t.test_decide_next(true).await?;
            request.await??;
        }
        assert!(t.authorize("write", "POST").await.is_err());
        assert_eq!(t.test_pending_count()?, 0);
        t.authorize("read", "GET").await?;
        let expired = Instant::now()
            .checked_sub(PROMPT_WINDOW)
            .ok_or_else(|| anyhow::anyhow!("test clock underflow"))?;
        for at in t
            .recent_prompts
            .lock()
            .map_err(|_| anyhow::anyhow!("test mutex"))?
            .iter_mut()
        {
            *at = expired;
        }
        let gate = t.clone();
        let request = tokio::spawn(async move { gate.authorize("write", "POST").await });
        t.test_decide_next(false).await?;
        assert!(request.await?.is_err());
        Ok(())
    }
    #[tokio::test]
    async fn pending_capacity_exhaustion_does_not_enqueue_another_prompt() -> Result<()> {
        let t = coordinator()?;
        let mut receivers = Vec::new();
        for index in 0..32 {
            receivers.push(pending(
                &t,
                &format!("{index:032}"),
                Some(456),
                Instant::now() + APPROVAL_TTL,
            )?);
        }
        assert!(t.authorize("write", "POST").await.is_err());
        assert_eq!(t.test_pending_count()?, 32);
        assert!(t.receive.lock().await.try_recv().is_err());
        drop(receivers);
        Ok(())
    }
    #[tokio::test]
    async fn concurrent_decisions_release_only_their_own_request() -> Result<()> {
        let t = coordinator()?;
        let mut tasks = Vec::new();
        let mut prompts = Vec::new();
        for _ in 0..2 {
            let gate = t.clone();
            tasks.push(tokio::spawn(async move {
                gate.authorize("write", "POST").await
            }));
            prompts.push(
                t.receive
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("missing prompt"))?,
            );
        }
        for (index, prompt) in prompts.iter().enumerate() {
            let hash: [u8; 32] = Sha256::digest(prompt.token.expose_secret().as_bytes()).into();
            t.pending
                .lock()
                .map_err(|_| anyhow::anyhow!("test mutex"))?
                .get_mut(&hash)
                .ok_or_else(|| anyhow::anyhow!("missing pending request"))?
                .message = Some(456 + i64::try_from(index)?);
        }
        let mut second = callback(prompts[1].token.expose_secret());
        assert!(!t.callback(&second)); // Another request's message cannot release this request.
        second["message"]["message_id"] = json!(457);
        assert!(t.callback(&second));
        assert!(!tasks[0].is_finished());
        let mut first = callback(prompts[0].token.expose_secret());
        first["data"] = json!(format!("d:{}", prompts[0].token.expose_secret()));
        assert!(t.callback(&first));
        assert!(tasks.remove(0).await?.is_err());
        tasks.remove(0).await??;
        assert!(!t.callback(&second));
        Ok(())
    }
    #[test]
    fn configured_channel_requires_operator_entry_without_reading_a_secret_at_boot() -> Result<()> {
        let config = TelegramConfig {
            user_id: 123,
            approval_capabilities: vec!["write".into()],
            approval_descriptions: HashMap::from([(
                "write".into(),
                "Write using the configured test policy".into(),
            )]),
        };
        let mut keepass = crate::test_support::config("developer");
        keepass.items.clear();
        let store = Arc::new(crate::keepass::KeePassStore::new(keepass.clone())?);
        assert!(Telegram::new(&config, "https://charon.example", store).is_err());
        keepass.telegram_bot_token_entry_id = Some(uuid::Uuid::from_u128(999).to_string());
        let store = Arc::new(crate::keepass::KeePassStore::new(keepass)?);
        Telegram::new(&config, "https://charon.example", store.clone())?;
        assert!(store.health().is_err());
        Ok(())
    }
    fn callback(token: &str) -> Value {
        json!({"from":{"id":123},"message":{"message_id":456,"chat":{"id":123,"type":"private"}},"data":format!("a:{token}")})
    }
    fn pending(
        t: &Telegram,
        token: &str,
        message: Option<i64>,
        expires: Instant,
    ) -> Result<oneshot::Receiver<bool>> {
        let (send, receive) = oneshot::channel();
        t.pending
            .lock()
            .map_err(|_| anyhow::anyhow!("test mutex"))?
            .insert(
                Sha256::digest(token.as_bytes()).into(),
                Pending {
                    expires,
                    message,
                    reply: send,
                    preview: RequestPreview {
                        action: "send authenticated POST request to https://example.test/write".into(),
                        summary: "Write using the configured test policy\n\nPermission: write\nMethod: POST".into(),
                        request: "POST https://example.test/write\n\n[body hidden]".into(),
                    },
                },
            );
        Ok(receive)
    }
    #[tokio::test]
    async fn callback_binds_actor_chat_message_and_consumes_once() -> Result<()> {
        let t = coordinator()?;
        let token = "abcdefghijklmnopqrstuvwxyz012345";
        let receive = pending(&t, token, Some(456), Instant::now() + APPROVAL_TTL)?;
        for pointer in ["/from/id", "/message/chat/id", "/message/message_id"] {
            let mut wrong = callback(token);
            *wrong
                .pointer_mut(pointer)
                .ok_or_else(|| anyhow::anyhow!("missing fixture field"))? = json!(999);
            assert!(!t.callback(&wrong));
        }
        let mut group = callback(token);
        group["message"]["chat"]["type"] = json!("group");
        assert!(!t.callback(&group));
        let mut missing = callback(token);
        missing["message"]["message_id"] = Value::Null;
        assert!(!t.callback(&missing));
        assert!(t.callback(&callback(token)));
        assert!(receive.await?);
        assert!(!t.callback(&callback(token)));
        Ok(())
    }
    #[tokio::test]
    async fn expired_unsent_canceled_and_denied_requests_fail_closed() -> Result<()> {
        let t = coordinator()?;
        let token = "abcdefghijklmnopqrstuvwxyz012345";
        let _expired = pending(
            &t,
            token,
            Some(456),
            Instant::now()
                .checked_sub(Duration::from_secs(1))
                .ok_or_else(|| anyhow::anyhow!("test clock underflow"))?,
        )?;
        assert!(!t.callback(&callback(token)));
        let _unsent = pending(&t, token, None, Instant::now() + APPROVAL_TTL)?;
        let mut missing = callback(token);
        missing["message"]["message_id"] = Value::Null;
        assert!(!t.callback(&missing));
        assert!(!t.callback(&callback(token)));
        let canceled = pending(&t, token, Some(456), Instant::now() + APPROVAL_TTL)?;
        drop(canceled);
        assert!(!t.callback(&callback(token)));
        let receive = pending(&t, token, Some(456), Instant::now() + APPROVAL_TTL)?;
        let mut deny = callback(token);
        deny["data"] = json!(format!("d:{token}"));
        assert!(t.callback(&deny));
        assert!(!receive.await?);
        Ok(())
    }
    #[tokio::test]
    async fn authorize_requires_live_decision_and_policy_is_exact() -> Result<()> {
        let t = coordinator()?;
        t.authorize("read", "GET").await?;
        let waiting = t.clone();
        let task = tokio::spawn(async move { waiting.authorize("write", "POST").await });
        let prompt = t
            .receive
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("no prompt"))?;
        let token = prompt.token.expose_secret();
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        t.pending
            .lock()
            .map_err(|_| anyhow::anyhow!("test mutex"))?
            .get_mut(&hash)
            .ok_or_else(|| anyhow::anyhow!("no pending request"))?
            .message = Some(456);
        assert!(t.callback(&callback(token)));
        task.await??;
        let cfg = TelegramConfig {
            user_id: 123,
            approval_capabilities: vec!["typo".into()],
            approval_descriptions: HashMap::from([(
                "typo".into(),
                "Unknown test capability".into(),
            )]),
        };
        assert!(cfg.validate_inventory(["write"].into_iter()).is_err());
        Ok(())
    }
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn worker_sends_boot_url_and_buttons_and_polls_the_decision() -> Result<()> {
        use axum::{Json, Router, extract::State, routing::post};
        #[derive(Clone)]
        struct Api {
            sent: mpsc::Sender<Value>,
            callbacks: Arc<tokio::sync::Mutex<mpsc::Receiver<Value>>>,
            edits: mpsc::Sender<(Value, oneshot::Sender<bool>)>,
            polls: Arc<std::sync::atomic::AtomicUsize>,
            poll_started: Arc<tokio::sync::Notify>,
            release_poll: Arc<tokio::sync::Notify>,
        }
        async fn send(State(api): State<Api>, Json(body): Json<Value>) -> Json<Value> {
            let _ = api.sent.send(body).await;
            Json(json!({"ok":true,"result":{"message_id":456}}))
        }
        async fn updates(State(api): State<Api>) -> Json<Value> {
            if api.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                api.poll_started.notify_one();
                api.release_poll.notified().await;
            }
            let callback =
                tokio::time::timeout(Duration::from_millis(20), api.callbacks.lock().await.recv())
                    .await;
            Json(
                json!({"ok":true,"result":match callback {Ok(Some(value))=>vec![json!({"update_id":1,"callback_query":value})],_=>vec![]}}),
            )
        }
        async fn ack() -> Json<Value> {
            Json(json!({"ok":true,"result":true}))
        }
        async fn edit(State(api): State<Api>, Json(body): Json<Value>) -> Json<Value> {
            let (reply, result) = oneshot::channel();
            let _ = api.edits.send((body, reply)).await;
            Json(json!({"ok":result.await.unwrap_or(false),"result":true}))
        }
        let (sent, mut messages) = mpsc::channel(4);
        let (callbacks, incoming) = mpsc::channel(4);
        let (edits, mut edited) = mpsc::channel(4);
        let api = Api {
            sent,
            callbacks: Arc::new(tokio::sync::Mutex::new(incoming)),
            edits,
            polls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            poll_started: Arc::new(tokio::sync::Notify::new()),
            release_poll: Arc::new(tokio::sync::Notify::new()),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let router = Router::new()
            .route("/botsynthetic:token/sendMessage", post(send))
            .route("/botsynthetic:token/getUpdates", post(updates))
            .route("/botsynthetic:token/answerCallbackQuery", post(ack))
            .route("/botsynthetic:token/editMessageText", post(edit))
            .with_state(api.clone());
        let api_task = tokio::spawn(async move { axum::serve(listener, router).await });
        for show_owner_link in [true, false] {
            let mut t = coordinator()?;
            let channel =
                Arc::get_mut(&mut t).ok_or_else(|| anyhow::anyhow!("coordinator shared"))?;
            channel.api_origin = Some(format!("http://{address}"));
            if !show_owner_link {
                channel.origin = None;
            }
            let worker = t.clone();
            let worker_task = tokio::spawn(async move { worker.run().await });
            let boot = tokio::time::timeout(Duration::from_secs(5), messages.recv())
                .await?
                .ok_or_else(|| anyhow::anyhow!("missing boot message"))?;
            if show_owner_link {
                assert!(
                    boot["text"]
                        .as_str()
                        .is_some_and(|text| text.contains("https://charon.example"))
                );
            } else {
                assert_eq!(
                    boot["text"],
                    json!(
                        "Charon live test is ready.\nAllow the first test request, then deny the second."
                    )
                );
            }
            assert!(boot.get("reply_markup").is_none());
            if show_owner_link {
                tokio::time::timeout(Duration::from_secs(5), api.poll_started.notified()).await?;
            }
            for (allow, edit_success) in [(true, true), (false, true), (true, false)] {
                let gate = t.clone();
                let request = tokio::spawn(async move {
                    let request = http::Request::builder()
                        .method("POST")
                        .uri("https://example.test/write?operation=update")
                        .header("authorization", "Bearer {{charon.write}}")
                        .body(Body::empty())?;
                    let (parts, mut body) = request.into_parts();
                    let target = url::Url::parse(&parts.uri.to_string())?;
                    gate.authorize_request(
                        "write",
                        &parts,
                        &target,
                        &mut body,
                        4096,
                        Some(&crate::broker::HydrationSink::Authorization),
                    )
                    .await
                });
                let prompt = tokio::time::timeout(Duration::from_secs(5), messages.recv())
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("missing approval prompt"))?;
                if show_owner_link && allow && edit_success {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    assert_eq!(
                        api.polls.load(std::sync::atomic::Ordering::SeqCst),
                        1,
                        "sending a prompt canceled and restarted the active long poll"
                    );
                    api.release_poll.notify_one();
                }
                assert_eq!(prompt["chat_id"], json!(123));
                let text = prompt["text"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing prompt text"))?;
                assert!(text.contains("Write using the configured test policy"));
                assert!(text.contains("Permission: write"));
                assert!(text.contains("POST https://example.test/write?operation=update"));
                assert_eq!(
                    prompt["reply_markup"]["inline_keyboard"][0][0]["text"],
                    json!("Allow once")
                );
                let data = prompt["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing callback"))?;
                let token = data
                    .strip_prefix("a:")
                    .ok_or_else(|| anyhow::anyhow!("missing decision"))?;
                // The send response must bind the message before a callback can authorize.
                for _ in 0..100 {
                    let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
                    if t.pending
                        .lock()
                        .is_ok_and(|p| p.get(&hash).is_some_and(|p| p.message == Some(456)))
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
                assert_eq!(
                    prompt["reply_markup"]["inline_keyboard"][1][0]["text"],
                    json!("Show request details")
                );
                let mut view = callback(token);
                view["id"] = json!("synthetic-view");
                view["data"] = json!(format!("v:{token}"));
                callbacks.send(view).await?;
                let (details, finish_view) =
                    tokio::time::timeout(Duration::from_secs(5), edited.recv())
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("missing full request view"))?;
                assert!(
                    details["text"]
                        .as_str()
                        .is_some_and(|text| text.starts_with("Request details (secrets hidden)\n"))
                );
                assert_eq!(details["entities"][0]["language"], json!("http"));
                assert_eq!(
                    details["reply_markup"]["inline_keyboard"][0][0]["text"],
                    json!("Allow once")
                );
                assert!(!request.is_finished());
                assert_eq!(t.test_pending_count()?, 1);
                finish_view
                    .send(true)
                    .map_err(|_| anyhow::anyhow!("view canceled"))?;
                let mut decision = callback(token);
                decision["id"] = json!("synthetic-callback");
                if !allow {
                    decision["data"] = json!(format!("d:{token}"));
                }
                callbacks.send(decision).await?;
                let (feedback, finish) =
                    tokio::time::timeout(Duration::from_secs(5), edited.recv())
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("missing decision edit"))?;
                assert_eq!(feedback["chat_id"], json!(123));
                assert_eq!(feedback["message_id"], json!(456));
                assert_eq!(feedback["reply_markup"]["inline_keyboard"], json!([]));
                assert_eq!(
                    feedback["text"],
                    json!(format!(
                        "{}: send authenticated POST request to https://example.test/write",
                        if allow { "Allowed once" } else { "Denied" }
                    ))
                );
                assert_eq!(feedback["entities"], json!([]));
                assert!(
                    !request.is_finished(),
                    "request released before decision feedback completed"
                );
                finish
                    .send(edit_success)
                    .map_err(|_| anyhow::anyhow!("edit canceled"))?;
                let result = tokio::time::timeout(Duration::from_secs(5), request).await??;
                assert_eq!(result.is_ok(), allow);
            }
            worker_task.abort();
        }
        api_task.abort();
        Ok(())
    }
}
