//! Optional private Telegram allow-once/deny prompts. No vault password enters this channel.
use anyhow::{Result, ensure};
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
struct Pending {
    expires: Instant,
    message: Option<i64>,
    reply: oneshot::Sender<bool>,
}
struct Prompt {
    token: SecretString,
    capability: String,
    method: String,
    description: String,
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
    origin: String,
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
            origin: origin.into(),
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
    /// Require an allow-once decision for a configured capability, otherwise return immediately.
    ///
    /// # Errors
    /// Denies timeout, cancellation, queue saturation, channel failure, or a human denial.
    pub async fn authorize(&self, capability: &str, method: &str) -> Result<()> {
        let Some(description) = self.capabilities.get(capability) else {
            return Ok(());
        };
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
                },
            );
        }
        let sent = self
            .send
            .try_send(Prompt {
                token,
                capability: capability.into(),
                method: method.into(),
                description: description.clone(),
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
        self.call("sendMessage",json!({"chat_id":self.user,"text":format!("Charon vault unlocked. Owner page: {}",self.origin),"link_preview_options":{"is_disabled":true}})).await?;
        let mut receiver = self.receive.lock().await;
        let mut offset = 0i64;
        loop {
            tokio::select! {
                prompt=receiver.recv()=>{
                    let Some(prompt)=prompt else{return Ok(());};
                    let hash: [u8;32]=Sha256::digest(prompt.token.expose_secret().as_bytes()).into();
                    let live=self.pending.lock().is_ok_and(|p|p.get(&hash).is_some_and(|p|p.expires>Instant::now()&&!p.reply.is_closed()));
                    if !live{continue;}
                    let sent=self.call("sendMessage",json!({"chat_id":self.user,"text":format!("Allow one use of this capability?\nCapability: {}\nAuthority: {}\nMethod: {}\nResource and request body are not reviewed by this approval.\nExpires within two minutes; the request deadline may be shorter.",prompt.capability,prompt.description,prompt.method),"reply_markup":{"inline_keyboard":[[{"text":"Allow once","callback_data":format!("a:{}",prompt.token.expose_secret())},{"text":"Deny","callback_data":format!("d:{}",prompt.token.expose_secret())}]]}})).await;
                    if let Ok(mut pending)=self.pending.lock(){
                        match sent.ok().and_then(|v|v.get("message_id").and_then(Value::as_i64)) {
                            Some(id)=>if let Some(p)=pending.get_mut(&hash){p.message=Some(id);},
                            None=>{pending.remove(&hash);}
                        }
                    }
                }
                updates=self.call("getUpdates",json!({"offset":offset,"timeout":10,"allowed_updates":["callback_query"]}))=>{
                    match updates {
                        Ok(Value::Array(updates))=>for update in updates {
                            if let Some(id)=update.get("update_id").and_then(Value::as_i64){offset=offset.max(id.saturating_add(1));}
                            if let Some(callback)=update.get("callback_query"){
                                let decided=self.callback(callback);
                                if let Some(id)=callback.get("id").and_then(Value::as_str){let _=self.call("answerCallbackQuery",json!({"callback_query_id":id,"text":if decided{"Decision recorded"}else{"Request expired or unavailable"}})).await;}
                                if decided && let Some(message)=callback.pointer("/message/message_id").and_then(Value::as_i64){let _=self.call("editMessageReplyMarkup",json!({"chat_id":self.user,"message_id":message,"reply_markup":{"inline_keyboard":[]}})).await;}
                            }
                        },
                        _=>{tokio::time::sleep(Duration::from_secs(2)).await;}
                    }
                }
            }
        }
    }
    fn callback(&self, callback: &Value) -> bool {
        if callback.pointer("/from/id").and_then(Value::as_i64) != Some(self.user)
            || callback.pointer("/message/chat/id").and_then(Value::as_i64) != Some(self.user)
            || callback
                .pointer("/message/chat/type")
                .and_then(Value::as_str)
                != Some("private")
        {
            return false;
        }
        let Some(data) = callback.get("data").and_then(Value::as_str) else {
            return false;
        };
        let Some((decision, token)) = data.split_once(':') else {
            return false;
        };
        if !matches!(decision, "a" | "d") || token.len() != 32 {
            return false;
        }
        let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let Ok(mut pending) = self.pending.lock() else {
            return false;
        };
        let Some(p) = pending.get(&hash) else {
            return false;
        };
        let Some(message) = callback
            .pointer("/message/message_id")
            .and_then(Value::as_i64)
            .filter(|id| *id > 0)
        else {
            return false;
        };
        if p.expires <= Instant::now() || p.reply.is_closed() || p.message != Some(message) {
            return false;
        }
        let Some(p) = pending.remove(&hash) else {
            return false;
        };
        p.reply.send(decision == "a").is_ok()
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
            .map_err(|_| anyhow::anyhow!("Telegram unavailable"))?;
        ensure!(response.status().is_success(), "Telegram unavailable");
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
        ensure!(
            value.get("ok").and_then(Value::as_bool) == Some(true),
            "Telegram unavailable"
        );
        Ok(value.get("result").cloned().unwrap_or(Value::Null))
    }
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
    async fn worker_sends_boot_url_and_buttons_and_polls_the_decision() -> Result<()> {
        use axum::{Json, Router, extract::State, routing::post};
        #[derive(Clone)]
        struct Api {
            sent: mpsc::Sender<Value>,
            callbacks: Arc<tokio::sync::Mutex<mpsc::Receiver<Value>>>,
        }
        async fn send(State(api): State<Api>, Json(body): Json<Value>) -> Json<Value> {
            let _ = api.sent.send(body).await;
            Json(json!({"ok":true,"result":{"message_id":456}}))
        }
        async fn updates(State(api): State<Api>) -> Json<Value> {
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
        let (sent, mut messages) = mpsc::channel(4);
        let (callbacks, incoming) = mpsc::channel(4);
        let api = Api {
            sent,
            callbacks: Arc::new(tokio::sync::Mutex::new(incoming)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let router = Router::new()
            .route("/botsynthetic:token/sendMessage", post(send))
            .route("/botsynthetic:token/getUpdates", post(updates))
            .route("/botsynthetic:token/answerCallbackQuery", post(ack))
            .route("/botsynthetic:token/editMessageReplyMarkup", post(ack))
            .with_state(api);
        let api_task = tokio::spawn(async move { axum::serve(listener, router).await });
        let mut t = coordinator()?;
        Arc::get_mut(&mut t)
            .ok_or_else(|| anyhow::anyhow!("coordinator shared"))?
            .api_origin = Some(format!("http://{address}"));
        let worker = t.clone();
        let worker_task = tokio::spawn(async move { worker.run().await });
        let boot = tokio::time::timeout(Duration::from_secs(5), messages.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing boot message"))?;
        assert!(
            boot["text"]
                .as_str()
                .is_some_and(|text| text.contains("https://charon.example"))
        );
        assert!(boot.get("reply_markup").is_none());
        let gate = t.clone();
        let request = tokio::spawn(async move { gate.authorize("write", "POST").await });
        let prompt = tokio::time::timeout(Duration::from_secs(5), messages.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing approval prompt"))?;
        assert_eq!(prompt["chat_id"], json!(123));
        let text = prompt["text"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing prompt text"))?;
        assert!(text.contains("Authority: Write using the configured test policy"));
        assert!(text.contains("Resource and request body are not reviewed"));
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
        callbacks.send(callback(token)).await?;
        tokio::time::timeout(Duration::from_secs(5), request).await???;
        worker_task.abort();
        api_task.abort();
        Ok(())
    }
}
