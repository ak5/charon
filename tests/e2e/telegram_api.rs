//! Offline Bot API transport. The production worker handles every callback.
use crate::telegram::{Telegram, TelegramConfig};
use anyhow::{Result, ensure};
use axum::{Json, Router, extract::State, routing::post};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicI64, Ordering},
};
use tokio::{net::TcpListener, sync::mpsc};
#[derive(Clone)]
struct Api {
    messages: mpsc::Sender<Value>,
    updates: Arc<tokio::sync::Mutex<mpsc::Receiver<Value>>>,
    next: Arc<AtomicI64>,
    fail_next: Arc<AtomicBool>,
}
async fn send(State(api): State<Api>, Json(mut body): Json<Value>) -> Json<Value> {
    if api.fail_next.swap(false, Ordering::SeqCst) {
        return Json(json!({"ok":false}));
    }
    let id = api.next.fetch_add(1, Ordering::SeqCst);
    body["message_id"] = json!(id);
    let _ = api.messages.send(body).await;
    Json(json!({"ok":true,"result":{"message_id":id}}))
}
async fn updates(State(api): State<Api>) -> Json<Value> {
    let update = tokio::time::timeout(
        std::time::Duration::from_millis(25),
        api.updates.lock().await.recv(),
    )
    .await;
    Json(json!({"ok":true,"result":match update{Ok(Some(value))=>vec![value],_=>vec![]}}))
}
async fn ack() -> Json<Value> {
    Json(json!({"ok":true,"result":true}))
}
pub struct Bot {
    pub channel: Arc<Telegram>,
    pub endpoint: String,
    fail_next: Arc<AtomicBool>,
    pub messages: mpsc::Receiver<Value>,
    updates: mpsc::Sender<Value>,
    next_update: i64,
    pub task: tokio::task::JoinHandle<()>,
}
impl Bot {
    pub async fn start(origin: &str, store: Arc<crate::keepass::KeePassStore>) -> Result<Self> {
        let (messages, receive) = mpsc::channel(32);
        let (update_sender, incoming) = mpsc::channel(32);
        let fail_next = Arc::new(AtomicBool::new(false));
        let api = Api {
            messages,
            updates: Arc::new(tokio::sync::Mutex::new(incoming)),
            next: Arc::new(AtomicI64::new(1)),
            fail_next: fail_next.clone(),
        };
        let router = Router::new()
            .route("/botsynthetic:token/sendMessage", post(send))
            .route("/botsynthetic:token/getUpdates", post(updates))
            .route("/botsynthetic:token/answerCallbackQuery", post(ack))
            .route("/botsynthetic:token/editMessageReplyMarkup", post(ack))
            .with_state(api);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let endpoint = format!("http://{address}");
        let channel = Telegram::test_api(&Self::config(), origin, &endpoint, store)?;
        Ok(Self {
            channel,
            endpoint,
            fail_next,
            messages: receive,
            updates: update_sender,
            next_update: 1,
            task,
        })
    }
    pub fn config() -> TelegramConfig {
        TelegramConfig {
            user_id: 123,
            approval_capabilities: vec!["first".into(), "second".into()],
            approval_descriptions: std::collections::HashMap::from([
                (
                    "first".into(),
                    "Send the first test API password to the configured first endpoint".into(),
                ),
                (
                    "second".into(),
                    "Send the second test API password to the configured second endpoint".into(),
                ),
            ]),
        }
    }
    pub fn fail_next_message(&self) {
        self.fail_next.store(true, Ordering::SeqCst);
    }
    pub async fn assert_idle(&mut self) -> Result<()> {
        ensure!(
            tokio::time::timeout(std::time::Duration::from_millis(150), self.messages.recv())
                .await
                .is_err(),
            "locked bot sent a message"
        );
        Ok(())
    }
    pub async fn message(&mut self) -> Result<Value> {
        tokio::time::timeout(std::time::Duration::from_secs(5), self.messages.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing bot message"))
    }
    pub async fn decide(&mut self, prompt: &Value, allow: bool, user: i64) -> Result<()> {
        let button = usize::from(!allow);
        let data = prompt["reply_markup"]["inline_keyboard"][0][button]["callback_data"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing callback"))?;
        ensure!(
            prompt["chat_id"].as_i64() == Some(123),
            "wrong prompt recipient"
        );
        let callback = json!({"id":format!("synthetic-{}",self.next_update),"from":{"id":user},"message":{"message_id":prompt["message_id"],"chat":{"id":123,"type":"private"}},"data":data});
        self.updates
            .send(json!({"update_id":self.next_update,"callback_query":callback}))
            .await?;
        self.next_update += 1;
        Ok(())
    }
}
