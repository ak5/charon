//! Connected, offline E2E: encrypted KDBX, passkey HTTPS admin, Telegram worker,
//! curl workload, intercepted TLS, password API, lock and restart.
mod fixture;
mod password_api;
mod telegram_api;
use anyhow::{Result, ensure};
use fixture::{BOT_TOKEN, Fixture, MASTER, PASSWORDS};
use serde_json::{Value, json};
use std::sync::atomic::Ordering;

async fn decision(fixture: &mut Fixture, name: &str, allow: bool) -> Result<(u16, String)> {
    let request = fixture.request(name);
    let prompt = fixture.bot.message().await?;
    ensure!(
        prompt["text"]
            .as_str()
            .is_some_and(|text| text.contains(&format!("Permission: {name}"))),
        "wrong approval capability"
    );
    let text = prompt["text"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing prompt text"))?;
    ensure!(
        text.contains(&format!(
            "Call the {name} test API using its saved password"
        )) && text.contains(&format!("POST https://password.test/{name}")),
        "misleading approval scope"
    );
    no_values(&prompt.to_string())?;
    let lookups = fixture.store.lookup_count();
    let details = fixture.bot.view(&prompt).await?;
    ensure!(
        !request.is_finished() && fixture.store.lookup_count() == lookups,
        "viewing details authorized a request"
    );
    ensure!(
        details["text"]
            .as_str()
            .is_some_and(|text| text.contains(r#""operation":"synthetic-e2e""#)
                && text.contains("authorization: Bearer {{charon.")),
        "public JSON operation missing from details"
    );
    ensure!(
        details["entities"][0]["language"] == "http",
        "HTTP code block missing"
    );
    no_values(&details.to_string())?;
    fixture.bot.decide(&prompt, allow, 123).await?;
    tokio::time::timeout(std::time::Duration::from_secs(5), request).await??
}
fn no_values(body: &str) -> Result<()> {
    ensure!(
        !body.contains(MASTER)
            && !body.contains(BOT_TOKEN)
            && PASSWORDS.iter().all(|password| !body.contains(password)),
        "response disclosed a seeded credential"
    );
    Ok(())
}
#[tokio::test]
#[ignore = "starts local HTTPS services and curl; run mise run e2e-flow"]
#[allow(clippy::too_many_lines)]
async fn two_passwords_approval_and_restart() -> Result<()> {
    let mut fixture = Fixture::new().await?;
    fixture.verify_password_api().await?;
    let encrypted_before = std::fs::read(fixture.directory.path().join("two-passwords.kdbx"))?;
    for value in [MASTER, PASSWORDS[0], PASSWORDS[1], BOT_TOKEN] {
        ensure!(
            !encrypted_before
                .windows(value.len())
                .any(|window| window == value.as_bytes()),
            "KDBX contains plaintext seed"
        );
    }
    fixture.bot.assert_idle().await?;
    ensure!(fixture.store.health().is_err(), "store should boot locked");
    let (status, body) = fixture.request("first").await??;
    ensure!(status == 403, "locked request allowed");
    no_values(&body)?;
    ensure!(
        fixture.calls.load(Ordering::SeqCst) == 0,
        "locked request reached API"
    );
    fixture.enroll().await?;
    ensure!(
        fixture
            .post("unlock", json!({"password":MASTER}), false)
            .await?
            .status()
            == 403,
        "unauthenticated unlock accepted"
    );
    ensure!(
        fixture
            .post("unlock", json!({"password":"wrong-synthetic-master"}), true)
            .await?
            .status()
            == 403,
        "wrong master accepted"
    );
    fixture.bot.fail_next_message();
    ensure!(
        fixture
            .post("unlock", json!({"password":MASTER}), true)
            .await?
            .status()
            == 204,
        "correct master rejected"
    );
    fixture.store.health()?;
    ensure!(
        fixture
            .admin_client
            .get("https://admin.charon.test/api/status")
            .send()
            .await?
            .status()
            .is_success(),
        "Telegram notification failure stopped HTTPS admin"
    );
    let started = fixture.bot.message().await?;
    ensure!(
        started["text"]
            .as_str()
            .is_some_and(|text| text.contains("unlocked")),
        "unlock notification absent"
    );
    for name in ["first", "second"] {
        let (status, body) = decision(&mut fixture, name, true).await?;
        ensure!(status == 200, "allowed request did not succeed");
        no_values(&body)?;
        let body: Value = serde_json::from_str(&body)?;
        ensure!(
            body == json!({"ok":true,"endpoint":name}),
            "API saw the wrong credential or endpoint"
        );
    }
    ensure!(
        fixture.calls.load(Ordering::SeqCst) == 2,
        "both API endpoints were not reached"
    );
    let lookups = fixture.store.lookup_count();
    let (status, body) = decision(&mut fixture, "first", false).await?;
    ensure!(status == 403, "denial ignored");
    no_values(&body)?;
    ensure!(
        fixture.store.lookup_count() == lookups && fixture.calls.load(Ordering::SeqCst) == 2,
        "denial performed lookup or API call"
    );
    let waiting = fixture.request("second");
    let prompt = fixture.bot.message().await?;
    fixture.bot.decide(&prompt, true, 999).await?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    ensure!(
        !waiting.is_finished() && fixture.calls.load(Ordering::SeqCst) == 2,
        "wrong user approved request"
    );
    fixture.bot.decide(&prompt, false, 123).await?;
    let (status, body) =
        tokio::time::timeout(std::time::Duration::from_secs(5), waiting).await???;
    ensure!(status == 403, "owner denial ignored");
    no_values(&body)?;
    // A consumed callback must not authorize the next request to the same route.
    let waiting = fixture.request("second");
    let next = fixture.bot.message().await?;
    fixture.bot.decide(&prompt, true, 123).await?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    ensure!(
        !waiting.is_finished() && fixture.calls.load(Ordering::SeqCst) == 2,
        "replayed decision approved new request"
    );
    fixture.bot.decide(&next, false, 123).await?;
    ensure!(
        tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
            .await???
            .0
            == 403,
        "replay denial ignored"
    );
    let waiting = fixture.request("first");
    let _ = fixture.bot.message().await?;
    let (status, body) =
        tokio::time::timeout(std::time::Duration::from_secs(5), waiting).await???;
    ensure!(
        status == 403 && fixture.calls.load(Ordering::SeqCst) == 2,
        "missing decision did not time out closed"
    );
    no_values(&body)?;
    let interrupted = fixture.request("first");
    let old_prompt = fixture.bot.message().await?;
    ensure!(
        fixture.post("lock", json!({}), true).await?.status() == 204,
        "lock failed"
    );
    ensure!(
        tokio::time::timeout(std::time::Duration::from_secs(1), interrupted)
            .await???
            .0
            == 403,
        "lock did not cancel pending approval"
    );
    let (status, body) = fixture.request("second").await??;
    fixture.bot.assert_idle().await?;
    ensure!(
        status == 403 && fixture.calls.load(Ordering::SeqCst) == 2,
        "lock did not prevent use"
    );
    no_values(&body)?;
    fixture.restart().await?;
    fixture.bot.assert_idle().await?;
    ensure!(
        fixture.store.health().is_err(),
        "restart retained decrypted snapshot"
    );
    let (status, body) = fixture.request("first").await??;
    ensure!(status == 403, "restart boot allowed use");
    no_values(&body)?;
    fixture.login().await?;
    ensure!(
        fixture
            .post("unlock", json!({"password":MASTER}), true)
            .await?
            .status()
            == 204,
        "unlock after restart failed"
    );
    let _started = fixture.bot.message().await?;
    let waiting = fixture.request("second");
    let new_prompt = fixture.bot.message().await?;
    fixture.bot.decide(&old_prompt, true, 123).await?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    ensure!(
        !waiting.is_finished(),
        "pre-lock callback authorized after restart"
    );
    fixture.bot.decide(&new_prompt, true, 123).await?;
    let (status, body) = waiting.await??;
    ensure!(status == 200, "second entry unavailable after restart");
    no_values(&body)?;
    ensure!(
        fixture.calls.load(Ordering::SeqCst) == 3,
        "unexpected API request count"
    );
    ensure!(
        encrypted_before == std::fs::read(fixture.directory.path().join("two-passwords.kdbx"))?,
        "Charon modified database"
    );
    for path in ["passkeys.json", "receipts.jsonl", "receipts.chain"] {
        let bytes = std::fs::read(fixture.directory.path().join(path))?;
        for value in [MASTER, PASSWORDS[0], PASSWORDS[1], BOT_TOKEN] {
            ensure!(
                !bytes
                    .windows(value.len())
                    .any(|window| window == value.as_bytes()),
                "persistent state disclosed a seeded credential"
            );
        }
    }
    println!(
        "E2E passed: real KDBX with two API passwords and operator bot token, HTTPS passkeys/unlock, curl proxy/API, bot allow/deny/actor/replay/timeout, lock and restart"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "sends real Telegram test prompts; run the explicit live wrapper"]
async fn live_telegram_allow_and_deny() -> Result<()> {
    // Show only our fixed channel metadata, never dependency HTTP URL diagnostics.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "off,charon::telegram=warn",
        ))
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .try_init();
    let user_id = std::env::var("CHARON_E2E_TELEGRAM_USER_ID")?.parse::<i64>()?;
    ensure!(user_id > 0, "positive private user ID required");
    let password = {
        let mut input = zeroize::Zeroizing::new(String::new());
        std::io::stdin().read_line(&mut input)?;
        secrecy::SecretString::from(input.trim_end_matches(['\r', '\n']).to_owned())
    };
    let mut fixture = Fixture::live(user_id).await?;
    fixture.enroll().await?;
    ensure!(
        fixture
            .post(
                "unlock",
                json!({"password":secrecy::ExposeSecret::expose_secret(&password)}),
                true
            )
            .await?
            .status()
            == 204,
        "test unlock failed"
    );
    drop(password);
    println!(
        "In your test bot's private chat, press Allow once for capability first (within two minutes)."
    );
    let (status, body) = tokio::time::timeout(
        std::time::Duration::from_secs(130),
        fixture.request("first"),
    )
    .await???;
    ensure!(
        status == 200
            && serde_json::from_str::<Value>(&body)? == json!({"ok":true,"endpoint":"first"}),
        "live allow expected successful first API JSON; received HTTP {status}"
    );
    no_values(&body)?;
    ensure!(
        fixture.calls.load(Ordering::SeqCst) == 1,
        "live allow expected one API call; received {}",
        fixture.calls.load(Ordering::SeqCst)
    );
    println!("Now press Deny for capability second.");
    let lookups = fixture.store.lookup_count();
    let (status, body) = tokio::time::timeout(
        std::time::Duration::from_secs(130),
        fixture.request("second"),
    )
    .await???;
    ensure!(
        status == 403,
        "live denial expected HTTP 403; received {status}"
    );
    ensure!(
        fixture.calls.load(Ordering::SeqCst) == 1,
        "live denial expected API call count 1; received {}",
        fixture.calls.load(Ordering::SeqCst)
    );
    ensure!(
        fixture.store.lookup_count() == lookups,
        "live denial changed credential lookup count from {lookups} to {}",
        fixture.store.lookup_count()
    );
    no_values(&body)?;
    println!(
        "Live Telegram E2E passed: first API call allowed, second denied before lookup/egress."
    );
    Ok(())
}
