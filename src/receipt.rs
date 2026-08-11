//! Bounded metadata-only data-plane receipt journal.

use std::{
    fs::{File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result, bail};
use axum::body::Bytes;
use futures_util::{Stream, StreamExt as _, stream};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;
use zeroize::Zeroize;

use crate::{config::ReceiptConfig, provider::ensure_private_file};

const MAX_RECEIPT_LINE_BYTES: usize = 64 * 1024;

/// Safe request outcome recorded without headers, arguments, or bodies.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptOutcome {
    /// The sanitized response stream completed.
    Completed,
    /// Delivery stopped after some safe bytes were emitted.
    Interrupted,
    /// Response mediation failed closed.
    ResponseSanitizationFailed,
    /// Authorization or policy denied execution.
    Denied,
}

/// Metadata allowed in the durable data-plane journal.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DataPlaneReceipt {
    /// Stable realm identifier.
    pub realm: String,
    /// Stable workload identifier.
    pub workload: String,
    /// Named public capability.
    pub capability: String,
    /// Policy service name, not a provider reference.
    pub service: String,
    /// Exact authorized destination hostname.
    pub destination: String,
    /// HTTP method.
    pub method: String,
    /// Authorized path without query values.
    pub path: String,
    /// Upstream status when available.
    pub status: Option<u16>,
    /// Bytes safely delivered to the caller.
    pub delivered_bytes: u64,
    /// Monotonic elapsed milliseconds.
    pub elapsed_ms: u64,
    /// Final delivery outcome.
    pub outcome: ReceiptOutcome,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptEnvelope {
    receipt: DataPlaneReceipt,
    chain: String,
}

/// Cloneable bounded journal handle.
#[derive(Clone)]
pub struct ReceiptJournal {
    sender: mpsc::Sender<DataPlaneReceipt>,
    healthy: Arc<AtomicBool>,
}

/// Capacity reserved before any credential resolution or upstream request.
pub struct ReceiptPermit {
    permit: Option<mpsc::OwnedPermit<DataPlaneReceipt>>,
}

impl ReceiptJournal {
    /// Open protected journal state and start its single append worker.
    ///
    /// # Errors
    ///
    /// Returns an error before listener bind when paths cannot be opened.
    pub fn start(config: &ReceiptConfig) -> Result<Self> {
        let journal_existed = config.journal_path.exists();
        drop(open_private_append(&config.journal_path)?);
        ensure_private_file(&config.journal_path, "receipt journal")?;
        if !journal_existed {
            sync_parent(&config.journal_path)?;
        }
        let previous = recover_chain(&config.journal_path, &config.state_path)?;
        let journal = open_private_append(&config.journal_path)?;
        let (sender, receiver) = mpsc::channel(config.queue_capacity);
        let healthy = Arc::new(AtomicBool::new(true));
        let worker_health = Arc::clone(&healthy);
        let state_path = config.state_path.clone();
        tokio::spawn(async move {
            if write_loop(journal, state_path, previous, receiver)
                .await
                .is_err()
            {
                worker_health.store(false, Ordering::Release);
            }
        });
        Ok(Self { sender, healthy })
    }

    /// Queue one final receipt without waiting for disk I/O.
    ///
    /// # Errors
    ///
    /// Fails closed when the writer has failed or the bounded queue is full.
    pub fn record(&self, receipt: DataPlaneReceipt) -> Result<()> {
        if !self.healthy.load(Ordering::Acquire) {
            bail!("receipt journal is unavailable");
        }
        self.sender
            .try_send(receipt)
            .map_err(|_| anyhow::anyhow!("receipt journal queue is unavailable"))
    }

    /// Reserve finalization capacity before execution begins.
    ///
    /// # Errors
    ///
    /// Fails when the writer is unhealthy, closed, or at its configured bound.
    pub fn reserve(&self) -> Result<ReceiptPermit> {
        if !self.healthy.load(Ordering::Acquire) {
            bail!("receipt journal is unavailable");
        }
        let permit = self
            .sender
            .clone()
            .try_reserve_owned()
            .map_err(|_| anyhow::anyhow!("receipt journal queue is unavailable"))?;
        Ok(ReceiptPermit {
            permit: Some(permit),
        })
    }

    /// Report whether the writer and queue remain available.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
            && !self.sender.is_closed()
            && self.sender.capacity() > 0
    }
}

/// Finalize one receipt from the actual mediated delivery stream.
pub fn receipt_stream<S, E>(
    upstream: S,
    permit: ReceiptPermit,
    receipt: DataPlaneReceipt,
    started: std::time::Instant,
) -> impl Stream<Item = std::io::Result<Bytes>> + Send
where
    S: Stream<Item = std::result::Result<Bytes, E>> + Send + 'static,
    E: std::fmt::Display,
{
    let state = DeliveryState {
        upstream: Box::pin(upstream),
        permit,
        receipt: Some(receipt),
        started,
        delivered: 0,
    };
    stream::unfold(state, |mut state| async move {
        match state.upstream.next().await {
            Some(Ok(chunk)) => {
                state.delivered = state.delivered.saturating_add(chunk.len() as u64);
                Some((Ok(chunk), state))
            }
            Some(Err(_)) => {
                state.finish(ReceiptOutcome::ResponseSanitizationFailed);
                Some((
                    Err(std::io::Error::other("mediated response interrupted")),
                    state,
                ))
            }
            None => {
                state.finish(ReceiptOutcome::Completed);
                None
            }
        }
    })
}

struct DeliveryState<S> {
    upstream: std::pin::Pin<Box<S>>,
    permit: ReceiptPermit,
    receipt: Option<DataPlaneReceipt>,
    started: std::time::Instant,
    delivered: u64,
}

impl<S> DeliveryState<S> {
    fn finish(&mut self, outcome: ReceiptOutcome) {
        let Some(mut receipt) = self.receipt.take() else {
            return;
        };
        receipt.outcome = outcome;
        receipt.delivered_bytes = self.delivered;
        receipt.elapsed_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let Some(permit) = self.permit.permit.take() else {
            tracing::error!(
                outcome = "receipt_lost",
                "receipt finalization permit is unavailable"
            );
            return;
        };
        let sender = permit.send(receipt);
        if sender.is_closed() {
            tracing::error!(
                outcome = "receipt_lost",
                "receipt writer closed during finalization"
            );
        }
    }
}

impl<S> Drop for DeliveryState<S> {
    fn drop(&mut self) {
        self.finish(ReceiptOutcome::Interrupted);
    }
}

async fn write_loop(
    mut journal: File,
    state_path: PathBuf,
    mut previous: [u8; 32],
    mut receiver: mpsc::Receiver<DataPlaneReceipt>,
) -> Result<()> {
    while let Some(receipt) = receiver.recv().await {
        let payload = serde_json::to_vec(&receipt).context("receipt encoding failed")?;
        let mut hasher = Sha256::new();
        hasher.update(previous);
        hasher.update(&payload);
        previous.copy_from_slice(&hasher.finalize());
        let envelope = ReceiptEnvelope {
            receipt,
            chain: hex(&previous),
        };
        serde_json::to_writer(&mut journal, &envelope).context("receipt append failed")?;
        journal.write_all(b"\n").context("receipt append failed")?;
        journal.sync_data().context("receipt sync failed")?;
        write_state(&state_path, &previous)?;
    }
    Ok(())
}

fn read_state(path: &Path) -> Result<Option<[u8; 32]>> {
    if !path.exists() {
        return Ok(None);
    }
    ensure_private_file(path, "receipt state")?;
    let value = std::fs::read_to_string(path).context("receipt state is unavailable")?;
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = decode_hex(value.trim()).context("receipt state is invalid")?;
    bytes
        .try_into()
        .map(Some)
        .map_err(|_| anyhow::anyhow!("receipt state is invalid"))
}

fn recover_chain(journal_path: &Path, state_path: &Path) -> Result<[u8; 32]> {
    let checkpoint = read_state(state_path)?;
    let mut checkpoint_seen = checkpoint.is_none_or(|value| value == [0; 32]);
    let mut previous = [0; 32];
    let mut journal = OpenOptions::new()
        .read(true)
        .write(true)
        .open(journal_path)
        .context("receipt journal is unavailable")?;
    let mut read_buffer = [0_u8; 8192];
    let mut pending = Vec::new();
    let mut offset = 0_u64;
    let mut complete_offset = 0_u64;
    loop {
        let count = journal
            .read(&mut read_buffer)
            .context("receipt journal replay failed")?;
        if count == 0 {
            break;
        }
        for byte in &read_buffer[..count] {
            offset += 1;
            if *byte == b'\n' {
                if pending.is_empty() {
                    bail!("receipt journal contains an empty entry");
                }
                previous = validate_envelope(&pending, &previous)?;
                checkpoint_seen |= checkpoint == Some(previous);
                pending.clear();
                complete_offset = offset;
            } else {
                if pending.len() >= MAX_RECEIPT_LINE_BYTES {
                    bail!("receipt journal entry exceeds its bound");
                }
                pending.push(*byte);
            }
        }
    }
    if !pending.is_empty() {
        pending.zeroize();
        if checkpoint.is_some_and(|value| value != previous) {
            bail!("receipt journal has an inconsistent truncated tail");
        }
        journal
            .set_len(complete_offset)
            .context("receipt journal tail recovery failed")?;
        journal.sync_data().context("receipt journal sync failed")?;
    }
    if !checkpoint_seen {
        bail!("receipt chain state is not present in the verified journal");
    }
    if checkpoint != Some(previous) {
        write_state(state_path, &previous)?;
    }
    Ok(previous)
}

fn validate_envelope(line: &[u8], previous: &[u8; 32]) -> Result<[u8; 32]> {
    let envelope: ReceiptEnvelope =
        serde_json::from_slice(line).context("receipt journal entry is invalid")?;
    let payload = serde_json::to_vec(&envelope.receipt).context("receipt encoding failed")?;
    let mut hasher = Sha256::new();
    hasher.update(previous);
    hasher.update(payload);
    let expected: [u8; 32] = hasher.finalize().into();
    if envelope.chain != hex(&expected) {
        bail!("receipt journal chain is invalid");
    }
    Ok(expected)
}

fn write_state(path: &Path, value: &[u8; 32]) -> Result<()> {
    let temporary = path.with_extension("tmp");
    if temporary.exists() {
        std::fs::remove_file(&temporary).context("stale receipt state update is unavailable")?;
    }
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .context("receipt state update is unavailable")?;
    file.write_all(hex(value).as_bytes())
        .context("receipt state update failed")?;
    file.sync_all().context("receipt state sync failed")?;
    drop(file);
    std::fs::rename(&temporary, path).context("receipt state commit failed")?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path.parent().context("receipt path has no parent")?;
    File::open(parent)
        .context("receipt directory is unavailable")?
        .sync_all()
        .context("receipt directory sync failed")
}

fn open_private_append(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).context("receipt state is unavailable")
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::time::Duration;

    use sha2::{Digest as _, Sha256};

    use super::{
        DataPlaneReceipt, ReceiptEnvelope, ReceiptJournal, ReceiptOutcome, hex,
        open_private_append, recover_chain, write_state,
    };
    use crate::config::ReceiptConfig;

    #[tokio::test]
    async fn journal_contains_only_the_closed_metadata_shape() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let journal_path = directory.path().join("receipts.jsonl");
        let state_path = directory.path().join("chain");
        let journal = ReceiptJournal::start(&ReceiptConfig {
            journal_path: journal_path.clone(),
            state_path,
            queue_capacity: 2,
        })
        .unwrap_or_else(|error| panic!("{error}"));
        journal
            .record(DataPlaneReceipt {
                realm: "realm-test".into(),
                workload: "workload-test".into(),
                capability: "api-read".into(),
                service: "api".into(),
                destination: "api.example.test".into(),
                method: "GET".into(),
                path: "/v1/profile".into(),
                status: Some(200),
                delivered_bytes: 12,
                elapsed_ms: 3,
                outcome: ReceiptOutcome::Completed,
            })
            .unwrap_or_else(|error| panic!("{error}"));
        for _ in 0..20 {
            if std::fs::read_to_string(&journal_path).is_ok_and(|value| !value.is_empty()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let output =
            std::fs::read_to_string(journal_path).unwrap_or_else(|error| panic!("{error}"));
        assert!(output.contains("api-read"));
        assert!(output.contains("\"chain\":"));
        for forbidden in [
            "authorization",
            "arguments",
            "result",
            "credential",
            "fixture-secret",
        ] {
            assert!(!output.contains(forbidden));
        }
    }

    #[test]
    fn startup_replays_journal_and_repairs_a_stale_checkpoint() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let journal_path = directory.path().join("receipts.jsonl");
        let state_path = directory.path().join("chain");
        let first = sample_receipt("first");
        let (first_line, first_chain) = envelope(&[0; 32], first);
        let (second_line, second_chain) = envelope(&first_chain, sample_receipt("second"));
        let mut journal =
            open_private_append(&journal_path).unwrap_or_else(|error| panic!("{error}"));
        journal
            .write_all(&[first_line, second_line].concat())
            .unwrap_or_else(|error| panic!("{error}"));
        journal
            .sync_data()
            .unwrap_or_else(|error| panic!("{error}"));
        write_state(&state_path, &first_chain).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            recover_chain(&journal_path, &state_path).unwrap_or_else(|error| panic!("{error}")),
            second_chain
        );
        assert_eq!(
            std::fs::read_to_string(state_path).unwrap_or_else(|error| panic!("{error}")),
            hex(&second_chain)
        );
    }

    #[test]
    fn startup_truncates_only_an_uncheckpointed_partial_tail() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let journal_path = directory.path().join("receipts.jsonl");
        let state_path = directory.path().join("chain");
        let (line, chain) = envelope(&[0; 32], sample_receipt("complete"));
        let mut journal =
            open_private_append(&journal_path).unwrap_or_else(|error| panic!("{error}"));
        journal
            .write_all(&[line.clone(), b"{\"receipt\":".to_vec()].concat())
            .unwrap_or_else(|error| panic!("{error}"));
        journal
            .sync_data()
            .unwrap_or_else(|error| panic!("{error}"));
        write_state(&state_path, &chain).unwrap_or_else(|error| panic!("{error}"));

        assert_eq!(
            recover_chain(&journal_path, &state_path).unwrap_or_else(|error| panic!("{error}")),
            chain
        );
        assert_eq!(
            std::fs::read(journal_path).unwrap_or_else(|error| panic!("{error}")),
            line
        );
    }

    #[test]
    fn startup_rejects_invalid_chain_and_unrecognized_checkpoint() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let journal_path = directory.path().join("receipts.jsonl");
        let state_path = directory.path().join("chain");
        let (mut line, _) = envelope(&[0; 32], sample_receipt("invalid"));
        let index = line
            .iter()
            .position(|byte| *byte == b'a')
            .unwrap_or_else(|| panic!("fixture contains no mutable chain byte"));
        line[index] = b'b';
        let mut journal =
            open_private_append(&journal_path).unwrap_or_else(|error| panic!("{error}"));
        journal
            .write_all(&line)
            .unwrap_or_else(|error| panic!("{error}"));
        journal
            .sync_data()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(recover_chain(&journal_path, &state_path).is_err());

        let other_journal = directory.path().join("other.jsonl");
        let other_state = directory.path().join("other-chain");
        let (valid, _) = envelope(&[0; 32], sample_receipt("valid"));
        let mut journal =
            open_private_append(&other_journal).unwrap_or_else(|error| panic!("{error}"));
        journal
            .write_all(&valid)
            .unwrap_or_else(|error| panic!("{error}"));
        journal
            .sync_data()
            .unwrap_or_else(|error| panic!("{error}"));
        write_state(&other_state, &[0x55; 32]).unwrap_or_else(|error| panic!("{error}"));
        assert!(recover_chain(&other_journal, &other_state).is_err());
    }

    fn sample_receipt(capability: &str) -> DataPlaneReceipt {
        DataPlaneReceipt {
            realm: "realm-test".into(),
            workload: "workload-test".into(),
            capability: capability.into(),
            service: "api".into(),
            destination: "api.example.test".into(),
            method: "GET".into(),
            path: "/v1/profile".into(),
            status: Some(200),
            delivered_bytes: 12,
            elapsed_ms: 3,
            outcome: ReceiptOutcome::Completed,
        }
    }

    fn envelope(previous: &[u8; 32], receipt: DataPlaneReceipt) -> (Vec<u8>, [u8; 32]) {
        let payload = serde_json::to_vec(&receipt).unwrap_or_else(|error| panic!("{error}"));
        let mut hasher = Sha256::new();
        hasher.update(previous);
        hasher.update(payload);
        let chain: [u8; 32] = hasher.finalize().into();
        let mut line = serde_json::to_vec(&ReceiptEnvelope {
            receipt,
            chain: hex(&chain),
        })
        .unwrap_or_else(|error| panic!("{error}"));
        line.push(b'\n');
        (line, chain)
    }
}
