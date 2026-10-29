//! Bounded streaming response mediation.

use std::{collections::HashSet, pin::Pin, time::Duration};

use anyhow::{Context, Result, bail};
use axum::body::Bytes;
use futures_util::{Stream, StreamExt as _, stream};
use http::{HeaderMap, HeaderName};
use secrecy::{ExposeSecret as _, SecretString};
use zeroize::Zeroize;

use crate::broker::{CompressionPolicy, StructuredStreamFormat};

const REDACTION: &[u8] = b"[REDACTED]";
const RESPONSE_FORBIDDEN_HEADERS: [&str; 8] = [
    "authentication-info",
    "proxy-authenticate",
    "proxy-authorization",
    "set-cookie",
    "set-cookie2",
    "www-authenticate",
    "x-debug-token",
    "x-session-token",
];

/// Maximum bytes delivered and whether delivery completed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeliveryProgress {
    /// Bytes released after mediation.
    pub bytes: u64,
    /// True only after the upstream body and sanitizer both completed.
    pub complete: bool,
}

/// Strip credential/session response headers before downstream headers exist.
///
/// `Location` and other remaining values are denied when they contain a known
/// protected value. Content encoding is governed explicitly because compressed
/// bytes cannot be truthfully described as scanned text.
///
/// # Errors
///
/// Rejects forbidden compression or a protected value in a retained header.
pub fn sanitize_headers(
    headers: &HeaderMap,
    protected: &[SecretString],
    compression: CompressionPolicy,
    opaque_body: bool,
) -> Result<HeaderMap> {
    let forbidden = RESPONSE_FORBIDDEN_HEADERS
        .iter()
        .map(|name| HeaderName::from_static(name))
        .collect::<HashSet<_>>();
    for encoding in headers.get_all(http::header::CONTENT_ENCODING) {
        let identity = encoding
            .to_str()
            .is_ok_and(|value| value.eq_ignore_ascii_case("identity"));
        match compression {
            CompressionPolicy::IdentityOnly | CompressionPolicy::Reject if !identity => {
                bail!("encoded response is not permitted")
            }
            CompressionPolicy::Opaque if !opaque_body => {
                bail!("encoded response requires an opaque response mode")
            }
            _ => {}
        }
    }

    let mut output = HeaderMap::new();
    for (name, value) in headers {
        if forbidden.contains(name) || is_hop_by_hop(name) || name == http::header::CONTENT_LENGTH {
            continue;
        }
        if contains_protected(value.as_bytes(), protected) {
            bail!("response header contains protected material");
        }
        output.append(name.clone(), value.clone());
    }
    Ok(output)
}

/// Stream text through a rolling redactor with backpressure and bounded state.
///
/// The sanitizer retains at most `6 * longest protected value + 12` uncommitted
/// bytes plus the current upstream chunk. Cancellation drops and zeroizes the
/// retained overlap. Stream errors expose only a fixed local message.
pub fn redact_text_stream<S, E>(
    upstream: S,
    protected: Vec<SecretString>,
    byte_limit: usize,
) -> Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send>>
where
    S: Stream<Item = std::result::Result<Bytes, E>> + Send + 'static,
    E: std::fmt::Display,
{
    let state = RedactionState {
        upstream: Box::pin(upstream),
        protected,
        pending: Vec::new(),
        received: 0,
        byte_limit,
        finished: false,
    };
    Box::pin(stream::unfold(state, |mut state| async move {
        loop {
            if state.finished {
                if state.pending.is_empty() {
                    return None;
                }
                let bytes = Bytes::from(redact_prefix(&mut state.pending, &state.protected, true));
                return Some((Ok(bytes), state));
            }
            match state.upstream.next().await {
                Some(Ok(chunk)) => {
                    state.received = match state.received.checked_add(chunk.len()) {
                        Some(total) if total <= state.byte_limit => total,
                        _ => {
                            state.pending.zeroize();
                            state.finished = true;
                            return Some((
                                Err(std::io::Error::other("response size limit exceeded")),
                                state,
                            ));
                        }
                    };
                    state.pending.extend_from_slice(&chunk);
                    let output = redact_prefix(&mut state.pending, &state.protected, false);
                    if !output.is_empty() {
                        return Some((Ok(Bytes::from(output)), state));
                    }
                }
                Some(Err(_)) => {
                    state.pending.zeroize();
                    state.finished = true;
                    return Some((
                        Err(std::io::Error::other("upstream response interrupted")),
                        state,
                    ));
                }
                None => state.finished = true,
            }
        }
    }))
}

/// Enforce aggregate bytes, total lifetime, and per-chunk idle time while
/// preserving downstream backpressure and cancellation.
pub fn guard_stream<S, E>(
    upstream: S,
    byte_limit: usize,
    lifetime: Duration,
    idle: Duration,
) -> Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send>>
where
    S: Stream<Item = std::result::Result<Bytes, E>> + Send + 'static,
    E: std::fmt::Display,
{
    let deadline = tokio::time::Instant::now() + lifetime;
    let state = (Box::pin(upstream), 0_usize, false);
    Box::pin(stream::unfold(
        state,
        move |(mut upstream, received, done)| async move {
            if done {
                return None;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Some((
                    Err(std::io::Error::other("response lifetime exceeded")),
                    (upstream, received, true),
                ));
            }
            let wait = idle.min(remaining);
            match tokio::time::timeout(wait, upstream.next()).await {
                Err(_) => Some((
                    Err(std::io::Error::other("response stream timed out")),
                    (upstream, received, true),
                )),
                Ok(None) => None,
                Ok(Some(Err(_))) => Some((
                    Err(std::io::Error::other("upstream response interrupted")),
                    (upstream, received, true),
                )),
                Ok(Some(Ok(chunk))) => {
                    let total = received.checked_add(chunk.len());
                    match total {
                        Some(total) if total <= byte_limit => {
                            Some((Ok(chunk), (upstream, total, false)))
                        }
                        _ => Some((
                            Err(std::io::Error::other("response size limit exceeded")),
                            (upstream, received, true),
                        )),
                    }
                }
            }
        },
    ))
}

const STRUCTURED_SCAN_WINDOW_BYTES: usize = 64 * 1024;

/// Parse, sanitize, and emit one bounded SSE event or NDJSON record at a time.
pub fn sanitize_structured_stream<S, E>(
    upstream: S,
    format: StructuredStreamFormat,
    max_record_bytes: usize,
    forbidden_fields: Vec<String>,
) -> Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send>>
where
    S: Stream<Item = std::result::Result<Bytes, E>> + Send + 'static,
    E: std::fmt::Display,
{
    let state = StructuredState {
        upstream: Box::pin(upstream),
        pending: Vec::new(),
        incoming: Bytes::new(),
        incoming_offset: 0,
        format,
        max_record_bytes,
        forbidden_fields,
        record_ready: false,
        finished: false,
    };
    Box::pin(stream::unfold(state, |mut state| async move {
        loop {
            if (state.record_ready || state.finished)
                && let Some((record, consumed)) =
                    next_record(&state.pending, state.format, state.finished)
            {
                state.pending.drain(..consumed);
                state.record_ready = false;
                if record.len() > state.max_record_bytes {
                    state.pending.zeroize();
                    state.finished = true;
                    return Some((
                        Err(std::io::Error::other(
                            "structured response record is too large",
                        )),
                        state,
                    ));
                }
                let output = sanitize_record(&record, state.format, &state.forbidden_fields)
                    .map(Bytes::from)
                    .map_err(|_| std::io::Error::other("structured response sanitization failed"));
                return Some((output, state));
            }
            if state.finished {
                return None;
            }
            if state.incoming_offset < state.incoming.len() {
                let remaining = &state.incoming[state.incoming_offset..];
                let scan_length = remaining.len().min(STRUCTURED_SCAN_WINDOW_BYTES);
                let scan = &remaining[..scan_length];
                let boundary_length =
                    bytes_through_next_boundary(&state.pending, scan, state.format);
                let framing_allowance = framing_allowance(state.format);
                let append_limit = state
                    .max_record_bytes
                    .saturating_add(framing_allowance)
                    .saturating_sub(state.pending.len())
                    .saturating_add(1);
                let append_length = boundary_length.unwrap_or(scan.len()).min(append_limit);
                state.pending.extend_from_slice(&scan[..append_length]);
                state.incoming_offset += append_length;
                state.record_ready = boundary_length == Some(append_length);
                if state.pending.len() > state.max_record_bytes.saturating_add(framing_allowance) {
                    state.pending.zeroize();
                    state.finished = true;
                    return Some((
                        Err(std::io::Error::other(
                            "structured response record is too large",
                        )),
                        state,
                    ));
                }
                if boundary_length != Some(append_length)
                    && state.incoming_offset < state.incoming.len()
                {
                    tokio::task::yield_now().await;
                }
                continue;
            }
            match state.upstream.next().await {
                Some(Ok(chunk)) => {
                    state.incoming = chunk;
                    state.incoming_offset = 0;
                }
                Some(Err(_)) => {
                    state.pending.zeroize();
                    state.finished = true;
                    return Some((
                        Err(std::io::Error::other("upstream response interrupted")),
                        state,
                    ));
                }
                None => state.finished = true,
            }
        }
    }))
}

/// Sanitize one bounded JSON document.
///
/// # Errors
///
/// Rejects invalid JSON and documents that cannot be re-encoded.
pub fn sanitize_json_document(input: &[u8], forbidden_fields: &[String]) -> Result<Vec<u8>> {
    let mut value: serde_json::Value =
        serde_json::from_slice(input).context("structured response is invalid JSON")?;
    remove_fields(&mut value, forbidden_fields);
    serde_json::to_vec(&value).context("structured response could not be encoded")
}

struct StructuredState<S> {
    upstream: Pin<Box<S>>,
    pending: Vec<u8>,
    incoming: Bytes,
    incoming_offset: usize,
    format: StructuredStreamFormat,
    max_record_bytes: usize,
    forbidden_fields: Vec<String>,
    record_ready: bool,
    finished: bool,
}

impl<S> Drop for StructuredState<S> {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

const fn framing_allowance(format: StructuredStreamFormat) -> usize {
    match format {
        StructuredStreamFormat::Sse => 4,
        StructuredStreamFormat::Ndjson => 1,
    }
}

fn bytes_through_next_boundary(
    pending: &[u8],
    incoming: &[u8],
    format: StructuredStreamFormat,
) -> Option<usize> {
    let mut earliest = None;
    let delimiters: &[&[u8]] = match format {
        StructuredStreamFormat::Sse => &[b"\n\n", b"\r\n\r\n"],
        StructuredStreamFormat::Ndjson => &[b"\n"],
    };
    for delimiter in delimiters {
        for pending_length in 1..delimiter.len() {
            let incoming_length = delimiter.len() - pending_length;
            if pending.len() >= pending_length
                && incoming.len() >= incoming_length
                && pending.ends_with(&delimiter[..pending_length])
                && incoming.starts_with(&delimiter[pending_length..])
            {
                earliest = Some(earliest.map_or(incoming_length, |current: usize| {
                    current.min(incoming_length)
                }));
            }
        }
        if let Some(index) = find_bytes(incoming, delimiter) {
            let through_boundary = index + delimiter.len();
            earliest = Some(earliest.map_or(through_boundary, |current: usize| {
                current.min(through_boundary)
            }));
        }
    }
    earliest
}

fn next_record(
    pending: &[u8],
    format: StructuredStreamFormat,
    finished: bool,
) -> Option<(Vec<u8>, usize)> {
    let boundary = match format {
        StructuredStreamFormat::Sse => {
            let lf = find_bytes(pending, b"\n\n").map(|index| (index, 2));
            let crlf = find_bytes(pending, b"\r\n\r\n").map(|index| (index, 4));
            match (lf, crlf) {
                (Some(left), Some(right)) => Some(if left.0 <= right.0 { left } else { right }),
                (left, right) => left.or(right),
            }
        }
        StructuredStreamFormat::Ndjson => find_bytes(pending, b"\n").map(|index| (index, 1)),
    };
    if let Some((index, delimiter_length)) = boundary {
        return Some((pending[..index].to_vec(), index + delimiter_length));
    }
    (finished && !pending.is_empty()).then(|| (pending.to_vec(), pending.len()))
}

fn sanitize_record(
    record: &[u8],
    format: StructuredStreamFormat,
    forbidden_fields: &[String],
) -> Result<Vec<u8>> {
    match format {
        StructuredStreamFormat::Ndjson => {
            let mut output = sanitize_json_document(record, forbidden_fields)?;
            output.push(b'\n');
            Ok(output)
        }
        StructuredStreamFormat::Sse => {
            let text = std::str::from_utf8(record).context("SSE event is not UTF-8")?;
            let mut output = Vec::new();
            let mut data_lines = Vec::new();
            for line in text.lines() {
                if let Some(data) = line.strip_prefix("data:") {
                    data_lines.push(data.strip_prefix(' ').unwrap_or(data));
                } else if line.starts_with(':')
                    || line.starts_with("event:")
                    || line.starts_with("id:")
                    || line.starts_with("retry:")
                {
                    output.extend_from_slice(line.as_bytes());
                    output.push(b'\n');
                } else {
                    bail!("SSE event contains an unsupported field");
                }
            }
            if !data_lines.is_empty() {
                let data = data_lines.join("\n");
                if data == "[DONE]" {
                    output.extend_from_slice(b"data: [DONE]\n");
                } else {
                    let sanitized = sanitize_json_document(data.as_bytes(), forbidden_fields)?;
                    output.extend_from_slice(b"data: ");
                    output.extend_from_slice(&sanitized);
                    output.push(b'\n');
                }
            }
            output.push(b'\n');
            Ok(output)
        }
    }
}

fn remove_fields(value: &mut serde_json::Value, forbidden_fields: &[String]) {
    match value {
        serde_json::Value::Object(object) => {
            object.retain(|name, _| !forbidden_fields.iter().any(|field| field == name));
            for child in object.values_mut() {
                remove_fields(child, forbidden_fields);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                remove_fields(item, forbidden_fields);
            }
        }
        _ => {}
    }
}

struct RedactionState<S> {
    upstream: Pin<Box<S>>,
    protected: Vec<SecretString>,
    pending: Vec<u8>,
    received: usize,
    byte_limit: usize,
    finished: bool,
}

impl<S> Drop for RedactionState<S> {
    fn drop(&mut self) {
        self.pending.zeroize();
    }
}

fn redact_prefix(buffer: &mut Vec<u8>, protected: &[SecretString], finished: bool) -> Vec<u8> {
    let mut output = Vec::new();
    let mut offset = 0;
    while offset < buffer.len() {
        let input = &buffer[offset..];
        let mut partial = false;
        let matched = protected
            .iter()
            .filter_map(|value| {
                let secret = value.expose_secret();
                if secret.is_empty() {
                    return None;
                }
                partial |= input.len() < secret.len() && secret.as_bytes().starts_with(input);
                let raw = input.starts_with(secret.as_bytes()).then_some(secret.len());
                let decoded = match json_secret_length(input, secret) {
                    Ok(length) => Some(length),
                    Err(incomplete) => {
                        partial |= incomplete;
                        None
                    }
                };
                raw.into_iter().chain(decoded).max()
            })
            .max();
        if partial && !finished {
            break;
        }
        if let Some(length) = matched {
            output.extend_from_slice(REDACTION);
            offset += length;
        } else {
            output.push(buffer[offset]);
            offset += 1;
        }
    }
    buffer[..offset].zeroize();
    buffer.drain(..offset);
    output
}

// Decode JSON characters during matching, including mixed escapes and surrogate pairs.
// This also covers JSON embedded in SSE/text without buffering an entire document.
fn json_secret_length(input: &[u8], secret: &str) -> Result<usize, bool> {
    let mut offset = 0;
    for expected in secret.chars() {
        let remaining = input.get(offset..).ok_or(true)?;
        if remaining.first() == Some(&b'\\') {
            let (character, length) = json_escape(remaining).ok_or(remaining.len() < 12)?;
            if character != expected {
                return Err(false);
            }
            offset += length;
        } else {
            let mut encoded = [0; 4];
            let bytes = expected.encode_utf8(&mut encoded).as_bytes();
            if !remaining.starts_with(bytes) {
                return Err(bytes.starts_with(remaining));
            }
            offset += bytes.len();
        }
    }
    Ok(offset)
}

fn json_escape(input: &[u8]) -> Option<(char, usize)> {
    let character = match *input.get(1)? {
        b'"' => '"',
        b'\\' => '\\',
        b'/' => '/',
        b'b' => '\u{8}',
        b'f' => '\u{c}',
        b'n' => '\n',
        b'r' => '\r',
        b't' => '\t',
        b'u' => {
            let hex = |bytes: &[u8]| u32::from_str_radix(std::str::from_utf8(bytes).ok()?, 16).ok();
            let first = hex(input.get(2..6)?)?;
            if (0xd800..=0xdbff).contains(&first) {
                if input.get(6..8)? != b"\\u" {
                    return None;
                }
                let second = hex(input.get(8..12)?)?;
                if !(0xdc00..=0xdfff).contains(&second) {
                    return None;
                }
                return Some((
                    char::from_u32(0x10000 + ((first - 0xd800) << 10) + second - 0xdc00)?,
                    12,
                ));
            }
            return Some((char::from_u32(first)?, 6));
        }
        _ => return None,
    };
    Some((character, 2))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|candidate| candidate == needle)
}

pub(crate) fn contains_protected(value: &[u8], protected: &[SecretString]) -> bool {
    protected.iter().any(|secret| {
        let needle = secret.expose_secret().as_bytes();
        !needle.is_empty()
            && (find_bytes(value, needle).is_some()
                || (0..value.len()).any(|offset| {
                    json_secret_length(&value[offset..], secret.expose_secret()).is_ok()
                }))
    })
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use axum::body::Bytes;
    use futures_util::{StreamExt as _, stream};
    use http::{HeaderMap, HeaderValue};
    use secrecy::SecretString;

    use super::{redact_text_stream, sanitize_headers};
    use crate::broker::CompressionPolicy;

    #[tokio::test]
    async fn redacts_a_secret_split_across_chunks() {
        let upstream = stream::iter([
            Ok::<_, std::io::Error>("before fixture-".into()),
            Ok("secret after".into()),
        ]);
        let chunks = redact_text_stream(upstream, vec![SecretString::from("fixture-secret")], 1024)
            .collect::<Vec<_>>()
            .await;
        let body = chunks
            .into_iter()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap_or_else(|error| panic!("{error}"))
            .concat();
        assert_eq!(body, b"before [REDACTED] after");
    }

    #[tokio::test]
    async fn redacts_json_escapes_and_replacement_text_at_every_chunk_boundary() {
        for (secret, input, expected) in [
            ("REDACTED", "REDACTED REDACTED", "[REDACTED] [REDACTED]"),
            (
                "a\"bcdefgh",
                r#"{"echo":"a\"bcdefgh"}"#,
                r#"{"echo":"[REDACTED]"}"#,
            ),
            (
                "a\"bcdefgh",
                r#"{"a\u0022b\u0063defgh":true}"#,
                r#"{"[REDACTED]":true}"#,
            ),
            (
                "ab😀cd/é",
                r#"data: {"echo":"\u0061b\uD83D\ude00cd\/\u00e9"}

"#,
                "data: {\"echo\":\"[REDACTED]\"}\n\n",
            ),
            (
                "ab\\cd\nef",
                r#"{"echo":"ab\\cd\nef"}"#,
                r#"{"echo":"[REDACTED]"}"#,
            ),
        ] {
            for split in 0..=input.len() {
                let chunks = [
                    Bytes::copy_from_slice(&input.as_bytes()[..split]),
                    Bytes::copy_from_slice(&input.as_bytes()[split..]),
                ];
                let output = redact_text_stream(
                    stream::iter(chunks.map(Ok::<_, std::io::Error>)),
                    vec![SecretString::from(secret)],
                    4096,
                )
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<std::io::Result<Vec<_>>>()
                .unwrap_or_else(|error| panic!("{error}"))
                .concat();
                assert_eq!(output, expected.as_bytes(), "split {split}");
            }
        }
    }

    #[tokio::test]
    async fn redaction_does_not_rescan_replacements_or_commit_partial_matches() {
        let input = format!(
            "{}fixture-secret-tail{}fixture-secret",
            "x".repeat(100),
            "y".repeat(100)
        );
        let chunks = input
            .as_bytes()
            .chunks(1)
            .map(|chunk| Ok::<_, std::io::Error>(Bytes::copy_from_slice(chunk)))
            .collect::<Vec<_>>();
        let output = redact_text_stream(
            stream::iter(chunks),
            vec![
                SecretString::from("fixture-secret"),
                SecretString::from("fixture-secret-tail"),
                SecretString::from("REDACTED"),
            ],
            4096,
        )
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap_or_else(|error| panic!("{error}"))
        .concat();
        assert_eq!(
            output,
            format!("{}[REDACTED]{}[REDACTED]", "x".repeat(100), "y".repeat(100)).as_bytes()
        );
    }

    #[tokio::test]
    async fn stream_guard_bounds_bytes_and_idle_time() {
        let guarded = super::guard_stream(
            stream::iter([Ok::<_, std::io::Error>("123".into()), Ok("456".into())]),
            5,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        )
        .collect::<Vec<_>>()
        .await;
        assert!(guarded[0].is_ok());
        assert!(guarded[1].is_err());
    }

    #[test]
    fn buffered_json_removes_forbidden_fields_recursively() {
        let output = super::sanitize_json_document(
            br#"{"ok":true,"token":"fixture-secret","nested":{"signed_url":"bad","value":1}}"#,
            &["token".into(), "signed_url".into()],
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let text = String::from_utf8(output).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(text, r#"{"nested":{"value":1},"ok":true}"#);
    }

    #[tokio::test]
    async fn sse_sanitizes_one_fragmented_event_at_a_time() {
        let upstream = stream::iter([
            Ok::<_, std::io::Error>(Bytes::from_static(b"data: {\"token\":\"fixture-")),
            Ok(Bytes::from_static(b"secret\",\"text\":\"safe\"}\n\n")),
        ]);
        let structured = super::sanitize_structured_stream(
            upstream,
            crate::broker::StructuredStreamFormat::Sse,
            1024,
            vec!["token".into()],
        );
        let output = structured
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap_or_else(|error| panic!("{error}"))
            .concat();
        assert_eq!(output, b"data: {\"text\":\"safe\"}\n\n");
    }

    #[tokio::test]
    async fn structured_stream_limits_records_not_coalesced_network_chunks() {
        let upstream = stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(
            b"{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n",
        ))]);
        let output = super::sanitize_structured_stream(
            upstream,
            crate::broker::StructuredStreamFormat::Ndjson,
            8,
            Vec::new(),
        )
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap_or_else(|error| panic!("{error}"))
        .concat();
        assert_eq!(output, b"{\"n\":1}\n{\"n\":2}\n{\"n\":3}\n");

        let oversized = stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(
            b"{\"number\":123}\n",
        ))]);
        let result = super::sanitize_structured_stream(
            oversized,
            crate::broker::StructuredStreamFormat::Ndjson,
            8,
            Vec::new(),
        )
        .collect::<Vec<_>>()
        .await;
        assert_eq!(result.len(), 1);
        assert!(result[0].is_err());

        let sse = stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(
            b"data: {\"n\":1}\n\ndata: {\"n\":2}\n\n",
        ))]);
        let output = super::sanitize_structured_stream(
            sse,
            crate::broker::StructuredStreamFormat::Sse,
            13,
            Vec::new(),
        )
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap_or_else(|error| panic!("{error}"))
        .concat();
        assert_eq!(output, b"data: {\"n\":1}\n\ndata: {\"n\":2}\n\n");
    }

    #[tokio::test]
    async fn structured_stream_rejects_a_large_delimiter_free_chunk() {
        let oversized = Bytes::from(vec![b'x'; super::STRUCTURED_SCAN_WINDOW_BYTES * 3]);
        let result = super::sanitize_structured_stream(
            stream::iter([Ok::<_, std::io::Error>(oversized)]),
            crate::broker::StructuredStreamFormat::Ndjson,
            super::STRUCTURED_SCAN_WINDOW_BYTES * 2,
            Vec::new(),
        )
        .collect::<Vec<_>>()
        .await;

        assert_eq!(result.len(), 1);
        assert!(result[0].is_err());
    }

    #[tokio::test]
    async fn structured_stream_detects_delimiters_split_between_chunks() {
        let upstream = stream::iter([
            Ok::<_, std::io::Error>(Bytes::from_static(b"data: {\"n\":1}\r\n")),
            Ok(Bytes::from_static(b"\r\ndata: {\"n\":2}\n")),
            Ok(Bytes::from_static(b"\n")),
        ]);
        let output = super::sanitize_structured_stream(
            upstream,
            crate::broker::StructuredStreamFormat::Sse,
            32,
            Vec::new(),
        )
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap_or_else(|error| panic!("{error}"))
        .concat();

        assert_eq!(output, b"data: {\"n\":1}\n\ndata: {\"n\":2}\n\n");
    }

    #[test]
    fn denies_json_escaped_headers_and_every_compression_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-echo",
            HeaderValue::from_static(r#"{"value":"a\u0022bcdefgh"}"#),
        );
        assert!(
            sanitize_headers(
                &headers,
                &[SecretString::from("a\"bcdefgh")],
                CompressionPolicy::IdentityOnly,
                false
            )
            .is_err()
        );
        headers.clear();
        headers.append("content-encoding", HeaderValue::from_static("identity"));
        headers.append("content-encoding", HeaderValue::from_static("gzip"));
        assert!(sanitize_headers(&headers, &[], CompressionPolicy::IdentityOnly, false).is_err());
    }

    #[test]
    fn strips_sessions_and_denies_reflection_in_retained_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "set-cookie",
            HeaderValue::from_static("session=fixture-secret"),
        );
        headers.insert(
            "location",
            HeaderValue::from_static("https://safe.example/next"),
        );
        let safe = sanitize_headers(
            &headers,
            &[SecretString::from("fixture-secret")],
            CompressionPolicy::IdentityOnly,
            false,
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(safe.get("set-cookie").is_none());

        headers.insert(
            "location",
            HeaderValue::from_static("https://safe.example/?token=fixture-secret"),
        );
        assert!(
            sanitize_headers(
                &headers,
                &[SecretString::from("fixture-secret")],
                CompressionPolicy::IdentityOnly,
                false,
            )
            .is_err()
        );
    }
}
