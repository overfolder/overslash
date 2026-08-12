//! A field-aware SSE client for tests.
//!
//! The in-repo client parser (`overslash-mcp-puppet/src/sse.rs`) deliberately
//! ignores `id:` and `event:` because the MCP transport never emits them, but
//! `GET /v1/events/stream` builds its whole resume contract on `id:` and names
//! every frame with `event:`. So the tests need their own reader.
//!
//! It lives here rather than in the file that first needed it: more than one
//! test file now asserts on the event wire (the stream's own contract, and the
//! expiry sweep's events), and a test file is not a helper module.

use std::time::Duration;

use futures_util::StreamExt;
use reqwest::Client;
use serde_json::Value;
use sqlx::PgPool;

/// Connection ceiling used by the stream tests. Long enough to observe a live
/// event, short enough that a test asserting "the server hangs up" finishes fast.
pub const STREAM_SECS: u64 = 3;

/// One parsed SSE frame. Keep-alive comments are dropped by the parser.
#[derive(Debug, Clone)]
pub struct Frame {
    pub id: Option<String>,
    pub event: Option<String>,
    pub data: String,
}

impl Frame {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.data).expect("frame data is json")
    }

    /// The `data` of the wire envelope — what a webhook subscriber would get.
    pub fn payload(&self) -> Value {
        self.json()
            .get("data")
            .cloned()
            .expect("envelope carries data")
    }

    pub fn cursor(&self) -> i64 {
        self.id
            .as_ref()
            .expect("event frames carry an id")
            .parse()
            .expect("id is the numeric cursor")
    }
}

/// Read an SSE response to completion, returning every frame. Bounded by
/// `timeout` so a stream the server forgot to close fails the test instead of
/// hanging it. Reached through [`read_stream`].
async fn collect_frames(resp: reqwest::Response, timeout: Duration) -> Vec<Frame> {
    assert!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .starts_with("text/event-stream"),
        "expected an SSE content-type, got {:?}",
        resp.headers().get("content-type")
    );

    let mut frames = Vec::new();
    let mut buf = String::new();
    let mut body = resp.bytes_stream();

    let read = async {
        while let Some(chunk) = body.next().await {
            let chunk = chunk.expect("stream chunk");
            buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(split) = find_frame_boundary(&buf) {
                let (raw, rest) = buf.split_at(split.0);
                let remainder = rest[split.1..].to_string();
                if let Some(frame) = parse_frame(raw) {
                    frames.push(frame);
                }
                buf = remainder;
            }
        }
    };
    // A clean server-side close ends `read` on its own; the timeout is the
    // backstop for a stream that never closes.
    let _ = tokio::time::timeout(timeout, read).await;
    frames
}

/// Byte offset of the next frame terminator and its length, handling both
/// `\n\n` and `\r\n\r\n`.
fn find_frame_boundary(buf: &str) -> Option<(usize, usize)> {
    match (buf.find("\r\n\r\n"), buf.find("\n\n")) {
        (Some(crlf), Some(lf)) if crlf <= lf => Some((crlf, 4)),
        (_, Some(lf)) => Some((lf, 2)),
        (Some(crlf), None) => Some((crlf, 4)),
        (None, None) => None,
    }
}

/// Parse one frame. Returns `None` for keep-alive comments and any block with
/// no `data:` line.
fn parse_frame(raw: &str) -> Option<Frame> {
    let mut id = None;
    let mut event = None;
    let mut data: Vec<String> = Vec::new();

    for line in raw.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "id" => id = Some(value.to_string()),
            "event" => event = Some(value.to_string()),
            "data" => data.push(value.to_string()),
            _ => {}
        }
    }

    if data.is_empty() {
        return None;
    }
    Some(Frame {
        id,
        event,
        data: data.join("\n"),
    })
}

/// Open a stream and read it to completion.
pub async fn read_stream(
    client: &Client,
    base: &str,
    key: &str,
    query: &str,
    last_event_id: Option<i64>,
) -> Vec<Frame> {
    let resp = open_stream(client, base, key, query, last_event_id).await;
    assert_eq!(resp.status(), 200, "stream should open");
    collect_frames(resp, Duration::from_secs(STREAM_SECS + 5)).await
}

pub async fn open_stream(
    client: &Client,
    base: &str,
    key: &str,
    query: &str,
    last_event_id: Option<i64>,
) -> reqwest::Response {
    let mut req = client
        .get(format!("{base}/v1/events/stream{query}"))
        .header("Accept", "text/event-stream")
        .header("Authorization", format!("Bearer {key}"));
    if let Some(cursor) = last_event_id {
        req = req.header("Last-Event-ID", cursor.to_string());
    }
    req.send().await.expect("stream request")
}

/// Boot an API whose Postgres `LISTEN` task is running.
///
/// Not the shared router: a stream outlives the shared harness's per-test
/// `ResourceGuard`, and live fan-out needs the listener that only
/// `start_api_with_event_stream` spawns.
pub async fn start_stream_api(pool: PgPool) -> (String, Client) {
    let (addr, client) = super::start_api_with_event_stream(pool, |config| {
        config.events_stream_max_connection_secs = STREAM_SECS;
    })
    .await;
    (format!("http://{addr}"), client)
}
