//! How big an upstream response was, recorded so the buffering caps can be
//! tuned against real traffic instead of guessed.
//!
//! Every `action.executed` row that saw an upstream response carries a
//! `detail.size` block built here, and the same observation feeds the
//! `overslash_action_response_bytes` histogram. The two exist for different
//! questions: the audit row answers "what does *this* org's Metabase return"
//! with SQL, the histogram answers "how much traffic sits over the 5 MB cap"
//! on a dashboard.
//!
//! `size.read` says how much of the body we actually saw:
//!
//! * `complete` — buffered in full; `bytes` is the size.
//! * `aborted_at_cap` — we stopped reading at `limit_bytes`. `bytes` is what
//!   was read before stopping (a lower bound, `0` when the declared
//!   `Content-Length` refused the body up front); `content_length`, when the
//!   upstream sent one, is the true size. We deliberately do not keep reading
//!   past the cap just to measure — that would spend the bandwidth the cap
//!   exists to save. A client that then redeems the minted download URL gets
//!   the real number on its `action.stream_completed` row.
//! * `streamed` — piped through without buffering, so at audit time only the
//!   declared `content_length` is known; the bytes that actually flowed land on
//!   the `action.stream_completed` row written when the stream ends.
//!
//! `bytes` counts what the upstream sent, before `String::from_utf8_lossy`
//! (which turns each invalid byte into a 3-byte U+FFFD, so a binary body
//! would read ~3× too large) — see `ActionResult::wire_bytes`. Results built
//! in-process, and MCP envelopes, fall back to the decoded length.
//! `content_length` is the declared wire size (compressed, when the upstream
//! compressed it).

use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Bytes;
use futures_util::Stream;
use overslash_core::types::ActionResult;
use serde_json::{Value, json};

/// How much of the body was observed. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeRead {
    Complete,
    AbortedAtCap,
    Streamed,
}

impl SizeRead {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::AbortedAtCap => "aborted_at_cap",
            Self::Streamed => "streamed",
        }
    }
}

/// One observation of an upstream response's size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseSize {
    /// Bytes actually read. `None` on the streamed path, where nothing has
    /// been read yet when the row is written.
    pub bytes: Option<u64>,
    /// The upstream's declared `Content-Length`, if it sent one.
    pub content_length: Option<u64>,
    pub read: SizeRead,
    /// The buffering cap in force. `None` where none applies (streamed).
    pub limit_bytes: Option<usize>,
}

impl ResponseSize {
    /// A body that was buffered in full. Counts the wire bytes when the HTTP
    /// caller recorded them, else the decoded body (MCP envelopes, results
    /// built in-process).
    pub fn complete(result: &ActionResult, limit_bytes: usize) -> Self {
        Self {
            bytes: Some(result.wire_bytes.unwrap_or(result.body.len() as u64)),
            content_length: content_length(&result.headers),
            read: SizeRead::Complete,
            limit_bytes: Some(limit_bytes),
        }
    }

    /// A body we stopped reading at the cap.
    pub fn aborted(bytes_read: u64, content_length: Option<u64>, limit_bytes: usize) -> Self {
        Self {
            bytes: Some(bytes_read),
            content_length,
            read: SizeRead::AbortedAtCap,
            limit_bytes: Some(limit_bytes),
        }
    }

    /// A body piped through unbuffered.
    pub fn streamed(content_length: Option<u64>) -> Self {
        Self {
            bytes: None,
            content_length,
            read: SizeRead::Streamed,
            limit_bytes: None,
        }
    }

    /// Best available figure for the true size: the declared length when the
    /// read was cut short, otherwise what we counted.
    pub fn best_estimate(&self) -> Option<u64> {
        match self.read {
            SizeRead::Complete => self.bytes,
            SizeRead::AbortedAtCap => self.content_length.or(self.bytes),
            SizeRead::Streamed => self.content_length,
        }
    }

    /// The `detail.size` object.
    pub fn to_json(&self) -> Value {
        json!({
            "bytes": self.bytes,
            "content_length": self.content_length,
            "read": self.read.as_str(),
            "limit_bytes": self.limit_bytes,
        })
    }

    /// Stamp `detail.size` onto an audit detail object.
    pub fn stamp(&self, detail: &mut Value) {
        if let Some(obj) = detail.as_object_mut() {
            obj.insert("size".into(), self.to_json());
        }
    }

    /// Feed `overslash_action_response_bytes`. Skipped when there is no
    /// figure to record (a streamed body without `Content-Length` — its
    /// completion records the counted bytes instead).
    pub fn record_metric(&self, template_key: &str, runtime: &str) {
        if let Some(bytes) = self.best_estimate() {
            overslash_metrics::actions::record_response_size(
                template_key,
                runtime,
                self.read.as_str(),
                bytes,
            );
        }
    }
}

/// The declared `Content-Length` from a buffered result's header map.
/// `http_caller` lowercases header names, so one lookup suffices.
pub fn content_length(headers: &HashMap<String, String>) -> Option<u64> {
    headers
        .get("content-length")
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// The `size` block for a transport failure, or `None` when the failure
/// never saw a body. Paired with `audit_capture::scrub_transport_error`,
/// which describes the *error*; this describes the *response*.
pub fn of_call_error(err: &super::http_caller::CallError) -> Option<ResponseSize> {
    match err {
        super::http_caller::CallError::ResponseTooLarge {
            content_length,
            limit_bytes,
            bytes_read,
            ..
        } => Some(ResponseSize::aborted(
            *bytes_read,
            *content_length,
            *limit_bytes,
        )),
        _ => None,
    }
}

/// Same as [`of_call_error`], for the MCP client's oversized-response error.
pub fn of_mcp_error(err: &super::mcp_client::McpClientError) -> Option<ResponseSize> {
    match err {
        super::mcp_client::McpClientError::ResponseTooLarge {
            limit_bytes,
            content_length,
            bytes_read,
        } => Some(ResponseSize::aborted(
            *bytes_read,
            *content_length,
            *limit_bytes,
        )),
        _ => None,
    }
}

/// What a metered stream saw by the time it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamTally {
    pub bytes: u64,
    /// `true` when the upstream body ended cleanly. `false` on an upstream
    /// error, an idle stall, or the client hanging up mid-transfer — in which
    /// case `bytes` is a lower bound.
    pub completed: bool,
}

type OnDone = Box<dyn FnOnce(StreamTally) + Send + 'static>;

/// Wraps a body stream, counts the bytes that flow through it, and calls
/// `on_done` exactly once: when the stream ends, errors, or is dropped
/// unfinished (a client that hung up). The callback runs on whatever task
/// polled or dropped the stream, so it must not block — spawn the audit
/// write rather than awaiting it.
pub struct Metered<S> {
    inner: Pin<Box<S>>,
    bytes: u64,
    /// The upstream's declared length. hyper stops polling a body once it has
    /// written `Content-Length` bytes and drops it without ever reading the
    /// end of the stream, so a drop that already carried this many bytes is a
    /// finished transfer, not a hang-up.
    expected: Option<u64>,
    on_done: Option<OnDone>,
}

impl<S> Metered<S> {
    pub fn new(
        inner: S,
        expected: Option<u64>,
        on_done: impl FnOnce(StreamTally) + Send + 'static,
    ) -> Self {
        Self {
            inner: Box::pin(inner),
            bytes: 0,
            expected,
            on_done: Some(Box::new(on_done)),
        }
    }

    fn finish(&mut self, completed: bool) {
        if let Some(f) = self.on_done.take() {
            f(StreamTally {
                bytes: self.bytes,
                completed,
            });
        }
    }
}

impl<S, E> Stream for Metered<S>
where
    S: Stream<Item = Result<Bytes, E>>,
{
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Fused: once the body has ended or errored, never poll the inner
        // stream again. hyper can poll a body past its end, and the stream
        // this wraps (`idle_guarded_stream`, an `unfold`) panics if polled
        // after it returned `None`.
        if self.on_done.is_none() {
            return Poll::Ready(None);
        }
        let polled = self.inner.as_mut().poll_next(cx);
        match &polled {
            Poll::Ready(Some(Ok(chunk))) => self.bytes += chunk.len() as u64,
            Poll::Ready(Some(Err(_))) => self.finish(false),
            Poll::Ready(None) => self.finish(true),
            Poll::Pending => {}
        }
        polled
    }
}

impl<S> Drop for Metered<S> {
    fn drop(&mut self) {
        let delivered_all = self.expected.is_some_and(|n| self.bytes >= n);
        self.finish(delivered_all);
    }
}

/// Histogram `read` label for a streamed transfer that ended before its
/// body did; its byte count is a lower bound.
pub const STREAM_CUT_SHORT: &str = "stream_cut_short";

/// Who and what a metered stream belongs to, so its end can be audited.
///
/// Written as `action.stream_completed` — a separate row from the
/// `action.streamed` / `action.downloaded` one, because those are written
/// when the headers arrive and the byte count only exists once the body has
/// finished. `detail.via` says which surface carried it: `prefer_stream`
/// (inline) or `download` (a redeemed capability URL, `resource_id` = the
/// token).
pub struct CompletionAudit {
    pub scope: overslash_db::scopes::OrgScope,
    pub identity_id: uuid::Uuid,
    pub service: Option<String>,
    pub action: Option<String>,
    /// Registry-bounded template key, for the metric label.
    pub template_key: String,
    pub via: &'static str,
    pub token_id: Option<uuid::Uuid>,
    pub ip: Option<String>,
}

impl CompletionAudit {
    /// The `on_done` callback for [`Metered`]: records the counted bytes on
    /// the histogram and spawns the audit write (the callback may run inside
    /// `Drop`, which cannot await).
    pub fn into_callback(self) -> impl FnOnce(StreamTally) + Send + 'static {
        move |tally| {
            // A transfer cut short (upstream error, stall, client hang-up)
            // only knows a floor. Labelled apart rather than dropped, so it
            // can't drag the completed distribution down but still shows how
            // often large transfers die mid-flight.
            let read = if tally.completed {
                SizeRead::Streamed.as_str()
            } else {
                STREAM_CUT_SHORT
            };
            overslash_metrics::actions::record_response_size(
                &self.template_key,
                "download",
                read,
                tally.bytes,
            );
            let Ok(rt) = tokio::runtime::Handle::try_current() else {
                return;
            };
            rt.spawn(async move {
                let detail = json!({
                    "via": self.via,
                    "service": self.service,
                    "action": self.action,
                    "bytes_streamed": tally.bytes,
                    "completed": tally.completed,
                });
                let _ = self
                    .scope
                    .log_audit(overslash_db::repos::audit::AuditEntry {
                        org_id: self.scope.org_id(),
                        identity_id: Some(self.identity_id),
                        action: "action.stream_completed",
                        resource_type: self.service.as_deref(),
                        resource_id: self.token_id,
                        detail,
                        description: None,
                        ip_address: self.ip.as_deref(),
                    })
                    .await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use std::sync::{Arc, Mutex};

    #[test]
    fn complete_reads_body_and_declared_length() {
        let mut result = ActionResult {
            status_code: 200,
            headers: HashMap::from([("content-length".to_string(), "5".to_string())]),
            body: "hello".into(),
            duration_ms: 0,
            filtered_body: None,
            wire_bytes: None,
        };
        let s = ResponseSize::complete(&result, 100);
        assert_eq!(
            s.to_json(),
            json!({"bytes": 5, "content_length": 5, "read": "complete", "limit_bytes": 100})
        );
        assert_eq!(s.best_estimate(), Some(5));

        // Wire bytes win over the decoded body: `from_utf8_lossy` turns each
        // invalid byte into a 3-byte U+FFFD, so a binary body would triple.
        result.body = "\u{FFFD}".repeat(5);
        result.wire_bytes = Some(5);
        assert_eq!(ResponseSize::complete(&result, 100).bytes, Some(5));
    }

    #[test]
    fn aborted_prefers_declared_length_and_falls_back_to_lower_bound() {
        let declared = ResponseSize::aborted(0, Some(31_000_000), 5_242_880);
        assert_eq!(declared.best_estimate(), Some(31_000_000));
        assert_eq!(declared.to_json()["read"], "aborted_at_cap");

        let chunked = ResponseSize::aborted(5_242_881, None, 5_242_880);
        assert_eq!(chunked.best_estimate(), Some(5_242_881));
        assert_eq!(chunked.to_json()["content_length"], Value::Null);
    }

    #[test]
    fn streamed_has_no_bytes_yet() {
        let s = ResponseSize::streamed(None);
        assert_eq!(s.best_estimate(), None);
        assert_eq!(
            s.to_json(),
            json!({"bytes": null, "content_length": null, "read": "streamed", "limit_bytes": null})
        );
    }

    #[test]
    fn of_call_error_only_sizes_oversized_bodies() {
        use crate::services::http_caller::CallError;
        let e = CallError::ResponseTooLarge {
            content_length: None,
            content_type: None,
            limit_bytes: 10,
            bytes_read: 12,
        };
        assert_eq!(of_call_error(&e), Some(ResponseSize::aborted(12, None, 10)));
        assert_eq!(of_call_error(&CallError::Timeout { timeout_ms: 1 }), None);
    }

    fn tally_sink() -> (
        Arc<Mutex<Vec<StreamTally>>>,
        impl FnOnce(StreamTally) + Send,
    ) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        (seen, move |t| s.lock().unwrap().push(t))
    }

    #[tokio::test]
    async fn metered_counts_a_clean_stream_once() {
        let (seen, sink) = tally_sink();
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"abc")),
            Ok(Bytes::from_static(b"de")),
        ];
        let mut m = Metered::new(futures_util::stream::iter(chunks), None, sink);
        while m.next().await.is_some() {}
        drop(m);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![StreamTally {
                bytes: 5,
                completed: true
            }]
        );
    }

    #[tokio::test]
    async fn metered_is_fused_after_the_end() {
        // An `unfold` panics if polled after it returned `None`; the meter
        // must absorb a caller that polls past the end (hyper does).
        let inner = futures_util::stream::unfold(0u8, |n| async move {
            (n == 0).then(|| (Ok::<_, std::io::Error>(Bytes::from_static(b"x")), 1))
        });
        let (seen, sink) = tally_sink();
        let mut m = Metered::new(inner, None, sink);
        assert!(m.next().await.is_some());
        assert!(m.next().await.is_none());
        assert!(
            m.next().await.is_none(),
            "polling past the end must not panic"
        );
        drop(m);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![StreamTally {
                bytes: 1,
                completed: true
            }]
        );
    }

    #[tokio::test]
    async fn metered_reports_incomplete_on_error_and_on_drop() {
        let (seen, sink) = tally_sink();
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"abc")),
            Err(std::io::Error::other("boom")),
        ];
        let mut m = Metered::new(futures_util::stream::iter(chunks), None, sink);
        while m.next().await.is_some() {}
        drop(m);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![StreamTally {
                bytes: 3,
                completed: false
            }]
        );

        // A client hanging up mid-transfer drops the stream unfinished.
        let (seen, sink) = tally_sink();
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            vec![Ok(Bytes::from_static(b"ab")), Ok(Bytes::from_static(b"cd"))];
        let mut m = Metered::new(futures_util::stream::iter(chunks), None, sink);
        m.next().await;
        drop(m);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![StreamTally {
                bytes: 2,
                completed: false
            }]
        );
        // hyper drops a body once it has written `Content-Length` bytes,
        // without polling for the end: that is a finished transfer.
        let (seen, sink) = tally_sink();
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            vec![Ok(Bytes::from_static(b"ab")), Ok(Bytes::from_static(b"cd"))];
        let mut m = Metered::new(futures_util::stream::iter(chunks), Some(4), sink);
        m.next().await;
        m.next().await;
        drop(m);
        assert_eq!(
            *seen.lock().unwrap(),
            vec![StreamTally {
                bytes: 4,
                completed: true
            }]
        );
    }
}
