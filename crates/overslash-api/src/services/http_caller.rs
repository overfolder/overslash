//! The thin HTTP transport under every action call.
//!
//! Deliberately dumb: it takes already-resolved values (including a
//! [`Duration`], never a [`crate::services::call_timeout::CallTimeout`]) and
//! knows nothing about where they came from.
//!
//! # Two different meanings of "timeout"
//!
//! The buffered and streaming paths bound *different things*, and conflating
//! them is the trap this module exists to avoid.
//!
//! `reqwest`'s [`RequestBuilder::timeout`] is a **total** deadline: it covers
//! connect, TLS, headers *and* the response body stream. For [`call`] that is
//! exactly right — the whole point is to have the complete body in hand.
//!
//! For [`call_streaming`] it is actively wrong. The deadline would fire while
//! the body was being piped to the client, i.e. *after* the audit row recorded
//! a 200 and after axum flushed the response headers: the client would see a
//! silently truncated body while the audit trail claimed success. So streaming
//! splits the two phases — [`call_streaming`] bounds time-to-first-byte with a
//! `tokio` timeout (nothing has been written to the client yet, so failure is
//! still a clean 504), and [`idle_guarded_stream`] bounds the *gap between
//! chunks* thereafter. A slow-but-live 900MB export runs as long as it needs;
//! a stalled one still dies.
//!
//! A per-request idle timeout is not available directly: `read_timeout` is
//! `ClientBuilder`-only in reqwest 0.13, and building a client per call would
//! cost a TLS handshake every time.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use overslash_core::types::ActionResult;

/// Errors from an HTTP call.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error(transparent)]
    Request(#[from] reqwest::Error),

    #[error("response too large")]
    ResponseTooLarge {
        content_length: Option<u64>,
        content_type: Option<String>,
        limit_bytes: usize,
    },

    /// The upstream did not answer within the resolved per-call timeout.
    ///
    /// Distinct from a `Request(e)` that happens to have `e.is_timeout()`:
    /// this one carries the budget that was actually applied, which is what
    /// makes the 504 actionable.
    #[error("upstream request timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
}

/// Build a reqwest request from the given parameters.
///
/// `total_timeout` is `Some` only for the buffered path — see the module docs
/// on why a total deadline must never reach a streamed body.
fn build_request(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
    total_timeout: Option<Duration>,
) -> reqwest::RequestBuilder {
    let method = method
        .parse::<reqwest::Method>()
        .unwrap_or(reqwest::Method::GET);
    let mut builder = client.request(method, url);

    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    if let Some(body) = body {
        if !headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("content-type"))
        {
            builder = builder.header("Content-Type", "application/json");
        }
        builder = builder.body(body.to_string());
    }

    if let Some(t) = total_timeout {
        builder = builder.timeout(t);
    }

    builder
}

/// Call an HTTP endpoint, buffering the response. Returns an error if the
/// response body exceeds `max_body_bytes`.
///
/// `timeout` is a total deadline covering connect through the last byte of the
/// body.
pub async fn call(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
    max_body_bytes: usize,
    timeout: Duration,
) -> Result<ActionResult, CallError> {
    let start = Instant::now();
    let timeout_ms = timeout.as_millis() as u64;

    let response = build_request(client, method, url, headers, body, Some(timeout))
        .send()
        .await
        .map_err(|e| map_reqwest_timeout(e, timeout_ms))?;
    let status_code = response.status().as_u16();

    let resp_headers: HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // Check Content-Length before consuming the body
    let content_length = response.content_length();
    let content_type = resp_headers.get("content-type").cloned();

    if let Some(len) = content_length
        && len > max_body_bytes as u64
    {
        return Err(CallError::ResponseTooLarge {
            content_length: Some(len),
            content_type,
            limit_bytes: max_body_bytes,
        });
    }

    // Read body with size limit (handles chunked responses without Content-Length)
    let mut collected = Vec::new();
    let mut stream = response.bytes_stream();
    use futures_util::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| map_reqwest_timeout(e, timeout_ms))?;
        collected.extend_from_slice(&chunk);
        if collected.len() > max_body_bytes {
            return Err(CallError::ResponseTooLarge {
                content_length,
                content_type,
                limit_bytes: max_body_bytes,
            });
        }
    }

    let body = String::from_utf8_lossy(&collected).into_owned();
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(ActionResult {
        status_code,
        headers: resp_headers,
        body,
        duration_ms,
        filtered_body: None,
    })
}

/// Call an HTTP endpoint and return the raw response for streaming.
/// The caller is responsible for consuming the response body — see
/// [`idle_guarded_stream`], which is how it should do that.
///
/// `timeout` bounds **only** the header phase (connect, TLS, response
/// headers). Nothing has reached the client when it fires, so the caller can
/// still turn it into a clean 504. See the module docs.
pub async fn call_streaming(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
    timeout: Duration,
) -> Result<reqwest::Response, CallError> {
    let timeout_ms = timeout.as_millis() as u64;
    match tokio::time::timeout(
        timeout,
        build_request(client, method, url, headers, body, None).send(),
    )
    .await
    {
        Ok(res) => res.map_err(|e| map_reqwest_timeout(e, timeout_ms)),
        Err(_elapsed) => Err(CallError::Timeout { timeout_ms }),
    }
}

/// Wrap a streamed response body so a *stall* is fatal but slowness is not.
///
/// Each chunk gets its own `idle` budget. A transfer that keeps delivering
/// runs indefinitely; one that goes quiet is cut. On elapse the stream yields
/// an `io::Error`, which aborts the axum body mid-flight — the response
/// already carries the upstream's `content-length`, so a conformant client
/// sees an unsatisfied length rather than silently accepting a short body.
pub fn idle_guarded_stream(
    response: reqwest::Response,
    idle: Duration,
) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> {
    use futures_util::StreamExt;

    // `Some(stream)` = still live; `None` = terminal, so a consumer that polls
    // once more after an error or a stall gets `None` instead of re-arming the
    // timer on a dead body.
    futures_util::stream::unfold(
        Some(Box::pin(response.bytes_stream())),
        move |state| async move {
            let mut stream = state?;
            match tokio::time::timeout(idle, stream.next()).await {
                Ok(Some(Ok(chunk))) => Some((Ok(chunk), Some(stream))),
                Ok(Some(Err(e))) => Some((Err(std::io::Error::other(e)), None)),
                Ok(None) => None,
                Err(_elapsed) => Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "upstream stalled for more than {}ms mid-response",
                            idle.as_millis()
                        ),
                    )),
                    None,
                )),
            }
        },
    )
}

/// Fold reqwest's own timeout signal into [`CallError::Timeout`].
///
/// Worth doing even though we set the deadline ourselves: when the total
/// timeout on the buffered path fires, reqwest reports it as an ordinary
/// request error, and letting that surface as a generic 502 would lose the one
/// fact the caller needs.
fn map_reqwest_timeout(e: reqwest::Error, timeout_ms: u64) -> CallError {
    if e.is_timeout() {
        CallError::Timeout { timeout_ms }
    } else {
        CallError::Request(e)
    }
}
