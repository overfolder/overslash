//! The HTTP transport under every action call.
//!
//! Deliberately dumb about *policy*: it takes already-resolved values
//! (including a [`Duration`], never a
//! [`crate::services::call_timeout::CallTimeout`]) and knows nothing about
//! where they came from.
//!
//! # The one thing it is not dumb about
//!
//! It builds its own client, from the URL, via
//! [`crate::services::ssrf_guard::outbound_client`] — it does not accept one.
//! Every outbound action request reaches the wire through the three functions
//! below, so owning client construction here is what makes "a Mode A call
//! cannot dial 169.254.169.254" a property of the transport rather than a rule
//! each of the five call sites has to remember. The guard resolves the host,
//! refuses private / loopback / link-local answers, pins the validated IP, and
//! disables redirects; it pools the resulting client per validated address, so
//! this is not a handshake per call. It also refuses plain `http` outside an
//! operator-allowed range ([`crate::services::outbound_tls`]), since every
//! request here may carry a vault credential.
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
//! A per-request idle timeout is still not available directly: `read_timeout`
//! is `ClientBuilder`-only in reqwest 0.13, and the pooled clients the guard
//! hands out are shared by calls with different budgets, so it cannot be set
//! per call there either. [`idle_guarded_stream`] remains the answer.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use overslash_core::types::ActionResult;

use crate::error::AppError;

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

    /// The SSRF guard refused the target before anything was dialed.
    ///
    /// Distinct from `Request(e)`: nothing left the process, and the caller
    /// asked for something we will not do — so it maps to a 400, not a 502.
    #[error("{0}")]
    Blocked(String),

    /// The guard could not reach a verdict — a resolver task that failed to
    /// join, or a client builder that refused to build.
    ///
    /// Kept apart from [`CallError::Blocked`] because the two say opposite
    /// things about whose fault it is: "we will not dial that" is the
    /// caller's answer and a 400, while "we could not tell" is ours and a
    /// 500. Collapsing them would have a transient host-level failure read
    /// as a malformed request, and a caller would retune a URL that was fine.
    #[error("{0}")]
    GuardFailed(String),

    /// The upstream kept redirecting past [`MAX_REDIRECTS`].
    #[error("upstream redirected more than {max} times")]
    TooManyRedirects { max: usize },

    /// The upstream did not answer within the resolved per-call timeout.
    ///
    /// Distinct from a `Request(e)` that happens to have `e.is_timeout()`:
    /// this one carries the budget that was actually applied, which is what
    /// makes the 504 actionable.
    #[error("upstream request timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },
}

/// What goes on the wire as the request body.
///
/// An enum rather than an `Option<&str>` alongside an out-of-band
/// `reqwest::Body` because the *default content type* differs per arm, and that
/// default is a contract rather than a convenience: JSON for a text body, and
/// nothing at all for a stream, since a byte route that sniffs its input treats
/// a stated `application/json` as a claim rather than a gap.
enum OutgoingBody<'a> {
    None,
    Text(&'a str),
    Stream(reqwest::Body),
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
    body: OutgoingBody<'_>,
    total_timeout: Option<Duration>,
) -> reqwest::RequestBuilder {
    let method = method
        .parse::<reqwest::Method>()
        .unwrap_or(reqwest::Method::GET);
    let mut builder = client.request(method, url);

    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    match body {
        OutgoingBody::None => {}
        OutgoingBody::Text(body) => {
            if !headers
                .keys()
                .any(|k| k.eq_ignore_ascii_case("content-type"))
            {
                builder = builder.header("Content-Type", "application/json");
            }
            builder = builder.body(body.to_string());
        }
        // No content-type default. The caller decides — and on the upload path
        // it deliberately sends none when it has none, so the upstream sniffs
        // the bytes instead of being told something untrue about them.
        OutgoingBody::Stream(body) => {
            builder = builder.body(body);
        }
    }

    if let Some(t) = total_timeout {
        builder = builder.timeout(t);
    }

    builder
}

/// Resolve, validate and pin the target, returning the client to send on and
/// the parsed URL to resolve a `Location` against.
///
/// The single place the transport acquires a client. See the module docs.
///
/// It also requires TLS ([`crate::services::outbound_tls`]), against the
/// address the guard pinned — on every hop, so a redirect cannot walk a
/// request down to plain `http` either.
async fn guarded_client(url: &str) -> Result<(reqwest::Client, url::Url), CallError> {
    let checked = async {
        let (client, parsed, ip) =
            crate::services::ssrf_guard::outbound_client_validated(url).await?;
        crate::services::outbound_tls::check_resolved(&parsed, &ip)?;
        Ok::<_, AppError>((client, parsed))
    };
    checked.await.map_err(|e| match e {
        // The guard is careful about this distinction — `BadRequest` for
        // anything about the target, `Internal` only for a failure of its
        // own machinery — so the transport keeps it rather than flattening
        // both into "blocked".
        AppError::BadRequest(msg) => CallError::Blocked(msg),
        other => CallError::GuardFailed(other.to_string()),
    })
}

/// How many redirects a call follows.
///
/// Above the 3 the template-import hop loop allows, because a cloud-storage
/// download routinely costs two (signed-URL issuer → CDN) and a third is
/// plausible; below the 10 `reqwest` follows by default, which was never a
/// deliberate choice here.
const MAX_REDIRECTS: usize = 5;

/// Headers that carry a credential and must not travel where it does not
/// belong.
///
/// On this path `Authorization` is an injected vault secret, so forwarding it
/// to wherever an upstream points is a credential disclosure — to a CDN in the
/// benign case and to whoever the upstream names in the other one. `reqwest`'s
/// own default policy strips exactly these; following redirects by hand means
/// re-implementing that rather than inheriting it.
fn is_credential_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("authorization")
        || name.eq_ignore_ascii_case("cookie")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("www-authenticate")
}

/// Whether a credential may follow this hop.
///
/// Only to the **same host**, and never onto a weaker transport. A different
/// host is a different party, whoever named it. An `https` → `http` downgrade
/// would put a vault secret on the wire in clear, which is worth refusing even
/// when the host is unchanged. A port change on the same host is neither of
/// those, and stripping there would break ordinary same-service redirects
/// without taking anything away from an attacker.
fn credential_may_follow(from: &url::Url, to: &url::Url) -> bool {
    from.host_str() == to.host_str() && !(from.scheme() == "https" && to.scheme() == "http")
}

/// Send, and follow redirects **with the guard re-run on every hop**.
///
/// The pinned client sets `Policy::none()`, because letting `reqwest` follow
/// is precisely the hole: a validated first hop says nothing about where a 302
/// points. But refusing to follow at all is not an option either — a Google
/// Drive download *is* a redirect to a signed URL on another host, which is
/// what `tests/large_file.rs::test_google_drive_redirect_stream` asserts. So
/// each hop gets its own resolve, its own policy check and its own pin, the
/// same shape `routes/templates/fetch.rs` already uses for OpenAPI import.
///
/// Method and body follow the convention `reqwest` and browsers use: 303
/// becomes a GET, 301/302 become a GET when the original was a POST, and
/// 307/308 replay both. A streamed request body cannot be replayed at all,
/// which is why [`call_streaming_upload`] does not come through here.
async fn send_following_redirects(
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
    total_timeout: Option<Duration>,
    timeout_ms: u64,
) -> Result<reqwest::Response, CallError> {
    let mut method = method.to_string();
    let mut body = body.map(str::to_owned);
    let mut headers = headers.clone();
    let mut target = url.to_string();

    for _hop in 0..=MAX_REDIRECTS {
        let (client, current) = guarded_client(&target).await?;
        let outgoing = match body.as_deref() {
            Some(b) => OutgoingBody::Text(b),
            None => OutgoingBody::None,
        };
        let response = build_request(&client, &method, &target, &headers, outgoing, total_timeout)
            .send()
            .await
            .map_err(|e| map_reqwest_timeout(e, timeout_ms))?;

        let status = response.status();
        if !status.is_redirection() {
            return Ok(response);
        }
        // A 3xx without a usable `Location` — a 304, or a 300 offering no
        // default — is the upstream's answer, not an instruction to move.
        let Some(location) = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
        else {
            return Ok(response);
        };

        let next = current.join(&location).map_err(|e| {
            CallError::Blocked(format!("upstream redirect is not a usable URL: {e}"))
        })?;
        if !credential_may_follow(&current, &next) {
            headers.retain(|name, _| !is_credential_header(name));
        }
        if status == 303
            || (matches!(status.as_u16(), 301 | 302) && method.eq_ignore_ascii_case("POST"))
        {
            method = "GET".to_string();
            body = None;
        }
        target = next.to_string();
    }

    Err(CallError::TooManyRedirects { max: MAX_REDIRECTS })
}

/// Call an HTTP endpoint, buffering the response. Returns an error if the
/// response body exceeds `max_body_bytes`.
///
/// `timeout` is a total deadline covering connect through the last byte of the
/// body.
pub async fn call(
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
    max_body_bytes: usize,
    timeout: Duration,
) -> Result<ActionResult, CallError> {
    let timeout_ms = timeout.as_millis() as u64;
    // One deadline over the whole thing, because `timeout` is documented as a
    // *total* one and neither of the per-request bounds inside is. The
    // `RequestBuilder::timeout` each hop carries restarts on every hop, so a
    // chain of redirects could spend `MAX_REDIRECTS × timeout`; and the host
    // lookup that precedes the first hop runs before any reqwest client
    // exists. Both are bounded individually — the guard caps DNS — but only
    // an outer deadline makes the documented contract true.
    match tokio::time::timeout(
        timeout,
        call_inner(
            method,
            url,
            headers,
            body,
            max_body_bytes,
            timeout,
            timeout_ms,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(CallError::Timeout { timeout_ms }),
    }
}

/// [`call`] without its deadline. Split out only so the deadline can wrap
/// every step, the body buffering included.
#[allow(clippy::too_many_arguments)]
async fn call_inner(
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
    max_body_bytes: usize,
    timeout: Duration,
    timeout_ms: u64,
) -> Result<ActionResult, CallError> {
    let start = Instant::now();
    let response =
        send_following_redirects(method, url, headers, body, Some(timeout), timeout_ms).await?;
    let status_code = response.status().as_u16();

    // Fold rather than collect: a `HashMap` built straight from the iterator
    // keeps only the *last* of any repeated field name, and `Link` legally
    // repeats — so a `rel="next"` could be lost here, one layer before the
    // compact render ever sees it. RFC 9110 §5.3 says repeated field lines
    // combine with ", "; `set-cookie` is the documented exception, where
    // comma-joining corrupts the cookies, so it keeps the old last-wins.
    let mut resp_headers: HashMap<String, String> = HashMap::new();
    for (k, v) in response.headers().iter() {
        let name = k.as_str();
        let value = v.to_str().unwrap_or("");
        match resp_headers.get_mut(name) {
            Some(existing) if name != "set-cookie" => {
                existing.push_str(", ");
                existing.push_str(value);
            }
            Some(existing) => *existing = value.to_string(),
            None => {
                resp_headers.insert(name.to_string(), value.to_string());
            }
        }
    }

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
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: Option<&str>,
    timeout: Duration,
) -> Result<reqwest::Response, CallError> {
    let timeout_ms = timeout.as_millis() as u64;
    // Inside the deadline: the guard resolves DNS, and a hostile resolver is
    // exactly as good a way to hang the header phase as a hostile upstream.
    match tokio::time::timeout(
        timeout,
        send_following_redirects(method, url, headers, body, None, timeout_ms),
    )
    .await
    {
        Ok(res) => res,
        Err(_elapsed) => Err(CallError::Timeout { timeout_ms }),
    }
}

/// Send a **streamed request body** and return the upstream response.
///
/// The inbound mirror of [`call_streaming`], and the only path that can carry a
/// body too large to hold: every other caller here materializes an owned
/// `String`, which is fine for a JSON payload and impossible for a hundred
/// megabytes of file.
///
/// # Why there is no timeout parameter
///
/// [`call_streaming`] bounds its header phase with a `tokio` timeout because on
/// a GET, `send()` resolves as soon as the response headers arrive. On an
/// upload it does not: `send()` waits for the last byte of the *request* body,
/// so a deadline here is a cap on total transfer duration, and a legitimate
/// large push over a slow link dies at it. That is the trap the module docs
/// describe for response streaming, inverted, so the same answer applies —
/// liveness is bounded per chunk, not in total. The caller meters the body (see
/// [`crate::services::proxy_upload::metered_body`]) and that meter carries both
/// the idle guard and the byte ceiling.
pub async fn call_streaming_upload(
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
    body: reqwest::Body,
) -> Result<reqwest::Response, CallError> {
    let (client, _) = guarded_client(url).await?;
    build_request(
        &client,
        method,
        url,
        headers,
        OutgoingBody::Stream(body),
        None,
    )
    .send()
    .await
    .map_err(CallError::Request)
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
