//! Generic upstream HTTP fake.
//!
//! Catches any path/method, echoes the request, and captures incoming
//! webhooks for assertion. Used both as a substitute for upstream service
//! APIs (with `OVERSLASH_SERVICE_BASE_OVERRIDES`) and as the test target for
//! Mode A raw HTTP flows.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Query, State},
    http::HeaderMap,
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::{Handle, bind, serve};

#[derive(Default)]
pub struct State_ {
    pub webhooks: Vec<Value>,
    pub webhook_headers: Vec<Value>,
    /// Every request the fallback `echo` handler serves is captured here so
    /// e2e callers can assert that a Mode-C action call landed on the fake
    /// (with the override applied) and carried the expected auth header.
    pub received_requests: Vec<Value>,
}

pub type SharedState = Arc<Mutex<State_>>;

pub struct OpenapiHandle {
    pub handle: Handle,
    pub state: SharedState,
}

/// Boot the generic upstream fake on `127.0.0.1:0` (OS-assigned).
pub async fn start() -> OpenapiHandle {
    start_on("127.0.0.1:0").await
}

pub async fn start_on(bind_addr: &str) -> OpenapiHandle {
    let (listener, addr, url) = bind(bind_addr).await.expect("bind openapi fake");
    let state: SharedState = Arc::new(Mutex::new(State_::default()));
    let app = router(state.clone());
    let handle = serve(listener, addr, url, app);
    OpenapiHandle { handle, state }
}

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route(
            "/echo",
            get(echo).post(echo).put(echo).delete(echo).patch(echo),
        )
        .route("/large-file", get(large_file))
        .route("/paged/cursor", get(paged_cursor))
        .route("/paged/offset", get(paged_offset))
        .route("/paged/link", get(paged_link))
        .route("/slow", get(slow).post(slow))
        .route("/slow-stream", get(slow_stream))
        .route("/things/{id}", get(thing_display))
        .route("/drive/files/download", get(drive_download))
        .route("/drive/files/content", get(drive_content))
        .route("/webhooks/receive", post(receive_webhook))
        .route("/webhooks/received", get(list_webhooks))
        .route(
            "/__received_requests",
            get(list_received_requests).delete(clear_received_requests),
        )
        .fallback(echo)
        .with_state(state)
}

async fn echo(
    State(s): State<SharedState>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Json<Value> {
    let h: serde_json::Map<String, Value> = headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), json!(v.to_str().unwrap_or(""))))
        .collect();
    let body_str = String::from_utf8_lossy(&body).to_string();
    let response = json!({
        "headers": h,
        "body": body_str,
        "uri": uri.to_string(),
    });
    // Record every echoed request (excluding the recorder paths themselves)
    // so callers can poll `/__received_requests` to assert the call landed.
    let path = uri.path();
    if !path.starts_with("/__received_requests") {
        let mut state = s.lock().await;
        state.received_requests.push(json!({
            "method": method.as_str(),
            "uri": uri.to_string(),
            "headers": response["headers"].clone(),
            "body": body_str,
        }));
    }
    Json(response)
}

async fn list_received_requests(State(s): State<SharedState>) -> Json<Value> {
    let state = s.lock().await;
    Json(json!({ "requests": state.received_requests.clone() }))
}

async fn clear_received_requests(State(s): State<SharedState>) -> &'static str {
    let mut state = s.lock().await;
    state.received_requests.clear();
    "ok"
}

/// Display-param resolver target: GET /things/{id} →
/// {"id", "name", "canonical_id"}.
///
/// Backs `resolve: {get, pick}` e2e tests — the resolver GET lands here and
/// picks `name`. Recorded in `received_requests` so tests can assert the
/// lookup happened exactly once (at resolve time, never at audit-write).
///
/// `canonical_id` is deliberately *different* from `id` so a test asserting
/// `resolve.scope` canonicalization cannot pass by accident: a no-op
/// canonicalization would leave the raw id in the permission key.
async fn thing_display(
    State(s): State<SharedState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    let mut state = s.lock().await;
    state.received_requests.push(json!({
        "method": "GET",
        "uri": format!("/things/{id}"),
        "headers": {},
        "body": "",
    }));
    Json(json!({
        "id": id,
        "name": format!("Thing {id}"),
        "canonical_id": format!("canon-{id}"),
    }))
}

async fn receive_webhook(
    State(s): State<SharedState>,
    headers: HeaderMap,
    Json(p): Json<Value>,
) -> &'static str {
    let h: serde_json::Map<String, Value> = headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), json!(v.to_str().unwrap_or(""))))
        .collect();
    let mut state = s.lock().await;
    state.webhooks.push(p);
    state.webhook_headers.push(json!(h));
    "ok"
}

async fn list_webhooks(State(s): State<SharedState>) -> Json<Value> {
    let state = s.lock().await;
    Json(json!({
        "webhooks": state.webhooks.clone(),
        "headers": state.webhook_headers.clone(),
    }))
}

/// Returns N bytes of 0xAB. Usage: GET /large-file?size=1000
async fn large_file(Query(params): Query<HashMap<String, String>>) -> axum::response::Response {
    let size: usize = params
        .get("size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1024);
    let data = vec![0xABu8; size];
    ([("content-type", "application/octet-stream")], data).into_response()
}

/// Sleep `?ms=` before answering. Exercises a total (buffered) timeout.
async fn slow(Query(params): Query<HashMap<String, String>>) -> Json<Value> {
    let ms: u64 = params.get("ms").and_then(|s| s.parse().ok()).unwrap_or(0);
    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    Json(json!({ "slept_ms": ms }))
}

/// Delay the *headers* by `?headers_ms=`, then dribble `?chunks=` chunks
/// `?gap_ms=` apart.
///
/// The two knobs exist to separate the two things a streaming timeout can
/// bound. `headers_ms` drives time-to-first-byte (which the resolved call
/// timeout bounds); `gap_ms` drives per-chunk idleness (which it must *not*
/// bound, or a slow-but-live transfer would die at an arbitrary total).
async fn slow_stream(Query(params): Query<HashMap<String, String>>) -> axum::response::Response {
    let headers_ms: u64 = params
        .get("headers_ms")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let chunks: usize = params
        .get("chunks")
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let gap_ms: u64 = params
        .get("gap_ms")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    tokio::time::sleep(std::time::Duration::from_millis(headers_ms)).await;

    let stream = futures_util::stream::unfold(0usize, move |i| async move {
        if i >= chunks {
            return None;
        }
        if i > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(gap_ms)).await;
        }
        Some((Ok::<_, std::io::Error>(Bytes::from_static(b"chunk")), i + 1))
    });

    (
        [("content-type", "application/octet-stream")],
        axum::body::Body::from_stream(stream),
    )
        .into_response()
}

/// Simulates Google Drive redirect: returns 302 to `/drive/files/content`
/// when the request is authenticated.
async fn drive_download(
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> axum::response::Response {
    let has_auth = headers.get("authorization").is_some();
    let size: usize = params
        .get("size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(4096);
    if !has_auth {
        return (axum::http::StatusCode::UNAUTHORIZED, "missing auth").into_response();
    }
    axum::response::Redirect::temporary(&format!("/drive/files/content?size={size}"))
        .into_response()
}

/// Serves file content (redirect target — no auth required, like Google's CDN).
async fn drive_content(Query(params): Query<HashMap<String, String>>) -> axum::response::Response {
    let size: usize = params
        .get("size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(4096);
    let data = vec![0xCDu8; size];
    ([("content-type", "application/pdf")], data).into_response()
}

// ── Paged collections ────────────────────────────────────────────────
//
// Three endpoints, one per continuation family the generic-pagination
// extension names. Each serves a fixed 25-row collection so a test can walk it
// to the end and see the last page announce itself, rather than only ever
// asserting on page one — which is where every off-by-one in this area lives.

const PAGED_TOTAL: usize = 25;

/// Rows `[start, start + size)` of the fixed collection, clamped to its end.
fn paged_rows(start: usize, size: usize) -> Vec<Value> {
    (start..PAGED_TOTAL.min(start + size))
        .map(|i| json!({"id": format!("row-{i}"), "name": format!("Row {i}")}))
        .collect()
}

fn paged_size(q: &HashMap<String, String>, key: &str, default: usize) -> usize {
    q.get(key)
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
        .clamp(1, PAGED_TOTAL)
}

/// Opaque-cursor paging, Google-shaped: `nextPageToken` sits *after* the rows,
/// and is absent on the last page rather than empty.
async fn paged_cursor(Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let size = paged_size(&q, "maxResults", 10);
    let start: usize = q
        .get("pageToken")
        .and_then(|t| t.strip_prefix("tok-"))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    let rows = paged_rows(start, size);
    let mut body = json!({"items": rows});
    let next = start + size;
    if next < PAGED_TOTAL {
        body["nextPageToken"] = json!(format!("tok-{next}"));
    }
    Json(body)
}

/// Offset paging with an explicit `has_more`, Stripe-shaped.
async fn paged_offset(Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let size = paged_size(&q, "limit", 10);
    let start: usize = q.get("offset").and_then(|v| v.parse().ok()).unwrap_or(0);
    let rows = paged_rows(start, size);
    let has_more = start + rows.len() < PAGED_TOTAL;
    Json(json!({"data": rows, "has_more": has_more}))
}

/// RFC 8288 paging, GitHub-shaped: the rows are a bare array and the way
/// forward is a header. Emits `prev` before `next` on purpose, so a reader
/// that stops at the first link finds the wrong one.
async fn paged_link(Query(q): Query<HashMap<String, String>>) -> impl IntoResponse {
    let size = paged_size(&q, "per_page", 10);
    let page: usize = q
        .get("page")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
        .max(1);
    let rows = paged_rows((page - 1) * size, size);

    let base = "https://upstream.example/paged/link";
    let mut links = Vec::new();
    if page > 1 {
        links.push(format!(
            "<{base}?page={}&per_page={size}>; rel=\"prev\"",
            page - 1
        ));
    }
    if page * size < PAGED_TOTAL {
        links.push(format!(
            "<{base}?page={}&per_page={size}>; rel=\"next\"",
            page + 1
        ));
    }

    let mut headers = HeaderMap::new();
    if !links.is_empty() {
        headers.insert(
            axum::http::header::LINK,
            links.join(", ").parse().expect("ascii link header"),
        );
    }
    (headers, Json(Value::Array(rows)))
}
