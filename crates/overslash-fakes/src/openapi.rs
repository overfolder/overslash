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
        .route("/drive/files/download", get(drive_download))
        .route("/drive/files/content", get(drive_content))
        .route("/webhooks/receive", post(receive_webhook))
        .route("/webhooks/received", get(list_webhooks))
        .fallback(echo)
        .with_state(state)
}

async fn echo(uri: axum::http::Uri, headers: HeaderMap, body: Bytes) -> Json<Value> {
    let h: serde_json::Map<String, Value> = headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), json!(v.to_str().unwrap_or(""))))
        .collect();
    Json(json!({
        "headers": h,
        "body": String::from_utf8_lossy(&body).to_string(),
        "uri": uri.to_string(),
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
