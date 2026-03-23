use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use tokio::sync::Mutex;

#[derive(Default)]
struct MockState {
    received_webhooks: Vec<Value>,
}

type SharedState = Arc<Mutex<MockState>>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state: SharedState = Arc::new(Mutex::new(MockState::default()));
    let port = std::env::var("PORT").unwrap_or_else(|_| "9999".into());

    let app = Router::new()
        .route("/echo", post(echo))
        .route("/auth-required", post(auth_required))
        .route("/webhooks/receive", post(receive_webhook))
        .route("/webhooks/received", get(list_webhooks))
        .route("/slow", post(slow))
        .route("/error", post(error))
        .route("/health", get(health))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap();
    tracing::info!("Mock target listening on {port}");
    axum::serve(listener, app).await.unwrap();
}

async fn echo(headers: HeaderMap, body: Bytes) -> Json<Value> {
    let headers_map: serde_json::Map<String, Value> = headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), json!(v.to_str().unwrap_or(""))))
        .collect();

    let body_str = String::from_utf8_lossy(&body).to_string();

    Json(json!({
        "headers": headers_map,
        "body": body_str,
    }))
}

async fn auth_required(headers: HeaderMap) -> (StatusCode, Json<Value>) {
    match headers.get("authorization") {
        Some(val) if !val.is_empty() => (StatusCode::OK, Json(json!({ "authenticated": true }))),
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthorized" })),
        ),
    }
}

async fn receive_webhook(
    State(state): State<SharedState>,
    Json(payload): Json<Value>,
) -> StatusCode {
    state.lock().await.received_webhooks.push(payload);
    StatusCode::OK
}

async fn list_webhooks(State(state): State<SharedState>) -> Json<Value> {
    let webhooks = state.lock().await.received_webhooks.clone();
    Json(json!({ "webhooks": webhooks }))
}

async fn slow() -> Json<Value> {
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    Json(json!({ "slow": true }))
}

async fn error() -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": "intentional error" })),
    )
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}
