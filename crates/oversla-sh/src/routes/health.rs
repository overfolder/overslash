use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use serde_json::{Value, json};

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    match state.storage.ping().await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ready" }))),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "not_ready", "reason": "valkey_unreachable" })),
        ),
    }
}
