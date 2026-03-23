use axum::{Json, Router, routing::get};
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

async fn ready() -> Json<Value> {
    Json(json!({ "status": "ready" }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_returns_ok() {
        let Json(body) = health().await;
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn ready_returns_ready() {
        let Json(body) = ready().await;
        assert_eq!(body["status"], "ready");
    }
}
