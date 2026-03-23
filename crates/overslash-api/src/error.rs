use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("request error: {0}")]
    Request(#[from] reqwest::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] overslash_core::crypto::CryptoError),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            Self::Internal(msg) => {
                tracing::error!("Internal error: {msg}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
            Self::Database(e) => {
                tracing::error!("Database error: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "database error".into())
            }
            Self::Request(e) => {
                tracing::error!("Request error: {e}");
                (StatusCode::BAD_GATEWAY, "external service error".into())
            }
            Self::Json(e) => {
                tracing::error!("JSON error: {e}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "serialization error".into(),
                )
            }
            Self::Crypto(e) => {
                tracing::error!("Crypto error: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "encryption error".into())
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
