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

    #[error("rate limit exceeded")]
    RateLimited {
        limit: u32,
        reset_at: u64,
        retry_after: u64,
    },

    #[error("response too large")]
    ResponseTooLarge {
        content_length: Option<u64>,
        content_type: Option<String>,
        limit_bytes: usize,
    },

    #[error("identity archived: {reason}")]
    IdentityArchived {
        reason: String,
        restorable_until: time::OffsetDateTime,
    },
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
            Self::RateLimited {
                limit,
                reset_at,
                retry_after,
            } => {
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                        "error": "rate limit exceeded",
                        "retry_after": retry_after,
                    })),
                )
                    .into_response();
                let headers = response.headers_mut();
                headers.insert("Retry-After", retry_after.to_string().parse().unwrap());
                headers.insert("X-RateLimit-Limit", limit.to_string().parse().unwrap());
                headers.insert("X-RateLimit-Remaining", "0".parse().unwrap());
                headers.insert("X-RateLimit-Reset", reset_at.to_string().parse().unwrap());
                return response;
            }
            Self::ResponseTooLarge {
                content_length,
                content_type,
                limit_bytes,
            } => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "error": "response_too_large",
                        "content_length": content_length,
                        "content_type": content_type,
                        "limit_bytes": limit_bytes,
                        "hint": "retry with prefer_stream: true to stream large responses"
                    })),
                )
                    .into_response();
            }
            Self::IdentityArchived {
                reason,
                restorable_until,
            } => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "identity_archived",
                        "reason": reason,
                        "restorable_until": restorable_until
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default(),
                        "hint": "POST /v1/identities/{id}/restore to recover within the retention window"
                    })),
                )
                    .into_response();
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
