use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("not found")]
    NotFound,

    #[error("unauthorized")]
    Unauthorized,

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("ttl out of range (min={min}, max={max}, got={got})")]
    TtlOutOfRange { min: u64, max: u64, got: u64 },

    #[error("storage unavailable")]
    StorageUnavailable(#[from] redis::RedisError),

    #[error("collision: failed to allocate a unique slug after {0} retries")]
    SlugCollision(u32),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, detail) = match &self {
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", None),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", None),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", Some(msg.clone())),
            Self::TtlOutOfRange { min, max, got } => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "ttl_out_of_range",
                Some(format!("ttl_seconds must be in [{min}, {max}] (got {got})")),
            ),
            Self::StorageUnavailable(e) => {
                // Don't leak Redis internals to the client, but log them server-side.
                tracing::error!(error = %e, "valkey error");
                (StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable", None)
            }
            Self::SlugCollision(retries) => {
                tracing::error!(retries = retries, "slug collision budget exhausted");
                (StatusCode::INTERNAL_SERVER_ERROR, "slug_collision", None)
            }
        };

        let body = match detail {
            Some(d) => json!({ "error": code, "detail": d }),
            None => json!({ "error": code }),
        };
        (status, Json(body)).into_response()
    }
}
