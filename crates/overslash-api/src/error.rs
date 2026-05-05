use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use overslash_core::openapi::validate_input::ArgError;
use serde_json::json;

/// API-layer mirror of `ArgError`. Owning the wire shape here keeps the
/// core crate free of serde contracts that the API renders.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArgErrorDto {
    Missing {
        field: String,
    },
    Unknown {
        field: String,
        suggestion: Option<String>,
        expected: Vec<String>,
    },
}

impl From<ArgError> for ArgErrorDto {
    fn from(e: ArgError) -> Self {
        match e {
            ArgError::Missing { field } => Self::Missing { field },
            ArgError::Unknown {
                field,
                suggestion,
                expected,
            } => Self::Unknown {
                field,
                suggestion,
                expected,
            },
        }
    }
}

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

    #[error("bad gateway: {0}")]
    BadGateway(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("gone: {0}")]
    Gone(String),

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

    #[error("filter syntax error: {0}")]
    FilterSyntax(String),

    #[error("invalid action args")]
    InvalidActionArgs {
        /// All required argument names for the action, sorted.
        required: Vec<String>,
        /// All declared argument names for the action, sorted.
        allowed: Vec<String>,
        /// Per-error details (missing fields, unknown fields).
        errors: Vec<ArgErrorDto>,
        /// One-line human summary — same string `format_errors` produces.
        detail: String,
    },

    #[error("identity archived: {reason}")]
    IdentityArchived {
        identity_id: uuid::Uuid,
        reason: String,
        restorable_until: time::OffsetDateTime,
    },

    #[error("template validation failed")]
    TemplateValidationFailed {
        report: overslash_core::template_validation::ValidationReport,
    },

    #[error("{message}")]
    ServiceResolution {
        status: StatusCode,
        message: String,
        matched_template: Option<String>,
        available_instances: Vec<String>,
        hint: Option<String>,
    },
}

impl AppError {
    /// Status code this error will eventually be rendered with.
    /// Mirrors `into_response` without consuming the error — used by
    /// metrics wrappers to classify outcomes before propagation.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) | Self::IdentityArchived { .. } => StatusCode::FORBIDDEN,
            Self::BadRequest(_) | Self::FilterSyntax(_) | Self::InvalidActionArgs { .. } => {
                StatusCode::BAD_REQUEST
            }
            Self::BadGateway(_) | Self::Request(_) | Self::ResponseTooLarge { .. } => {
                StatusCode::BAD_GATEWAY
            }
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Gone(_) => StatusCode::GONE,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::TemplateValidationFailed { .. } => StatusCode::BAD_REQUEST,
            Self::ServiceResolution { status, .. } => *status,
            Self::Internal(_) | Self::Database(_) | Self::Json(_) | Self::Crypto(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::BadGateway(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            Self::FilterSyntax(msg) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "filter_syntax_error",
                        "detail": msg,
                    })),
                )
                    .into_response();
            }
            Self::InvalidActionArgs {
                required,
                allowed,
                errors,
                detail,
            } => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "invalid_action_args",
                        "detail": detail,
                        "required": required,
                        "allowed": allowed,
                        "errors": errors,
                    })),
                )
                    .into_response();
            }
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            Self::Gone(msg) => (StatusCode::GONE, msg.clone()),
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
                identity_id,
                reason,
                restorable_until,
            } => {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "identity_archived",
                        "identity_id": identity_id,
                        "reason": reason,
                        "restorable_until": restorable_until
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_default(),
                        "hint": format!(
                            "POST /v1/identities/{identity_id}/restore to recover within the retention window"
                        ),
                    })),
                )
                    .into_response();
            }
            Self::TemplateValidationFailed { report } => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": "validation_failed",
                        "report": report,
                    })),
                )
                    .into_response();
            }
            Self::ServiceResolution {
                status,
                message,
                matched_template,
                available_instances,
                hint,
            } => {
                let mut body = json!({ "error": message });
                if let Some(t) = matched_template {
                    body["matched_template"] = json!(t);
                }
                body["available_instances"] = json!(available_instances);
                if let Some(h) = hint {
                    body["hint"] = json!(h);
                }
                return (*status, Json(body)).into_response();
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
