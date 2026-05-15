use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts},
};
use subtle::ConstantTimeEq;

use crate::{AppState, error::AppError};

/// Extractor that enforces `Authorization: Bearer <api_key>` against the
/// configured key using a constant-time comparison. No `Debug` derive —
/// the extractor carries no secret payload, just marks success.
pub struct ApiKey;

impl<S> FromRequestParts<S> for ApiKey
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let state = AppState::from_ref(state);
        let header_value = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;

        let Some(token) = header_value.strip_prefix("Bearer ") else {
            return Err(AppError::Unauthorized);
        };
        let token = token.trim();

        let expected = state.api_key.as_bytes();
        let presented = token.as_bytes();
        // `ct_eq` short-circuits on length mismatch (so length is leaked, which
        // is fine — both keys are server-configured and not secret-sized).
        if expected.len() != presented.len() {
            return Err(AppError::Unauthorized);
        }
        if expected.ct_eq(presented).unwrap_u8() == 1 {
            Ok(ApiKey)
        } else {
            Err(AppError::Unauthorized)
        }
    }
}
