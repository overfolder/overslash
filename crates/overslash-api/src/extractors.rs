use std::net::SocketAddr;

use axum::{extract::FromRequestParts, http::request::Parts};
use uuid::Uuid;

use crate::{AppState, error::AppError};

/// Extracts the client IP address from request headers or connection info.
#[derive(Debug, Clone)]
pub struct ClientIp(pub Option<String>);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &AppState,
    ) -> std::result::Result<Self, Self::Rejection> {
        // X-Forwarded-For: first IP in the chain
        if let Some(forwarded) = parts.headers.get("x-forwarded-for") {
            if let Ok(value) = forwarded.to_str() {
                if let Some(first) = value.split(',').next() {
                    let ip = first.trim();
                    if !ip.is_empty() {
                        return Ok(ClientIp(Some(ip.to_string())));
                    }
                }
            }
        }

        // X-Real-IP
        if let Some(real_ip) = parts.headers.get("x-real-ip") {
            if let Ok(value) = real_ip.to_str() {
                let ip = value.trim();
                if !ip.is_empty() {
                    return Ok(ClientIp(Some(ip.to_string())));
                }
            }
        }

        // Fall back to ConnectInfo
        if let Some(addr) = parts
            .extensions
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
        {
            return Ok(ClientIp(Some(addr.0.ip().to_string())));
        }

        Ok(ClientIp(None))
    }
}

/// Context extracted from a valid API key.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub org_id: Uuid,
    pub identity_id: Option<Uuid>,
    pub key_id: Uuid,
}

/// Extractor that validates the API key and provides AuthContext.
impl FromRequestParts<AppState> for AuthContext {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing authorization header".into()))?;

        let raw_key = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid authorization format".into()))?;

        if !raw_key.starts_with("osk_") {
            return Err(AppError::Unauthorized("invalid key format".into()));
        }

        // Extract prefix (first 12 chars of the key, including osk_)
        let prefix = if raw_key.len() >= 12 {
            &raw_key[..12]
        } else {
            return Err(AppError::Unauthorized("key too short".into()));
        };

        let key_row = overslash_db::repos::api_key::find_by_prefix(&state.db, prefix)
            .await
            .map_err(|e| AppError::Internal(format!("db error: {e}")))?
            .ok_or_else(|| AppError::Unauthorized("invalid api key".into()))?;

        // Check expiry
        if let Some(expires_at) = key_row.expires_at {
            if expires_at < time::OffsetDateTime::now_utc() {
                return Err(AppError::Unauthorized("api key expired".into()));
            }
        }

        // Verify hash
        let parsed_hash = argon2::PasswordHash::new(&key_row.key_hash)
            .map_err(|_| AppError::Internal("invalid stored hash".into()))?;

        argon2::PasswordVerifier::verify_password(
            &argon2::Argon2::default(),
            raw_key.as_bytes(),
            &parsed_hash,
        )
        .map_err(|_| AppError::Unauthorized("invalid api key".into()))?;

        // Touch last_used (fire and forget)
        let db = state.db.clone();
        let key_id = key_row.id;
        tokio::spawn(async move {
            let _ = overslash_db::repos::api_key::touch_last_used(&db, key_id).await;
        });

        Ok(AuthContext {
            org_id: key_row.org_id,
            identity_id: key_row.identity_id,
            key_id: key_row.id,
        })
    }
}
