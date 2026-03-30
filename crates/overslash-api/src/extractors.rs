use std::net::SocketAddr;

use axum::{extract::FromRequestParts, http::request::Parts};
use uuid::Uuid;

use crate::{AppState, error::AppError, services::jwt};

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

/// Context extracted from a valid API key or JWT session cookie.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub org_id: Uuid,
    pub identity_id: Option<Uuid>,
    pub key_id: Option<Uuid>,
}

/// Extractor that validates the API key or JWT cookie and provides AuthContext.
impl FromRequestParts<AppState> for AuthContext {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Try API key auth first
        if let Some(auth_header) = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
        {
            if let Some(raw_key) = auth_header.strip_prefix("Bearer ") {
                if raw_key.starts_with("osk_") {
                    return Self::from_api_key(raw_key, state).await;
                }
            }
        }

        // Fall back to JWT session cookie
        if let Some(token) = extract_cookie(&parts.headers, "oss_session") {
            return Self::from_jwt(&token, state);
        }

        Err(AppError::Unauthorized("missing authorization".into()))
    }
}

impl AuthContext {
    async fn from_api_key(raw_key: &str, state: &AppState) -> Result<Self, AppError> {
        if raw_key.len() < 12 {
            return Err(AppError::Unauthorized("key too short".into()));
        }

        let prefix = &raw_key[..12];

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
            key_id: Some(key_row.id),
        })
    }

    fn from_jwt(token: &str, state: &AppState) -> Result<Self, AppError> {
        let signing_key = signing_key_bytes(&state.config.signing_key);
        let claims = jwt::verify(&signing_key, token)
            .map_err(|_| AppError::Unauthorized("invalid or expired session".into()))?;

        Ok(AuthContext {
            org_id: claims.org,
            identity_id: Some(claims.sub),
            key_id: None,
        })
    }
}

/// Auth context from either a JWT session cookie or an API key.
/// Tries JWT cookie first (dashboard users), falls back to Bearer API key (CLI/programmatic).
#[derive(Debug, Clone)]
pub struct UserOrKeyAuth {
    pub org_id: Uuid,
    pub identity_id: Option<Uuid>,
}

impl FromRequestParts<AppState> for UserOrKeyAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Try JWT session cookie first
        if let Some(token) = extract_cookie(&parts.headers, "oss_session") {
            let signing_key = signing_key_bytes(&state.config.signing_key);
            if let Ok(claims) = jwt::verify(&signing_key, &token) {
                return Ok(UserOrKeyAuth {
                    org_id: claims.org,
                    identity_id: Some(claims.sub),
                });
            }
        }

        // Fall back to API key
        let auth_ctx = AuthContext::from_request_parts(parts, state).await?;
        Ok(UserOrKeyAuth {
            org_id: auth_ctx.org_id,
            identity_id: auth_ctx.identity_id,
        })
    }
}

fn extract_cookie(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(&format!("{name}=")) {
            return Some(value.to_string());
        }
    }
    None
}

fn signing_key_bytes(signing_key: &str) -> Vec<u8> {
    hex::decode(signing_key).unwrap_or_else(|_| signing_key.as_bytes().to_vec())
}
