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

/// Context extracted from a valid API key or session cookie.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub org_id: Uuid,
    pub identity_id: Option<Uuid>,
    pub key_id: Uuid,
}

/// Helper to derive JWT secret from the encryption key (same as auth.rs).
fn jwt_secret(encryption_key: &str) -> Vec<u8> {
    let bytes = hex::decode(encryption_key).unwrap_or_else(|_| encryption_key.as_bytes().to_vec());
    bytes[..32.min(bytes.len())].to_vec()
}

/// Extract cookie value by name from the Cookie header.
fn extract_cookie(parts: &Parts, name: &str) -> Option<String> {
    let cookie_header = parts.headers.get("cookie")?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(&format!("{name}=")) {
            return Some(value.to_string());
        }
    }
    None
}

/// Extractor that validates the session cookie or API key and provides AuthContext.
impl FromRequestParts<AppState> for AuthContext {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Try session cookie first
        if let Some(token) = extract_cookie(parts, "oss_session") {
            let secret = jwt_secret(&state.config.secrets_encryption_key);
            if let Ok(claims) = jwt::verify(&secret, &token) {
                return Ok(AuthContext {
                    org_id: claims.org,
                    identity_id: Some(claims.sub),
                    key_id: Uuid::nil(),
                });
            }
        }

        // Fall back to API key auth
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
            let signing_key = hex::decode(&state.config.signing_key)
                .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());
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
