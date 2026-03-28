use std::net::SocketAddr;

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
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

/// Extractor that validates authentication via API key or JWT session cookie.
///
/// Priority: API key (Bearer osk_*) first, then oss_session JWT cookie.
impl FromRequestParts<AppState> for AuthContext {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Try API key first
        if let Some(ctx) = try_api_key_auth(parts, state).await? {
            return Ok(ctx);
        }

        // Fall back to JWT session cookie
        if let Some(ctx) = try_jwt_cookie_auth(parts, state)? {
            return Ok(ctx);
        }

        Err(AppError::Unauthorized(
            "missing authorization header or session cookie".into(),
        ))
    }
}

/// Attempt authentication via Bearer API key (osk_*).
/// Returns Ok(None) if no API key header is present, Ok(Some) if valid, Err if invalid.
async fn try_api_key_auth(
    parts: &mut Parts,
    state: &AppState,
) -> Result<Option<AuthContext>, AppError> {
    let auth_header = match parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h,
        None => return Ok(None),
    };

    let raw_key = match auth_header.strip_prefix("Bearer ") {
        Some(k) if k.starts_with("osk_") => k,
        _ => return Ok(None),
    };

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

    Ok(Some(AuthContext {
        org_id: key_row.org_id,
        identity_id: key_row.identity_id,
        key_id: Some(key_row.id),
    }))
}

/// Attempt authentication via oss_session JWT cookie.
/// Returns Ok(None) if no cookie is present, Ok(Some) if valid, Err if invalid.
fn try_jwt_cookie_auth(
    parts: &mut Parts,
    state: &AppState,
) -> Result<Option<AuthContext>, AppError> {
    let cookie_header = match parts
        .headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h,
        None => return Ok(None),
    };

    let token = match extract_cookie_value(cookie_header, "oss_session") {
        Some(t) => t,
        None => return Ok(None),
    };

    let jwt_secret = jwt_secret(&state.config.secrets_encryption_key);
    let claims = jwt::verify(&jwt_secret, &token)
        .map_err(|_| AppError::Unauthorized("invalid or expired session".into()))?;

    Ok(Some(AuthContext {
        org_id: claims.org,
        identity_id: Some(claims.sub),
        key_id: None,
    }))
}

fn extract_cookie_value(cookie_header: &str, name: &str) -> Option<String> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(&format!("{name}=")) {
            return Some(value.to_string());
        }
    }
    None
}

fn jwt_secret(encryption_key: &str) -> Vec<u8> {
    let bytes = hex::decode(encryption_key).unwrap_or_else(|_| encryption_key.as_bytes().to_vec());
    bytes[..32.min(bytes.len())].to_vec()
}
