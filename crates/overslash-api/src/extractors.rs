use std::net::SocketAddr;

use axum::{extract::FromRequestParts, http::request::Parts};
use overslash_db::{AgentScope, OrgScope, SystemScope, UserScope};
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

// ── Org ACL extractors ──────────────────────────────────────────────
//
// ACL is enforced via group grants on the "overslash" service instance.
// These extractors resolve the caller's highest access level for the
// overslash service and reject if insufficient.

use overslash_core::permissions::AccessLevel;

/// Resolved ACL level for the overslash platform service.
#[derive(Debug, Clone)]
pub struct OrgAcl {
    pub org_id: Uuid,
    pub identity_id: Option<Uuid>,
    pub access_level: AccessLevel,
}

impl FromRequestParts<AppState> for OrgAcl {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = UserOrKeyAuth::from_request_parts(parts, state).await?;

        // Org-level API keys (no identity) are treated as admin
        let Some(identity_id) = auth.identity_id else {
            return Ok(OrgAcl {
                org_id: auth.org_id,
                identity_id: None,
                access_level: AccessLevel::Admin,
            });
        };

        // Resolve the ceiling user (agents use their owner's groups)
        let ceiling_user_id =
            crate::services::group_ceiling::resolve_ceiling_user_id(&state.db, identity_id).await?;

        // Get all grants across groups for this user
        let ceiling =
            overslash_db::repos::group::get_ceiling_for_user(&state.db, ceiling_user_id).await?;

        // Find the highest access level for the overslash service
        let access_level = ceiling
            .grants
            .iter()
            .filter(|g| g.template_key == "overslash")
            .filter_map(|g| AccessLevel::parse(&g.access_level))
            .max()
            .unwrap_or(AccessLevel::Read);

        Ok(OrgAcl {
            org_id: auth.org_id,
            identity_id: Some(identity_id),
            access_level,
        })
    }
}

/// Requires at least write-level ACL access to the overslash platform.
#[derive(Debug, Clone)]
pub struct WriteAcl(pub OrgAcl);

impl FromRequestParts<AppState> for WriteAcl {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let acl = OrgAcl::from_request_parts(parts, state).await?;
        if acl.access_level < AccessLevel::Write {
            return Err(AppError::Forbidden("write access required".into()));
        }
        Ok(WriteAcl(acl))
    }
}

/// Requires admin-level ACL access to the overslash platform.
#[derive(Debug, Clone)]
pub struct AdminAcl(pub OrgAcl);

impl FromRequestParts<AppState> for AdminAcl {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let acl = OrgAcl::from_request_parts(parts, state).await?;
        if acl.access_level < AccessLevel::Admin {
            return Err(AppError::Forbidden("admin access required".into()));
        }
        Ok(AdminAcl(acl))
    }
}

/// Optional ACL extractor for endpoints that allow unauthenticated bootstrap.
/// Returns `Ok(Some(acl))` if valid auth was provided, `Ok(None)` only when
/// NO auth was provided at all, and `Err` if auth was provided but invalid.
/// This prevents an attacker from bypassing auth by sending a bad token.
#[derive(Debug, Clone)]
pub struct OptionalOrgAcl(pub Option<OrgAcl>);

impl FromRequestParts<AppState> for OptionalOrgAcl {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Check if any auth was provided (Authorization header OR session cookie)
        let has_auth_header = parts.headers.get("authorization").is_some();
        let has_session_cookie = extract_cookie(&parts.headers, "oss_session").is_some();

        if !has_auth_header && !has_session_cookie {
            // Truly unauthenticated — bootstrap path
            return Ok(OptionalOrgAcl(None));
        }

        // Auth was provided — require it to be valid
        let acl = OrgAcl::from_request_parts(parts, state).await?;
        Ok(OptionalOrgAcl(Some(acl)))
    }
}

// ---------------------------------------------------------------------------
// Capability scopes.
//
// Currently only `OrgScope` has an Axum extractor; the other scope types
// (`UserScope`, `AgentScope`) exist for downstream code to build against
// and will gain extractors as handlers begin consuming them.
// `SystemScope` is intentionally not extractable from a request — it is
// minted by background workers via `SystemScope::new_internal(db)`.
// ---------------------------------------------------------------------------

/// Axum extractor that mints an `OrgScope` from a verified API key or
/// session cookie. Any authenticated caller in any role can produce one.
impl FromRequestParts<AppState> for OrgScope {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = UserOrKeyAuth::from_request_parts(parts, state).await?;
        Ok(OrgScope::new(auth.org_id, state.db.clone()))
    }
}

// Compile-time probe to ensure every scope type stays importable from
// `overslash-db` even before its extractor exists. Remove names from this
// signature as real extractors are added.
#[allow(dead_code)]
fn _scope_types_exist(_: UserScope, _: AgentScope, _: SystemScope) {}

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
