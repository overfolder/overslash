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
    /// `None` when the caller authenticated via dashboard session cookie
    /// (no API key was used).
    pub key_id: Option<Uuid>,
    /// Set for session-cookie callers whose JWT carries the new `user_id`
    /// claim. `None` for API-key callers and for legacy session tokens
    /// minted before the multi-org rewire.
    pub user_id: Option<Uuid>,
}

/// Enforces subdomain↔JWT consistency: if the request hit `<slug>.<apex>`
/// and the JWT's org claim points somewhere else, reject with
/// `org_mismatch` so the dashboard can forward through `/auth/switch-org`.
fn check_subdomain_matches_jwt(parts: &Parts, jwt_org: Uuid) -> Result<(), AppError> {
    use crate::middleware::subdomain::RequestOrgContext;
    if let Some(RequestOrgContext::Org { org_id, .. }) = parts.extensions.get::<RequestOrgContext>()
    {
        if *org_id != jwt_org {
            return Err(AppError::Unauthorized("org_mismatch".into()));
        }
    }
    Ok(())
}

/// Extractor that validates the API key and provides AuthContext.
impl FromRequestParts<AppState> for AuthContext {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Try JWT session cookie first (dashboard users). This mirrors
        // `UserOrKeyAuth` so any v1 endpoint extracted via `AuthContext`
        // works for the dashboard without needing an API key.
        if let Some(token) = extract_cookie(&parts.headers, "oss_session") {
            let signing_key = hex::decode(&state.config.signing_key)
                .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());
            if let Ok(claims) = jwt::verify(&signing_key, &token, jwt::AUD_SESSION) {
                check_subdomain_matches_jwt(parts, claims.org)?;
                return Ok(AuthContext {
                    org_id: claims.org,
                    identity_id: Some(claims.sub),
                    key_id: None,
                    user_id: claims.user_id,
                });
            }
        }

        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::Unauthorized("missing authorization header".into()))?;

        let raw_key = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::Unauthorized("invalid authorization format".into()))?;

        // MCP access token: JWT with aud=mcp, signed with the same signing_key.
        // Checked before the osk_ prefix so MCP clients don't need to rename
        // their tokens and agent keys keep their existing shape.
        //
        // MCP tokens MUST resolve to an agent identity. Tokens whose `sub`
        // points at a user-kind identity are rejected even though the JWT
        // itself is valid — this enforces the invariant "MCP OAuth enrolls
        // an agent" at the authenticator, so a legacy pre-enrollment token
        // can't slip through to business logic.
        if !raw_key.starts_with("osk_") {
            let signing_key = hex::decode(&state.config.signing_key)
                .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());
            if let Ok(claims) = jwt::verify(&signing_key, raw_key, jwt::AUD_MCP) {
                let identity =
                    overslash_db::repos::identity::get_by_id(&state.db, claims.org, claims.sub)
                        .await
                        .map_err(|e| AppError::Internal(format!("db error: {e}")))?;
                let identity = identity.ok_or_else(|| {
                    AppError::Unauthorized("token identity no longer exists".into())
                })?;
                if identity.kind == "user" {
                    return Err(AppError::Unauthorized(
                        "MCP tokens must be bound to an agent identity; re-authenticate to enroll"
                            .into(),
                    ));
                }
                if identity.archived_at.is_some() {
                    return Err(AppError::Unauthorized("agent identity archived".into()));
                }
                return Ok(AuthContext {
                    org_id: claims.org,
                    identity_id: Some(claims.sub),
                    key_id: None,
                    user_id: None,
                });
            }
            return Err(AppError::Unauthorized("invalid key format".into()));
        }

        // Extract prefix (first 12 chars of the key, including osk_)
        let prefix = if raw_key.len() >= 12 {
            &raw_key[..12]
        } else {
            return Err(AppError::Unauthorized("key too short".into()));
        };

        // Use the variant that also returns keys auto-revoked because their
        // identity was archived, so we can return 403 identity_archived instead
        // of a misleading 401 invalid_api_key.
        // Cross-org by design: at this point in the request lifecycle there
        // is no org context — the API key row is what tells us which org the
        // caller belongs to. The lookup runs through `SystemScope`, which is
        // the documented home for the bootstrap path.
        let key_row = SystemScope::new_internal(state.db.clone())
            .find_api_key_by_prefix_including_archived(prefix)
            .await
            .map_err(|e| AppError::Internal(format!("db error: {e}")))?
            .ok_or_else(|| AppError::Unauthorized("invalid api key".into()))?;

        // Verify hash first — gate any further info disclosure on a valid key.
        let parsed_hash = argon2::PasswordHash::new(&key_row.key_hash)
            .map_err(|_| AppError::Internal("invalid stored hash".into()))?;

        argon2::PasswordVerifier::verify_password(
            &argon2::Argon2::default(),
            raw_key.as_bytes(),
            &parsed_hash,
        )
        .map_err(|_| AppError::Unauthorized("invalid api key".into()))?;

        // If the key is bound to an identity, check it's not archived (return
        // a clear 403 instead of treating the key as invalid) and stamp
        // last_active_at so the idle-cleanup loop doesn't reap it.
        // Every API key is identity-bound (migration 028). Check the bound
        // identity is not archived (return a clear 403 instead of treating
        // the key as invalid) and stamp last_active_at so the idle-cleanup
        // loop doesn't reap it.
        let mut identity_archive_error: Option<AppError> = None;
        let identity_id = key_row.identity_id;
        {
            let key_scope = OrgScope::new(key_row.org_id, state.db.clone());
            let identity = key_scope
                .get_identity(identity_id)
                .await
                .map_err(|e| AppError::Internal(format!("db error: {e}")))?;
            if let Some(ident) = identity {
                if let Some(archived_at) = ident.archived_at {
                    let retention_days =
                        overslash_db::repos::org::get_by_id(&state.db, ident.org_id)
                            .await
                            .map_err(|e| AppError::Internal(format!("db error: {e}")))?
                            .map(|o| o.subagent_archive_retention_days)
                            .unwrap_or(0);
                    let restorable_until =
                        archived_at + time::Duration::days(retention_days as i64);
                    identity_archive_error = Some(AppError::IdentityArchived {
                        identity_id,
                        reason: ident.archived_reason.unwrap_or_else(|| "unknown".into()),
                        restorable_until,
                    });
                } else if ident.kind == "sub_agent" {
                    // Sub-agents only: keep idle-cleanup tracking current.
                    let touch_scope = OrgScope::new(key_row.org_id, state.db.clone());
                    tokio::spawn(async move {
                        let _ = touch_scope.touch_identity_last_active(identity_id).await;
                    });
                }
            }
        }

        // Identity-archived takes precedence over both key revoke and key expiry
        // because it's the most actionable error (the client can call /restore).
        if let Some(err) = identity_archive_error {
            return Err(err);
        }

        // The "_including_archived" lookup intentionally returns auto-revoked
        // keys so we can serve a clear 403. But after the identity is purged,
        // api_keys.identity_id becomes NULL via FK SET NULL while revoked_at
        // and revoked_reason remain. Such an orphan must NOT authenticate.
        if key_row.revoked_at.is_some() {
            return Err(AppError::Unauthorized("invalid api key".into()));
        }

        // Per-key absolute expiry (independent of identity activity).
        if let Some(expires_at) = key_row.expires_at {
            if expires_at < time::OffsetDateTime::now_utc() {
                return Err(AppError::Unauthorized("api key expired".into()));
            }
        }

        // Touch api_key last_used (fire and forget). Bounded to the key's
        // own org via OrgScope.
        let touch_scope = OrgScope::new(key_row.org_id, state.db.clone());
        let key_id = key_row.id;
        tokio::spawn(async move {
            let _ = touch_scope.touch_api_key_last_used(key_id).await;
        });

        Ok(AuthContext {
            org_id: key_row.org_id,
            identity_id: Some(key_row.identity_id),
            key_id: Some(key_row.id),
            user_id: None,
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
            if let Ok(claims) = jwt::verify(&signing_key, &token, jwt::AUD_SESSION) {
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

/// Dashboard-only auth: requires a valid JWT session cookie. Bearer API
/// keys are explicitly rejected. Use this for endpoints whose audience is
/// the dashboard UI and which must not be reachable by an agent's API key
/// (e.g. read access to the secret vault).
#[derive(Debug, Clone)]
pub struct SessionAuth {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    /// The human behind the identity. `None` only for legacy session tokens
    /// minted before the multi-org rewire — they continue to work until
    /// they expire, at which point the user signs in again and gets the
    /// new claim.
    pub user_id: Option<Uuid>,
}

impl FromRequestParts<AppState> for SessionAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = extract_cookie(&parts.headers, "oss_session")
            .ok_or_else(|| AppError::Unauthorized("session cookie required".into()))?;
        let signing_key = hex::decode(&state.config.signing_key)
            .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());
        let claims = jwt::verify(&signing_key, &token, jwt::AUD_SESSION)
            .map_err(|_| AppError::Unauthorized("invalid session".into()))?;
        check_subdomain_matches_jwt(parts, claims.org)?;
        Ok(SessionAuth {
            org_id: claims.org,
            identity_id: claims.sub,
            user_id: claims.user_id,
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

        // After migration 028 every authenticated caller is identity-bound;
        // a None here would mean a stale bootstrap key slipped through and
        // must be refused rather than silently elevated.
        let identity_id = auth
            .identity_id
            .ok_or_else(|| AppError::Forbidden("identity-bound credential required".into()))?;

        // Fast-path: Users with the org-admin flag get Admin without needing
        // group lookup. Agents and non-admin users still go through the
        // overslash service group-grant path below.
        let scope_for_admin = OrgScope::new(auth.org_id, state.db.clone());
        if let Some(ident) = scope_for_admin.get_identity(identity_id).await? {
            if ident.is_org_admin {
                return Ok(OrgAcl {
                    org_id: auth.org_id,
                    identity_id: Some(identity_id),
                    access_level: AccessLevel::Admin,
                });
            }
        }

        // Construct an OrgScope inline (extractors are the official scope
        // construction site, per `scopes/mod.rs`) so the identity lookup
        // and the ceiling SQL are both bounded by the caller's org.
        let scope = OrgScope::new(auth.org_id, state.db.clone());

        // Resolve the ceiling user (agents use their owner's groups)
        let ceiling_user_id =
            crate::services::group_ceiling::resolve_ceiling_user_id(&scope, identity_id).await?;
        let ceiling = scope.get_ceiling_for_user(ceiling_user_id).await?;

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
// `OrgScope` and `UserScope` have Axum extractors. `AgentScope` exists for
// downstream code to build against and will gain an extractor when handlers
// begin consuming it. `SystemScope` is intentionally not extractable from
// a request — it is minted by background workers via
// `SystemScope::new_internal(db)`.
// ---------------------------------------------------------------------------

/// Axum extractor that mints a `UserScope` from a verified API key or
/// session cookie. The caller MUST be identity-bound — org-level keys
/// (no `identity_id`) are rejected with 400, since a `UserScope` requires
/// an `(org_id, user_id)` pair at the type level.
impl FromRequestParts<AppState> for UserScope {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = UserOrKeyAuth::from_request_parts(parts, state).await?;
        let identity_id = auth.identity_id.ok_or_else(|| {
            AppError::BadRequest("this endpoint requires an identity-bound credential".into())
        })?;
        Ok(UserScope::new(auth.org_id, identity_id, state.db.clone()))
    }
}

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
fn _scope_types_exist(_: AgentScope, _: SystemScope) {}

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
