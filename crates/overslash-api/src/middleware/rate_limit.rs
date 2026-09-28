use axum::http::{Extensions, HeaderMap, HeaderValue};
use axum::response::IntoResponse;
use axum::{extract::State, http::Request, middleware::Next, response::Response};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AppState;
use crate::cookies;
use crate::error::AppError;
use crate::services::jwt;
use crate::services::rate_limit::now_unix;

/// Who a `/v1` request is charged to. Resolved the same way the auth
/// extractors resolve the caller — session cookie first, then the bearer — so
/// the principal that pays is the principal that authenticates. Nothing here
/// authenticates anything: an unresolvable request passes through and the
/// extractor rejects it.
enum Principal {
    /// An `osk_` API key or an MCP access token: an identity acting for an
    /// owner user, whose bucket all of that user's agents share.
    Identity {
        org_id: Uuid,
        identity_id: Uuid,
        owner_user_id: Option<Uuid>,
    },
    /// A dashboard session cookie. Its own bucket, sized from the same user
    /// budget, so a runaway agent cannot lock its owner out of the dashboard
    /// they would use to stop it.
    Session { org_id: Uuid, identity_id: Uuid },
}

async fn resolve_principal(
    state: &AppState,
    headers: &HeaderMap,
    ext: &Extensions,
) -> Option<Principal> {
    if let Some(claims) = verify_session_cookie(state, headers) {
        return Some(Principal::Session {
            org_id: claims.org,
            identity_id: claims.sub,
        });
    }

    if let Some(prefix) = osk_prefix(headers) {
        let (org_id, identity_id, owner_user_id) = resolve_identity(state, ext, &prefix).await?;
        return Some(Principal::Identity {
            org_id,
            identity_id: identity_id?,
            owner_user_id,
        });
    }

    // MCP access token. `routes::mcp::forward` re-issues every tool call here
    // over loopback with the client's own bearer, so this is where MCP traffic
    // pays against its owner's budget — once per call, like any agent key.
    let claims = verify_mcp_bearer(state, headers)?;
    let owner_user_id = owner_of(state, ext, claims.org, claims.sub).await;
    Some(Principal::Identity {
        org_id: claims.org,
        identity_id: claims.sub,
        owner_user_id,
    })
}

/// The claims of a valid dashboard session cookie, or `None`.
pub fn verify_session_cookie(state: &AppState, headers: &HeaderMap) -> Option<jwt::Claims> {
    let token = cookies::read_session(headers, state)?;
    jwt::verify(
        &jwt::signing_key_bytes(&state.config.signing_key),
        &token,
        jwt::AUD_SESSION,
    )
    .ok()
}

/// The claims of a valid MCP access token (`aud=mcp`) in the Authorization
/// header, or `None`. Signature and expiry only — whether the identity still
/// exists is the auth extractor's call.
pub fn verify_mcp_bearer(state: &AppState, headers: &HeaderMap) -> Option<jwt::Claims> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let token = auth.strip_prefix("Bearer ")?;
    if token.starts_with("osk_") {
        return None;
    }
    jwt::verify(
        &jwt::signing_key_bytes(&state.config.signing_key),
        token,
        jwt::AUD_MCP,
    )
    .ok()
}

pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let Some(principal) = resolve_principal(&state, request.headers(), request.extensions()).await
    else {
        // No credential we can attribute → let the auth extractor reject it.
        return next.run(request).await;
    };

    let (org_id, identity_id, owner_user_id, is_session) = match principal {
        Principal::Identity {
            org_id,
            identity_id,
            owner_user_id,
        } => (org_id, Some(identity_id), owner_user_id, false),
        Principal::Session {
            org_id,
            identity_id,
        } => (org_id, Some(identity_id), None, true),
    };

    // Free-unlimited courtesy tier: bypass user bucket + identity cap entirely.
    // Set out-of-band by an operator via `UPDATE orgs SET plan='free_unlimited'`.
    // Emit a sentinel string ("unlimited") in the rate-limit headers so
    // clients that integer-parse the values fail loudly rather than silently
    // treating a missing/zero value as the limit.
    if state
        .free_unlimited_cache(request.extensions())
        .is_free_unlimited(state.db(request.extensions()), org_id)
        .await
    {
        overslash_metrics::rate_limit::record_decision("free_unlimited", "allow");
        let mut response = next.run(request).await;
        let headers = response.headers_mut();
        headers.insert("X-RateLimit-Limit", HeaderValue::from_static("unlimited"));
        headers.insert(
            "X-RateLimit-Remaining",
            HeaderValue::from_static("unlimited"),
        );
        return response;
    }

    // Check user bucket first (primary limit), then identity cap.
    // Order matters: we increment the user bucket first so that if the identity cap
    // rejects, we've only over-counted one user-bucket request (acceptable).
    // If we did identity cap first, a user-bucket rejection would waste the cap.

    // Counter 1: User bucket (always enforced).
    // For identity-bound keys, bucket on the owning user (so all agents share).
    // For org-level keys (no identity_id), bucket on the org itself — otherwise
    // unbound keys would bypass rate limiting entirely.
    //
    // A session is a user identity, so its budget resolves through the same
    // user chain; only the bucket it counts against differs.
    let user_id = owner_user_id.or(identity_id);
    let (bucket_key, budget) = if let Some(user_id) = user_id {
        let budget = state
            .rate_limit_cache(request.extensions())
            .resolve_user_budget(
                state.db(request.extensions()),
                &state.config,
                org_id,
                user_id,
            )
            .await;
        let bucket = if is_session { "session" } else { "user" };
        (format!("rl:{org_id}:{bucket}:{user_id}"), budget)
    } else {
        // Org-level fallback: use the org default (or system fallback)
        let budget = state
            .rate_limit_cache(request.extensions())
            .resolve_org_budget(state.db(request.extensions()), &state.config, org_id)
            .await;
        (format!("rl:{org_id}:org"), budget)
    };
    let user_scope_label = match (is_session, user_id.is_some()) {
        (true, _) => "session",
        (false, true) => "user",
        (false, false) => "org",
    };
    let user_budget = {
        let result = state
            .rate_limiter(request.extensions())
            .check_and_increment(&bucket_key, budget.max_requests, budget.window_seconds)
            .await;
        if !result.allowed {
            overslash_metrics::rate_limit::record_decision(user_scope_label, "deny");
            let now = now_unix();
            let retry_after = result.reset_at.saturating_sub(now);
            return AppError::RateLimited {
                limit: result.limit,
                reset_at: result.reset_at,
                retry_after,
            }
            .into_response();
        }
        overslash_metrics::rate_limit::record_decision(user_scope_label, "allow");
        Some(result)
    };

    // Counter 2: Identity cap (optional, tighter ceiling for specific agents).
    // Not for sessions: the cap is an agent throttle, and a human's own
    // identity cap would otherwise double-charge their dashboard clicks.
    if !is_session
        && let Some(identity_id) = identity_id
        && let Some(cap) = state
            .rate_limit_cache(request.extensions())
            .resolve_identity_cap(state.db(request.extensions()), org_id, identity_id)
            .await
    {
        let key = format!("rl:{org_id}:id:{identity_id}");
        let result = state
            .rate_limiter(request.extensions())
            .check_and_increment(&key, cap.max_requests, cap.window_seconds)
            .await;
        if !result.allowed {
            overslash_metrics::rate_limit::record_decision("identity_cap", "deny");
            let now = now_unix();
            let retry_after = result.reset_at.saturating_sub(now);
            return AppError::RateLimited {
                limit: result.limit,
                reset_at: result.reset_at,
                retry_after,
            }
            .into_response();
        }
        overslash_metrics::rate_limit::record_decision("identity_cap", "allow");
    }

    // Execute the actual handler
    let mut response = next.run(request).await;

    // Append rate limit headers from user bucket result
    if let Some(result) = user_budget {
        let headers = response.headers_mut();
        if let Ok(v) = result.limit.to_string().parse() {
            headers.insert("X-RateLimit-Limit", v);
        }
        if let Ok(v) = result.remaining.to_string().parse() {
            headers.insert("X-RateLimit-Remaining", v);
        }
        if let Ok(v) = result.reset_at.to_string().parse() {
            headers.insert("X-RateLimit-Reset", v);
        }
    }

    response
}

/// Extract the 12-char `osk_` prefix from the Authorization header.
pub fn extract_osk_prefix(request: &Request<axum::body::Body>) -> Option<String> {
    osk_prefix(request.headers())
}

/// [`extract_osk_prefix`] over bare headers, for callers that must not hold
/// the request (it is not `Sync`) across an await.
pub fn osk_prefix(headers: &HeaderMap) -> Option<String> {
    let auth = headers.get("authorization")?.to_str().ok()?;
    let key = auth.strip_prefix("Bearer ")?;
    if !key.starts_with("osk_") || key.len() < 12 {
        return None;
    }
    Some(key[..12].to_string())
}

/// Resolve (org_id, identity_id, owner_user_id) from the API key prefix.
///
/// We deliberately do NOT cache the lookup. Caching introduces TOCTOU windows
/// where revoked or expired keys still consume rate limit budget until the cache
/// entry expires. The DB lookup is a single indexed query (uses idx_api_keys_prefix)
/// and is much cheaper than the argon2 verification done by the AuthContext extractor.
/// `find_by_prefix` already filters `revoked_at IS NULL`, so revoked keys are skipped.
pub async fn resolve_identity(
    state: &AppState,
    ext: &axum::http::Extensions,
    prefix: &str,
) -> Option<(Uuid, Option<Uuid>, Option<Uuid>)> {
    // Look up API key by prefix (no argon2 — just identification).
    // Include archive-auto-revoked keys so an attacker hammering a stolen key
    // belonging to an archived identity still gets rate-limited (the 403 reject
    // still costs us DB lookups + argon2 in the auth extractor).
    // Cross-org by design — see `SystemScope::find_api_key_by_prefix_including_archived`.
    let key_row = overslash_db::SystemScope::new_internal(state.db_pool(ext))
        .find_api_key_by_prefix_including_archived(prefix)
        .await
        .ok()
        .flatten()?;

    // Skip expired keys to avoid consuming rate limit budget for invalid requests
    if let Some(expires_at) = key_row.expires_at
        && expires_at < OffsetDateTime::now_utc()
    {
        return None;
    }

    let identity_id = key_row.identity_id;
    let owner_user_id = owner_of(state, ext, key_row.org_id, identity_id).await;
    Some((key_row.org_id, Some(identity_id), owner_user_id))
}

/// The user whose bucket an identity spends: itself for a user, its owner for
/// an agent. Bounded to `org_id`.
async fn owner_of(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
    identity_id: Uuid,
) -> Option<Uuid> {
    let scope = overslash_db::OrgScope::new(org_id, state.db_pool(ext));
    match scope.get_identity(identity_id).await {
        Ok(Some(identity)) if identity.kind == "user" => Some(identity.id),
        Ok(Some(identity)) => identity.owner_id,
        _ => None,
    }
}
