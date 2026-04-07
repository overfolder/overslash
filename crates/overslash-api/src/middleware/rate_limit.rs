use axum::response::IntoResponse;
use axum::{extract::State, http::Request, middleware::Next, response::Response};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AppState;
use crate::error::AppError;
use crate::services::rate_limit::now_unix;

pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Extract API key prefix from Authorization header
    let prefix = match extract_osk_prefix(&request) {
        Some(p) => p,
        None => return next.run(request).await, // No API key auth → skip rate limiting
    };

    // Resolve identity from prefix cache
    let identity = match resolve_identity(&state, &prefix).await {
        Some(id) => id,
        None => return next.run(request).await, // Unknown key → let auth extractor reject
    };

    let org_id = identity.0;
    let identity_id = identity.1;
    let owner_user_id = identity.2;

    // Check user bucket first (primary limit), then identity cap.
    // Order matters: we increment the user bucket first so that if the identity cap
    // rejects, we've only over-counted one user-bucket request (acceptable).
    // If we did identity cap first, a user-bucket rejection would waste the cap.

    // Counter 1: User bucket (always enforced).
    // For identity-bound keys, bucket on the owning user (so all agents share).
    // For org-level keys (no identity_id), bucket on the org itself — otherwise
    // unbound keys would bypass rate limiting entirely.
    let user_id = owner_user_id.or(identity_id);
    let (bucket_key, budget) = if let Some(user_id) = user_id {
        let budget = state
            .rate_limit_cache
            .resolve_user_budget(&state.db, &state.config, org_id, user_id)
            .await;
        (format!("rl:{org_id}:user:{user_id}"), budget)
    } else {
        // Org-level fallback: use the org default (or system fallback)
        let budget = state
            .rate_limit_cache
            .resolve_org_budget(&state.db, &state.config, org_id)
            .await;
        (format!("rl:{org_id}:org"), budget)
    };
    let user_budget = {
        let result = state
            .rate_limiter
            .check_and_increment(&bucket_key, budget.max_requests, budget.window_seconds)
            .await;
        if !result.allowed {
            let now = now_unix();
            let retry_after = result.reset_at.saturating_sub(now);
            return AppError::RateLimited {
                limit: result.limit,
                reset_at: result.reset_at,
                retry_after,
            }
            .into_response();
        }
        Some(result)
    };

    // Counter 2: Identity cap (optional, tighter ceiling for specific agents)
    if let Some(identity_id) = identity_id {
        if let Some(cap) = state
            .rate_limit_cache
            .resolve_identity_cap(&state.db, org_id, identity_id)
            .await
        {
            let key = format!("rl:{org_id}:id:{identity_id}");
            let result = state
                .rate_limiter
                .check_and_increment(&key, cap.max_requests, cap.window_seconds)
                .await;
            if !result.allowed {
                let now = now_unix();
                let retry_after = result.reset_at.saturating_sub(now);
                return AppError::RateLimited {
                    limit: result.limit,
                    reset_at: result.reset_at,
                    retry_after,
                }
                .into_response();
            }
        }
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
    let auth = request.headers().get("authorization")?.to_str().ok()?;
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
    prefix: &str,
) -> Option<(Uuid, Option<Uuid>, Option<Uuid>)> {
    // Look up API key by prefix (no argon2 — just identification).
    // Include archive-auto-revoked keys so an attacker hammering a stolen key
    // belonging to an archived identity still gets rate-limited (the 403 reject
    // still costs us DB lookups + argon2 in the auth extractor).
    // Cross-org by design — see `SystemScope::find_api_key_by_prefix_including_archived`.
    let key_row = overslash_db::SystemScope::new_internal(state.db.clone())
        .find_api_key_by_prefix_including_archived(prefix)
        .await
        .ok()
        .flatten()?;

    // Skip expired keys to avoid consuming rate limit budget for invalid requests
    if let Some(expires_at) = key_row.expires_at {
        if expires_at < OffsetDateTime::now_utc() {
            return None;
        }
    }

    // Resolve owner_user_id from the identity, bounded to the key's org.
    let owner_user_id = if let Some(identity_id) = key_row.identity_id {
        let scope = overslash_db::OrgScope::new(key_row.org_id, state.db.clone());
        match scope.get_identity(identity_id).await {
            Ok(Some(identity)) => {
                if identity.kind == "user" {
                    Some(identity.id)
                } else {
                    identity.owner_id
                }
            }
            _ => None,
        }
    } else {
        None
    };

    Some((key_row.org_id, key_row.identity_id, owner_user_id))
}
