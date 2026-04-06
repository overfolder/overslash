use std::time::{Duration, Instant};

use axum::response::IntoResponse;
use axum::{extract::State, http::Request, middleware::Next, response::Response};
use dashmap::DashMap;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AppState;
use crate::error::AppError;
use crate::services::rate_limit::now_unix;

/// Cached identity info resolved from an API key prefix.
struct CachedIdentity {
    org_id: Uuid,
    identity_id: Option<Uuid>,
    /// The owning user's identity ID. For users, this is the same as identity_id.
    owner_user_id: Option<Uuid>,
    /// Key expiry time (None = never expires). Used to skip rate limiting for expired keys.
    expires_at: Option<OffsetDateTime>,
    fetched_at: Instant,
}

/// Lightweight prefix → identity cache to avoid DB lookups on every request.
/// This does NOT verify the key (no argon2) — it only identifies the caller.
pub struct PrefixCache {
    entries: DashMap<String, CachedIdentity>,
    ttl: Duration,
}

impl PrefixCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            ttl,
        }
    }

    /// Remove cache entries that have outlived their TTL.
    /// Called periodically from a background task to prevent unbounded growth
    /// from rotating or deleted API keys.
    pub fn evict_expired(&self) {
        let ttl = self.ttl;
        self.entries
            .retain(|_, entry| entry.fetched_at.elapsed() < ttl);
    }
}

// Module-level lazy static for the prefix cache.
// Initialized once, shared across all requests.
static PREFIX_CACHE: std::sync::LazyLock<PrefixCache> =
    std::sync::LazyLock::new(|| PrefixCache::new(Duration::from_secs(60)));

/// Evict expired entries from the global prefix cache.
/// Spawned as a background task in `create_app` to prevent unbounded memory growth.
pub fn evict_prefix_cache() {
    PREFIX_CACHE.evict_expired();
}

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

    // Counter 1: User bucket (always enforced)
    let user_id = owner_user_id.or(identity_id);
    let user_budget = if let Some(user_id) = user_id {
        let budget = state
            .rate_limit_cache
            .resolve_user_budget(&state.db, &state.config, org_id, user_id)
            .await;
        let key = format!("rl:{org_id}:user:{user_id}");
        let result = state
            .rate_limiter
            .check_and_increment(&key, budget.max_requests, budget.window_seconds)
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
    } else {
        None
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
fn extract_osk_prefix(request: &Request<axum::body::Body>) -> Option<String> {
    let auth = request.headers().get("authorization")?.to_str().ok()?;
    let key = auth.strip_prefix("Bearer ")?;
    if !key.starts_with("osk_") || key.len() < 12 {
        return None;
    }
    Some(key[..12].to_string())
}

/// Resolve (org_id, identity_id, owner_user_id) from the API key prefix.
/// Uses a lightweight cache to avoid DB lookups on every request.
/// Returns None for expired keys to avoid consuming rate limit budget.
async fn resolve_identity(
    state: &AppState,
    prefix: &str,
) -> Option<(Uuid, Option<Uuid>, Option<Uuid>)> {
    // Check cache
    if let Some(entry) = PREFIX_CACHE.entries.get(prefix) {
        if entry.fetched_at.elapsed() < PREFIX_CACHE.ttl {
            // Skip expired keys — don't consume rate limit budget for invalid requests
            if let Some(expires_at) = entry.expires_at {
                if expires_at < OffsetDateTime::now_utc() {
                    return None;
                }
            }
            return Some((entry.org_id, entry.identity_id, entry.owner_user_id));
        }
    }

    // Look up API key by prefix (no argon2 — just identification)
    let key_row = overslash_db::repos::api_key::find_by_prefix(&state.db, prefix)
        .await
        .ok()
        .flatten()?;

    // Skip expired keys
    if let Some(expires_at) = key_row.expires_at {
        if expires_at < OffsetDateTime::now_utc() {
            return None;
        }
    }

    // Resolve owner_user_id from the identity
    let owner_user_id = if let Some(identity_id) = key_row.identity_id {
        match overslash_db::repos::identity::get_by_id(&state.db, identity_id).await {
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

    PREFIX_CACHE.entries.insert(
        prefix.to_string(),
        CachedIdentity {
            org_id: key_row.org_id,
            identity_id: key_row.identity_id,
            owner_user_id,
            expires_at: key_row.expires_at,
            fetched_at: Instant::now(),
        },
    );

    Some((key_row.org_id, key_row.identity_id, owner_user_id))
}
