use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;

// ── Types ───────────────────────────────────────────────────────────

/// Result of a rate limit check.
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_at: u64,
}

/// Resolved rate limit config (max_requests, window_seconds).
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window_seconds: u32,
}

// ── Store trait ─────────────────────────────────────────────────────

pub trait RateLimitStore: Send + Sync {
    fn check_and_increment(
        &self,
        key: &str,
        max_requests: u32,
        window_seconds: u32,
    ) -> Pin<Box<dyn Future<Output = RateLimitResult> + Send + '_>>;
}

// ── Redis implementation ────────────────────────────────────────────

pub struct RedisRateLimitStore {
    conn: redis::aio::ConnectionManager,
}

impl RateLimitStore for RedisRateLimitStore {
    fn check_and_increment(
        &self,
        key: &str,
        max_requests: u32,
        window_seconds: u32,
    ) -> Pin<Box<dyn Future<Output = RateLimitResult> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            let now = now_unix();
            let window_start = now / window_seconds as u64 * window_seconds as u64;
            let reset_at = window_start + window_seconds as u64;
            let window_key = format!("{key}:{window_start}");

            let result: Result<(u32,), _> = redis::pipe()
                .atomic()
                .cmd("INCR")
                .arg(&window_key)
                .cmd("EXPIRE")
                .arg(&window_key)
                .arg(window_seconds as i64)
                .ignore()
                .query_async(&mut self.conn.clone())
                .await;

            match result {
                Ok((count,)) => {
                    let allowed = count <= max_requests;
                    let remaining = if allowed { max_requests - count } else { 0 };
                    RateLimitResult {
                        allowed,
                        limit: max_requests,
                        remaining,
                        reset_at,
                    }
                }
                Err(e) => {
                    // Fail open: allow the request if Redis is unavailable
                    tracing::warn!("Redis rate limit check failed, allowing request: {e}");
                    RateLimitResult {
                        allowed: true,
                        limit: max_requests,
                        remaining: max_requests,
                        reset_at,
                    }
                }
            }
        })
    }
}

// ── In-memory implementation ────────────────────────────────────────

#[derive(Default)]
pub struct InMemoryRateLimitStore {
    /// Map from window_key → (count, window_start_unix)
    counters: DashMap<String, (u32, u64)>,
}

impl InMemoryRateLimitStore {
    pub fn new() -> Self {
        Self {
            counters: DashMap::new(),
        }
    }

    /// Remove expired entries. Called periodically from a background task.
    /// Uses a generous retention window (1 hour) to avoid evicting counters for
    /// large configurable windows (e.g., hourly rate limits).
    pub fn evict_expired(&self) {
        let now = now_unix();
        self.counters
            .retain(|_, (_, window_start)| *window_start + 3600 > now);
    }
}

impl RateLimitStore for InMemoryRateLimitStore {
    fn check_and_increment(
        &self,
        key: &str,
        max_requests: u32,
        window_seconds: u32,
    ) -> Pin<Box<dyn Future<Output = RateLimitResult> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            let now = now_unix();
            let window_start = now / window_seconds as u64 * window_seconds as u64;
            let reset_at = window_start + window_seconds as u64;
            let window_key = format!("{key}:{window_start}");

            let mut entry = self.counters.entry(window_key).or_insert((0, window_start));
            let (count, stored_start) = entry.value_mut();

            // If the stored window is stale, reset
            if *stored_start != window_start {
                *count = 0;
                *stored_start = window_start;
            }

            *count += 1;
            let current = *count;
            drop(entry);

            let allowed = current <= max_requests;
            let remaining = if allowed { max_requests - current } else { 0 };

            RateLimitResult {
                allowed,
                limit: max_requests,
                remaining,
                reset_at,
            }
        })
    }
}

// ── Config cache ────────────────────────────────────────────────────

struct CachedConfig {
    config: Option<RateLimitConfig>,
    fetched_at: Instant,
}

/// Caches resolved rate limit configs to avoid DB lookups on every request.
pub struct RateLimitConfigCache {
    /// User budget cache: (org_id, user_id) → config
    user_budget: DashMap<(Uuid, Uuid), CachedConfig>,
    /// Identity cap cache: (org_id, identity_id) → config (None = no cap)
    identity_cap: DashMap<(Uuid, Uuid), CachedConfig>,
    ttl: Duration,
}

impl RateLimitConfigCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            user_budget: DashMap::new(),
            identity_cap: DashMap::new(),
            ttl,
        }
    }

    /// Resolve the User bucket config. Uses cache, falls back to DB resolution chain.
    pub async fn resolve_user_budget(
        &self,
        pool: &PgPool,
        config: &Config,
        org_id: Uuid,
        user_id: Uuid,
    ) -> RateLimitConfig {
        // Check cache
        if let Some(entry) = self.user_budget.get(&(org_id, user_id)) {
            if entry.fetched_at.elapsed() < self.ttl {
                return entry.config.unwrap_or(RateLimitConfig {
                    max_requests: config.default_rate_limit,
                    window_seconds: config.default_rate_window_secs,
                });
            }
        }

        // Resolve from DB
        let resolved = resolve_user_budget_from_db(pool, org_id, user_id).await;
        self.user_budget.insert(
            (org_id, user_id),
            CachedConfig {
                config: resolved,
                fetched_at: Instant::now(),
            },
        );

        resolved.unwrap_or(RateLimitConfig {
            max_requests: config.default_rate_limit,
            window_seconds: config.default_rate_window_secs,
        })
    }

    /// Resolve an identity cap. Returns None if no cap is configured.
    pub async fn resolve_identity_cap(
        &self,
        pool: &PgPool,
        org_id: Uuid,
        identity_id: Uuid,
    ) -> Option<RateLimitConfig> {
        // Check cache
        if let Some(entry) = self.identity_cap.get(&(org_id, identity_id)) {
            if entry.fetched_at.elapsed() < self.ttl {
                return entry.config;
            }
        }

        // Resolve from DB
        let resolved = overslash_db::repos::rate_limit::get_for_identity(
            pool,
            org_id,
            identity_id,
            "identity_cap",
        )
        .await
        .ok()
        .flatten()
        .map(|row| RateLimitConfig {
            max_requests: row.max_requests as u32,
            window_seconds: row.window_seconds as u32,
        });

        self.identity_cap.insert(
            (org_id, identity_id),
            CachedConfig {
                config: resolved,
                fetched_at: Instant::now(),
            },
        );

        resolved
    }
}

/// Resolution chain for user budget: user override → group default → org default.
async fn resolve_user_budget_from_db(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
) -> Option<RateLimitConfig> {
    // 1. Per-user override
    if let Ok(Some(row)) =
        overslash_db::repos::rate_limit::get_for_identity(pool, org_id, user_id, "user").await
    {
        return Some(RateLimitConfig {
            max_requests: row.max_requests as u32,
            window_seconds: row.window_seconds as u32,
        });
    }

    // 2. Group default (most permissive)
    if let Ok(groups) = overslash_db::repos::group::list_groups_for_identity(pool, user_id).await {
        if !groups.is_empty() {
            let group_ids: Vec<Uuid> = groups.iter().map(|g| g.id).collect();
            if let Ok(Some(row)) = overslash_db::repos::rate_limit::get_most_permissive_for_groups(
                pool, org_id, &group_ids,
            )
            .await
            {
                return Some(RateLimitConfig {
                    max_requests: row.max_requests as u32,
                    window_seconds: row.window_seconds as u32,
                });
            }
        }
    }

    // 3. Org default
    if let Ok(Some(row)) = overslash_db::repos::rate_limit::get_org_default(pool, org_id).await {
        return Some(RateLimitConfig {
            max_requests: row.max_requests as u32,
            window_seconds: row.window_seconds as u32,
        });
    }

    // 4. No DB config — caller uses Config fallback
    None
}

// ── Factory ─────────────────────────────────────────────────────────

/// Create the store and return it along with an optional eviction handle for in-memory stores.
/// Returns (store, Some(in_memory_ref)) if in-memory, (store, None) if Redis.
pub async fn create_store_with_eviction(
    config: &Config,
) -> (Arc<dyn RateLimitStore>, Option<Arc<InMemoryRateLimitStore>>) {
    if let Some(ref url) = config.redis_url {
        match redis::Client::open(url.as_str()) {
            Ok(client) => match client.get_connection_manager().await {
                Ok(mgr) => {
                    tracing::info!("Rate limiter: using Redis/Valkey");
                    return (Arc::new(RedisRateLimitStore { conn: mgr }), None);
                }
                Err(e) => {
                    tracing::warn!(
                        "Redis connection failed, falling back to in-memory rate limiter: {e}"
                    );
                }
            },
            Err(e) => {
                tracing::warn!("Invalid REDIS_URL, falling back to in-memory rate limiter: {e}");
            }
        }
    }

    tracing::info!("Rate limiter: using in-memory store");
    let store = Arc::new(InMemoryRateLimitStore::new());
    (store.clone(), Some(store))
}

// ── Helpers ─────────────────────────────────────────────────────────

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
