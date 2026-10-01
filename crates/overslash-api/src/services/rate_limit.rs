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
    /// This request is the one that took the bucket over its limit in this
    /// window (`count == max + 1`). Exactly one request per bucket per window
    /// sees it — across instances too, since Valkey's `INCR` is atomic — which
    /// makes it the natural "log once" trigger. See [`refuse`].
    pub first_denied: bool,
}

/// Resolved rate limit config (max_requests, window_seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

            // Use i64 to match Redis INCR's native return type and avoid
            // truncation/overflow on long-window high-traffic counters.
            let result: Result<(i64,), _> = redis::pipe()
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
                    let max_i64 = max_requests as i64;
                    let allowed = count <= max_i64;
                    let remaining = if allowed {
                        (max_i64 - count).max(0) as u32
                    } else {
                        0
                    };
                    RateLimitResult {
                        allowed,
                        limit: max_requests,
                        remaining,
                        reset_at,
                        first_denied: count == max_i64 + 1,
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
                        first_denied: false,
                    }
                }
            }
        })
    }
}

// ── In-memory implementation ────────────────────────────────────────

/// In-memory counter entry: tracks count, window start time, and the window size
/// so eviction can correctly determine when each entry has fully elapsed.
#[derive(Debug, Clone, Copy)]
struct CounterEntry {
    count: u32,
    window_start: u64,
    window_seconds: u32,
}

#[derive(Default)]
pub struct InMemoryRateLimitStore {
    /// Map from window_key → CounterEntry
    counters: DashMap<String, CounterEntry>,
}

impl InMemoryRateLimitStore {
    pub fn new() -> Self {
        Self {
            counters: DashMap::new(),
        }
    }

    /// Remove entries whose configured window has fully elapsed.
    /// Each entry stores its own `window_seconds` so we evict per-entry rather
    /// than using a single hardcoded retention period (which could prematurely
    /// evict counters for limits with large windows).
    pub fn evict_expired(&self) {
        let now = now_unix();
        self.counters
            .retain(|_, entry| entry.window_start + entry.window_seconds as u64 > now);
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

            let mut entry = self.counters.entry(window_key).or_insert(CounterEntry {
                count: 0,
                window_start,
                window_seconds,
            });

            // If the stored window is stale, reset
            if entry.window_start != window_start {
                entry.count = 0;
                entry.window_start = window_start;
                entry.window_seconds = window_seconds;
            }

            entry.count += 1;
            let current = entry.count;
            drop(entry);

            let allowed = current <= max_requests;
            let remaining = if allowed { max_requests - current } else { 0 };

            RateLimitResult {
                allowed,
                limit: max_requests,
                remaining,
                reset_at,
                first_denied: current as u64 == max_requests as u64 + 1,
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
    /// Org-level fallback budget cache: org_id → config (None = no DB row, use system fallback)
    org_budget: DashMap<Uuid, CachedConfig>,
    ttl: Duration,
}

impl RateLimitConfigCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            user_budget: DashMap::new(),
            identity_cap: DashMap::new(),
            org_budget: DashMap::new(),
            ttl,
        }
    }

    /// Drop all cache entries scoped to an org. Used when a rate limit config
    /// is upserted/deleted so changes take effect immediately.
    ///
    /// Group/org-default changes can affect any user, so we conservatively
    /// invalidate everything for the org rather than tracking which user_ids
    /// belong to which group.
    pub fn invalidate_org(&self, org_id: Uuid) {
        self.user_budget.retain(|(o, _), _| *o != org_id);
        self.identity_cap.retain(|(o, _), _| *o != org_id);
        self.org_budget.remove(&org_id);
    }

    /// Drop the cached identity cap entry for a specific identity.
    pub fn invalidate_identity_cap(&self, org_id: Uuid, identity_id: Uuid) {
        self.identity_cap.remove(&(org_id, identity_id));
    }

    /// Drop the cached user budget entry for a specific user.
    pub fn invalidate_user_budget(&self, org_id: Uuid, user_id: Uuid) {
        self.user_budget.remove(&(org_id, user_id));
    }

    /// Remove entries past their TTL. The resolve methods only check
    /// freshness on read — without periodic eviction, every unique
    /// (org, user/identity) pair that ever hits the API stays resident
    /// for the life of the process (slow memory growth on long-lived
    /// instances).
    pub fn evict_expired(&self) {
        self.user_budget
            .retain(|_, entry| entry.fetched_at.elapsed() < self.ttl);
        self.identity_cap
            .retain(|_, entry| entry.fetched_at.elapsed() < self.ttl);
        self.org_budget
            .retain(|_, entry| entry.fetched_at.elapsed() < self.ttl);
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
        if let Some(entry) = self.user_budget.get(&(org_id, user_id))
            && entry.fetched_at.elapsed() < self.ttl
        {
            return entry.config.unwrap_or(RateLimitConfig {
                max_requests: config.default_rate_limit,
                window_seconds: config.default_rate_window_secs,
            });
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

    /// Resolve the org-level fallback budget for unbound API keys.
    /// Uses the org default if set, otherwise the system fallback config.
    /// Cached with the same TTL as user budgets.
    pub async fn resolve_org_budget(
        &self,
        pool: &PgPool,
        config: &Config,
        org_id: Uuid,
    ) -> RateLimitConfig {
        let fallback = RateLimitConfig {
            max_requests: config.default_rate_limit,
            window_seconds: config.default_rate_window_secs,
        };

        // Check cache
        if let Some(entry) = self.org_budget.get(&org_id)
            && entry.fetched_at.elapsed() < self.ttl
        {
            return entry.config.unwrap_or(fallback);
        }

        // Resolve from DB
        let scope = overslash_db::OrgScope::new(org_id, pool.clone());
        let resolved = scope
            .get_org_default_rate_limit()
            .await
            .ok()
            .flatten()
            .map(|row| RateLimitConfig {
                max_requests: row.max_requests as u32,
                window_seconds: row.window_seconds as u32,
            });

        self.org_budget.insert(
            org_id,
            CachedConfig {
                config: resolved,
                fetched_at: Instant::now(),
            },
        );

        resolved.unwrap_or(fallback)
    }

    /// Resolve an identity cap. Returns None if no cap is configured.
    pub async fn resolve_identity_cap(
        &self,
        pool: &PgPool,
        org_id: Uuid,
        identity_id: Uuid,
    ) -> Option<RateLimitConfig> {
        // Check cache
        if let Some(entry) = self.identity_cap.get(&(org_id, identity_id))
            && entry.fetched_at.elapsed() < self.ttl
        {
            return entry.config;
        }

        // Resolve from DB
        let scope = overslash_db::OrgScope::new(org_id, pool.clone());
        let resolved = scope
            .get_rate_limit_for_identity(identity_id, "identity_cap")
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
    let scope = overslash_db::OrgScope::new(org_id, pool.clone());

    // 1. Per-user override
    if let Ok(Some(row)) = scope.get_rate_limit_for_identity(user_id, "user").await {
        return Some(RateLimitConfig {
            max_requests: row.max_requests as u32,
            window_seconds: row.window_seconds as u32,
        });
    }

    // 2. Group default (most permissive)
    if let Ok(groups) = scope.list_groups_for_identity(user_id).await
        && !groups.is_empty()
    {
        let group_ids: Vec<Uuid> = groups.iter().map(|g| g.id).collect();
        if let Ok(Some(row)) = scope.most_permissive_group_rate_limit(&group_ids).await {
            return Some(RateLimitConfig {
                max_requests: row.max_requests as u32,
                window_seconds: row.window_seconds as u32,
            });
        }
    }

    // 3. Org default
    if let Ok(Some(row)) = scope.get_org_default_rate_limit().await {
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

/// Fleet-wide ceiling on deny log lines, spent from the same store as the
/// limits themselves. The first-deny rule already holds each bucket to one line
/// per window, but an attacker can mint IP buckets at will (a botnet, or one
/// IPv6 host walking its /64), so the total needs a cap of its own.
pub const DENY_LOG_BUDGET: RateLimitConfig = RateLimitConfig {
    max_requests: 60,
    window_seconds: 60,
};
const DENY_LOG_BUDGET_KEY: &str = "rl:deny-log-budget";

/// What [`log_first_deny`] did with a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyLog {
    /// Not the first deny in this bucket's window: nothing to say.
    Repeat,
    /// Logged.
    Logged,
    /// First deny, but the fleet-wide budget was spent; counted instead.
    Suppressed,
}

/// Log a refusal once: only the request that took `key` over its limit in this
/// window, and only while [`DENY_LOG_BUDGET`] lasts. The metric
/// (`overslash_rate_limit_decisions_total`) counts *every* deny, which costs
/// the same at any volume; this is the line that says *who*, and a log line
/// per deny would let a flood fill the logs.
///
/// `key` is the bucket key, which names the principal: `rl:{org}:user:{id}`,
/// `rl:{org}:session:{id}`, `rl:{org}:id:{id}`, `rl:{org}:mcp:client:{id}`,
/// `rl:ip:{oauth|dcr}:{ip}`.
pub async fn log_first_deny(
    store: &dyn RateLimitStore,
    budget: RateLimitConfig,
    scope: &'static str,
    key: &str,
    result: &RateLimitResult,
) -> DenyLog {
    if !result.first_denied {
        return DenyLog::Repeat;
    }
    let spend = store
        .check_and_increment(
            DENY_LOG_BUDGET_KEY,
            budget.max_requests,
            budget.window_seconds,
        )
        .await;
    if !spend.allowed {
        overslash_metrics::rate_limit::record_deny_log_suppressed(scope);
        return DenyLog::Suppressed;
    }
    tracing::warn!(
        scope,
        bucket = key,
        limit = result.limit,
        reset_at = result.reset_at,
        "rate limit exceeded; further denies for this bucket are not logged until it resets"
    );
    DenyLog::Logged
}

/// The whole of a refusal: the deny metric, the once-per-window log line, and
/// the 429.
pub async fn refuse(
    store: &dyn RateLimitStore,
    scope: &'static str,
    key: &str,
    result: &RateLimitResult,
) -> axum::response::Response {
    overslash_metrics::rate_limit::record_decision(scope, "deny");
    log_first_deny(store, DENY_LOG_BUDGET, scope, key, result).await;
    too_many_requests(result)
}

/// The 429 for a refused check: `Retry-After`, `X-RateLimit-*` and the JSON
/// body, all from [`crate::error::AppError::RateLimited`].
pub fn too_many_requests(result: &RateLimitResult) -> axum::response::Response {
    use axum::response::IntoResponse;
    crate::error::AppError::RateLimited {
        limit: result.limit,
        reset_at: result.reset_at,
        retry_after: result.reset_at.saturating_sub(now_unix()),
    }
    .into_response()
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> CachedConfig {
        CachedConfig {
            config: None,
            fetched_at: Instant::now(),
        }
    }

    #[test]
    fn evict_expired_drops_stale_entries_from_all_maps() {
        // TTL of zero → every entry is stale the moment it's inserted.
        let cache = RateLimitConfigCache::new(Duration::ZERO);
        let org = Uuid::new_v4();
        cache.user_budget.insert((org, Uuid::new_v4()), entry());
        cache.identity_cap.insert((org, Uuid::new_v4()), entry());
        cache.org_budget.insert(org, entry());

        cache.evict_expired();

        assert!(cache.user_budget.is_empty());
        assert!(cache.identity_cap.is_empty());
        assert!(cache.org_budget.is_empty());
    }

    fn cfg(max_requests: u32) -> RateLimitConfig {
        RateLimitConfig {
            max_requests,
            window_seconds: 3600,
        }
    }

    #[tokio::test]
    async fn only_the_request_that_crosses_the_limit_is_first_denied() {
        let store = InMemoryRateLimitStore::new();
        let mut flags = Vec::new();
        for _ in 0..5 {
            flags.push(store.check_and_increment("k", 2, 3600).await.first_denied);
        }
        assert_eq!(flags, [false, false, true, false, false]);
    }

    #[tokio::test]
    async fn a_bucket_logs_once_per_window() {
        let store = InMemoryRateLimitStore::new();
        let mut outcomes = Vec::new();
        for _ in 0..4 {
            let r = store.check_and_increment("rl:ip:oauth:1", 1, 3600).await;
            if !r.allowed {
                outcomes
                    .push(log_first_deny(&store, cfg(10), "oauth_ip", "rl:ip:oauth:1", &r).await);
            }
        }
        assert_eq!(
            outcomes,
            [DenyLog::Logged, DenyLog::Repeat, DenyLog::Repeat]
        );
    }

    #[tokio::test]
    async fn many_buckets_share_one_log_budget() {
        let store = InMemoryRateLimitStore::new();
        let mut outcomes = Vec::new();
        for ip in 0..4 {
            let key = format!("rl:ip:oauth:10.0.0.{ip}");
            store.check_and_increment(&key, 1, 3600).await;
            let r = store.check_and_increment(&key, 1, 3600).await;
            outcomes.push(log_first_deny(&store, cfg(2), "oauth_ip", &key, &r).await);
        }
        assert_eq!(
            outcomes,
            [
                DenyLog::Logged,
                DenyLog::Logged,
                DenyLog::Suppressed,
                DenyLog::Suppressed
            ]
        );
    }

    #[test]
    fn evict_expired_keeps_fresh_entries() {
        let cache = RateLimitConfigCache::new(Duration::from_secs(60));
        let org = Uuid::new_v4();
        cache.user_budget.insert((org, Uuid::new_v4()), entry());
        cache.org_budget.insert(org, entry());

        cache.evict_expired();

        assert_eq!(cache.user_budget.len(), 1);
        assert_eq!(cache.org_budget.len(), 1);
    }
}
