use std::time::{Duration, Instant};

use dashmap::DashMap;
use sqlx::PgPool;
use uuid::Uuid;

/// Caches per-org billing-tier lookups so the rate-limit middleware can decide
/// whether to bypass without hitting Postgres on every request.
///
/// `free_unlimited` orgs are set out-of-band by an operator (`UPDATE orgs SET
/// plan='free_unlimited' WHERE slug='...'`); the only way the cache can become
/// stale is when an operator flips that column. A 30s TTL matches
/// `RateLimitConfigCache` and bounds how long the change takes to propagate.
pub struct FreeUnlimitedCache {
    /// org_id → (plan, fetched_at)
    entries: DashMap<Uuid, (String, Instant)>,
    ttl: Duration,
}

impl FreeUnlimitedCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: DashMap::new(),
            ttl,
        }
    }

    /// Returns true iff the org's `plan` is `free_unlimited`. Cache miss or
    /// stale entry → DB lookup. A DB error is treated as "not free_unlimited"
    /// (fail closed — better to rate-limit a courtesy org during a DB blip
    /// than to let a paying org bypass).
    pub async fn is_free_unlimited(&self, pool: &PgPool, org_id: Uuid) -> bool {
        if let Some(entry) = self.entries.get(&org_id) {
            if entry.1.elapsed() < self.ttl {
                return entry.0 == "free_unlimited";
            }
        }

        let plan = match overslash_db::repos::org::get_plan(pool, org_id).await {
            Ok(Some(p)) => p,
            _ => return false,
        };
        let is_free = plan == "free_unlimited";
        self.entries.insert(org_id, (plan, Instant::now()));
        is_free
    }

    /// Drop the cached entry for an org so the next lookup hits the DB.
    /// Used by tests and by any future admin tooling that flips the column.
    pub fn invalidate(&self, org_id: Uuid) {
        self.entries.remove(&org_id);
    }
}
