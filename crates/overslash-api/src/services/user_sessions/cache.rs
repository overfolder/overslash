//! Validation cache for the session gate: `jti → identity_id` of a session
//! that was live when last read from Postgres, or the nil id for one that was
//! dead.
//!
//! Live answers are cached for [`super::CACHE_TTL`] at most, and every
//! revocation deletes the ids it touched. Dead answers are terminal and cached
//! for [`super::DEAD_CACHE_TTL`]. With Valkey that delete
//! reaches every replica. Without `REDIS_URL` production runs with no cache
//! at all — a process-local map could not be invalidated on the other
//! replicas, and "logout works, eventually" is exactly the gap this closes.
//! The in-memory backend exists for the test harness, which is one process.
//!
//! Every method swallows its own failures, like the resolver cache: a cache
//! miss costs one primary-key lookup, a cache error must not cost a 5xx.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use uuid::Uuid;

use crate::config::Config;

const KEY_PREFIX: &str = "overslash:session:";
const REDIS_TIMEOUT: Duration = Duration::from_millis(100);
/// In-memory cap; far above what one test process touches.
const MEMORY_MAX_ENTRIES: usize = 100_000;

#[async_trait]
pub trait SessionCache: Send + Sync {
    /// The identity a live session was last seen scoped to, if cached.
    async fn get(&self, jti: Uuid) -> Option<Uuid>;
    async fn put(&self, jti: Uuid, identity_id: Uuid, ttl: Duration);
    async fn invalidate(&self, jtis: &[Uuid]);
    /// `redis`, `memory` or `disabled`.
    fn backend(&self) -> &'static str;
}

fn key(jti: Uuid) -> String {
    format!("{KEY_PREFIX}{jti}")
}

// ── Redis / Valkey ──────────────────────────────────────────────────

struct RedisSessionCache {
    conn: redis::aio::ConnectionManager,
}

#[async_trait]
impl SessionCache for RedisSessionCache {
    async fn get(&self, jti: Uuid) -> Option<Uuid> {
        let mut conn = self.conn.clone();
        let mut cmd = redis::cmd("GET");
        cmd.arg(key(jti));
        let fut = cmd.query_async::<Option<String>>(&mut conn);
        match tokio::time::timeout(REDIS_TIMEOUT, fut).await {
            Ok(Ok(v)) => v.and_then(|s| s.parse().ok()),
            Ok(Err(e)) => {
                tracing::warn!("session cache read failed, checking Postgres: {e}");
                None
            }
            Err(_) => {
                tracing::warn!("session cache read timed out, checking Postgres");
                None
            }
        }
    }

    async fn put(&self, jti: Uuid, identity_id: Uuid, ttl: Duration) {
        let mut conn = self.conn.clone();
        let mut cmd = redis::cmd("SET");
        cmd.arg(key(jti))
            .arg(identity_id.to_string())
            .arg("EX")
            .arg(ttl.as_secs().max(1));
        let fut = cmd.query_async::<()>(&mut conn);
        match tokio::time::timeout(REDIS_TIMEOUT, fut).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!("session cache write failed: {e}"),
            Err(_) => tracing::warn!("session cache write timed out"),
        }
    }

    async fn invalidate(&self, jtis: &[Uuid]) {
        if jtis.is_empty() {
            return;
        }
        let mut cmd = redis::cmd("DEL");
        for jti in jtis {
            cmd.arg(key(*jti));
        }
        let mut conn = self.conn.clone();
        // A failed delete leaves a revoked session usable until its entry
        // expires — bounded by CACHE_TTL, and loud.
        match tokio::time::timeout(REDIS_TIMEOUT, cmd.query_async::<()>(&mut conn)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(
                count = jtis.len(),
                "session cache invalidation failed; revoked sessions stay cached up to their TTL: {e}"
            ),
            Err(_) => tracing::error!(
                count = jtis.len(),
                "session cache invalidation timed out; revoked sessions stay cached up to their TTL"
            ),
        }
    }

    fn backend(&self) -> &'static str {
        "redis"
    }
}

// ── In-memory (tests) ───────────────────────────────────────────────

struct MemorySessionCache {
    entries: DashMap<Uuid, (Uuid, Instant)>,
}

#[async_trait]
impl SessionCache for MemorySessionCache {
    async fn get(&self, jti: Uuid) -> Option<Uuid> {
        self.entries
            .get(&jti)
            .filter(|e| e.1 > Instant::now())
            .map(|e| e.0)
    }

    async fn put(&self, jti: Uuid, identity_id: Uuid, ttl: Duration) {
        if self.entries.len() >= MEMORY_MAX_ENTRIES {
            let now = Instant::now();
            self.entries.retain(|_, e| e.1 > now);
        }
        self.entries
            .insert(jti, (identity_id, Instant::now() + ttl));
    }

    async fn invalidate(&self, jtis: &[Uuid]) {
        for jti in jtis {
            self.entries.remove(jti);
        }
    }

    fn backend(&self) -> &'static str {
        "memory"
    }
}

// ── Disabled ────────────────────────────────────────────────────────

struct DisabledSessionCache;

#[async_trait]
impl SessionCache for DisabledSessionCache {
    async fn get(&self, _jti: Uuid) -> Option<Uuid> {
        None
    }
    async fn put(&self, _jti: Uuid, _identity_id: Uuid, _ttl: Duration) {}
    async fn invalidate(&self, _jtis: &[Uuid]) {}
    fn backend(&self) -> &'static str {
        "disabled"
    }
}

/// A process-local cache. For the test harness and single-process tools only.
pub fn in_memory() -> Arc<dyn SessionCache> {
    Arc::new(MemorySessionCache {
        entries: DashMap::new(),
    })
}

/// No cache: every session check reads Postgres.
pub fn disabled() -> Arc<dyn SessionCache> {
    Arc::new(DisabledSessionCache)
}

/// A Valkey-backed cache, or why not.
pub async fn redis(url: &str) -> Result<Arc<dyn SessionCache>, redis::RedisError> {
    let conn = redis::Client::open(url)?.get_connection_manager().await?;
    Ok(Arc::new(RedisSessionCache { conn }))
}

/// Valkey when `REDIS_URL` is set and reachable at boot, otherwise none.
pub async fn create_session_cache(config: &Config) -> Arc<dyn SessionCache> {
    if let Some(ref url) = config.redis_url {
        match redis(url).await {
            Ok(cache) => {
                tracing::info!("Session cache: using Redis/Valkey");
                return cache;
            }
            Err(e) => {
                tracing::warn!("Redis unavailable, session checks go to Postgres uncached: {e}")
            }
        }
    }
    tracing::info!("Session cache: disabled (no REDIS_URL); one Postgres lookup per request");
    disabled()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_cache_round_trips_expires_and_invalidates() {
        let c = in_memory();
        let (a, b, ident) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        c.put(a, ident, Duration::from_secs(60)).await;
        c.put(b, ident, Duration::ZERO).await;
        assert_eq!(c.get(a).await, Some(ident));
        assert_eq!(c.get(b).await, None, "a zero TTL is already expired");
        c.invalidate(&[a]).await;
        assert_eq!(c.get(a).await, None);
    }

    #[tokio::test]
    async fn disabled_cache_never_hits() {
        let c = disabled();
        let a = Uuid::new_v4();
        c.put(a, a, Duration::from_secs(60)).await;
        assert_eq!(c.get(a).await, None);
    }
}
