//! Backends for the resolver cache, and the boot-time choice between them.
//!
//! Byte-oriented on purpose: encryption and projection live one level up, so
//! both backends store identical ciphertext and there is exactly one place
//! where a plaintext name becomes bytes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;

use crate::config::Config;

/// How many entries the in-memory backend drops when it hits its cap. Small
/// enough to be cheap, large enough that a full map doesn't pay the scan on
/// every single insert.
const OVERFLOW_SAMPLE: usize = 64;

// ── Store trait + backends ──────────────────────────────────────────

/// One slot of a batched read: the stored bytes, nothing stored, or the
/// backend could not answer.
///
/// `Failed` is distinct from `Absent` so the caller does not count a transport
/// failure as N cold keys — that would inflate the miss denominator with
/// errors the metrics contract counts separately, and make an outage look like
/// a cache that is merely cold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    Hit(Vec<u8>),
    Absent,
    Failed,
}

/// A byte-oriented, best-effort KV store with per-entry TTLs.
///
/// Every method swallows its own failures: a cache that can propagate an error
/// into the call path is worse than no cache. A backend problem shows up as a
/// miss (and a metric), never as a 5xx.
///
/// Uses `#[async_trait]` rather than `RateLimitStore`'s hand-rolled
/// `Pin<Box<dyn Future>>` — this trait returns owned data, so there is no
/// borrow to thread through by hand.
#[async_trait]
pub trait ResolveCacheStore: Send + Sync {
    /// Batched read. Returns one slot per key, in order.
    async fn get_many(&self, keys: &[String]) -> Vec<Slot>;
    /// Batched write. Each entry carries its own TTL.
    async fn put_many(&self, entries: &[(String, Vec<u8>, Duration)]);
    /// Bounded label for metrics: `redis`, `memory`, or `disabled`.
    fn backend(&self) -> &'static str;
}

// ── Redis / Valkey ──────────────────────────────────────────────────

pub struct RedisResolveCache {
    conn: redis::aio::ConnectionManager,
    timeout: Duration,
}

#[async_trait]
impl ResolveCacheStore for RedisResolveCache {
    async fn get_many(&self, keys: &[String]) -> Vec<Slot> {
        if keys.is_empty() {
            return Vec::new();
        }
        // A pipeline of single-key GETs rather than one MGET: MGET is a
        // cross-slot command and hard-errors on a clustered Valkey, whereas a
        // pipeline degrades to per-slot routing. Both are one round trip.
        // Not `.atomic()` — MULTI/EXEC buys nothing for reads and costs a round
        // trip through some proxies.
        let mut pipe = redis::pipe();
        for key in keys {
            pipe.cmd("GET").arg(key);
        }
        let started = Instant::now();
        let result: Result<Vec<Option<Vec<u8>>>, redis::RedisError> = match tokio::time::timeout(
            self.timeout,
            pipe.query_async(&mut self.conn.clone()),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => {
                // A wedged backend is the case this bound exists for: the
                // point of the cache is latency, so waiting on it longer
                // than the lookup it replaces would be self-defeating.
                tracing::warn!(
                    timeout_ms = self.timeout.as_millis(),
                    "resolve cache read timed out, resolving live"
                );
                overslash_metrics::resolve_cache::record_lookup("redis", "error");
                return vec![Slot::Failed; keys.len()];
            }
        };
        overslash_metrics::resolve_cache::record_op("redis", "get", started.elapsed());

        match result {
            Ok(values) if values.len() == keys.len() => values
                .into_iter()
                .map(|v| match v {
                    Some(bytes) => Slot::Hit(bytes),
                    None => Slot::Absent,
                })
                .collect(),
            // A short batch is the "cache that quietly does nothing" case: the
            // pipeline answered, but not for every key we asked about, so we
            // cannot say which slot is which. Treated as a failure, not as
            // absence.
            Ok(_) => {
                tracing::warn!("resolve cache: pipelined GET returned a short result");
                overslash_metrics::resolve_cache::record_lookup("redis", "error");
                vec![Slot::Failed; keys.len()]
            }
            Err(e) => {
                tracing::warn!("resolve cache read failed, resolving live: {e}");
                overslash_metrics::resolve_cache::record_lookup("redis", "error");
                vec![Slot::Failed; keys.len()]
            }
        }
    }

    async fn put_many(&self, entries: &[(String, Vec<u8>, Duration)]) {
        if entries.is_empty() {
            return;
        }
        // One `SET .. EX` per entry rather than a shared expiry: the TTL is
        // per-resolver, so a positive and a negative result written in the same
        // batch legitimately expire at different times.
        let mut pipe = redis::pipe();
        for (key, blob, ttl) in entries {
            pipe.cmd("SET")
                .arg(key)
                .arg(blob.as_slice())
                .arg("EX")
                .arg(ttl.as_secs().max(1))
                .ignore();
        }
        let started = Instant::now();
        let result: Result<(), redis::RedisError> = match tokio::time::timeout(
            self.timeout,
            pipe.query_async(&mut self.conn.clone()),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => {
                tracing::warn!(
                    timeout_ms = self.timeout.as_millis(),
                    "resolve cache write timed out"
                );
                overslash_metrics::resolve_cache::record_write("redis", "error");
                return;
            }
        };
        overslash_metrics::resolve_cache::record_op("redis", "set", started.elapsed());
        if let Err(e) = result {
            tracing::warn!("resolve cache write failed: {e}");
            overslash_metrics::resolve_cache::record_write("redis", "error");
        }
    }

    fn backend(&self) -> &'static str {
        "redis"
    }
}

// ── In-memory ───────────────────────────────────────────────────────

struct Entry {
    blob: Vec<u8>,
    expires_at: Instant,
}

/// Process-local fallback. Correct for a single replica, and the common case
/// today: `enable_valkey` defaults off.
///
/// Entries carry their own `expires_at` rather than sharing one cache-level
/// TTL (the shape `RateLimitConfigCache` uses), because here the TTL is a
/// per-resolver property.
pub struct InMemoryResolveCache {
    entries: DashMap<String, Entry>,
    max_entries: usize,
}

impl InMemoryResolveCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: DashMap::new(),
            max_entries,
        }
    }

    /// Drop entries past their expiry. Reads only check freshness, so without
    /// this every key ever touched stays resident for the life of the process.
    pub fn evict_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, e| e.expires_at > now);
    }

    /// Make room for one insert. Expired entries first; if the map is still
    /// full, drop a bounded arbitrary sample.
    ///
    /// Approximately random replacement, which is what Redis's own
    /// `allkeys-random` does. The alternative — declining the insert — would
    /// freeze the map on whatever arrived first, so a hot key could never be
    /// re-admitted after expiring while a flood of one-shot arguments squatted.
    fn make_room(&self) {
        if self.entries.len() < self.max_entries {
            return;
        }
        self.evict_expired();
        if self.entries.len() < self.max_entries {
            return;
        }
        let victims: Vec<String> = self
            .entries
            .iter()
            .take(OVERFLOW_SAMPLE)
            .map(|e| e.key().clone())
            .collect();
        for key in victims {
            self.entries.remove(&key);
        }
        overslash_metrics::resolve_cache::record_write("memory", "evicted_for_capacity");
    }
}

#[async_trait]
impl ResolveCacheStore for InMemoryResolveCache {
    async fn get_many(&self, keys: &[String]) -> Vec<Slot> {
        let now = Instant::now();
        keys.iter()
            .map(|key| {
                self.entries
                    .get(key)
                    .filter(|e| e.expires_at > now)
                    .map(|e| Slot::Hit(e.blob.clone()))
                    .unwrap_or(Slot::Absent)
            })
            .collect()
    }

    async fn put_many(&self, entries: &[(String, Vec<u8>, Duration)]) {
        for (key, blob, ttl) in entries {
            self.make_room();
            self.entries.insert(
                key.clone(),
                Entry {
                    blob: blob.clone(),
                    expires_at: Instant::now() + *ttl,
                },
            );
        }
    }

    fn backend(&self) -> &'static str {
        "memory"
    }
}

// ── Disabled ────────────────────────────────────────────────────────

/// A store that never hits. Used when caching is switched off, and by tests
/// that want the pre-D64 behaviour without touching env.
pub struct DisabledResolveCache;

#[async_trait]
impl ResolveCacheStore for DisabledResolveCache {
    async fn get_many(&self, keys: &[String]) -> Vec<Slot> {
        vec![Slot::Absent; keys.len()]
    }
    async fn put_many(&self, _entries: &[(String, Vec<u8>, Duration)]) {}
    fn backend(&self) -> &'static str {
        "disabled"
    }
}

/// A no-op store. Used by the factory when caching is switched off, and
/// available to tests that want the pre-D64 behaviour.
pub(super) fn disabled() -> Arc<dyn ResolveCacheStore> {
    Arc::new(DisabledResolveCache)
}

/// A fresh process-local store. Used by the per-test-router harnesses, where a
/// store per `AppState` is what keeps one test's resolved names from answering
/// another's lookup — `BootstrapFixtures.org_id` is shared, so a process-wide
/// store would alias.
pub fn in_memory(max_entries: usize) -> Arc<dyn ResolveCacheStore> {
    Arc::new(InMemoryResolveCache::new(max_entries))
}

// ── Factory ─────────────────────────────────────────────────────────

/// Build the store, plus an eviction handle when it is the in-memory one.
///
/// Mirrors `rate_limit::create_store_with_eviction`, including the fallback:
/// `REDIS_URL` unset, invalid, or unreachable at boot means process-local. The
/// operator setting `REDIS_URL` *is* the decision to share the cache.
///
/// One backend per process, chosen here. A Redis error at request time must
/// never silently fall through to the in-memory map, or whether a call hits
/// would depend on which of two stores answered.
pub async fn create_resolve_cache(
    config: &Config,
) -> (
    Arc<dyn ResolveCacheStore>,
    Option<Arc<InMemoryResolveCache>>,
) {
    if config.resolve_cache_ttl_secs == 0 {
        tracing::info!("Resolver cache: disabled (RESOLVE_CACHE_TTL_SECS=0)");
        return (disabled(), None);
    }
    let timeout = Duration::from_millis(config.resolve_cache_timeout_ms);
    if let Some(ref url) = config.redis_url {
        match redis::Client::open(url.as_str()) {
            Ok(client) => match client.get_connection_manager().await {
                Ok(conn) => {
                    tracing::info!("Resolver cache: using Redis/Valkey");
                    return (Arc::new(RedisResolveCache { conn, timeout }), None);
                }
                Err(e) => {
                    tracing::warn!(
                        "Redis connection failed, falling back to in-memory resolver cache: {e}"
                    );
                }
            },
            Err(e) => {
                tracing::warn!("Invalid REDIS_URL, falling back to in-memory resolver cache: {e}");
            }
        }
    }
    tracing::info!("Resolver cache: using in-memory store");
    let store = Arc::new(InMemoryResolveCache::new(config.resolve_cache_max_entries));
    (store.clone(), Some(store))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn in_memory_round_trips_and_expires() {
        let store = InMemoryResolveCache::new(10);
        let k = vec!["a".to_string()];
        store
            .put_many(&[("a".into(), b"blob".to_vec(), Duration::from_secs(60))])
            .await;
        assert_eq!(store.get_many(&k).await, vec![Slot::Hit(b"blob".to_vec())]);

        // A zero TTL is already expired when read back.
        store
            .put_many(&[("a".into(), b"blob".to_vec(), Duration::ZERO)])
            .await;
        assert_eq!(store.get_many(&k).await, vec![Slot::Absent]);
    }

    #[tokio::test]
    async fn evict_expired_drops_only_stale_entries() {
        let store = InMemoryResolveCache::new(10);
        store
            .put_many(&[
                ("fresh".into(), b"x".to_vec(), Duration::from_secs(60)),
                ("stale".into(), b"x".to_vec(), Duration::ZERO),
            ])
            .await;
        store.evict_expired();
        assert_eq!(store.entries.len(), 1);
        assert!(store.entries.contains_key("fresh"));
    }

    /// Overflow drops a sample and inserts, rather than declining the insert.
    /// Declining would freeze the map on whatever arrived first, so a hot key
    /// could never be re-admitted after expiring while one-shot arguments
    /// squatted — the opposite of what a cache is for.
    #[tokio::test]
    async fn overflow_makes_room_instead_of_refusing_the_write() {
        let cap = OVERFLOW_SAMPLE * 2;
        let store = InMemoryResolveCache::new(cap);
        for i in 0..cap {
            store
                .put_many(&[(format!("k{i}"), b"x".to_vec(), Duration::from_secs(60))])
                .await;
        }
        assert_eq!(store.entries.len(), cap);

        store
            .put_many(&[("hot".into(), b"x".to_vec(), Duration::from_secs(60))])
            .await;
        assert!(
            store.entries.contains_key("hot"),
            "the new entry must be admitted"
        );
        assert!(store.entries.len() <= cap);
    }

    #[tokio::test]
    async fn the_disabled_store_never_hits() {
        let store = DisabledResolveCache;
        store
            .put_many(&[("a".into(), b"x".to_vec(), Duration::from_secs(60))])
            .await;
        assert_eq!(store.get_many(&["a".to_string()]).await, vec![Slot::Absent]);
    }

    /// A positive resolution that projects to nothing is still positive — it
    /// is held at the success TTL, not the much shorter failure one. `neg` is
    /// The Redis backend, exercised against a real server when one is
    /// configured. Skipped otherwise — `enable_valkey` defaults off and CI
    /// gives the API job no `REDIS_URL`, so this would be a permanently-red
    /// test if it demanded one.
    ///
    /// Worth having gated rather than not at all: the in-memory tests above
    /// cover the semantics, but nothing else covers the pipelined `GET` /
    /// `SET .. EX` encoding, and a batch that silently returned the wrong
    /// arity would degrade to "every lookup misses" — a cache that quietly
    /// does nothing, which is the failure mode hardest to notice in
    /// production.
    #[tokio::test]
    async fn redis_backend_round_trips_a_batch() {
        let Ok(url) = std::env::var("REDIS_URL") else {
            eprintln!("skipping: REDIS_URL not set");
            return;
        };
        let client = redis::Client::open(url.as_str()).expect("valid REDIS_URL");
        let Ok(conn) = client.get_connection_manager().await else {
            eprintln!("skipping: could not connect to REDIS_URL");
            return;
        };
        let store = RedisResolveCache {
            conn,
            timeout: Duration::from_secs(2),
        };

        // Unique per run so a shared Valkey can't leak between invocations.
        let a = format!("osr:test:{}:a", Uuid::new_v4());
        let b = format!("osr:test:{}:b", Uuid::new_v4());
        let missing = format!("osr:test:{}:gone", Uuid::new_v4());

        store
            .put_many(&[
                (a.clone(), b"alpha".to_vec(), Duration::from_secs(60)),
                (b.clone(), b"beta".to_vec(), Duration::from_secs(60)),
            ])
            .await;

        // Order and arity must both survive the pipeline, including the hole
        // where a key was never written.
        let got = store
            .get_many(&[a.clone(), missing.clone(), b.clone()])
            .await;
        assert_eq!(
            got,
            vec![
                Slot::Hit(b"alpha".to_vec()),
                Slot::Absent,
                Slot::Hit(b"beta".to_vec())
            ]
        );

        // An empty batch must not round-trip at all.
        assert!(store.get_many(&[]).await.is_empty());

        // `SET .. EX` actually expires: a sub-second TTL is floored to 1s, so
        // this is the shortest window the backend can express.
        let short = format!("osr:test:{}:short", Uuid::new_v4());
        store
            .put_many(&[(short.clone(), b"x".to_vec(), Duration::from_millis(1))])
            .await;
        assert_eq!(
            store.get_many(std::slice::from_ref(&short)).await,
            vec![Slot::Hit(b"x".to_vec())]
        );
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(
            store.get_many(&[short]).await,
            vec![Slot::Absent],
            "EX must expire the key"
        );
    }
}
