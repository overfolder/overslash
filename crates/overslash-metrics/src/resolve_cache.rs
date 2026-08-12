//! Display-param resolver cache metrics.
//!
//! A resolver lookup is an authenticated round trip against the provider, made
//! before an approval is minted. The cache exists to stop paying for one on
//! every call, so the thing worth measuring is the hit rate and, when the
//! backend is shared, how long the backend itself takes — a cache that answers
//! slower than the lookup it replaces is worse than none.
//!
//! Every label here is a bounded enum. Neither the org nor the template key
//! appears: templates are org-authored, so their keys are unbounded
//! cardinality.

use std::time::Duration;

use metrics::{counter, histogram};

/// One cache read for one resolver.
///
/// `backend` ∈ {`redis`, `memory`, `disabled`}. `outcome`:
/// - `hit_positive` — a stored resolution was reused; no upstream call.
/// - `hit_negative` — a stored *failure* was reused; the caller falls back to
///   the raw argument without paying the resolver timeout again.
/// - `miss` — nothing stored; the resolver runs.
/// - `unreadable` — an entry *was* stored but could not be decrypted, parsed,
///   or version-matched. Counted apart from `miss` because the two look
///   identical from the hit rate while meaning very different things: a cold
///   key versus a keyring or namespace problem that will never warm up.
/// - `disabled` — caching is off for this resolver (`cache_ttl: 0`) or
///   deployment-wide, so no lookup was attempted.
/// - `error` — the backend failed or timed out. Counted separately from `miss`
///   because the call is identical from the caller's side (both resolve live)
///   but only one of them means the cache is broken.
pub fn record_lookup(backend: &str, outcome: &str) {
    counter!(
        "overslash_resolve_cache_lookups_total",
        "backend" => backend.to_string(),
        "outcome" => outcome.to_string(),
    )
    .increment(1);
}

/// One cache write (or a write that was declined).
///
/// `kind`:
/// - `positive` / `negative` — stored, at the success or failure TTL.
/// - `suppressed` — deliberately not stored: the failure was *ours* (a
///   credential build that failed locally), not an answer from the provider,
///   and caching it would make a transient config error sticky across replicas.
/// - `evicted_for_capacity` — the in-memory backend was at `max_entries` and
///   dropped a sample to make room.
/// - `error` — the write failed. Harmless to the call in flight; it just means
///   the next one misses.
pub fn record_write(backend: &str, kind: &str) {
    counter!(
        "overslash_resolve_cache_writes_total",
        "backend" => backend.to_string(),
        "kind" => kind.to_string(),
    )
    .increment(1);
}

/// How long one backend round trip took. `op` ∈ {`get`, `set`}; `backend` as
/// above. Batched: one
/// observation covers every resolver on the action, which is the unit that
/// matters for the call's latency.
pub fn record_op(backend: &str, op: &str, elapsed: Duration) {
    histogram!(
        "overslash_resolve_cache_op_duration_seconds",
        "backend" => backend.to_string(),
        "op" => op.to_string(),
    )
    .record(elapsed.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_does_not_panic() {
        record_lookup("memory", "hit_positive");
        record_lookup("redis", "error");
        record_write("redis", "negative");
        record_write("memory", "evicted_for_capacity");
        record_op("redis", "get", Duration::from_millis(2));
    }
}
