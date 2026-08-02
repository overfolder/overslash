//! Process-local fan-out for the SSE stream.
//!
//! Writers never publish to the bus directly. Every event goes to Postgres,
//! whose `AFTER INSERT` trigger notifies the `overslash_events` channel, and
//! each replica's [`run_pg_listener`] task turns that notification back into a
//! row and publishes it here. Routing everything through the database — even
//! for a subscriber connected to the very replica that produced the event —
//! costs one extra round trip and buys a single delivery path: one ordering,
//! one dedupe rule, and no divergence between the single-replica case we test
//! and the multi-replica case we deploy.
//!
//! The channel is global rather than per-org. Event volume is human-paced
//! (approvals, OAuth connects), and the per-subscriber filter is a handful of
//! comparisons against an `Arc`'d row, so sharding by org would only buy
//! lifecycle bookkeeping — creating channels on demand and reaping empty ones.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use tokio::sync::broadcast;
use uuid::Uuid;

use overslash_db::SystemScope;
use overslash_db::repos::event::EventRow;

use crate::error::AppError;

/// Postgres NOTIFY channel carrying event cursors.
pub const NOTIFY_CHANNEL: &str = "overslash_events";

/// Buffered events per subscriber. A subscriber that falls this far behind is
/// dropped by `tokio::broadcast` with `Lagged`, which the stream handler turns
/// into a clean disconnect — the client then resumes from its cursor and the
/// backlog is served durably from Postgres instead of from memory.
const BROADCAST_CAPACITY: usize = 256;

/// Concurrent streams one identity may hold on a single replica. Four covers
/// a few browser tabs plus an agent; beyond that it is a runaway client.
const MAX_STREAMS_PER_IDENTITY: usize = 4;

/// Concurrent streams one org may hold on a single replica.
const MAX_STREAMS_PER_ORG: usize = 64;

/// How much history the log keeps. Only has to outlive a reconnect (30s), so
/// this is generous purely to leave a forensic trail.
const RETENTION_DAYS: i64 = 7;

/// Rows the listener will replay in one catch-up sweep after reconnecting.
const CATCH_UP_LIMIT: i64 = 500;

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Arc<EventRow>>,
    /// Live stream counts, per replica. Not shared across replicas: a global
    /// cap would need a round trip on every connect to enforce a limit whose
    /// only job is bounding one process's memory.
    per_identity: Arc<DashMap<Uuid, usize>>,
    per_org: Arc<DashMap<Uuid, usize>>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            tx,
            per_identity: Arc::new(DashMap::new()),
            per_org: Arc::new(DashMap::new()),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<EventRow>> {
        self.tx.subscribe()
    }

    /// Publish to every subscriber on this replica. Fails silently when
    /// nobody is listening, which is the common case.
    pub fn publish(&self, event: Arc<EventRow>) {
        let _ = self.tx.send(event);
    }

    /// Reserve a stream slot. The returned permit releases both counters when
    /// dropped, which happens when the stream future is dropped — including
    /// when the client disconnects mid-stream.
    ///
    /// Refusal is a 429 with `Retry-After`: the caller is not malformed, it is
    /// early, and a connection will free up as soon as one of its open streams
    /// hits the 30-second ceiling.
    pub fn try_acquire(&self, org_id: Uuid, identity_id: Uuid) -> Result<ConnPermit, AppError> {
        // Take the org slot first, then the identity slot, so the rollback on
        // the second failure has exactly one counter to undo.
        {
            let mut org_count = self.per_org.entry(org_id).or_insert(0);
            if *org_count >= MAX_STREAMS_PER_ORG {
                return Err(too_many_streams(MAX_STREAMS_PER_ORG));
            }
            *org_count += 1;
        }
        {
            let mut identity_count = self.per_identity.entry(identity_id).or_insert(0);
            if *identity_count >= MAX_STREAMS_PER_IDENTITY {
                drop(identity_count);
                release(&self.per_org, org_id);
                return Err(too_many_streams(MAX_STREAMS_PER_IDENTITY));
            }
            *identity_count += 1;
        }
        Ok(ConnPermit {
            per_identity: self.per_identity.clone(),
            per_org: self.per_org.clone(),
            org_id,
            identity_id,
        })
    }
}

/// A slot will free within one connection lifetime, so point the client at
/// that rather than leaving it to guess.
fn too_many_streams(limit: usize) -> AppError {
    const RETRY_AFTER_SECS: u64 = 5;
    AppError::RateLimited {
        limit: limit as u32,
        reset_at: (time::OffsetDateTime::now_utc().unix_timestamp() as u64)
            .saturating_add(RETRY_AFTER_SECS),
        retry_after: RETRY_AFTER_SECS,
    }
}

/// Decrement a counter, removing the entry at zero so the maps do not grow
/// unboundedly with one entry per identity ever seen.
fn release(map: &DashMap<Uuid, usize>, key: Uuid) {
    if let Some(mut slot) = map.get_mut(&key) {
        *slot = slot.saturating_sub(1);
        if *slot > 0 {
            return;
        }
    } else {
        return;
    }
    // `remove_if` re-checks under the write lock, so a concurrent acquire
    // between the decrement above and here is not lost.
    map.remove_if(&key, |_, count| *count == 0);
}

/// Holds a stream's slot in the per-identity and per-org caps.
pub struct ConnPermit {
    per_identity: Arc<DashMap<Uuid, usize>>,
    per_org: Arc<DashMap<Uuid, usize>>,
    org_id: Uuid,
    identity_id: Uuid,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        release(&self.per_identity, self.identity_id);
        release(&self.per_org, self.org_id);
    }
}

/// Bridge Postgres notifications onto the local bus. Runs forever; reconnects
/// with backoff and replays anything committed while it was disconnected, so a
/// dropped LISTEN connection costs latency rather than events.
pub async fn run_pg_listener(pool: PgPool, bus: EventBus) {
    let system = SystemScope::new_internal(pool.clone());
    let mut high_watermark: i64 = 0;
    let mut backoff = Duration::from_secs(1);

    loop {
        match PgListener::connect_with(&pool).await {
            Ok(mut listener) => {
                if let Err(e) = listener.listen(NOTIFY_CHANNEL).await {
                    tracing::warn!("event listener: LISTEN failed: {e}");
                } else {
                    backoff = Duration::from_secs(1);
                    // Anything committed while we were away never produced a
                    // notification we saw. Replay it before tailing.
                    if high_watermark > 0 {
                        match system
                            .get_events_after(high_watermark, CATCH_UP_LIMIT)
                            .await
                        {
                            Ok(rows) => {
                                for row in rows {
                                    high_watermark = high_watermark.max(row.id);
                                    bus.publish(Arc::new(row));
                                }
                            }
                            Err(e) => tracing::warn!("event listener: catch-up failed: {e}"),
                        }
                    }
                    high_watermark = tail(&mut listener, &system, &bus, high_watermark).await;
                }
            }
            Err(e) => tracing::warn!("event listener: connect failed: {e}"),
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// Consume notifications until the connection breaks. Returns the highest
/// cursor published, so the caller can replay from there after reconnecting.
async fn tail(
    listener: &mut PgListener,
    system: &SystemScope,
    bus: &EventBus,
    mut high_watermark: i64,
) -> i64 {
    loop {
        let notification = match listener.recv().await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("event listener: recv failed: {e}");
                return high_watermark;
            }
        };
        let Ok(cursor) = notification.payload().parse::<i64>() else {
            tracing::warn!(
                "event listener: unparseable payload {:?}",
                notification.payload()
            );
            continue;
        };
        match system.get_event_by_cursor(cursor).await {
            Ok(Some(row)) => {
                high_watermark = high_watermark.max(row.id);
                bus.publish(Arc::new(row));
            }
            // Pruned between notify and fetch. Nothing to deliver.
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("event listener: fetch {cursor} failed: {e}");
                return high_watermark;
            }
        }
    }
}

/// Retention sweep for the event log.
pub async fn run_prune_loop(pool: PgPool) {
    let system = SystemScope::new_internal(pool);
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;

        let start = std::time::Instant::now();
        let cutoff = time::OffsetDateTime::now_utc() - time::Duration::days(RETENTION_DAYS);
        match system.prune_events(cutoff).await {
            Ok(removed) => {
                let status = if removed == 0 { "noop" } else { "ok" };
                overslash_metrics::background::record_tick("events_prune", status, start.elapsed());
                overslash_metrics::background::set_last_success("events_prune");
            }
            Err(e) => {
                tracing::error!("event prune failed: {e}");
                overslash_metrics::background::record_tick("events_prune", "err", start.elapsed());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_cap_rejects_the_extra_stream_and_frees_on_drop() {
        let bus = EventBus::new();
        let org = Uuid::new_v4();
        let identity = Uuid::new_v4();

        let permits: Vec<_> = (0..MAX_STREAMS_PER_IDENTITY)
            .map(|_| bus.try_acquire(org, identity).expect("under cap"))
            .collect();
        assert!(bus.try_acquire(org, identity).is_err());

        drop(permits);
        // Counters must be back to zero, not merely below the cap.
        assert!(bus.per_identity.get(&identity).is_none());
        assert!(bus.per_org.get(&org).is_none());
        bus.try_acquire(org, identity).expect("slot freed");
    }

    #[test]
    fn rejecting_on_the_identity_cap_does_not_leak_an_org_slot() {
        let bus = EventBus::new();
        let org = Uuid::new_v4();
        let identity = Uuid::new_v4();

        let _permits: Vec<_> = (0..MAX_STREAMS_PER_IDENTITY)
            .map(|_| bus.try_acquire(org, identity).expect("under cap"))
            .collect();
        assert!(bus.try_acquire(org, identity).is_err());

        // The failed acquire took an org slot before hitting the identity cap;
        // if it forgot to roll back, the org counter would exceed the number
        // of live streams and eventually wedge the org.
        assert_eq!(
            *bus.per_org.get(&org).expect("org tracked"),
            MAX_STREAMS_PER_IDENTITY
        );
    }
}
