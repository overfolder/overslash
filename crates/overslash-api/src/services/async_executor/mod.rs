//! The async-execution worker: a claim-and-lease sweeper over queued
//! `executions` rows. See DECISIONS D62 and `docs/design/async-execution.md`.
//!
//! # Why a leased row and not a detached task
//!
//! The instinct for "run this off the request path" is `tokio::spawn`. That is
//! wrong here, and not because of CPU throttling — this service runs with CPU
//! always allocated (the provider only defaults `cpu_idle` to true when the
//! `resources` block is absent, and ours is present). It is wrong because of
//! **scale-in**.
//!
//! Cloud Run's autoscaler is request-driven: a container doing background work
//! with no in-flight requests still reads as idle, and a queued row in Postgres
//! creates no scale-out pressure because Cloud Run cannot see the queue. Every
//! scale-in and every revision rollout sends SIGTERM and then SIGKILL ~10s
//! later. So losing the process mid-job is the **normal** case, not the
//! exceptional one, and the work has to survive it: a durable row under a
//! renewable lease makes a killed job *late* rather than lost.
//!
//! # Coexisting with replicas
//!
//! `max_instances = 3`, so up to three of these loops run at once.
//! `FOR UPDATE SKIP LOCKED` in the claim is the whole answer — no leader
//! election needed. Note this is deliberately *not* the shape of
//! `webhook_dispatcher::spawn_retry_loop`, which has no claim at all and has
//! every replica retrying the same rows; that is the wrong precedent to copy.

pub mod job;

use std::sync::Arc;

use tokio::sync::{Semaphore, watch};

use overslash_db::scopes::SystemScope;
use sqlx::PgPool;

use crate::AppState;

/// How often the worker looks for queued rows.
///
/// Two seconds rather than folding into the 60s maintenance loop: a
/// "non-blocking" call that sits up to a minute before it even starts defeats
/// the point. The cost is one index-only claim against a partial index over a
/// queue measured in tens of rows.
///
/// A follow-up could drop this to zero by having the enqueue `NOTIFY` and the
/// worker wake on it — the `LISTEN` bridge already exists in
/// `services::events::bus` — but the coupling is not worth it for v1.
const TICK: std::time::Duration = std::time::Duration::from_secs(2);

/// How long to wait for in-flight jobs to release their leases at shutdown.
///
/// Bounds the *release*, never the job: an async job may legitimately have
/// minutes left, and waiting for it would guarantee the SIGKILL we are trying
/// to be graceful about. K releases at K <= worker_concurrency is a couple of
/// single-row UPDATEs, so this is generous.
const DRAIN_BUDGET: std::time::Duration = std::time::Duration::from_secs(3);

/// Identifies this process in `executions.worker_id`. Only has to be unique
/// among live replicas, which a per-process UUID trivially is.
/// This process's worker id.
///
/// Public so a test can claim a row as the same worker `job::execute` will
/// later try to release it as — `release_async_execution` matches on it.
pub fn worker_id() -> &'static str {
    static ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ID.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

/// Run the claim loop until shutdown.
///
/// `background_db` is the same pool the maintenance loop uses. It is passed
/// explicitly rather than read off `state` because of a trap: the call
/// pipeline reaches the database through `state.db(ext)`, and a background task
/// has no request `Extensions`. `Extensions::default()` therefore resolves to
/// `state.db` — the *request* pool in production, and the shared bootstrap pool
/// in the test harness, which would silently cross-talk between tests. Handing
/// the worker an `AppState` whose `db` **is** the background pool, with the
/// test resolver cleared, makes `Extensions::default()` correct by
/// construction everywhere.
pub async fn run(state: AppState, background_db: PgPool) {
    run_with_shutdown(state, background_db, crate::services::shutdown::subscribe()).await
}

/// The loop proper, with its shutdown signal injected.
///
/// Separate from [`run`] for the same reason `job::execute` takes one: a test
/// can drive the shutdown path with its own channel instead of tripping a
/// `OnceLock` that every other test in the binary would then observe.
pub async fn run_with_shutdown(
    state: AppState,
    background_db: PgPool,
    mut shutdown: watch::Receiver<bool>,
) {
    let cfg = state.config.async_execution.clone();

    let mut worker_state = state.clone();
    worker_state.db = background_db.clone();
    worker_state.test_resources = None;

    let system = SystemScope::new_internal(background_db.clone());
    let sem = Arc::new(Semaphore::new(cfg.worker_concurrency));

    tracing::info!(
        worker_id = worker_id(),
        concurrency = cfg.worker_concurrency,
        "async execution worker started"
    );

    // `changed()` only fires on a *transition*, and `subscribe()` marks the
    // current value seen — so a signal that arrived before this loop subscribed
    // would never be observed and the worker would keep claiming straight
    // through the shutdown it was supposed to stop for. Same reasoning as the
    // pre-check in `job::execute`; the loop needs it too.
    if *shutdown.borrow_and_update() {
        tracing::info!("async worker started during shutdown; not claiming");
        return;
    }

    loop {
        tokio::select! {
            _ = tokio::time::sleep(TICK) => {}
            _ = shutdown.changed() => break,
        }

        // Never claim more than we can immediately run: a claimed row holds a
        // lease that must be heartbeaten, so claiming 20 and running 2 would
        // mean 18 leases quietly expiring and 18 attempts burned.
        let free = sem.available_permits();
        if free == 0 {
            continue;
        }

        let started = std::time::Instant::now();
        match system
            .claim_async_executions(worker_id(), cfg.lease_ttl_secs as i64, free as i64)
            .await
        {
            Ok(rows) => {
                let outcome = if rows.is_empty() { "noop" } else { "ok" };
                for row in rows {
                    let Ok(permit) = sem.clone().acquire_owned().await else {
                        break; // semaphore closed; only happens at teardown
                    };
                    tokio::spawn(job::run_claim(
                        worker_state.clone(),
                        background_db.clone(),
                        row,
                        permit,
                    ));
                }
                overslash_metrics::background::record_tick(
                    "async_worker",
                    outcome,
                    started.elapsed(),
                );
                overslash_metrics::background::set_last_success("async_worker");
            }
            Err(e) => {
                tracing::error!("async claim failed: {e}");
                overslash_metrics::background::record_tick(
                    "async_worker",
                    "err",
                    started.elapsed(),
                );
            }
        }
    }

    // Stop claiming immediately — that alone is most of the value, since it
    // means nothing new is picked up in the last seconds of this instance's
    // life. Then wait only for in-flight jobs to hand their leases back.
    tracing::info!("async worker draining");
    let all = sem.acquire_many(cfg.worker_concurrency as u32);
    if tokio::time::timeout(DRAIN_BUDGET, all).await.is_err() {
        tracing::warn!("async worker drain timed out; leases will be reclaimed on expiry");
    }
}
