//! Background worker for Google Workspace Directory group sync.
//!
//! Every replica runs one loop. Each tick leases due configs out of
//! `org_google_directory_configs` with `FOR UPDATE SKIP LOCKED`, so replicas
//! share the work without two of them sweeping the same org. A config is due
//! when its interval elapsed (`next_sync_at`, 8h by default) or an admin
//! queued a run with "Sync now" (`sync_requested_at`, at most one queued).
//! The sign-in pull does not come through here — it is a spawned per-user
//! task off the login path.

use overslash_db::scopes::SystemScope;
use uuid::Uuid;

use crate::AppState;
use crate::services::directory_sync;

/// How often each replica looks for due work. Also the worst-case latency of
/// "Sync now".
pub const TICK: std::time::Duration = std::time::Duration::from_secs(30);
/// A replica killed mid-sweep holds its row this long before another may
/// take it. Comfortably longer than any sweep this is built for.
pub const LEASE_TTL_SECS: i64 = 15 * 60;
/// Orgs one replica sweeps per tick. Sweeps are sequential, so this bounds a
/// tick's length rather than its concurrency.
const BATCH: i64 = 4;

pub async fn spawn_loop(state: AppState) {
    let worker_id = format!("gdir-{}", Uuid::new_v4());
    loop {
        tokio::time::sleep(TICK).await;
        let start = std::time::Instant::now();
        match run_once(&state, &worker_id).await {
            Ok(n) => {
                overslash_metrics::background::record_tick(
                    "google_directory_sync",
                    if n == 0 { "noop" } else { "ok" },
                    start.elapsed(),
                );
                overslash_metrics::background::set_last_success("google_directory_sync");
            }
            Err(e) => {
                tracing::error!(error = %e, "google directory sync: claim failed");
                overslash_metrics::background::record_tick(
                    "google_directory_sync",
                    "err",
                    start.elapsed(),
                );
            }
        }
    }
}

/// Claim and run one batch of due syncs. Returns how many ran. Exposed so
/// tests drive the worker deterministically instead of sleeping on [`TICK`].
///
/// Only a failure to *claim* is an error: a sweep that fails is recorded on
/// its own row (`last_sync_status = 'error'`) and does not stop the others.
pub async fn run_once(state: &AppState, worker_id: &str) -> Result<usize, sqlx::Error> {
    let system = SystemScope::new_internal(state.db.clone());
    let org_ids = system
        .claim_due_google_directory_syncs(worker_id, LEASE_TTL_SECS, BATCH)
        .await?;
    for &org_id in &org_ids {
        let outcome = directory_sync::sync_google_directory_full(state, org_id).await;
        let (status, error, stats) = match &outcome {
            Ok(stats) => {
                tracing::info!(%org_id, ?stats, "google directory sync");
                ("ok", None, serde_json::to_value(stats).ok())
            }
            Err(e) => {
                tracing::warn!(%org_id, error = %e, "google directory sync failed");
                ("error", Some(e.to_string()), None)
            }
        };
        if let Err(e) = system
            .finish_google_directory_sync(
                org_id,
                worker_id,
                status,
                error.as_deref(),
                stats.as_ref(),
            )
            .await
        {
            // The lease expires on its own; the next claim retries the org.
            tracing::warn!(%org_id, error = %e, "google directory sync: recording outcome failed");
        }
    }
    Ok(org_ids.len())
}
