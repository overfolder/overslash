//! The one invariant that makes `execution: "hybrid"` safe: a hybrid row never
//! returns to `pending`.
//!
//! `claim_async_batch` takes `pending AND request IS NOT NULL`. A hybrid row
//! was already dialled from a request path, so any path back to `pending` hands
//! a live upstream request to another replica to send a second time — and an
//! action call carries no idempotency key. Three statements could do it
//! (`requeue_expired_leases`, `fail_exhausted_async`, `release_async`); all
//! three exclude hybrid, and these tests are what keep that true.
//!
//! Run with `--test-threads=4` (or similar) — see CLAUDE.md.

#![allow(clippy::disallowed_methods)]

use crate::common;

use overslash_db::repos::execution::AsyncExecutionInput;
use overslash_db::scopes::SystemScope;
use sqlx::PgPool;
use uuid::Uuid;

async fn seed_identity(pool: &PgPool) -> (Uuid, Uuid) {
    let (org_id, user_id, _key) = common::seed_org_user_key(
        pool,
        common::SeedOptions {
            is_personal: false,
            is_admin: true,
        },
    )
    .await;
    (org_id, user_id)
}

fn payload() -> serde_json::Value {
    serde_json::json!({
        "action": { "method": "GET", "url": "http://127.0.0.1:1/never", "headers": {} },
        "prefer_stream": false
    })
}

fn input<'a>(
    org_id: Uuid,
    identity_id: Uuid,
    request: &'a serde_json::Value,
) -> AsyncExecutionInput<'a> {
    AsyncExecutionInput {
        org_id,
        identity_id,
        request,
        service_key: None,
        service_instance_id: None,
        tags: &[],
        render_verbose: None,
        template_key: Some("test"),
        description: Some("test hybrid call"),
        client_ip: None,
        expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(15),
    }
}

/// Insert a hybrid row already claimed by `worker`, as the fork does.
async fn start_hybrid(pool: &PgPool, org_id: Uuid, identity_id: Uuid, worker: &str) -> Uuid {
    let p = payload();
    SystemScope::new_internal(pool.clone())
        .scope_for_org(org_id)
        .create_hybrid_execution(input(org_id, identity_id, &p), worker, 60)
        .await
        .expect("start hybrid execution")
        .id
}

async fn queue_async(pool: &PgPool, org_id: Uuid, identity_id: Uuid) -> Uuid {
    let p = payload();
    SystemScope::new_internal(pool.clone())
        .scope_for_org(org_id)
        .create_async_execution(input(org_id, identity_id, &p))
        .await
        .expect("queue async execution")
        .id
}

async fn expire_lease(pool: &PgPool, id: Uuid) {
    sqlx::query!(
        "UPDATE executions SET lease_expires_at = now() - interval '5 minutes' WHERE id = $1",
        id
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn row(pool: &PgPool, id: Uuid) -> (String, Option<String>, i32) {
    let r = sqlx::query!(
        "SELECT status, error, attempts FROM executions WHERE id = $1",
        id
    )
    .fetch_one(pool)
    .await
    .unwrap();
    (r.status, r.error, r.attempts)
}

/// Run every lease-reclaim sweep, in the order the maintenance loop runs them.
async fn run_sweeps(pool: &PgPool, max_attempts: i32) {
    let system = SystemScope::new_internal(pool.clone());
    system
        .requeue_expired_async_leases(max_attempts, 900)
        .await
        .unwrap();
    system
        .fail_exhausted_async_executions(max_attempts)
        .await
        .unwrap();
    system.fail_expired_hybrid_leases().await.unwrap();
}

/// The headline. A replica that died mid-call leaves an expired lease; the row
/// is failed with a distinct reason, and no attempt is charged, because there
/// was never an attempt to spend — only a result that will not arrive.
#[tokio::test]
async fn an_expired_hybrid_lease_fails_and_never_requeues() {
    let pool = common::test_pool().await;
    let (org_id, identity_id) = seed_identity(&pool).await;
    let id = start_hybrid(&pool, org_id, identity_id, "dead-replica").await;
    expire_lease(&pool, id).await;

    run_sweeps(&pool, 1).await;

    let (status, error, attempts) = row(&pool, id).await;
    assert_eq!(
        status, "failed",
        "a lost hybrid row must not go back to the queue"
    );
    assert_eq!(error.as_deref(), Some("hybrid_instance_lost"));
    assert_eq!(attempts, 0, "no attempt is charged for a call already sent");
}

/// The case that would pass by arithmetic accident. At `max_attempts = 1` a
/// hybrid row falls into the exhaust arm and is failed either way; raise the
/// knob and, without the `triggered_by` predicate, it lands in the requeue arm
/// and gets dialled again. The invariant must not depend on an operator's
/// configuration.
#[tokio::test]
async fn a_hybrid_row_still_fails_when_max_attempts_is_raised() {
    let pool = common::test_pool().await;
    let (org_id, identity_id) = seed_identity(&pool).await;
    let id = start_hybrid(&pool, org_id, identity_id, "dead-replica").await;
    expire_lease(&pool, id).await;

    run_sweeps(&pool, 3).await;

    let (status, error, attempts) = row(&pool, id).await;
    assert_eq!(
        status, "failed",
        "must not requeue even with attempts to spare"
    );
    assert_eq!(error.as_deref(), Some("hybrid_instance_lost"));
    assert_eq!(attempts, 0);
}

/// After the sweep there is no resurrection path: the row is terminal, so the
/// claim loop cannot pick it up on a later tick.
#[tokio::test]
async fn a_failed_hybrid_row_is_never_claimed_afterwards() {
    let pool = common::test_pool().await;
    let (org_id, identity_id) = seed_identity(&pool).await;
    let id = start_hybrid(&pool, org_id, identity_id, "dead-replica").await;
    expire_lease(&pool, id).await;
    run_sweeps(&pool, 1).await;

    let claimed = SystemScope::new_internal(pool.clone())
        .claim_async_executions("fresh-replica", 60, 10)
        .await
        .unwrap();
    assert!(
        !claimed.iter().any(|c| c.id == id),
        "a failed hybrid row must stay failed"
    );
}

/// Graceful shutdown calls `release_async`, which sets `pending`. For a hybrid
/// row that is the exact re-dial this design forbids, so the statement itself
/// refuses — belt to the job's own branch, because SIGKILL beats a graceful
/// shutdown often enough that the predicate has to be the real defence.
#[tokio::test]
async fn release_cannot_return_a_hybrid_row_to_pending() {
    let pool = common::test_pool().await;
    let (org_id, identity_id) = seed_identity(&pool).await;
    let id = start_hybrid(&pool, org_id, identity_id, "this-replica").await;

    let released = SystemScope::new_internal(pool.clone())
        .release_async_execution(id, "this-replica", 900)
        .await
        .unwrap();

    assert!(!released, "release must refuse a hybrid row");
    let (status, _, _) = row(&pool, id).await;
    assert_eq!(status, "executing", "and must leave it exactly as it was");
}

/// The wall-clock backstop **does** reach a hybrid row, and that is deliberate.
///
/// The two *reclaim* sweeps are guarded because they set `pending`, which
/// `claim_async_batch` takes — that is the re-dial this design forbids. This one
/// sets `failed`, which is terminal and safe, and it is the only thing that can
/// reap a hybrid job that is alive enough to heartbeat but wedged on an upstream
/// (such a job has no expired lease, so `fail_expired_hybrid_leases` cannot see
/// it either). Guarding it too would leave that row `executing` forever.
///
/// It cannot fire early on a healthy call: the sweep runs at
/// `async_wall_clock() + 60` = 965s, while a hybrid job's own timeout fires at
/// `async_wall_clock()` = 905s and its budget is capped at 900s.
#[tokio::test]
async fn the_wall_clock_backstop_still_reaches_a_wedged_hybrid_job() {
    let pool = common::test_pool().await;
    let (org_id, identity_id) = seed_identity(&pool).await;
    let id = start_hybrid(&pool, org_id, identity_id, "wedged-replica").await;

    // Alive: the lease is still valid, so neither lease sweep can see it.
    // Only the wall clock, which keys on `started_at`, can.
    sqlx::query!(
        "UPDATE executions SET started_at = now() - interval '30 minutes' WHERE id = $1",
        id
    )
    .execute(&pool)
    .await
    .unwrap();

    SystemScope::new_internal(pool.clone())
        .fail_expired_hybrid_leases()
        .await
        .unwrap();
    assert_eq!(
        row(&pool, id).await.0,
        "executing",
        "a live lease is invisible to the lease sweep, which is the point"
    );

    SystemScope::new_internal(pool.clone())
        .fail_async_executions_over_wall(965)
        .await
        .unwrap();

    let (status, error, _) = row(&pool, id).await;
    assert_eq!(status, "failed", "the backstop must still reach it");
    assert_eq!(error.as_deref(), Some("async_wall_clock"));
}

/// Three sweep families now share one table. Each pair has to be shown disjoint
/// by predicate, or one family silently starts eating another's rows.
#[tokio::test]
async fn the_hybrid_sweep_and_the_async_sweeps_do_not_overlap() {
    let pool = common::test_pool().await;
    let (org_id, identity_id) = seed_identity(&pool).await;

    // A queued async row that a worker claimed and then lost.
    let async_id = queue_async(&pool, org_id, identity_id).await;
    let claimed = SystemScope::new_internal(pool.clone())
        .claim_async_executions("worker-a", 60, 10)
        .await
        .unwrap();
    assert!(claimed.iter().any(|c| c.id == async_id));
    expire_lease(&pool, async_id).await;

    let hybrid_id = start_hybrid(&pool, org_id, identity_id, "worker-b").await;
    expire_lease(&pool, hybrid_id).await;

    // The hybrid sweep alone must not touch the async row.
    SystemScope::new_internal(pool.clone())
        .fail_expired_hybrid_leases()
        .await
        .unwrap();
    assert_eq!(
        row(&pool, async_id).await.0,
        "executing",
        "the hybrid sweep must leave a queued async row alone"
    );
    assert_eq!(row(&pool, hybrid_id).await.0, "failed");

    // And the async requeue sweep must not have been the one to touch hybrid.
    SystemScope::new_internal(pool.clone())
        .requeue_expired_async_leases(3, 900)
        .await
        .unwrap();
    assert_eq!(
        row(&pool, async_id).await.0,
        "pending",
        "a lost async row is requeued — that is still correct"
    );
    assert_eq!(
        row(&pool, hybrid_id).await.0,
        "failed",
        "and hybrid stays failed"
    );
}
