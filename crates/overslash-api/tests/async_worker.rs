//! Worker-level semantics for async executions, driven directly.
//!
//! These call the repo/scope functions rather than waiting on the 2s loop —
//! the established pattern for the maintenance sweeps (insert, backdate with
//! raw SQL, invoke the function, assert). It keeps the tests deterministic and
//! fast, and it means a failure points at the claim/lease logic rather than at
//! scheduling.

use sqlx::PgPool;
use uuid::Uuid;

use overslash_db::repos::execution::{AsyncExecutionInput, AsyncOutcome};
use overslash_db::scopes::SystemScope;

use crate::common;

/// Insert an org + identity and return `(org_id, identity_id)`.
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

/// Queue an async execution and return its id.
async fn queue_async(pool: &PgPool, org_id: Uuid, identity_id: Uuid) -> Uuid {
    let scope = SystemScope::new_internal(pool.clone()).scope_for_org(org_id);
    let payload = serde_json::json!({
        "action": { "method": "GET", "url": "http://127.0.0.1:1/never", "headers": {} },
        "prefer_stream": false
    });
    let row = scope
        .create_async_execution(AsyncExecutionInput {
            org_id,
            identity_id,
            request: &payload,
            service_key: None,
            service_instance_id: None,
            tags: &[],
            render_verbose: None,
            template_key: Some("test"),
            description: Some("test async call"),
            client_ip: None,
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::minutes(15),
        })
        .await
        .expect("queue async execution");
    row.id
}

async fn status_of(pool: &PgPool, id: Uuid) -> String {
    sqlx::query_scalar!("SELECT status FROM executions WHERE id = $1", id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn attempts_of(pool: &PgPool, id: Uuid) -> i32 {
    sqlx::query_scalar!("SELECT attempts FROM executions WHERE id = $1", id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Two workers racing the same queue must never both get the same row. This is
/// the property `FOR UPDATE SKIP LOCKED` exists for, and the one that would
/// silently produce duplicate upstream calls if it regressed.
#[tokio::test]
async fn concurrent_claims_are_disjoint() {
    let pool = common::test_pool().await;
    let (org_id, identity_id) = seed_identity(&pool).await;
    let system = SystemScope::new_internal(pool.clone());

    let mut queued = Vec::new();
    for _ in 0..6 {
        queued.push(queue_async(&pool, org_id, identity_id).await);
    }

    let (a, b) = tokio::join!(
        system.claim_async_executions("worker-a", 60, 6),
        system.claim_async_executions("worker-b", 60, 6),
    );
    let a: Vec<Uuid> = a.unwrap().into_iter().map(|c| c.id).collect();
    let b: Vec<Uuid> = b.unwrap().into_iter().map(|c| c.id).collect();

    for id in &a {
        assert!(!b.contains(id), "row {id} was claimed by both workers");
    }
    let mut all: Vec<Uuid> = a.iter().chain(b.iter()).copied().collect();
    all.sort();
    all.dedup();
    assert_eq!(all.len(), a.len() + b.len(), "claims overlapped");
    for id in queued {
        assert!(all.contains(&id), "row {id} was never claimed");
    }
}

/// A dead worker's row comes back, exactly once, and then gives up.
///
/// Also pins that `attempts` is charged by the *reclaim*, not by the claim —
/// which is what makes a clean hand-back at shutdown free.
#[tokio::test]
async fn expired_lease_requeues_then_exhausts() {
    let pool = common::test_pool().await;
    let (org_id, identity_id) = seed_identity(&pool).await;
    let system = SystemScope::new_internal(pool.clone());

    let id = queue_async(&pool, org_id, identity_id).await;
    let claimed = system
        .claim_async_executions("dead-worker", 60, 10)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(
        attempts_of(&pool, id).await,
        0,
        "claiming must not charge an attempt"
    );

    // The worker died: age the lease out.
    sqlx::query!(
        "UPDATE executions SET lease_expires_at = now() - interval '1 second' WHERE id = $1",
        id,
    )
    .execute(&pool)
    .await
    .unwrap();

    // max_attempts = 2 so the first expiry requeues rather than failing.
    let requeued = system.requeue_expired_async_leases(2, 900).await.unwrap();
    assert_eq!(requeued, 1);
    assert_eq!(status_of(&pool, id).await, "pending");
    assert_eq!(attempts_of(&pool, id).await, 1);

    // Second time around it has no attempts left.
    system
        .claim_async_executions("dead-worker-2", 60, 10)
        .await
        .unwrap();
    sqlx::query!(
        "UPDATE executions SET lease_expires_at = now() - interval '1 second' WHERE id = $1",
        id,
    )
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        system.requeue_expired_async_leases(2, 900).await.unwrap(),
        0
    );
    assert_eq!(system.fail_exhausted_async_executions(2).await.unwrap(), 1);
    assert_eq!(status_of(&pool, id).await, "failed");
}

/// A row claimed near its queue deadline must not be requeued already-expired.
///
/// Without the `GREATEST(expires_at, …)` in the requeue, this row would come
/// back `pending` with a past `expires_at` and be swept to `expired` before any
/// worker could take it — a retry silently lost.
#[tokio::test]
async fn requeue_extends_the_queue_deadline() {
    let pool = common::test_pool().await;
    let (org_id, identity_id) = seed_identity(&pool).await;
    let system = SystemScope::new_internal(pool.clone());

    let id = queue_async(&pool, org_id, identity_id).await;
    system.claim_async_executions("w", 60, 10).await.unwrap();
    sqlx::query!(
        "UPDATE executions
            SET lease_expires_at = now() - interval '1 second',
                expires_at = now() - interval '1 second'
          WHERE id = $1",
        id,
    )
    .execute(&pool)
    .await
    .unwrap();

    assert_eq!(
        system.requeue_expired_async_leases(5, 900).await.unwrap(),
        1
    );
    assert_eq!(status_of(&pool, id).await, "pending");

    // The pending-expiry sweep must not now kill it.
    assert_eq!(system.expire_stale_executions().await.unwrap(), 0);
    assert_eq!(status_of(&pool, id).await, "pending");
}

/// Releasing at shutdown returns the row without charging an attempt — the
/// whole reason `attempts` counts lost leases rather than claims.
#[tokio::test]
async fn release_does_not_charge_an_attempt() {
    let pool = common::test_pool().await;
    let (org_id, identity_id) = seed_identity(&pool).await;
    let system = SystemScope::new_internal(pool.clone());

    let id = queue_async(&pool, org_id, identity_id).await;
    system.claim_async_executions("w", 60, 10).await.unwrap();
    assert!(system.release_async_execution(id, "w", 900).await.unwrap());

    assert_eq!(status_of(&pool, id).await, "pending");
    assert_eq!(attempts_of(&pool, id).await, 0);
}

/// Finalizing with a stale `worker_id` must not land: another worker may
/// already own the row, and a late result overwriting a fresh attempt is
/// exactly the corruption the lease exists to prevent.
#[tokio::test]
async fn finalize_with_a_lost_lease_is_refused() {
    let pool = common::test_pool().await;
    let (org_id, identity_id) = seed_identity(&pool).await;
    let system = SystemScope::new_internal(pool.clone());

    let id = queue_async(&pool, org_id, identity_id).await;
    system
        .claim_async_executions("real-owner", 60, 10)
        .await
        .unwrap();

    let result = serde_json::json!({"status_code": 200});
    let out = system
        .finalize_async_execution(org_id, id, "impostor", AsyncOutcome::Executed(&result))
        .await
        .unwrap();
    assert!(out.is_none(), "a stale worker must not be able to finalize");
    assert_eq!(status_of(&pool, id).await, "executing");
}

/// Cancel is immediate before start and cooperative after it.
#[tokio::test]
async fn cancel_is_immediate_before_start_and_cooperative_after() {
    let pool = common::test_pool().await;
    let (org_id, identity_id) = seed_identity(&pool).await;
    let system = SystemScope::new_internal(pool.clone());
    let scope = system.scope_for_org(org_id);

    // Pending: terminal straight away, so no pending row ever carries a live
    // cancel flag into a claim.
    let pending = queue_async(&pool, org_id, identity_id).await;
    let row = scope
        .request_execution_cancel(pending)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "cancelled");

    // Executing: intent recorded, status untouched, heartbeat reports it.
    let running = queue_async(&pool, org_id, identity_id).await;
    system.claim_async_executions("w", 60, 10).await.unwrap();
    let row = scope
        .request_execution_cancel(running)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.status, "executing");
    assert!(row.cancel_requested);

    let stop = system
        .heartbeat_async_execution(running, "w", 60)
        .await
        .unwrap();
    assert_eq!(stop, Some(true), "the heartbeat is the cancel poll");
}

/// The regression that matters most: the async sweeps and the pre-existing
/// orphan reap must never touch each other's rows. An approval-backed
/// execution has `request IS NULL`, so no async sweep may see it — and the
/// orphan reap must still see it.
#[tokio::test]
async fn async_sweeps_never_touch_approval_backed_rows() {
    let pool = common::test_pool().await;
    let (org_id, identity_id) = seed_identity(&pool).await;
    let system = SystemScope::new_internal(pool.clone());

    // An approval-backed execution, stuck `executing` well past any wall.
    let approval_id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO approvals (id, org_id, identity_id, action_summary, permission_keys,
                                status, token, expires_at, current_resolver_identity_id)
         VALUES ($1, $2, $3, 'legacy', '{}', 'allowed', $4, now() + interval '1 hour', $3)",
        approval_id,
        org_id,
        identity_id,
        Uuid::new_v4().to_string(),
    )
    .execute(&pool)
    .await
    .unwrap();

    let exec_id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO executions (id, approval_id, org_id, identity_id, status, started_at,
                                 lease_expires_at, expires_at)
         VALUES ($1, $2, $3, $4, 'executing', now() - interval '1 hour',
                 now() - interval '1 hour', now() + interval '1 hour')",
        exec_id,
        approval_id,
        org_id,
        identity_id,
    )
    .execute(&pool)
    .await
    .unwrap();

    // Every async sweep must ignore it, despite the deliberately expired lease.
    assert_eq!(
        system.requeue_expired_async_leases(5, 900).await.unwrap(),
        0
    );
    assert_eq!(system.fail_exhausted_async_executions(1).await.unwrap(), 0);
    assert_eq!(system.fail_async_executions_over_wall(60).await.unwrap(), 0);
    assert_eq!(status_of(&pool, exec_id).await, "executing");

    // And the claim must never pick it up: it is not a queued async row.
    let claimed = system.claim_async_executions("w", 60, 50).await.unwrap();
    assert!(claimed.iter().all(|c| c.id != exec_id));

    // The pre-existing orphan reap still owns it — semantics unchanged.
    assert_eq!(system.expire_orphaned_executions(60).await.unwrap(), 1);
    assert_eq!(status_of(&pool, exec_id).await, "failed");
}

/// The wall-clock backstop catches a worker that heartbeats forever on an
/// upstream that never answers — the case neither lease sweep can see.
#[tokio::test]
async fn wall_clock_backstop_fails_a_wedged_job() {
    let pool = common::test_pool().await;
    let (org_id, identity_id) = seed_identity(&pool).await;
    let system = SystemScope::new_internal(pool.clone());

    let id = queue_async(&pool, org_id, identity_id).await;
    system.claim_async_executions("w", 3600, 10).await.unwrap();
    // Lease is healthy; only `started_at` is old.
    sqlx::query!(
        "UPDATE executions SET started_at = now() - interval '2 hours' WHERE id = $1",
        id
    )
    .execute(&pool)
    .await
    .unwrap();

    assert_eq!(
        system.requeue_expired_async_leases(5, 900).await.unwrap(),
        0
    );
    assert_eq!(
        system.fail_async_executions_over_wall(3600).await.unwrap(),
        1
    );
    assert_eq!(status_of(&pool, id).await, "failed");
}
