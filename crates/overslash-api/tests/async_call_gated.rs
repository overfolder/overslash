//! Gated async: a call that hit the permission chain, was approved, and runs on
//! the worker instead of on the connection that approved it (D66).
//!
//! The shape under test is the seam between two subsystems that used to be
//! unaware of each other — `approvals.execution_mode` decides which trigger runs
//! (`claim` vs `enqueue`), and the worker owes the approval the same tail the
//! inline replay owes it.
//!
//! Run with `--test-threads=4` (or similar) — see CLAUDE.md.

#![allow(clippy::disallowed_methods)]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use axum::{Json, Router, routing::get};
use reqwest::Client;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use uuid::Uuid;

use overslash_db::scopes::SystemScope;

use crate::common;

// ── Harness ─────────────────────────────────────────────────────────────

/// A mock that counts every hit. "The upstream was not dialled" is the central
/// assertion of this file — an enqueue that quietly ran the call inline would
/// otherwise pass every status check.
async fn start_counting_mock() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    common::allow_loopback_ssrf();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let app = Router::new()
        .route(
            "/echo",
            get(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"ok": true}))
                }
            }),
        )
        // Long enough for a cancel to land mid-flight. The worker drops the
        // future rather than waiting this out, which is the whole point.
        .route(
            "/slow",
            get(|| async {
                tokio::time::sleep(Duration::from_secs(30)).await;
                Json(json!({"ok": true}))
            }),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, hits)
}

struct Fixture {
    base: String,
    client: Client,
    agent_key: String,
    admin_key: String,
    agent_id: Uuid,
    org_id: Uuid,
    mock: std::net::SocketAddr,
    hits: Arc<AtomicUsize>,
    pool: sqlx::PgPool,
}

/// Boot an API with the worker flag on, plus an agent with no permission rules
/// and a secret to inject — which is what makes the call gate.
async fn setup(pool: sqlx::PgPool) -> Fixture {
    setup_with(pool, |cfg| cfg.async_execution.enabled = true).await
}

async fn setup_with<F>(pool: sqlx::PgPool, customize: F) -> Fixture
where
    F: FnOnce(&mut overslash_api::config::Config),
{
    let (mock, hits) = start_counting_mock().await;
    let (addr, client) = common::start_api_with(pool.clone(), customize).await;
    let base = format!("http://{addr}");
    let (org_id, agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    client
        .put(format!("{base}/v1/secrets/tk"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"value": "v"}))
        .send()
        .await
        .unwrap();

    Fixture {
        base,
        client,
        agent_key,
        admin_key,
        agent_id,
        org_id,
        mock,
        hits,
        pool,
    }
}

impl Fixture {
    /// Make a call that trips the permission chain. `execution` is passed
    /// through verbatim so the sync control uses the identical shape.
    async fn gated_call(&self, extra: Value) -> (u16, Value) {
        let mut body = json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{}/echo", self.mock),
            "secrets": [{"name": "tk", "inject_as": "header", "header_name": "X-Auth"}],
        });
        let obj = body.as_object_mut().unwrap();
        for (k, v) in extra.as_object().unwrap() {
            obj.insert(k.clone(), v.clone());
        }
        let resp = self
            .client
            .post(format!("{}/v1/actions/call", self.base))
            .header(
                common::auth(&self.agent_key).0,
                common::auth(&self.agent_key).1,
            )
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    /// File a gated async approval and return its id.
    async fn pending_async_approval(&self) -> String {
        let (status, body) = self.gated_call(json!({"execution": "async"})).await;
        assert_eq!(status, 202, "expected pending_approval, got {body}");
        assert_eq!(
            body["status"], "pending_approval",
            "the gate fires above the async fork, so async never changes this \
             envelope: {body}"
        );
        body["approval_id"].as_str().unwrap().to_string()
    }

    async fn resolve(&self, approval_id: &str, resolution: &str) {
        let resp = self
            .client
            .post(format!("{}/v1/approvals/{approval_id}/resolve", self.base))
            .header(
                common::auth(&self.admin_key).0,
                common::auth(&self.admin_key).1,
            )
            .json(&json!({"resolution": resolution}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "resolve failed");
    }

    async fn call_approval(&self, approval_id: &str) -> (u16, Value) {
        let resp = self
            .client
            .post(format!("{}/v1/approvals/{approval_id}/call", self.base))
            .header(
                common::auth(&self.agent_key).0,
                common::auth(&self.agent_key).1,
            )
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn set_auto_call(&self, enabled: bool) {
        self.client
            .patch(format!(
                "{}/v1/identities/{}/auto-call-on-approve",
                self.base, self.agent_id
            ))
            .header(
                common::auth(&self.admin_key).0,
                common::auth(&self.admin_key).1,
            )
            .json(&json!({"enabled": enabled}))
            .send()
            .await
            .unwrap();
    }

    async fn execution_mode(&self, approval_id: &str) -> String {
        let id: Uuid = approval_id.parse().unwrap();
        sqlx::query_scalar!("SELECT execution_mode FROM approvals WHERE id = $1", id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    /// The execution row's id and whether it carries a stored payload — i.e.
    /// whether it belongs to the worker.
    async fn execution_row(&self, approval_id: &str) -> (Uuid, String, bool) {
        let id: Uuid = approval_id.parse().unwrap();
        let row = sqlx::query!(
            "SELECT id, status, (request IS NOT NULL) AS \"queued!\"
               FROM executions WHERE approval_id = $1",
            id
        )
        .fetch_one(&self.pool)
        .await
        .unwrap();
        (row.id, row.status, row.queued)
    }

    /// Wait for the enqueue to land — auto-call runs in a spawned task.
    async fn await_queued(&self, approval_id: &str) -> Uuid {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let (id, _status, queued) = self.execution_row(approval_id).await;
            if queued {
                return id;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "execution was never queued for the worker"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Claim the row the way the loop would, then run it to a terminal state.
    async fn run_worker(&self, execution_id: Uuid) {
        let system = SystemScope::new_internal(self.pool.clone());
        let claims = system
            .claim_async_executions(overslash_api::services::async_executor::worker_id(), 60, 10)
            .await
            .unwrap();
        let claim = claims
            .into_iter()
            .find(|c| c.id == execution_id)
            .expect("the queued row must be claimable");
        let state = common::make_app_state(self.pool.clone()).await;
        let (_tx, rx) = tokio::sync::watch::channel(false);
        overslash_api::services::async_executor::job::execute(
            state,
            self.pool.clone(),
            claim,
            rx,
            overslash_api::services::async_executor::job::JobMode::Queued,
        )
        .await
        .unwrap();
    }

    async fn audit_count(&self, action: &str) -> i64 {
        sqlx::query_scalar!(
            "SELECT count(*) AS \"n!\" FROM audit_log WHERE org_id = $1 AND action = $2",
            self.org_id,
            action,
        )
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    /// Events are emitted fire-and-forget, so poll rather than sample once.
    async fn await_events(&self, event_type: &str, want: usize) -> Vec<Value> {
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            let rows = sqlx::query_scalar!(
                "SELECT payload FROM events WHERE org_id = $1 AND type = $2 ORDER BY id",
                self.org_id,
                event_type,
            )
            .fetch_all(&self.pool)
            .await
            .unwrap();
            if rows.len() >= want || std::time::Instant::now() >= deadline {
                return rows;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

// ── The stamp ───────────────────────────────────────────────────────────

/// The gate fires above the async fork, so the caller gets the ordinary
/// `pending_approval` envelope — and the only record that they asked for async
/// is the column stamped on the approval.
#[tokio::test]
async fn a_gated_async_call_files_an_approval_stamped_async() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let approval_id = fx.pending_async_approval().await;

    assert_eq!(fx.execution_mode(&approval_id).await, "async");
    assert_eq!(fx.hits.load(Ordering::SeqCst), 0, "nothing was dialled yet");
}

/// The control. Without it the test above passes on a column default.
#[tokio::test]
async fn a_gated_sync_call_stamps_sync() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let (status, body) = fx.gated_call(json!({})).await;
    assert_eq!(status, 202, "{body}");
    let approval_id = body["approval_id"].as_str().unwrap();

    assert_eq!(fx.execution_mode(approval_id).await, "sync");
}

/// The stamp records intent, but the deployment decides. A gated async call on
/// a deployment with no worker must be refused *before* an approval is filed —
/// otherwise a human approves something nothing will ever drain.
#[tokio::test]
async fn async_disabled_refuses_a_gated_async_call_up_front() {
    let pool = common::test_pool().await;
    let fx = setup_with(pool, |cfg| cfg.async_execution.enabled = false).await;

    let (status, body) = fx.gated_call(json!({"execution": "async"})).await;
    assert_eq!(status, 400, "{body}");

    let approvals: i64 = sqlx::query_scalar!(
        "SELECT count(*) AS \"n!\" FROM approvals WHERE org_id = $1",
        fx.org_id
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(approvals, 0, "a refused call must not file an approval");
}

/// The point of the whole feature: an async call may ask for a budget the
/// synchronous ceiling refuses, and the gated path inherits that because the
/// timeout resolves above the gate.
#[tokio::test]
async fn a_gated_async_call_may_exceed_the_sync_ceiling() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let (status, body) = fx
        .gated_call(json!({"execution": "async", "timeout_ms": 300_000}))
        .await;
    assert_eq!(
        status, 202,
        "300s is above the 110s sync ceiling but under the async one: {body}"
    );
    let approval_id: Uuid = body["approval_id"].as_str().unwrap().parse().unwrap();

    let stored: Option<i64> = sqlx::query_scalar!(
        "SELECT (replay_payload->>'timeout_ms')::bigint FROM approvals WHERE id = $1",
        approval_id
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(
        stored,
        Some(300_000),
        "the replay must reproduce the budget the caller asked for"
    );

    // And the same request without async is still refused by the sync ceiling.
    let (sync_status, _) = fx.gated_call(json!({"timeout_ms": 300_000})).await;
    assert_eq!(sync_status, 400);
}

// ── The trigger ─────────────────────────────────────────────────────────

/// Triggering an approved async call queues it and answers 202. The upstream is
/// untouched: the response the caller gets back is a receipt, not a result.
#[tokio::test]
async fn approving_then_calling_queues_and_returns_202() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let approval_id = fx.pending_async_approval().await;
    fx.resolve(&approval_id, "allow").await;

    let (status, body) = fx.call_approval(&approval_id).await;
    assert_eq!(
        status, 202,
        "a queued replay is accepted, not completed: {body}"
    );
    assert_eq!(body["execution_mode"], "async");
    assert_eq!(body["execution"]["status"], "pending");
    assert_eq!(
        body["execution"]["queued"], true,
        "`queued` is what tells a client 'waiting on a worker', not 'waiting on you'"
    );
    assert!(body["poll_after_ms"].as_u64().unwrap() > 0);

    let (exec_id, status, queued) = fx.execution_row(&approval_id).await;
    assert_eq!(status, "pending");
    assert!(queued, "the row must carry the stored payload");
    assert_eq!(
        body["execution"]["id"].as_str().unwrap(),
        exec_id.to_string()
    );
    assert_eq!(fx.hits.load(Ordering::SeqCst), 0, "nothing was dialled");
}

/// The load-bearing exclusion. The enqueue leaves the row `pending` — exactly
/// what the synchronous claim accepts — so without `request IS NULL` on the
/// claim a manual `/call` would dial inline while a worker dialled the same row.
#[tokio::test]
async fn a_manual_call_cannot_claim_a_queued_row() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let approval_id = fx.pending_async_approval().await;
    fx.resolve(&approval_id, "allow").await;
    let (first, _) = fx.call_approval(&approval_id).await;
    assert_eq!(first, 202);

    let (second, body) = fx.call_approval(&approval_id).await;
    assert_eq!(second, 409, "a queued row is a conflict, not a second dial");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("queued"),
        "the conflict must name the recovery path: {body}"
    );

    let (exec_id, status, queued) = fx.execution_row(&approval_id).await;
    assert_eq!(status, "pending", "the row is still the worker's");
    assert!(queued);
    assert_eq!(fx.hits.load(Ordering::SeqCst), 0);

    // And the exclusion is in the predicate, not in the handler that happened to
    // probe first: the synchronous claim itself must refuse a queued row. It is
    // reachable with the async branch skipped — a deployment that turned the
    // worker off between the enqueue and the trigger — and every other guard
    // above it is advisory by comparison.
    let scope = SystemScope::new_internal(fx.pool.clone()).scope_for_org(fx.org_id);
    let claimed = scope
        .claim_execution(approval_id.parse().unwrap(), "agent")
        .await
        .unwrap();
    assert!(
        claimed.is_none(),
        "the synchronous claim must never take a row that belongs to the worker"
    );
    assert_eq!(
        fx.execution_row(&approval_id).await,
        (exec_id, "pending".to_string(), true),
        "a refused claim must leave the row untouched"
    );
}

/// `auto_call_on_approve` still means "fire on approve" — it just enqueues
/// instead of dialling.
#[tokio::test]
async fn auto_call_on_approve_enqueues_instead_of_dialling_inline() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;
    fx.set_auto_call(true).await;

    let approval_id = fx.pending_async_approval().await;
    fx.resolve(&approval_id, "allow").await;

    let exec_id = fx.await_queued(&approval_id).await;
    assert_eq!(
        fx.hits.load(Ordering::SeqCst),
        0,
        "auto-call must not have dialled the upstream on the resolve path"
    );

    fx.run_worker(exec_id).await;
    assert_eq!(fx.hits.load(Ordering::SeqCst), 1);
    let (_id, status, _queued) = fx.execution_row(&approval_id).await;
    assert_eq!(status, "executed");
}

/// A pre-`replay_payload` approval has nothing to hand the worker, so the
/// trigger falls back to the inline replay rather than refusing.
#[tokio::test]
async fn a_legacy_approval_without_a_payload_falls_back_to_the_inline_replay() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let approval_id = fx.pending_async_approval().await;
    fx.resolve(&approval_id, "allow").await;

    // Strip the payload the way a pre-feature row would have been stored.
    let id: Uuid = approval_id.parse().unwrap();
    sqlx::query!(
        "UPDATE approvals SET replay_payload = NULL WHERE id = $1",
        id
    )
    .execute(&fx.pool)
    .await
    .unwrap();

    let (status, body) = fx.call_approval(&approval_id).await;
    assert_eq!(
        status, 200,
        "the inline replay answers with the result: {body}"
    );
    assert_eq!(body["execution"]["status"], "executed");
    assert_eq!(fx.hits.load(Ordering::SeqCst), 1);
}

// ── The worker ──────────────────────────────────────────────────────────

/// The worker owes the approval everything the inline replay owes it — and owes
/// it exactly once. The counts matter more than the existence: a tail that was
/// copied rather than moved passes an existence check.
#[tokio::test]
async fn the_worker_runs_a_queued_approval_and_writes_the_full_tail() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let approval_id = fx.pending_async_approval().await;
    fx.resolve(&approval_id, "allow").await;
    let (status, _) = fx.call_approval(&approval_id).await;
    assert_eq!(status, 202);
    let (exec_id, _, _) = fx.execution_row(&approval_id).await;

    fx.run_worker(exec_id).await;

    let (_id, status, _queued) = fx.execution_row(&approval_id).await;
    assert_eq!(status, "executed");
    assert_eq!(fx.hits.load(Ordering::SeqCst), 1, "dialled exactly once");

    assert_eq!(fx.audit_count("approval.executed").await, 1);
    assert_eq!(fx.audit_count("approval.execution_failed").await, 0);

    // The `action.executed` row must be traceable back to the approval that
    // authorised it, exactly as the inline replay's is.
    let stamped: i64 = sqlx::query_scalar!(
        "SELECT count(*) AS \"n!\" FROM audit_log
          WHERE org_id = $1 AND action = 'action.executed'
            AND detail->>'replayed_from_approval' = $2",
        fx.org_id,
        approval_id,
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(stamped, 1, "the audit trail must name the approval");

    let approval_events = fx.await_events("approval.executed", 1).await;
    assert_eq!(approval_events.len(), 1);
    assert_eq!(approval_events[0]["approval_id"], json!(approval_id));
    let execution_events = fx.await_events("execution.completed", 1).await;
    assert_eq!(execution_events.len(), 1);
    assert_eq!(execution_events[0]["origin"], "approval");
}

/// "Allow & Remember" is part of the tail, so it has to happen on the worker
/// too — otherwise approving-with-remember silently stops writing rules the
/// moment a call is async.
#[tokio::test]
async fn allow_and_remember_writes_its_rule_from_the_worker() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let approval_id = fx.pending_async_approval().await;
    fx.resolve(&approval_id, "allow_remember").await;
    let (status, _) = fx.call_approval(&approval_id).await;
    assert_eq!(status, 202);
    let (exec_id, _, _) = fx.execution_row(&approval_id).await;

    let before: i64 = sqlx::query_scalar!(
        "SELECT count(*) AS \"n!\" FROM permission_rules WHERE org_id = $1",
        fx.org_id
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(
        before, 0,
        "the rule must be written by the replay, not earlier"
    );

    fx.run_worker(exec_id).await;

    let after: i64 = sqlx::query_scalar!(
        "SELECT count(*) AS \"n!\" FROM permission_rules WHERE org_id = $1 AND effect = 'allow'",
        fx.org_id
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert!(
        after > 0,
        "a successful async replay must commit its remembered rule"
    );
}

// ── Cancellation ────────────────────────────────────────────────────────

/// A queued row has not been claimed, so cancelling it is immediate — and the
/// worker must never be able to pick it up afterwards.
#[tokio::test]
async fn cancelling_a_queued_row_is_immediate() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let approval_id = fx.pending_async_approval().await;
    fx.resolve(&approval_id, "allow").await;
    let (status, _) = fx.call_approval(&approval_id).await;
    assert_eq!(status, 202);

    let resp = fx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/cancel", fx.base))
        .header(common::auth(&fx.agent_key).0, common::auth(&fx.agent_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let (_id, status, _queued) = fx.execution_row(&approval_id).await;
    assert_eq!(status, "cancelled");

    let claims = SystemScope::new_internal(fx.pool.clone())
        .claim_async_executions("late-worker", 60, 10)
        .await
        .unwrap();
    assert!(
        claims.is_empty(),
        "a cancelled row must be invisible to the claim"
    );
}

/// Once a worker owns the row, cancelling can only *ask* it to stop. The row
/// stays `executing` and the worker emits the terminal event when it observes
/// the flag — announcing `cancelled` here would show a cancelled row that keeps
/// running.
#[tokio::test]
async fn cancelling_a_running_row_is_cooperative() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let approval_id = fx.pending_async_approval().await;
    fx.resolve(&approval_id, "allow").await;
    let (status, _) = fx.call_approval(&approval_id).await;
    assert_eq!(status, 202);
    let (exec_id, _, _) = fx.execution_row(&approval_id).await;

    // Claim it the way a worker would, but never run it.
    let system = SystemScope::new_internal(fx.pool.clone());
    let claims = system
        .claim_async_executions("busy-worker", 60, 10)
        .await
        .unwrap();
    assert!(claims.iter().any(|c| c.id == exec_id));

    let resp = fx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/cancel", fx.base))
        .header(common::auth(&fx.agent_key).0, common::auth(&fx.agent_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "the button must keep working while a background job runs"
    );

    let row = sqlx::query!(
        "SELECT status, cancel_requested FROM executions WHERE id = $1",
        exec_id
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(row.status, "executing", "the worker still owns the row");
    assert!(row.cancel_requested);

    // The heartbeat is the cancel poll: the worker learns about it there.
    assert_eq!(
        system
            .heartbeat_async_execution(exec_id, "busy-worker", 60)
            .await
            .unwrap(),
        Some(true)
    );

    let announced = fx.await_events("approval.execution_cancelled", 1).await;
    assert!(
        announced.is_empty(),
        "the terminal event belongs to the worker, once it actually stops"
    );
}

/// The cooperative cancel still owes the approvals topic a terminal event — it
/// is just the worker's to emit, once it has actually stopped.
///
/// `POST /v1/approvals/{id}/cancel` deliberately stays silent on that branch, so
/// without this the signal SPEC promises subscribers would simply vanish for
/// every queued replay. Asserting the request-time silence alone would have
/// passed on exactly that bug.
#[tokio::test]
async fn a_worker_announces_the_cancellation_it_observes() {
    let pool = common::test_pool().await;
    let fx = setup(pool).await;

    let (status, body) = fx
        .gated_call(json!({
            "execution": "async",
            "url": format!("http://{}/slow", fx.mock),
        }))
        .await;
    assert_eq!(status, 202, "{body}");
    let approval_id = body["approval_id"].as_str().unwrap().to_string();
    fx.resolve(&approval_id, "allow").await;
    let (called, _) = fx.call_approval(&approval_id).await;
    assert_eq!(called, 202);
    let (exec_id, _, _) = fx.execution_row(&approval_id).await;

    // Run the job for real, with a lease short enough that its heartbeat — the
    // cancel poll — fires inside the test's patience.
    let system = SystemScope::new_internal(fx.pool.clone());
    let claim = system
        .claim_async_executions(overslash_api::services::async_executor::worker_id(), 60, 10)
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.id == exec_id)
        .expect("queued row must be claimable");
    let mut state = common::make_app_state(fx.pool.clone()).await;
    state.config.async_execution.lease_ttl_secs = 3;
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let job = tokio::spawn(overslash_api::services::async_executor::job::execute(
        state,
        fx.pool.clone(),
        claim,
        rx,
        overslash_api::services::async_executor::job::JobMode::Queued,
    ));

    let resp = fx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/cancel", fx.base))
        .header(common::auth(&fx.agent_key).0, common::auth(&fx.agent_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    job.await.unwrap().unwrap();

    let (_id, status, _queued) = fx.execution_row(&approval_id).await;
    assert_eq!(
        status, "cancelled",
        "the worker must finalize what it stopped"
    );

    let announced = fx.await_events("approval.execution_cancelled", 1).await;
    assert_eq!(
        announced.len(),
        1,
        "exactly one approval-topic cancellation, emitted by the worker"
    );
    assert_eq!(announced[0]["approval_id"], json!(approval_id));
    assert_eq!(fx.await_events("execution.cancelled", 1).await.len(), 1);
}
