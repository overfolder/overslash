//! The approval-expiry sweep and the events it publishes.
//!
//! Mostly about *reach*: does the event exist on the log, does it carry the
//! right audience, does it land on a live stream, does it reach a webhook. Plus
//! the two properties a cross-org sweep must hold once it returns rows to emit
//! from instead of a count — it stays bounded, and it never crosses a tenant
//! boundary.
//!
//! Approvals are seeded straight through `OrgScope::create_approval` with an
//! `expires_at` already in the past, and the sweep is invoked synchronously.
//! The real loop ticks once a minute, which no test may wait for.

use std::time::Duration;

use reqwest::Client;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use overslash_db::scopes::{OrgScope, SystemScope};

use crate::common;
use crate::common::sse::{Frame, read_stream, start_stream_api as start};

/// Long enough that a sweep's fire-and-forget emit task has landed, short
/// enough that a genuine regression fails the test rather than stalling it.
const EMIT_WAIT: Duration = Duration::from_secs(5);

/// A three-deep chain in one org: user → agent → sub-agent, with the sub-agent
/// as requester and the agent as the resolver holding the decision.
struct Chain {
    org_id: Uuid,
    user_id: Uuid,
    agent_id: Uuid,
    agent_key: String,
    sub_id: Uuid,
    org_key: String,
}

async fn chain(base: &str, client: &Client, pool: &PgPool) -> Chain {
    let (org_id, agent_id, agent_key, org_key) = common::bootstrap_org_identity(base, client).await;
    let sub_id = create_identity(base, client, &org_key, "expiry-sub", "sub_agent", agent_id).await;
    let user_id = common::owner_user_id(pool, org_id).await;
    Chain {
        org_id,
        user_id,
        agent_id,
        agent_key,
        sub_id,
        org_key,
    }
}

async fn create_identity(
    base: &str,
    client: &Client,
    org_key: &str,
    name: &str,
    kind: &str,
    parent_id: Uuid,
) -> Uuid {
    client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&serde_json::json!({ "name": name, "kind": kind, "parent_id": parent_id }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

/// Seed one approval that is already past its deadline.
async fn stale_approval(
    scope: &OrgScope,
    requester: Uuid,
    resolver: Uuid,
    summary: &str,
    tags: &[String],
) -> Uuid {
    seed_approval(scope, requester, resolver, summary, tags, -60).await
}

async fn seed_approval(
    scope: &OrgScope,
    requester: Uuid,
    resolver: Uuid,
    summary: &str,
    tags: &[String],
    expires_in_secs: i64,
) -> Uuid {
    scope
        .create_approval(overslash_db::repos::approval::CreateApproval {
            identity_id: requester,
            current_resolver_identity_id: resolver,
            action_summary: summary,
            action_detail: None,
            disclosed_fields: None,
            replay_payload: None,
            permission_keys: &["http:POST:example.com/x".to_string()],
            token: &format!("tok_{}", Uuid::new_v4()),
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::seconds(expires_in_secs),
            tags,
            execution_mode: "sync",
        })
        .await
        .unwrap()
        .id
}

async fn sweep(pool: &PgPool) -> u64 {
    let system = SystemScope::new_internal(pool.clone());
    overslash_api::services::approval_expiry::process_expiry(&system, &Client::new())
        .await
        .unwrap()
}

/// One row of the durable event log. Emission is fire-and-forget, so every
/// read of it polls.
struct LoggedEvent {
    payload: Value,
    audience: Vec<Uuid>,
}

/// Read the event log once `want` rows have shown up, or once the wait runs out.
///
/// `want` matters: emission is fire-and-forget per org batch, so a helper that
/// returned on the first non-empty read would let a test asserting on three
/// events pass or fail on scheduler timing.
async fn await_events(
    pool: &PgPool,
    org_id: Uuid,
    event_type: &str,
    want: usize,
) -> Vec<LoggedEvent> {
    let deadline = std::time::Instant::now() + EMIT_WAIT;
    loop {
        let rows = sqlx::query!(
            "SELECT payload, audience FROM events
             WHERE org_id = $1 AND type = $2 ORDER BY id",
            org_id,
            event_type,
        )
        .fetch_all(pool)
        .await
        .unwrap();
        if rows.len() >= want || std::time::Instant::now() >= deadline {
            return rows
                .into_iter()
                .map(|r| LoggedEvent {
                    payload: r.payload,
                    audience: r.audience,
                })
                .collect();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Assert nothing was emitted. Spends the whole [`EMIT_WAIT`] on purpose — a
/// negative has to outlast the emit task to mean anything.
async fn assert_no_events(pool: &PgPool, org_id: Uuid, event_type: &str, why: &str) {
    let found = await_events(pool, org_id, event_type, usize::MAX).await;
    assert!(found.is_empty(), "{why}");
}

async fn status_of(scope: &OrgScope, approval_id: Uuid) -> String {
    scope
        .get_approval(approval_id)
        .await
        .unwrap()
        .expect("approval still exists")
        .status
}

// ── The event itself ────────────────────────────────────────────────

#[tokio::test]
async fn expiry_emits_approval_resolved_with_status_expired() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool.clone()).await;
    let c = chain(&base, &client, &pool).await;
    let scope = OrgScope::new(c.org_id, pool.clone());
    let approval_id = stale_approval(&scope, c.sub_id, c.agent_id, "send an email", &[]).await;

    assert_eq!(sweep(&pool).await, 1);
    assert_eq!(status_of(&scope, approval_id).await, "expired");

    let events = await_events(&pool, c.org_id, "approval.resolved", 1).await;
    assert_eq!(events.len(), 1, "exactly one verdict for one approval");
    let p = &events[0].payload;
    assert_eq!(p["approval_id"], approval_id.to_string());
    assert_eq!(p["status"], "expired");
    assert_eq!(p["resolved_by"], "system");
    assert_eq!(p["action_summary"], "send an email");
    // The human resolve path nests an `execution` here. Nothing ran, so there
    // must be nothing for a subscriber to try to replay.
    assert!(p.get("execution").is_none(), "expiry executes nothing");
}

#[tokio::test]
async fn an_expired_approval_reaches_a_live_subscriber() {
    // The whole point of the change: the resolver watching the stream learns
    // the thing it was sitting on ran out of time, without polling.
    let pool = common::test_pool().await;
    let (base, client) = start(pool.clone()).await;
    let c = chain(&base, &client, &pool).await;
    let scope = OrgScope::new(c.org_id, pool.clone());
    let approval_id = stale_approval(&scope, c.sub_id, c.agent_id, "delete a row", &[]).await;

    sweep(&pool).await;

    // Replay from the beginning rather than racing a subscription against the
    // sweep — same delivery predicate, no timing coupling.
    let frames = read_stream(&client, &base, &c.agent_key, "", Some(0)).await;
    let resolved = frames
        .iter()
        .find(|f: &&Frame| f.event.as_deref() == Some("approval.resolved"))
        .expect("the resolver receives approval.resolved");
    let p = resolved.payload();
    assert_eq!(p["approval_id"], approval_id.to_string());
    assert_eq!(p["status"], "expired");
}

#[tokio::test]
async fn expiry_reaches_webhook_subscribers_too() {
    // The sweep is the only path that reaches the webhook dispatcher with a
    // client cloned into a background task rather than one held by a request
    // handler, so "it works on the stream" does not imply this.
    let pool = common::test_pool().await;
    let (base, client) = start(pool.clone()).await;
    let c = chain(&base, &client, &pool).await;

    let resp = client
        .post(format!("{base}/v1/webhooks"))
        .header("Authorization", format!("Bearer {}", c.org_key))
        .json(&serde_json::json!({
            "url": "http://127.0.0.1:9/unused",
            "events": ["approval.resolved"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "webhook subscription should be created");

    let approval_id = stale_approval(
        &OrgScope::new(c.org_id, pool.clone()),
        c.sub_id,
        c.agent_id,
        "webhook me",
        &[],
    )
    .await;
    sweep(&pool).await;

    // The HTTP delivery fails — nothing listens on port 9 — but the row records
    // the payload that was signed and sent, which is what proves the routing.
    let deadline = std::time::Instant::now() + EMIT_WAIT;
    let delivered = loop {
        let row: Option<Value> = sqlx::query_scalar!(
            "SELECT payload FROM webhook_deliveries WHERE event = 'approval.resolved'
             ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        if let Some(payload) = row {
            break payload;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "expiry never reached the webhook dispatcher"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(delivered["approval_id"], approval_id.to_string());
    assert_eq!(delivered["status"], "expired");
}

#[tokio::test]
async fn the_audience_is_the_requester_and_resolver_chains() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool.clone()).await;
    let c = chain(&base, &client, &pool).await;
    // A sibling under the same user: in the org, on neither chain.
    let sibling = create_identity(&base, &client, &c.org_key, "sibling", "agent", c.user_id).await;
    let scope = OrgScope::new(c.org_id, pool.clone());
    stale_approval(&scope, c.sub_id, c.agent_id, "read a doc", &[]).await;

    sweep(&pool).await;

    let events = await_events(&pool, c.org_id, "approval.resolved", 1).await;
    let audience = &events[0].audience;
    for (who, id) in [
        ("requester", c.sub_id),
        ("resolver", c.agent_id),
        ("owner user", c.user_id),
    ] {
        assert!(audience.contains(&id), "{who} should see the expiry");
    }
    assert!(
        !audience.contains(&sibling),
        "a sibling agent is on neither chain and must not see it"
    );
}

// ── Boundedness ─────────────────────────────────────────────────────

#[tokio::test]
async fn the_batch_limit_bounds_one_statement() {
    // The sweep is cross-org and bulk by design, so returning rows must not
    // turn one UPDATE into an unbounded result set. This is the guard, and it
    // is asserted against the statement because the statement is where a plan
    // change could quietly lose it.
    let pool = common::test_pool().await;
    let (base, client) = start(pool.clone()).await;
    let c = chain(&base, &client, &pool).await;
    let scope = OrgScope::new(c.org_id, pool.clone());
    for i in 0..3 {
        stale_approval(&scope, c.sub_id, c.agent_id, &format!("call {i}"), &[]).await;
    }

    let system = SystemScope::new_internal(pool.clone());
    let first = system.expire_stale_approvals(2).await.unwrap();
    assert_eq!(first.len(), 2, "a batch never exceeds its limit");

    let second = system.expire_stale_approvals(2).await.unwrap();
    assert_eq!(second.len(), 1, "the remainder drains on the next pass");

    let third = system.expire_stale_approvals(2).await.unwrap();
    assert!(third.is_empty(), "nothing left to expire");
}

#[tokio::test]
async fn one_tick_drains_several_batches() {
    // The drain loop, at a batch size a test can afford: three approvals at one
    // per batch is three passes inside a single tick, all of them emitted.
    let pool = common::test_pool().await;
    let (base, client) = start(pool.clone()).await;
    let c = chain(&base, &client, &pool).await;
    let scope = OrgScope::new(c.org_id, pool.clone());
    for i in 0..3 {
        stale_approval(&scope, c.sub_id, c.agent_id, &format!("call {i}"), &[]).await;
    }

    let system = SystemScope::new_internal(pool.clone());
    let expired = overslash_api::services::approval_expiry::process_expiry_batched(
        &system,
        &Client::new(),
        1,
    )
    .await
    .unwrap();
    assert_eq!(expired, 3, "one tick drains past the first batch");
    let events = await_events(&pool, c.org_id, "approval.resolved", 3).await;
    assert_eq!(events.len(), 3, "every batch in the tick emitted");
}

#[tokio::test]
async fn a_backlog_past_the_tick_ceiling_is_left_for_the_next_tick() {
    // MAX_BATCHES_PER_TICK is 4, so at one row per batch a fifth stale approval
    // must survive the tick rather than extending it — and must still be
    // waiting, not lost, for the tick after.
    let pool = common::test_pool().await;
    let (base, client) = start(pool.clone()).await;
    let c = chain(&base, &client, &pool).await;
    let scope = OrgScope::new(c.org_id, pool.clone());
    for i in 0..5 {
        stale_approval(&scope, c.sub_id, c.agent_id, &format!("call {i}"), &[]).await;
    }

    let system = SystemScope::new_internal(pool.clone());
    let first = overslash_api::services::approval_expiry::process_expiry_batched(
        &system,
        &Client::new(),
        1,
    )
    .await
    .unwrap();
    assert_eq!(first, 4, "the tick stops at its ceiling");

    let second = overslash_api::services::approval_expiry::process_expiry_batched(
        &system,
        &Client::new(),
        1,
    )
    .await
    .unwrap();
    assert_eq!(second, 1, "the remainder is picked up, not dropped");
}

#[tokio::test]
async fn a_live_approval_survives_the_sweep() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool.clone()).await;
    let c = chain(&base, &client, &pool).await;
    let scope = OrgScope::new(c.org_id, pool.clone());
    let live = seed_approval(&scope, c.sub_id, c.agent_id, "still waiting", &[], 3600).await;

    assert_eq!(sweep(&pool).await, 0);
    assert_eq!(status_of(&scope, live).await, "pending");
    assert_no_events(
        &pool,
        c.org_id,
        "approval.resolved",
        "an approval that has not expired emits nothing",
    )
    .await;
}

#[tokio::test]
async fn a_second_sweep_re_emits_nothing() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool.clone()).await;
    let c = chain(&base, &client, &pool).await;
    let scope = OrgScope::new(c.org_id, pool.clone());
    stale_approval(&scope, c.sub_id, c.agent_id, "once only", &[]).await;

    assert_eq!(sweep(&pool).await, 1);
    assert_eq!(sweep(&pool).await, 0, "the rows are no longer pending");

    // Ask for two so the helper spends its whole window looking for a second
    // one; asking for one would return the moment the first landed and prove
    // nothing about the duplicate this test is here to rule out.
    let events = await_events(&pool, c.org_id, "approval.resolved", 2).await;
    assert_eq!(events.len(), 1, "a subscriber must not see it expire twice");
}

// ── Tenancy ─────────────────────────────────────────────────────────

#[tokio::test]
async fn expiry_never_crosses_tenants() {
    // One sweep, two orgs. Each event is filed against its own org and its
    // audience is drawn only from that org's chains.
    let pool = common::test_pool().await;
    let (base, client) = start(pool.clone()).await;
    let a = chain(&base, &client, &pool).await;
    let b = chain(&base, &client, &pool).await;
    let scope_a = OrgScope::new(a.org_id, pool.clone());
    let scope_b = OrgScope::new(b.org_id, pool.clone());
    stale_approval(&scope_a, a.sub_id, a.agent_id, "org a call", &[]).await;
    stale_approval(&scope_b, b.sub_id, b.agent_id, "org b call", &[]).await;

    assert_eq!(sweep(&pool).await, 2);

    let events_a = await_events(&pool, a.org_id, "approval.resolved", 1).await;
    let events_b = await_events(&pool, b.org_id, "approval.resolved", 1).await;
    assert_eq!(events_a.len(), 1);
    assert_eq!(events_b.len(), 1);
    assert_eq!(events_a[0].payload["action_summary"], "org a call");
    assert_eq!(events_b[0].payload["action_summary"], "org b call");
    for id in [b.sub_id, b.agent_id, b.user_id] {
        assert!(
            !events_a[0].audience.contains(&id),
            "org a's event must not name an org b identity"
        );
    }
}

// ── Audit ───────────────────────────────────────────────────────────

#[tokio::test]
async fn an_audit_row_records_the_expiry() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool.clone()).await;
    let c = chain(&base, &client, &pool).await;
    let scope = OrgScope::new(c.org_id, pool.clone());
    let tags = vec!["service:email".to_string(), "risk:high".to_string()];
    let approval_id = stale_approval(&scope, c.sub_id, c.agent_id, "send an email", &tags).await;

    sweep(&pool).await;

    let row = sqlx::query!(
        "SELECT identity_id, detail, tags FROM audit_log
         WHERE org_id = $1 AND action = 'approval.expired' AND resource_id = $2",
        c.org_id,
        approval_id,
    )
    .fetch_one(&pool)
    .await
    .expect("expiry is recorded in the audit log");

    // Attributed to the subject, not a resolver — there is no resolver to
    // credit, which is the whole reason the approval expired.
    assert_eq!(row.identity_id, Some(c.sub_id));
    let detail = row.detail;
    assert_eq!(detail["resolved_by"], "system");
    assert_eq!(
        detail["current_resolver_identity_id"],
        c.agent_id.to_string()
    );
    // Tag-scoped audit reads must see expiries like any other approval event.
    assert_eq!(row.tags, tags);
}
