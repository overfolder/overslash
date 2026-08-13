//! `execution: "hybrid"` on `POST /v1/actions/call` — both response shapes, and
//! the row that exists under either of them.
//!
//! The central claim under test is that a hybrid call is *async that the
//! connection waits on*, not sync that gets promoted: the row is durable and
//! already claimed before the upstream answers, so which envelope the caller
//! receives changes only who reports the result.
//!
//! Run with `--test-threads=4` (or similar) — see CLAUDE.md.

#![allow(clippy::disallowed_methods)]

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

/// Boot an API with async execution on and a handoff short enough to be worth
/// racing against, plus a bootstrapped org/agent.
async fn setup(pool: sqlx::PgPool, handoff_ms: u64) -> (String, Client, String, String, Uuid) {
    common::allow_loopback_ssrf();
    let (addr, client) = common::start_api_with(pool, move |cfg| {
        cfg.async_execution.enabled = true;
        cfg.async_execution.hybrid_handoff_ms = handoff_ms;
        cfg.async_execution.hybrid_handoff_max_ms = 30_000;
    })
    .await;
    let base = format!("http://{addr}");
    let (org_id, _ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    common::grant_service_to_everyone(&base, &client, &admin_key, "http").await;
    (base, client, agent_key, admin_key, org_id)
}

async fn call(base: &str, client: &Client, key: &str, body: Value) -> (u16, Value) {
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(key).0, common::auth(key).1)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let json: Value = resp.json().await.unwrap_or(Value::Null);
    (status, json)
}

async fn get_execution(base: &str, client: &Client, key: &str, id: &str) -> (u16, Value) {
    let resp = client
        .get(format!("{base}/v1/executions/{id}"))
        .header(common::auth(key).0, common::auth(key).1)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

fn hybrid_call(url: &str) -> Value {
    json!({ "service": "http", "method": "GET", "url": url, "execution": "hybrid" })
}

/// Beat the handoff and the envelope is the ordinary `called` one — same shape
/// a synchronous call produces, so a fast hybrid call is indistinguishable from
/// the mode it replaces.
#[tokio::test]
async fn a_fast_hybrid_call_answers_inline_and_leaves_a_terminal_row() {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    let (base, client, key, _admin, _org) = setup(pool.clone(), 30_000).await;

    let (status, body) = call(
        &base,
        &client,
        &key,
        hybrid_call(&format!("http://{mock}/slow?ms=0")),
    )
    .await;

    assert_eq!(status, 200, "fast hybrid call should answer inline: {body}");
    assert_eq!(body["status"], "called");
    let exec_id = body["execution_id"]
        .as_str()
        .expect("a hybrid 200 carries the row it ran on");

    // The correlation handle points at a row that is already terminal — it is
    // not an invitation to poll.
    let (status, detail) = get_execution(&base, &client, &key, exec_id).await;
    assert_eq!(status, 200);
    assert_eq!(detail["status"], "executed", "{detail}");
    assert_eq!(detail["origin"], "hybrid", "{detail}");
}

/// Miss the handoff and the caller gets the same `accepted` envelope
/// `execution: "async"` produces, and polls the same row.
#[tokio::test]
async fn a_slow_hybrid_call_hands_off_and_completes_on_the_row() {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    let (base, client, key, _admin, _org) = setup(pool.clone(), 300).await;

    let (status, body) = call(
        &base,
        &client,
        &key,
        hybrid_call(&format!("http://{mock}/slow?ms=2500")),
    )
    .await;

    assert_eq!(status, 202, "slow hybrid call should hand off: {body}");
    assert_eq!(body["status"], "accepted", "{body}");
    let exec_id = body["execution_id"].as_str().unwrap().to_string();
    assert!(body["execution_url"].as_str().unwrap().contains(&exec_id));
    assert!(body["timeout_ms"].as_u64().unwrap() > 0);
    assert!(body["poll_after_ms"].as_u64().unwrap() > 0);

    // The job kept running on the task that started it. Poll to terminal.
    let mut detail = Value::Null;
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let (_, d) = get_execution(&base, &client, &key, &exec_id).await;
        if d["status"] == "executed" || d["status"] == "failed" {
            detail = d;
            break;
        }
    }
    assert_eq!(detail["status"], "executed", "{detail}");
    assert_eq!(detail["origin"], "hybrid", "{detail}");
    assert!(
        detail["result"].to_string().contains("slept_ms"),
        "the handed-off row carries the upstream body: {detail}"
    );
}

/// The design claim, asserted where it actually lives: the row exists, is
/// `executing`, and is owned by this process *while the upstream is still
/// hanging*. Nothing else pins durability-from-t=0.
#[tokio::test]
async fn the_row_is_durable_and_claimed_before_the_upstream_answers() {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    let (base, client, key, _admin, org_id) = setup(pool.clone(), 200).await;

    let (status, body) = call(
        &base,
        &client,
        &key,
        hybrid_call(&format!("http://{mock}/slow?ms=3000")),
    )
    .await;
    assert_eq!(status, 202, "{body}");
    let exec_id: Uuid = body["execution_id"].as_str().unwrap().parse().unwrap();

    let row = sqlx::query!(
        "SELECT status, worker_id, lease_expires_at, triggered_by, attempts,
                (request IS NOT NULL) AS \"has_request!\"
           FROM executions WHERE id = $1 AND org_id = $2",
        exec_id,
        org_id
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(row.status, "executing", "still running, not queued");
    assert_eq!(row.triggered_by.as_deref(), Some("hybrid"));
    assert!(row.worker_id.is_some(), "inserted already claimed");
    assert!(row.lease_expires_at.is_some(), "claimed rows carry a lease");
    assert!(row.has_request, "the payload is stored, as async stores it");
    assert_eq!(row.attempts, 0);
}

/// A live hybrid row must be invisible to the claim loop. If a worker could
/// take it, the upstream would be sent the same request twice — and an action
/// call has no idempotency key.
#[tokio::test]
async fn a_worker_cannot_claim_a_live_hybrid_row() {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    let (base, client, key, _admin, _org) = setup(pool.clone(), 200).await;

    let (status, _) = call(
        &base,
        &client,
        &key,
        hybrid_call(&format!("http://{mock}/slow?ms=3000")),
    )
    .await;
    assert_eq!(status, 202);

    let system = overslash_db::scopes::SystemScope::new_internal(pool.clone());
    let claimed = system
        .claim_async_executions("some-other-replica", 60, 10)
        .await
        .unwrap();
    assert!(
        claimed.is_empty(),
        "a hybrid row is never `pending`, so no worker may take it: {claimed:?}"
    );
}

/// `handoff_after_ms` is refused, not clamped, whenever the caller named a
/// number that cannot mean what they asked for.
#[tokio::test]
async fn handoff_after_ms_is_validated_against_the_caller_not_clamped() {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    let (base, client, key, _admin, _org) = setup(pool, 5_000).await;
    let url = format!("http://{mock}/slow?ms=0");

    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "above the deployment maximum",
            json!({"service":"http","method":"GET","url":url,"execution":"hybrid","handoff_after_ms":45_000}),
            "exceeds the maximum",
        ),
        (
            "not less than the call's own budget",
            json!({"service":"http","method":"GET","url":url,"execution":"hybrid","handoff_after_ms":9_000,"timeout_ms":9_000}),
            "not less than",
        ),
        (
            "named without the mode it belongs to",
            json!({"service":"http","method":"GET","url":url,"execution":"async","handoff_after_ms":1_000}),
            "only valid with",
        ),
    ];

    for (name, body, needle) in cases {
        let (status, resp) = call(&base, &client, &key, body).await;
        assert_eq!(status, 400, "{name} should be refused, got {resp}");
        assert!(
            resp.to_string().contains(needle),
            "{name} should explain why; got {resp}"
        );
    }
}

/// Hybrid inherits async's refusal set verbatim. It shares one code path with
/// async in `flags`, and this is what keeps that true.
#[tokio::test]
async fn hybrid_inherits_the_deferred_refusals() {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    let (base, client, key, _admin, _org) = setup(pool, 5_000).await;
    let url = format!("http://{mock}/slow?ms=0");

    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "prefer_stream",
            json!({"service":"http","method":"GET","url":url,"execution":"hybrid","prefer_stream":true}),
            "no response to stream onto",
        ),
        (
            "deliver:url",
            json!({"service":"http","method":"GET","url":url,"execution":"hybrid","deliver":"url"}),
            "before the call runs",
        ),
        (
            "return_url",
            json!({"service":"http","method":"GET","url":url,"execution":"hybrid","return_url":"https://example.com/back"}),
            "no caller waiting",
        ),
    ];

    for (name, body, needle) in cases {
        let (status, resp) = call(&base, &client, &key, body).await;
        assert_eq!(status, 400, "{name} should be refused, got {resp}");
        assert!(
            resp.to_string().contains(needle),
            "{name} should explain why; got {resp}"
        );
        assert!(
            resp.to_string().contains("hybrid"),
            "the message should name the mode the caller asked for; got {resp}"
        );
    }
}

/// With the flag off the mode is refused outright rather than quietly running
/// synchronously — a caller that asked for hybrid and got a 504 at the sync
/// ceiling would have no way to tell what happened.
#[tokio::test]
async fn hybrid_is_refused_when_the_deployment_flag_is_off() {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    common::allow_loopback_ssrf();
    let (addr, client) = common::start_api_with(pool, |cfg| {
        cfg.async_execution.enabled = false;
    })
    .await;
    let base = format!("http://{addr}");
    let (_org, _ident, key, admin) = common::bootstrap_org_identity(&base, &client).await;
    common::grant_service_to_everyone(&base, &client, &admin, "http").await;

    let (status, body) = call(
        &base,
        &client,
        &key,
        hybrid_call(&format!("http://{mock}/slow?ms=0")),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.to_string().contains("not enabled"), "{body}");
    assert!(body.to_string().contains("hybrid"), "{body}");
}

/// `origin` separates hybrid from `async_call`, and the list filter accepts the
/// value the detail endpoint emits. A server that reports a value its own
/// filter rejects is the same bug wearing a different hat.
#[tokio::test]
async fn origin_reports_hybrid_and_the_list_filter_accepts_it() {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    let (base, client, key, _admin, _org) = setup(pool, 30_000).await;

    let (status, body) = call(
        &base,
        &client,
        &key,
        hybrid_call(&format!("http://{mock}/slow?ms=0")),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let exec_id = body["execution_id"].as_str().unwrap().to_string();

    let listed = |origin: &'static str| {
        let (base, client, key) = (base.clone(), client.clone(), key.clone());
        async move {
            let resp = client
                .get(format!("{base}/v1/executions?origin={origin}"))
                .header(common::auth(&key).0, common::auth(&key).1)
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status().as_u16(), 200, "origin={origin} must be valid");
            resp.json::<Value>().await.unwrap()
        }
    };

    let hybrid_rows = listed("hybrid").await;
    assert!(
        hybrid_rows.to_string().contains(&exec_id),
        "?origin=hybrid should return it: {hybrid_rows}"
    );

    let async_rows = listed("async_call").await;
    assert!(
        !async_rows.to_string().contains(&exec_id),
        "?origin=async_call must not: {async_rows}"
    );
}
