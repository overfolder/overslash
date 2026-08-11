//! Layered call timeouts (D56), end-to-end through the gateway.
//!
//! The resolver's cascade and clamp arithmetic is unit-tested in
//! `services::call_timeout`; this file covers what only a live request can
//! show: that the resolved number actually reaches the transport, that the
//! 504 carries the provenance a caller needs, that an audit row survives the
//! failure, and — most importantly — that the streaming path does *not*
//! inherit the buffered path's total deadline.

use crate::common;

use serde_json::{Value, json};

/// Boot an API whose deployment defaults are small enough to hit in a test,
/// plus the combined fake as the upstream.
///
/// `default_ms` / `max_ms` stand in for `CALL_TIMEOUT_MS` /
/// `CALL_TIMEOUT_MAX_MS`.
async fn boot(
    pool: sqlx::PgPool,
    default_ms: u64,
    max_ms: u64,
) -> (String, String, uuid::Uuid, std::net::SocketAddr) {
    common::allow_loopback_ssrf();
    let (addr, client) = common::start_api_with(pool, |cfg| {
        cfg.call_timeout_ms = default_ms;
        cfg.call_timeout_max_ms = max_ms;
    })
    .await;
    let base = format!("http://{addr}");
    let mock = common::start_mock().await;
    let (org_id, _ident, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    (base, admin_key, org_id, mock)
}

/// A Mode-A raw HTTP call. The admin identity is a *user*, which Layer 2
/// gates by group only — so these calls execute straight through rather than
/// filing an approval, which is what lets the tests observe the transport.
async fn call_slow(
    base: &str,
    key: &str,
    mock: std::net::SocketAddr,
    sleep_ms: u64,
    timeout_ms: Option<u64>,
) -> reqwest::Response {
    let mut body = json!({
        "service": "http",
        "method": "GET",
        "url": format!("http://{mock}/slow?ms={sleep_ms}"),
    });
    if let Some(t) = timeout_ms {
        body["timeout_ms"] = json!(t);
    }
    reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn patch_org_timeouts(base: &str, key: &str, org_id: uuid::Uuid, patch: Value) -> Value {
    let resp = reqwest::Client::new()
        .patch(format!("{base}/v1/orgs/{org_id}/execution-settings"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&patch)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert!(status.is_success(), "patch failed {status}: {body}");
    body
}

// ── the deployment default actually bounds a call ───────────────────

#[tokio::test]
async fn an_upstream_slower_than_the_default_times_out_with_provenance() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, mock) = boot(pool, 300, 110_000).await;

    let resp = call_slow(&base, &key, mock, 3_000, None).await;
    assert_eq!(resp.status(), 504, "expected a gateway timeout");

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "upstream_timeout");
    assert_eq!(body["timeout_ms"], 300);
    // Nothing in the template or the org said anything, so the deployment
    // default is what bit — and the body must say so, or the caller has no
    // idea which knob to reach for.
    assert_eq!(body["timeout_source"], "global_default");
    assert_eq!(body["max_timeout_ms"], 110_000);
}

#[tokio::test]
async fn a_call_inside_the_default_still_succeeds() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, mock) = boot(pool, 5_000, 110_000).await;

    let resp = call_slow(&base, &key, mock, 50, None).await;
    assert_eq!(resp.status(), 200, "a fast call must not be affected");
}

// ── the per-call rung ───────────────────────────────────────────────

#[tokio::test]
async fn a_per_call_timeout_raises_the_budget_above_the_default() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, mock) = boot(pool, 300, 110_000).await;

    // Same upstream latency that times out on the default above.
    let resp = call_slow(&base, &key, mock, 1_000, Some(20_000)).await;
    assert_eq!(
        resp.status(),
        200,
        "per-call timeout should have covered it"
    );
}

#[tokio::test]
async fn a_per_call_timeout_above_the_maximum_is_refused_not_clamped() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, mock) = boot(pool, 30_000, 50_000).await;

    let resp = call_slow(&base, &key, mock, 10, Some(90_000)).await;
    // A caller who asked explicitly gets told no, rather than silently
    // running at a budget they did not choose.
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    let msg = body["error"].as_str().unwrap_or_default().to_string()
        + body["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("50000"),
        "the 400 must name the ceiling, got: {body}"
    );
}

#[tokio::test]
async fn a_zero_per_call_timeout_is_refused() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, mock) = boot(pool, 30_000, 110_000).await;

    let resp = call_slow(&base, &key, mock, 10, Some(0)).await;
    assert_eq!(resp.status(), 400);
}

// ── the org rungs ───────────────────────────────────────────────────

#[tokio::test]
async fn the_org_default_raises_the_budget_with_no_per_call_value() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, org, mock) = boot(pool, 300, 110_000).await;

    patch_org_timeouts(&base, &key, org, json!({"call_timeout_ms": 20_000})).await;

    let resp = call_slow(&base, &key, mock, 1_000, None).await;
    assert_eq!(resp.status(), 200, "org default should have covered it");
}

#[tokio::test]
async fn the_org_maximum_binds_a_per_call_request() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, org, mock) = boot(pool, 30_000, 110_000).await;

    patch_org_timeouts(&base, &key, org, json!({"max_call_timeout_ms": 40_000})).await;

    let resp = call_slow(&base, &key, mock, 10, Some(90_000)).await;
    assert_eq!(resp.status(), 400, "org max is tighter than the global max");
    let body: Value = resp.json().await.unwrap();
    let msg = format!("{body}");
    assert!(msg.contains("40000"), "must name the org ceiling: {body}");
}

#[tokio::test]
async fn clearing_an_org_timeout_returns_it_to_the_deployment_default() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, org, _mock) = boot(pool, 30_000, 110_000).await;

    let set = patch_org_timeouts(&base, &key, org, json!({"call_timeout_ms": 20_000})).await;
    assert_eq!(set["call_timeout_ms"], 20_000);

    // An explicit null is the only way back off an org override — absent
    // would mean "leave it alone".
    let cleared = patch_org_timeouts(&base, &key, org, json!({"call_timeout_ms": null})).await;
    assert!(
        cleared["call_timeout_ms"].is_null(),
        "explicit null must clear: {cleared}"
    );
}

#[tokio::test]
async fn a_partial_patch_leaves_the_other_execution_settings_alone() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, org, _mock) = boot(pool, 30_000, 110_000).await;

    patch_org_timeouts(
        &base,
        &key,
        org,
        json!({"default_deferred_execution": true}),
    )
    .await;
    let after = patch_org_timeouts(&base, &key, org, json!({"call_timeout_ms": 20_000})).await;

    // The flag was not in the second patch, so it must survive it.
    assert_eq!(after["default_deferred_execution"], true);
    assert_eq!(after["call_timeout_ms"], 20_000);
}

#[tokio::test]
async fn a_default_above_the_maximum_is_rejected() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, org, _mock) = boot(pool, 30_000, 110_000).await;

    patch_org_timeouts(&base, &key, org, json!({"max_call_timeout_ms": 20_000})).await;

    let resp = reqwest::Client::new()
        .patch(format!("{base}/v1/orgs/{org}/execution-settings"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({"call_timeout_ms": 90_000}))
        .send()
        .await
        .unwrap();
    // Checked against the resulting row, not just the patch body — the
    // maximum was set by an earlier request.
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn an_out_of_range_timeout_is_rejected_before_the_db_constraint() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, org, _mock) = boot(pool, 30_000, 110_000).await;

    for bad in [1u64, 9_000_000] {
        let resp = reqwest::Client::new()
            .patch(format!("{base}/v1/orgs/{org}/execution-settings"))
            .header("Authorization", format!("Bearer {key}"))
            .json(&json!({ "call_timeout_ms": bad }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "{bad} should be out of range");
    }
}

// ── streaming: the trap this feature exists to avoid ────────────────

#[tokio::test]
async fn a_stream_that_is_slow_to_start_times_out_before_anything_is_sent() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, mock) = boot(pool, 400, 110_000).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock}/slow-stream?headers_ms=3000&chunks=2"),
            "prefer_stream": true,
        }))
        .send()
        .await
        .unwrap();

    // Time-to-first-byte exceeded the budget. Nothing had been written to the
    // client yet, so this is still a clean, typed 504 rather than a truncated
    // 200.
    assert_eq!(resp.status(), 504);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "upstream_timeout");
}

/// The regression test for the whole streaming design.
///
/// `RequestBuilder::timeout` in reqwest is a *total* deadline covering the
/// response body, so the obvious implementation would kill this transfer at
/// 400ms — mid-body, after the audit row already recorded a 200 and after the
/// response headers were flushed. The client would silently receive a short
/// body. The resolved timeout must bound only time-to-first-byte.
#[tokio::test]
async fn a_live_stream_outlives_the_resolved_timeout() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, mock) = boot(pool, 400, 110_000).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "service": "http",
            "method": "GET",
            // Headers arrive promptly, then 6 chunks 200ms apart — a total of
            // ~1.2s, well past the 400ms budget, but never idle for long.
            "url": format!("http://{mock}/slow-stream?headers_ms=10&chunks=6&gap_ms=200"),
            "prefer_stream": true,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "a live transfer must not be cut");
    let bytes = resp.bytes().await.unwrap();
    assert_eq!(
        bytes.len(),
        5 * 6,
        "every chunk must arrive, not a truncated prefix"
    );
}

// ── the audit trail survives a timeout ──────────────────────────────

#[tokio::test]
async fn a_timed_out_call_still_writes_an_audit_row() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, mock) = boot(pool, 300, 110_000).await;

    let resp = call_slow(&base, &key, mock, 3_000, None).await;
    assert_eq!(resp.status(), 504);

    // The audit write is fire-and-forget, so give it a moment to land.
    let mut detail = Value::Null;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        // `GET /v1/audit` returns a bare array.
        let entries: Vec<Value> = reqwest::Client::new()
            .get(format!("{base}/v1/audit?limit=20"))
            .header("Authorization", format!("Bearer {key}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if let Some(row) = entries
            .iter()
            .find(|e| e["detail"]["error"]["kind"] == "timeout")
        {
            detail = row["detail"].clone();
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    assert!(
        !detail.is_null(),
        "a timed-out call must leave an audit trail, not vanish"
    );
    assert_eq!(detail["error"]["timeout_ms"], 300);
}
