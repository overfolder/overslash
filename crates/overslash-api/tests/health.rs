//! Integration tests for `/health` and `/ready`.
//!
//! These pin the split that the endpoints exist to encode:
//!
//!   1. `/health` is liveness. It reports database state in the *body* and
//!      always returns 200, because Cloud Run's startup and liveness probes
//!      point at it — a 503 there would recycle containers mid-outage and
//!      block redeploys (see `infra/modules/cloud-run/main.tf`).
//!   2. `/ready` is readiness. It returns 503 when Postgres is unreachable.
//!
//! The unreachable-database branch is covered by a unit test in
//! `src/routes/health.rs`, which can point a lazy pool at a dead port without
//! disturbing the Postgres instance this suite shares across threads.

use crate::common;

use serde_json::Value;

#[tokio::test]
async fn health_reports_db_up() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;

    let res = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();

    // The Better Stack monitor and `scripts/e2e-up.sh` both key off this
    // exact value — it must not drift.
    assert_eq!(body["status"], "ok");
    assert_eq!(body["db"], "up");
    assert!(body["db_latency_ms"].is_number());
    assert!(body.get("db_error").is_none());

    // Build identity, so a monitor or a deploy check can tell which build
    // answered. `version.rs` pins that `GET /v1/version` agrees.
    assert!(body["version"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(body["commit"].as_str().is_some_and(|c| !c.is_empty()));
    assert_eq!(
        body["sql_policy"].as_bool(),
        Some(cfg!(feature = "sql_policy"))
    );
}

#[tokio::test]
async fn ready_reports_db_up() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;

    let res = client
        .get(format!("http://{addr}/ready"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();

    assert_eq!(body["status"], "ready");
    assert_eq!(body["db"], "up");
    assert!(body["db_latency_ms"].is_number());
    assert!(body["version"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(body["commit"].as_str().is_some_and(|c| !c.is_empty()));
    assert_eq!(
        body["sql_policy"].as_bool(),
        Some(cfg!(feature = "sql_policy"))
    );
}

/// `/health` must stay outside the auth gate — probes carry no API key.
#[tokio::test]
async fn health_and_ready_need_no_api_key() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;

    for path in ["health", "ready"] {
        let res = client
            .get(format!("http://{addr}/{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "/{path} should not require auth");
    }
}
