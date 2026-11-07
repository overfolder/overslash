//! Integration tests for `/health`, `/ready` and `/livez`.
//!
//! `/health` and `/ready` return 200 when Postgres answers and 503 `degraded`
//! when it does not; `/health` is what the uptime check and Better Stack probe.
//! Cloud Run's own probes hit `/livez` (`infra/modules/cloud-run/main.tf`),
//! which reads no dependency, so a database outage cannot restart a container.
//!
//! The unreachable-database branch is covered by unit tests in
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
async fn probes_need_no_api_key() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;

    for path in ["health", "ready", "livez"] {
        let res = client
            .get(format!("http://{addr}/{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "/{path} should not require auth");
    }
}

/// The reason `/livez` exists: with Postgres gone, `/health` fails and Cloud
/// Run must still see a live container. A middleware that starts reading the
/// database on this path would fail here, not in the next outage.
#[tokio::test]
async fn livez_stays_up_when_postgres_is_unreachable() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgres://nobody@127.0.0.1:1/nonexistent")
        .expect("lazy pool");
    let (addr, client) = common::start_api(pool).await;

    let res = client
        .get(format!("http://{addr}/livez"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["status"], "alive");

    let res = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 503, "/health must still report the outage");
}
