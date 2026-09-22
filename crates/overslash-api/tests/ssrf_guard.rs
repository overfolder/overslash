//! The SSRF guard, end-to-end on the two paths that carry a caller-supplied
//! URL all the way to a socket: Mode A raw HTTP (`POST /v1/actions/call`) and
//! webhook delivery.
//!
//! # Why these tests can run at all
//!
//! The whole suite runs with `OVERSLASH_SSRF_ALLOW_PRIVATE=1`, because Mode A
//! and Mode C fakes are bound to 127.0.0.1. That hatch opens **loopback and
//! nothing else** (see `services::ssrf_guard::default_policy`), which is what
//! makes this file possible: the fakes stay reachable while the link-local,
//! RFC1918 and CGNAT addresses an attacker actually wants stay refused. If the
//! hatch is ever widened back to "block nothing", every test here goes green
//! for the wrong reason — the positive controls are what would still catch it.

use crate::common;

use axum::response::{IntoResponse, Redirect};
use serde_json::{Value, json};

/// The AWS/GCP/Azure instance-metadata address — the canonical SSRF target,
/// and the one CASA 5.1.5 is written about.
const METADATA: &str = "http://169.254.169.254/latest/meta-data/";

async fn boot(pool: sqlx::PgPool) -> (String, String, uuid::Uuid, std::net::SocketAddr) {
    common::allow_loopback_ssrf();
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let mock = common::start_mock().await;
    let (org_id, _ident, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    (base, admin_key, org_id, mock)
}

/// A Mode A raw-HTTP call. The admin identity is a *user*, which Layer 2 gates
/// by group only, so these execute straight through instead of filing an
/// approval — which is exactly what puts the transport under test.
async fn raw_http(base: &str, key: &str, url: &str) -> reqwest::Response {
    raw_http_body(
        base,
        key,
        json!({ "service": "http", "method": "GET", "url": url }),
    )
    .await
}

async fn raw_http_body(base: &str, key: &str, body: Value) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .unwrap()
}

// ── Mode A: the addresses that must never be dialed ─────────────────

#[tokio::test]
async fn mode_a_refuses_the_cloud_metadata_endpoint() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    let resp = raw_http(&base, &key, METADATA).await;
    assert_eq!(
        resp.status(),
        400,
        "the metadata endpoint must be refused, not proxied"
    );
    let body: Value = resp.json().await.unwrap();
    let msg = body.to_string();
    assert!(
        msg.contains("169.254.169.254") && msg.contains("refusing to connect"),
        "expected an SSRF refusal, got {msg}"
    );
    // The point of the finding: the response must not be the metadata body.
    assert!(!msg.contains("ami-id"), "leaked an upstream body: {msg}");
}

#[tokio::test]
async fn mode_a_refuses_private_and_cgnat_addresses() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    for url in [
        "http://10.0.0.1/admin",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        // Carrier-grade NAT — the range a cloud load balancer's internal
        // plane lives on.
        "http://100.64.0.1/",
        // IPv6 unique-local and the v4-mapped spelling of RFC1918.
        "http://[fd00::1]/",
        "http://[::ffff:10.0.0.1]/",
    ] {
        let resp = raw_http(&base, &key, url).await;
        assert_eq!(resp.status(), 400, "{url} should have been refused");
    }
}

#[tokio::test]
async fn mode_a_refuses_a_non_http_scheme() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    let resp = raw_http(&base, &key, "file:///etc/passwd").await;
    assert_eq!(resp.status(), 400);
}

/// The streamed fork has its own transport call. It must refuse the same
/// addresses — a guard that only covers the buffered path is not a guard.
#[tokio::test]
async fn mode_a_refuses_the_metadata_endpoint_when_streaming() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    let resp = raw_http_body(
        &base,
        &key,
        json!({
            "service": "http",
            "method": "GET",
            "url": METADATA,
            "prefer_stream": true,
        }),
    )
    .await;
    assert_eq!(resp.status(), 400, "the streamed fork must refuse too");
}

// ── Mode A: the positive controls ───────────────────────────────────

/// Without this the file could pass with the transport simply broken.
#[tokio::test]
async fn mode_a_still_reaches_a_loopback_fake() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, mock) = boot(pool).await;

    let resp = raw_http(&base, &key, &format!("http://{mock}/echo?ok=1")).await;
    assert_eq!(resp.status(), 200, "the loopback hatch must still work");
}

/// A redirect is the other half of the finding: a host allowlist checked at
/// the URL layer is defeated by a cooperative server answering 302. The
/// pinned client disables redirects, so the 3xx comes back to the caller as
/// the upstream's own answer and the `Location` is never followed.
#[tokio::test]
async fn mode_a_does_not_follow_a_redirect_to_the_metadata_endpoint() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    // A loopback server whose only job is to point somewhere it must not be
    // followed to.
    let app = axum::Router::new().route(
        "/bounce",
        axum::routing::get(|| async { Redirect::temporary(METADATA).into_response() }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirector = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let resp = raw_http(&base, &key, &format!("http://{redirector}/bounce")).await;
    assert_eq!(resp.status(), 200, "the call itself succeeds");

    let body: Value = resp.json().await.unwrap();
    let status = body["result"]["status_code"]
        .as_u64()
        .unwrap_or_else(|| panic!("no upstream status in {body}"));
    assert_eq!(
        status, 307,
        "the redirect must be handed back, not followed: {body}"
    );
    assert!(
        !body.to_string().contains("ami-id"),
        "followed the redirect: {body}"
    );
}

// ── Webhook delivery ────────────────────────────────────────────────

async fn create_subscription(base: &str, key: &str, url: &str, event: &str) -> uuid::Uuid {
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/webhooks"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({ "url": url, "events": [event] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "webhook creation failed");
    let body: Value = resp.json().await.unwrap();
    body["id"].as_str().unwrap().parse().unwrap()
}

/// `(status_code, response_body)` of the single delivery recorded for a
/// subscription.
async fn only_delivery(pool: &sqlx::PgPool, sub: uuid::Uuid) -> (Option<i32>, Option<String>) {
    let rows = sqlx::query!(
        "SELECT status_code, response_body FROM webhook_deliveries WHERE subscription_id = $1",
        sub
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1, "expected exactly one delivery attempt");
    (rows[0].status_code, rows[0].response_body.clone())
}

/// The registrant-supplied URL is the SSRF vector, and the delivery row
/// records the response *body* — so an unguarded dispatcher is a read oracle,
/// not just a blind request.
#[tokio::test]
async fn webhook_delivery_refuses_a_link_local_endpoint() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, org_id, _mock) = boot(pool.clone()).await;

    let sub = create_subscription(&base, &key, METADATA, "ssrf.probe").await;

    overslash_api::services::webhook_dispatcher::dispatch(
        &pool,
        org_id,
        "ssrf.probe",
        json!({ "probe": true }),
    )
    .await;

    let (status, body) = only_delivery(&pool, sub).await;
    assert_eq!(status, None, "nothing answered, so there is no status");
    let body = body.unwrap_or_default();
    assert!(
        body.contains("refusing to connect") && body.contains("169.254.169.254"),
        "expected the guard's refusal on the delivery row, got {body:?}"
    );
}

#[tokio::test]
async fn webhook_delivery_still_reaches_a_loopback_endpoint() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, org_id, mock) = boot(pool.clone()).await;

    let sub = create_subscription(
        &base,
        &key,
        &format!("http://{mock}/webhooks/receive"),
        "ssrf.probe",
    )
    .await;

    overslash_api::services::webhook_dispatcher::dispatch(
        &pool,
        org_id,
        "ssrf.probe",
        json!({ "probe": true }),
    )
    .await;

    let (status, _body) = only_delivery(&pool, sub).await;
    assert_eq!(
        status,
        Some(200),
        "the loopback endpoint must still deliver"
    );
}
