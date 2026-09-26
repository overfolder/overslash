//! CASA 7.1.1 — webhook traffic is HTTPS-only.
//!
//! Registration refuses `http://` with a 400; the dispatcher refuses to dial
//! one even when a row carries it (written before the check, or around it);
//! and a row the 124 migration disabled stays visible to its owner with the
//! reason, and receives nothing.
//!
//! Plain `http` to loopback is still accepted: the suite allow-lists loopback
//! in `OVERSLASH_SSRF_ALLOWED_CIDRS` (see `tests/ssrf_guard.rs`), which is the
//! one knob that opens it — the webhook fakes elsewhere in the suite rely on it.

use crate::common;

use serde_json::{Value, json};

async fn boot(pool: sqlx::PgPool) -> (String, String, uuid::Uuid, std::net::SocketAddr) {
    common::allow_loopback_ssrf();
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let mock = common::start_mock().await;
    let (org_id, _ident, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    (base, admin_key, org_id, mock)
}

async fn register(base: &str, key: &str, url: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/v1/webhooks"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({ "url": url, "events": ["tls.probe"] }))
        .send()
        .await
        .unwrap()
}

async fn list(base: &str, key: &str) -> Vec<Value> {
    reqwest::Client::new()
        .get(format!("{base}/v1/webhooks"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// A subscription row written straight to the table, the way a pre-7.1.1
/// registration left it — the API no longer lets one be created. Marked
/// verified (as migration 125 grandfathered every existing row), so what is
/// under test is the scheme check, not the ownership handshake.
async fn insert_raw_subscription(
    pool: &sqlx::PgPool,
    org_id: uuid::Uuid,
    url: &str,
    active: bool,
    disabled_reason: Option<&str>,
) -> uuid::Uuid {
    let events = vec!["tls.probe".to_string()];
    sqlx::query_scalar!(
        "INSERT INTO webhook_subscriptions
             (org_id, url, events, secret, active, disabled_reason, verification_status, grandfathered)
         VALUES ($1, $2, $3, 'test-secret', $4, $5, 'verified', true) RETURNING id",
        org_id,
        url,
        &events,
        active,
        disabled_reason,
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn deliveries(pool: &sqlx::PgPool, sub: uuid::Uuid) -> Vec<(Option<i32>, Option<String>)> {
    sqlx::query!(
        "SELECT status_code, response_body FROM webhook_deliveries WHERE subscription_id = $1",
        sub
    )
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .map(|r| (r.status_code, r.response_body))
    .collect()
}

#[tokio::test]
async fn plain_http_is_refused_at_registration() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    for url in [
        "http://hooks.example.com/receive",
        // Allow-listed for dialing in this suite, but not loopback — so still
        // not allowed in the clear.
        "http://10.0.0.5/receive",
        "ftp://hooks.example.com/receive",
        "not a url",
    ] {
        let resp = register(&base, &key, url).await;
        assert_eq!(resp.status(), 400, "{url} should be refused");
        let body: Value = resp.json().await.unwrap();
        let msg = body["error"].as_str().unwrap_or_default();
        assert!(msg.contains("invalid webhook url"), "{url}: {body}");
    }
    let resp = register(&base, &key, "http://hooks.example.com/receive").await;
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("https://"),
        "the refusal should say what to use instead: {body}"
    );
    assert!(list(&base, &key).await.is_empty(), "nothing was stored");
}

#[tokio::test]
async fn https_is_accepted_at_registration() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org, _mock) = boot(pool).await;

    let resp = register(&base, &key, "https://hooks.example.com/receive").await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["url"], "https://hooks.example.com/receive");
    assert_eq!(body["active"], true);
    assert!(body["secret"].as_str().is_some_and(|s| !s.is_empty()));
    // Nothing on the internet answers the ownership challenge for this host.
    assert_eq!(body["verification_status"], "pending_verification");
}

/// The operator escape hatch: loopback is on the SSRF allow-list in this
/// suite, so a local `http` fake registers and is delivered to.
#[tokio::test]
async fn plain_http_to_an_allow_listed_loopback_is_accepted_and_delivered() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, org_id, mock) = boot(pool.clone()).await;

    let resp = register(&base, &key, &format!("http://{mock}/webhooks/receive")).await;
    assert_eq!(resp.status(), 200);
    let sub: uuid::Uuid = resp.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    overslash_api::services::webhook_dispatcher::dispatch(
        &pool,
        org_id,
        "tls.probe",
        json!({ "probe": true }),
    )
    .await;

    let rows = deliveries(&pool, sub).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, Some(200), "loopback delivery failed: {rows:?}");
}

/// Defence in depth: a plaintext row that is still `active` (it predates the
/// registration check and escaped the migration, or was written around the
/// API) gets a failed delivery with the reason — and no request.
#[tokio::test]
async fn dispatcher_refuses_a_plain_http_endpoint() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (_base, _key, org_id, _mock) = boot(pool.clone()).await;

    let sub = insert_raw_subscription(
        &pool,
        org_id,
        "http://hooks.example.com/receive",
        true,
        None,
    )
    .await;

    overslash_api::services::webhook_dispatcher::dispatch(
        &pool,
        org_id,
        "tls.probe",
        json!({ "probe": true }),
    )
    .await;

    let rows = deliveries(&pool, sub).await;
    assert_eq!(rows.len(), 1, "the attempt is recorded");
    let (status, body) = &rows[0];
    assert_eq!(*status, None, "nothing was dialed, so there is no status");
    let body = body.clone().unwrap_or_default();
    assert!(
        body.contains("webhook delivery refused") && body.contains("https://"),
        "expected the TLS refusal on the delivery row, got {body:?}"
    );
}

/// What the 124 migration leaves behind for a pre-existing plaintext
/// subscription: listed, inactive, with a reason the owner can act on — and
/// not dispatched to.
#[tokio::test]
async fn a_disabled_plaintext_subscription_is_listed_with_its_reason_and_skipped() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (base, key, org_id, _mock) = boot(pool.clone()).await;

    let sub = insert_raw_subscription(
        &pool,
        org_id,
        "http://hooks.example.com/receive",
        false,
        Some("needs_https"),
    )
    .await;

    let listed = list(&base, &key).await;
    let row = listed
        .iter()
        .find(|w| w["id"] == sub.to_string())
        .unwrap_or_else(|| panic!("disabled subscription missing from the list: {listed:?}"));
    assert_eq!(row["active"], false);
    assert_eq!(row["disabled_reason"], "needs_https");

    overslash_api::services::webhook_dispatcher::dispatch(
        &pool,
        org_id,
        "tls.probe",
        json!({ "probe": true }),
    )
    .await;
    assert!(
        deliveries(&pool, sub).await.is_empty(),
        "nothing dispatched"
    );
}
