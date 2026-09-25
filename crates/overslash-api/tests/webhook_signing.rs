//! CASA 7.2.3 — outbound webhooks carry a signed timestamp.
//!
//! Every attempt is sent with `X-Overslash-Timestamp` and
//! `X-Overslash-Signature-V1: v1=<hmac("<ts>.<body>")>`, next to the legacy
//! body-only `X-Overslash-Signature: sha256=<hex>` that existing verifiers
//! read. A retry is re-signed with a fresh timestamp.

// Forcing a failed delivery due now is a one-off UPDATE on a row the test
// owns; the checked macros would add a sqlx offline-cache entry for it.
#![allow(clippy::disallowed_methods)]

use crate::common;

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use hmac::{Hmac, Mac, digest::KeyInit};
use serde_json::{Value, json};
use sha2::Sha256;

use overslash_api::services::webhook_dispatcher;

struct Received {
    event: String,
    timestamp: String,
    v1: String,
    legacy: String,
    raw: String,
}

/// Echoes every verification challenge; answers the first `fail_events`
/// events with a 500 and the rest with a 200.
#[derive(Clone)]
struct Receiver {
    received: Arc<Mutex<Vec<Received>>>,
    fail_events: Arc<Mutex<usize>>,
}

impl Receiver {
    fn of(&self, event: &str) -> Vec<(String, String, String, String)> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.event == event)
            .map(|r| {
                (
                    r.timestamp.clone(),
                    r.v1.clone(),
                    r.legacy.clone(),
                    r.raw.clone(),
                )
            })
            .collect()
    }
}

async fn receive(State(r): State<Receiver>, headers: HeaderMap, raw: String) -> Response {
    let header = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    let body: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    r.received.lock().unwrap().push(Received {
        event: header("x-overslash-event"),
        timestamp: header("x-overslash-timestamp"),
        v1: header("x-overslash-signature-v1"),
        legacy: header("x-overslash-signature"),
        raw,
    });
    if body["type"] == "webhook.verification" {
        return Json(json!({ "challenge": body["data"]["challenge"] })).into_response();
    }
    let mut fail = r.fail_events.lock().unwrap();
    if *fail > 0 {
        *fail -= 1;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    "ok".into_response()
}

async fn start_receiver(fail_events: usize) -> (String, Receiver) {
    let r = Receiver {
        received: Arc::default(),
        fail_events: Arc::new(Mutex::new(fail_events)),
    };
    let app = Router::new()
        .route("/hook", post(receive))
        .with_state(r.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    // Plain http to loopback: allow-listed for the suite (see webhook_https.rs).
    (format!("http://{addr}/hook"), r)
}

fn hmac_hex(secret: &str, msg: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Verify one received attempt the way a consumer is told to, and return its
/// timestamp.
fn assert_signed(secret: &str, (ts, v1, legacy, raw): &(String, String, String, String)) -> i64 {
    let t: i64 = ts.parse().unwrap_or_else(|_| panic!("timestamp {ts:?}"));
    assert!((now_unix() - t).abs() <= 5, "timestamp {t} is not now");
    assert_eq!(
        *v1,
        format!("v1={}", hmac_hex(secret, &format!("{ts}.{raw}"))),
        "v1 covers <timestamp>.<raw body>"
    );
    assert_eq!(
        *legacy,
        format!("sha256={}", hmac_hex(secret, raw)),
        "the legacy body-only signature is still sent, unchanged"
    );
    t
}

struct Api {
    base: String,
    key: String,
    org_id: uuid::Uuid,
    pool: sqlx::PgPool,
}

async fn boot() -> Api {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    common::allow_loopback_ssrf();
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, _ident, _agent_key, key) = common::bootstrap_org_identity(&base, &client).await;
    Api {
        base,
        key,
        org_id,
        pool,
    }
}

impl Api {
    /// Register `url` and return `(id, secret)`.
    async fn register(&self, url: &str) -> (String, String) {
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/webhooks", self.base))
            .header("Authorization", format!("Bearer {}", self.key))
            .json(&json!({ "url": url, "events": ["probe.fired"] }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let wh: Value = resp.json().await.unwrap();
        assert_eq!(wh["verification_status"], "verified", "{wh}");
        (
            wh["id"].as_str().unwrap().to_string(),
            wh["secret"].as_str().unwrap().to_string(),
        )
    }

    async fn fire(&self) {
        webhook_dispatcher::dispatch(&self.pool, self.org_id, "probe.fired", json!({ "n": 1 }))
            .await;
    }
}

#[tokio::test]
async fn events_and_the_handshake_carry_a_signed_timestamp_and_the_legacy_signature() {
    let api = boot().await;
    let (url, rx) = start_receiver(0).await;
    let (_id, secret) = api.register(&url).await;

    let handshake = rx.of("webhook.verification");
    assert_eq!(handshake.len(), 1);
    assert_signed(&secret, &handshake[0]);

    api.fire().await;
    let events = rx.of("probe.fired");
    assert_eq!(events.len(), 1);
    let (ts, v1, _, raw) = &events[0];
    assert_signed(&secret, &events[0]);

    // What the timestamp buys: the same body under another timestamp — a
    // replay with the header bumped — does not verify.
    let forged_ts = (ts.parse::<i64>().unwrap() + 600).to_string();
    assert_ne!(
        *v1,
        format!("v1={}", hmac_hex(&secret, &format!("{forged_ts}.{raw}")))
    );
}

#[tokio::test]
async fn a_retry_is_re_signed_with_a_fresh_timestamp() {
    let api = boot().await;
    let (url, rx) = start_receiver(1).await;
    let (id, secret) = api.register(&url).await;

    api.fire().await;
    assert_eq!(rx.of("probe.fired").len(), 1, "first attempt answered 500");

    // Unix seconds: step past the first attempt's second, then make the
    // failed row due instead of waiting out the backoff.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    sqlx::query(
        "UPDATE webhook_deliveries SET next_retry_at = now()
         WHERE subscription_id = $1::uuid AND delivered_at IS NULL",
    )
    .bind(&id)
    .execute(&api.pool)
    .await
    .unwrap();
    webhook_dispatcher::retry_pending_once(&api.pool)
        .await
        .unwrap();

    let attempts = rx.of("probe.fired");
    assert_eq!(attempts.len(), 2);
    let first = assert_signed(&secret, &attempts[0]);
    let retry = assert_signed(&secret, &attempts[1]);
    assert!(retry > first, "retry signed at {retry}, first at {first}");

    // Same bytes, same legacy signature — only the timestamped one moved.
    assert_eq!(attempts[0].3, attempts[1].3);
    assert_eq!(attempts[0].2, attempts[1].2);
    assert_ne!(attempts[0].1, attempts[1].1);
}
