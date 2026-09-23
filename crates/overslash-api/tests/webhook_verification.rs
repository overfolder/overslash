//! CASA 7.1.2 — the provider verifies endpoint ownership before delivering.
//!
//! A new subscription starts `pending_verification`; registration POSTs a
//! signed `webhook.verification` challenge and only an endpoint that echoes it
//! back with a 2xx becomes `verified`. Until then nothing is sent: events are
//! recorded as held deliveries and released when the subscription verifies.
//! Subscriptions that predate the handshake were grandfathered by migration
//! 125 so existing consumers keep receiving events.

// The migration test runs the real down/up SQL and seeds the pre-125 table
// shape, which the checked macros cannot describe.
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
use uuid::Uuid;

use overslash_api::services::webhook_dispatcher;

const MIGRATION_125_UP: &str =
    include_str!("../../overslash-db/migrations/125_webhook_endpoint_verification.up.sql");
const MIGRATION_125_DOWN: &str =
    include_str!("../../overslash-db/migrations/125_webhook_endpoint_verification.down.sql");

// ── A receiver whose answer to the challenge the test controls ──────

#[derive(Clone, Copy)]
enum Answer {
    /// `{"challenge": "<value>"}`
    EchoJson,
    /// The bare challenge as the body.
    EchoPlain,
    /// 2xx, but the wrong value.
    Wrong,
    /// Refuses the request.
    Unauthorized,
    /// The headers after 6s and the correct echo 6s later: each half fits
    /// inside 10s on its own, the whole exchange does not.
    EchoTooSlowly,
}

struct Received {
    event: String,
    signature: String,
    raw: String,
    body: Value,
}

#[derive(Clone)]
struct Receiver {
    answer: Arc<Mutex<Answer>>,
    received: Arc<Mutex<Vec<Received>>>,
}

impl Receiver {
    fn set(&self, a: Answer) {
        *self.answer.lock().unwrap() = a;
    }

    /// Event types seen, handshakes included, in arrival order.
    fn events(&self) -> Vec<String> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.event.clone())
            .collect()
    }

    fn deliveries_of(&self, event: &str) -> usize {
        self.events().iter().filter(|e| *e == event).count()
    }
}

async fn receive(State(r): State<Receiver>, headers: HeaderMap, raw: String) -> Response {
    let body: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
    let header = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    let challenge = body["data"]["challenge"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    r.received.lock().unwrap().push(Received {
        event: header("x-overslash-event"),
        signature: header("x-overslash-signature"),
        raw,
        body: body.clone(),
    });
    if body["type"] != "webhook.verification" {
        return "ok".into_response();
    }
    let answer = *r.answer.lock().unwrap();
    match answer {
        Answer::EchoJson => Json(json!({ "challenge": challenge })).into_response(),
        Answer::EchoPlain => format!("{challenge}\n").into_response(),
        Answer::Wrong => Json(json!({ "challenge": "not-the-challenge" })).into_response(),
        Answer::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
        Answer::EchoTooSlowly => {
            tokio::time::sleep(std::time::Duration::from_secs(6)).await;
            let late = futures_util::stream::once(async move {
                tokio::time::sleep(std::time::Duration::from_secs(6)).await;
                Ok::<_, std::convert::Infallible>(challenge)
            });
            axum::body::Body::from_stream(late).into_response()
        }
    }
}

async fn start_receiver(answer: Answer) -> (String, Receiver) {
    let r = Receiver {
        answer: Arc::new(Mutex::new(answer)),
        received: Arc::new(Mutex::new(Vec::new())),
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

// ── API helpers ─────────────────────────────────────────────────────

struct Api {
    base: String,
    key: String,
    org_id: Uuid,
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
    async fn register(&self, url: &str) -> Value {
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/webhooks", self.base))
            .header("Authorization", format!("Bearer {}", self.key))
            .json(&json!({ "url": url, "events": ["probe.fired"] }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        resp.json().await.unwrap()
    }

    async fn verify(&self, id: &str) -> (u16, Value) {
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/webhooks/{id}/verify", self.base))
            .header("Authorization", format!("Bearer {}", self.key))
            .send()
            .await
            .unwrap();
        (resp.status().as_u16(), resp.json().await.unwrap())
    }

    async fn listed(&self, id: &str) -> Value {
        let rows: Vec<Value> = reqwest::Client::new()
            .get(format!("{}/v1/webhooks", self.base))
            .header("Authorization", format!("Bearer {}", self.key))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        rows.into_iter()
            .find(|w| w["id"] == id)
            .unwrap_or_else(|| panic!("webhook {id} not listed"))
    }

    async fn deliveries(&self, id: &str) -> Vec<Value> {
        reqwest::Client::new()
            .get(format!("{}/v1/webhooks/{id}/deliveries", self.base))
            .header("Authorization", format!("Bearer {}", self.key))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    async fn fire(&self) {
        webhook_dispatcher::dispatch(&self.pool, self.org_id, "probe.fired", json!({ "n": 1 }))
            .await;
    }
}

fn hmac_hex(secret: &str, body: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

// ── Tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn nothing_is_delivered_before_verification() {
    let api = boot().await;
    let (url, rx) = start_receiver(Answer::Wrong).await;

    let wh = api.register(&url).await;
    let id = wh["id"].as_str().unwrap();
    assert_eq!(wh["verification_status"], "pending_verification");

    api.fire().await;
    // The sweep only sends for verified subscriptions.
    webhook_dispatcher::retry_pending_once(&api.pool)
        .await
        .unwrap();

    assert_eq!(
        rx.events(),
        vec!["webhook.verification"],
        "only the handshake may reach an unverified endpoint"
    );

    // Not dropped: recorded as held, undialed.
    let rows = api.deliveries(id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["held_reason"], "pending_verification");
    assert_eq!(rows[0]["attempts"], 0);
    assert!(rows[0]["status_code"].is_null());
    assert!(rows[0]["delivered_at"].is_null());
}

#[tokio::test]
async fn a_wrong_or_refused_echo_stays_pending() {
    let api = boot().await;

    for (answer, expect) in [
        (Answer::Wrong, "did not echo the challenge"),
        (Answer::Unauthorized, "HTTP 401"),
    ] {
        let (url, rx) = start_receiver(answer).await;
        let wh = api.register(&url).await;
        let id = wh["id"].as_str().unwrap();
        assert_eq!(wh["verification_status"], "pending_verification");
        assert!(wh["verified_at"].is_null());
        let err = wh["verification_error"].as_str().unwrap_or_default();
        assert!(err.contains(expect), "expected {expect:?}, got {err:?}");

        // Re-triggering with the same wrong answer changes nothing.
        let (status, body) = api.verify(id).await;
        assert_eq!(status, 200);
        assert_eq!(body["verification_status"], "pending_verification");
        assert!(
            body["verification_error"]
                .as_str()
                .unwrap_or_default()
                .contains(expect)
        );
        assert_eq!(rx.deliveries_of("webhook.verification"), 2);
        assert_eq!(
            api.listed(id).await["verification_status"],
            "pending_verification"
        );
    }
}

/// One deadline covers the whole handshake. An endpoint that takes most of it
/// to send headers and then trickles the (correct) echo in must not stretch
/// registration past it — nor get verified for answering at 12s.
#[tokio::test]
async fn a_correct_echo_that_arrives_after_the_deadline_fails() {
    let api = boot().await;
    let (url, _rx) = start_receiver(Answer::EchoTooSlowly).await;

    let started = std::time::Instant::now();
    let wh = api.register(&url).await;
    let took = started.elapsed();

    assert_eq!(wh["verification_status"], "pending_verification");
    let err = wh["verification_error"].as_str().unwrap_or_default();
    assert!(err.contains("within 10s"), "{err:?}");
    assert!(
        took < std::time::Duration::from_secs(12),
        "registration waited {took:?}, past the 10s handshake deadline"
    );
}

#[tokio::test]
async fn a_correct_echo_verifies_and_events_flow() {
    let api = boot().await;
    let (url, rx) = start_receiver(Answer::EchoJson).await;

    let wh = api.register(&url).await;
    let id = wh["id"].as_str().unwrap();
    assert_eq!(wh["verification_status"], "verified", "{wh}");
    assert!(wh["verified_at"].is_string());
    assert_eq!(wh["grandfathered"], false);
    assert!(wh.get("verification_error").is_none());

    // The challenge was a signed envelope like any event — a receiver can
    // check it with the secret it just got back.
    let secret = wh["secret"].as_str().unwrap();
    {
        let got = rx.received.lock().unwrap();
        let hs = &got[0];
        assert_eq!(hs.event, "webhook.verification");
        assert_eq!(hs.body["type"], "webhook.verification");
        assert_eq!(hs.body["data"]["challenge"].as_str().unwrap().len(), 64);
        assert_eq!(
            hs.signature,
            format!("sha256={}", hmac_hex(secret, &hs.raw))
        );
    }

    api.fire().await;
    assert_eq!(rx.deliveries_of("probe.fired"), 1);
    let rows = api.deliveries(id).await;
    assert_eq!(rows[0]["status_code"], 200);
    assert!(rows[0].get("held_reason").is_none());
}

#[tokio::test]
async fn held_events_are_released_once_the_endpoint_verifies() {
    let api = boot().await;
    let (url, rx) = start_receiver(Answer::Unauthorized).await;

    let wh = api.register(&url).await;
    let id = wh["id"].as_str().unwrap();
    api.fire().await;
    assert_eq!(rx.deliveries_of("probe.fired"), 0);

    // The receiver is fixed, and the owner re-runs the handshake.
    rx.set(Answer::EchoPlain);
    let (status, body) = api.verify(id).await;
    assert_eq!(status, 200);
    assert_eq!(body["verification_status"], "verified");
    assert!(body.get("verification_error").is_none());

    let rows = api.deliveries(id).await;
    assert!(rows[0].get("held_reason").is_none(), "released: {rows:?}");

    webhook_dispatcher::retry_pending_once(&api.pool)
        .await
        .unwrap();
    assert_eq!(rx.deliveries_of("probe.fired"), 1, "{:?}", rx.events());
    let rows = api.deliveries(id).await;
    assert_eq!(rows[0]["status_code"], 200);
    assert!(rows[0]["delivered_at"].is_string());
}

/// The compensating control for subscriptions that predate the handshake:
/// migration 125 marks every existing row verified and grandfathered, so
/// current consumers keep receiving events; rows created afterwards start
/// pending.
#[tokio::test]
async fn existing_subscriptions_are_grandfathered_by_the_migration() {
    let api = boot().await;
    let (url, rx) = start_receiver(Answer::Wrong).await;

    // Back to the pre-125 table, seeded the way an old registration left it.
    sqlx::raw_sql(MIGRATION_125_DOWN)
        .execute(&api.pool)
        .await
        .unwrap();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO webhook_subscriptions (org_id, url, events, secret)
         VALUES ($1, $2, ARRAY['probe.fired'], 'legacy-secret') RETURNING id",
    )
    .bind(api.org_id)
    .bind(&url)
    .fetch_one(&api.pool)
    .await
    .unwrap();
    sqlx::raw_sql(MIGRATION_125_UP)
        .execute(&api.pool)
        .await
        .unwrap();

    let (status, verified_at, grandfathered): (String, Option<time::OffsetDateTime>, bool) =
        sqlx::query_as(
            "SELECT verification_status, verified_at, grandfathered
             FROM webhook_subscriptions WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&api.pool)
        .await
        .unwrap();
    assert_eq!(status, "verified");
    assert!(verified_at.is_some());
    assert!(grandfathered);

    let listed = api.listed(&id.to_string()).await;
    assert_eq!(listed["verification_status"], "verified");
    assert_eq!(listed["grandfathered"], true);

    // Still receives events, with no handshake having happened.
    api.fire().await;
    assert_eq!(rx.events(), vec!["probe.fired"]);

    // A failed re-check leaves a working subscription alone…
    let (_, body) = api.verify(&id.to_string()).await;
    assert_eq!(body["verification_status"], "verified");
    assert_eq!(body["grandfathered"], true);
    assert!(body["verification_error"].is_string());
    // …and a passing one replaces the grandfathering with a real verification.
    rx.set(Answer::EchoJson);
    let (_, body) = api.verify(&id.to_string()).await;
    assert_eq!(body["verification_status"], "verified");
    assert_eq!(body["grandfathered"], false);
    assert!(body.get("verification_error").is_none());

    // The backfill is not the default: a row written now starts pending.
    let fresh: String = sqlx::query_scalar(
        "INSERT INTO webhook_subscriptions (org_id, url, events, secret)
         VALUES ($1, 'https://127.0.0.1:9/x', ARRAY['probe.fired'], 's')
         RETURNING verification_status",
    )
    .bind(api.org_id)
    .fetch_one(&api.pool)
    .await
    .unwrap();
    assert_eq!(fresh, "pending_verification");
}

#[tokio::test]
async fn verifying_an_unknown_webhook_is_404() {
    let api = boot().await;
    let (status, _) = api.verify(&Uuid::new_v4().to_string()).await;
    assert_eq!(status, 404);
}
