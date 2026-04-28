//! Integration tests for Stripe billing: geo detection, billing gate, DB repos,
//! webhook handler (checkout.session.completed, subscription lifecycle),
//! checkout status polling, portal session, and config validation.
// Test setup requires dynamic SQL.
#![allow(clippy::disallowed_methods)]

mod common;

use axum::{Json, Router, extract::Form, routing::post};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Mock Stripe server
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct MockStripeState {
    customers: Arc<Mutex<Vec<Value>>>,
    checkout_sessions: Arc<Mutex<Vec<Value>>>,
    portal_sessions: Arc<Mutex<Vec<Value>>>,
    subscriptions: Arc<Mutex<std::collections::HashMap<String, Value>>>,
}

async fn start_mock_stripe(
    preset_subscriptions: Vec<(String, Value)>,
) -> (std::net::SocketAddr, MockStripeState) {
    use axum::extract::State;

    type S = MockStripeState;

    async fn create_customer(
        State(s): State<S>,
        Form(params): Form<Vec<(String, String)>>,
    ) -> Json<Value> {
        let id = format!("cus_{}", Uuid::new_v4().simple());
        let email = params
            .iter()
            .find(|(k, _)| k == "email")
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
            .to_string();
        let obj = json!({ "id": id, "email": email, "object": "customer" });
        s.customers.lock().await.push(obj.clone());
        Json(obj)
    }

    async fn create_checkout_session(
        State(s): State<S>,
        Form(params): Form<Vec<(String, String)>>,
    ) -> Json<Value> {
        let id = format!("cs_{}", Uuid::new_v4().simple());
        let url = format!("https://checkout.stripe.com/c/pay/{id}");
        let mode = params
            .iter()
            .find(|(k, _)| k == "mode")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let obj = json!({ "id": id, "url": url, "mode": mode, "object": "checkout.session", "status": "open" });
        s.checkout_sessions.lock().await.push(obj.clone());
        Json(obj)
    }

    async fn create_portal_session(
        State(s): State<S>,
        Form(params): Form<Vec<(String, String)>>,
    ) -> Json<Value> {
        let id = format!("bps_{}", Uuid::new_v4().simple());
        let url = format!("https://billing.stripe.com/p/session/{id}");
        let customer = params
            .iter()
            .find(|(k, _)| k == "customer")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let obj = json!({ "id": id, "url": url, "customer": customer, "object": "billing_portal.session" });
        s.portal_sessions.lock().await.push(obj.clone());
        Json(obj)
    }

    async fn get_subscription(
        State(s): State<S>,
        axum::extract::Path(sub_id): axum::extract::Path<String>,
    ) -> Json<Value> {
        let subs = s.subscriptions.lock().await;
        if let Some(sub) = subs.get(&sub_id) {
            Json(sub.clone())
        } else {
            Json(json!({
                "id": sub_id,
                "object": "subscription",
                "status": "active",
                "items": { "data": [{ "quantity": 3 }] },
                "current_period_start": 1700000000_i64,
                "current_period_end": 1702592000_i64,
                "cancel_at_period_end": false,
                "customer": "cus_test"
            }))
        }
    }

    let state = MockStripeState::default();
    for (id, sub) in preset_subscriptions {
        state.subscriptions.lock().await.insert(id, sub);
    }

    let app = Router::new()
        .route("/customers", post(create_customer))
        .route("/checkout/sessions", post(create_checkout_session))
        .route("/billing_portal/sessions", post(create_portal_session))
        .route("/subscriptions/:id", axum::routing::get(get_subscription))
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (addr, state)
}

/// Build a Stripe-Signature header for the given payload/timestamp/secret.
fn stripe_sig(secret: &str, timestamp: i64, payload: &[u8]) -> String {
    let ts = timestamp.to_string();
    let mut signed = ts.as_bytes().to_vec();
    signed.push(b'.');
    signed.extend_from_slice(payload);
    let mut mac: Hmac<Sha256> = Hmac::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(&signed);
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("t={ts},v1={sig}")
}

// ---------------------------------------------------------------------------
// Helper: start API with billing enabled pointing at mock Stripe
// ---------------------------------------------------------------------------

async fn start_billing_api(
    pool: PgPool,
    stripe_addr: std::net::SocketAddr,
) -> (std::net::SocketAddr, reqwest::Client) {
    let stripe_base = format!("http://{stripe_addr}");
    common::start_api_with(pool, move |c| {
        c.cloud_billing = true;
        c.stripe_secret_key = Some("sk_test_secret".into());
        c.stripe_webhook_secret = Some("whsec_test".into());
        c.stripe_eur_price_id = Some("price_eur".into());
        c.stripe_usd_price_id = Some("price_usd".into());
        c.stripe_api_base = stripe_base.clone();
    })
    .await
}

// ---------------------------------------------------------------------------
// Tests: GET /v1/billing/geo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_geo_eu_country_returns_eur() {
    let pool = common::test_pool().await;
    let (stripe_addr, _) = start_mock_stripe(vec![]).await;
    let (addr, client) = start_billing_api(pool, stripe_addr).await;
    let base = format!("http://{addr}");

    let resp: Value = client
        .get(format!("{base}/v1/billing/geo"))
        .header("CF-IPCountry", "DE")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["currency"], "eur");
    assert_eq!(resp["base_price"], 15);
}

#[tokio::test]
async fn test_geo_non_eu_country_returns_usd() {
    let pool = common::test_pool().await;
    let (stripe_addr, _) = start_mock_stripe(vec![]).await;
    let (addr, client) = start_billing_api(pool, stripe_addr).await;
    let base = format!("http://{addr}");

    let resp: Value = client
        .get(format!("{base}/v1/billing/geo"))
        .header("CF-IPCountry", "US")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["currency"], "usd");
    assert_eq!(resp["base_price"], 20);
}

#[tokio::test]
async fn test_geo_no_header_returns_usd() {
    let pool = common::test_pool().await;
    let (stripe_addr, _) = start_mock_stripe(vec![]).await;
    let (addr, client) = start_billing_api(pool, stripe_addr).await;
    let base = format!("http://{addr}");

    let resp: Value = client
        .get(format!("{base}/v1/billing/geo"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["currency"], "usd");
}

// ---------------------------------------------------------------------------
// Tests: billing gate in POST /v1/orgs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_org_gate_blocks_team_org_when_billing_enabled() {
    let pool = common::test_pool().await;
    let (stripe_addr, _) = start_mock_stripe(vec![]).await;
    let (addr, client) = start_billing_api(pool.clone(), stripe_addr).await;
    let base = format!("http://{addr}");

    let (org_id, _, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/orgs"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "name": "Team Org", "slug": "team-org-slug" }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "team_org_requires_subscription");

    let _ = org_id;
}

#[tokio::test]
async fn test_org_gate_allows_personal_org_when_billing_enabled() {
    let pool = common::test_pool().await;
    let (stripe_addr, _) = start_mock_stripe(vec![]).await;
    let (addr, client) = start_billing_api(pool.clone(), stripe_addr).await;
    let base = format!("http://{addr}");

    let (_, _, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    let slug = format!("personal-{}", Uuid::new_v4().simple());
    let resp = client
        .post(format!("{base}/v1/orgs"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "name": "My Personal Org", "slug": slug, "is_personal": true }))
        .send()
        .await
        .unwrap();

    // Personal orgs bypass the billing gate.
    assert_eq!(resp.status(), 200, "personal org should be allowed");
}

#[tokio::test]
async fn test_org_gate_absent_when_billing_disabled() {
    // Default config: cloud_billing=false — team orgs allowed freely.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let (_, _, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    let slug = format!("team-{}", Uuid::new_v4().simple());
    let resp = client
        .post(format!("{base}/v1/orgs"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({ "name": "Team Org", "slug": slug }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        200,
        "team org creation should be free when billing disabled"
    );
}

// ---------------------------------------------------------------------------
// Tests: billing DB repos
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_billing_db_pending_checkout_lifecycle() {
    let pool = common::test_pool().await;

    // We need a real user_id — bootstrap one.
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, user_id, _, _) = common::bootstrap_org_identity(&base, &client).await;

    let session_id = format!("cs_{}", Uuid::new_v4().simple());

    // Insert pending checkout.
    overslash_db::repos::billing::insert_pending_checkout(
        &pool,
        &session_id,
        user_id,
        "Test Org",
        "test-org-slug",
        3,
        "usd",
    )
    .await
    .unwrap();

    // get_pending_checkout (unexpired) returns it.
    let pc = overslash_db::repos::billing::get_pending_checkout(&pool, &session_id)
        .await
        .unwrap()
        .expect("pending checkout should exist");
    assert_eq!(pc.org_name, "Test Org");
    assert_eq!(pc.org_slug, "test-org-slug");
    assert_eq!(pc.seats, 3);
    assert_eq!(pc.currency, "usd");
    assert!(pc.fulfilled_org_id.is_none());

    // get_pending_checkout_any also finds it.
    let pc2 = overslash_db::repos::billing::get_pending_checkout_any(&pool, &session_id)
        .await
        .unwrap()
        .expect("should exist via _any");
    assert_eq!(pc2.org_name, pc.org_name);

    // Fulfill it.
    overslash_db::repos::billing::fulfill_pending_checkout(&pool, &session_id, org_id)
        .await
        .unwrap();

    // Now fulfilled_org_id is set.
    let fulfilled = overslash_db::repos::billing::get_pending_checkout_any(&pool, &session_id)
        .await
        .unwrap()
        .expect("should still exist after fulfillment");
    assert_eq!(fulfilled.fulfilled_org_id, Some(org_id));
}

#[tokio::test]
async fn test_billing_db_stripe_customer_roundtrip() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_, user_id, _, _) = common::bootstrap_org_identity(&base, &client).await;

    // Initially none.
    let cid = overslash_db::repos::billing::get_stripe_customer(&pool, user_id)
        .await
        .unwrap();
    assert!(cid.is_none());

    // Set it.
    overslash_db::repos::billing::set_stripe_customer(&pool, user_id, "cus_test123")
        .await
        .unwrap();

    // Now it's there.
    let cid = overslash_db::repos::billing::get_stripe_customer(&pool, user_id)
        .await
        .unwrap();
    assert_eq!(cid.as_deref(), Some("cus_test123"));
}

#[tokio::test]
async fn test_billing_db_org_subscription_upsert_and_update() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, _, _, _) = common::bootstrap_org_identity(&base, &client).await;

    // Initially none.
    let sub = overslash_db::repos::billing::get_org_subscription(&pool, org_id)
        .await
        .unwrap();
    assert!(sub.is_none());

    // Upsert.
    let params = overslash_db::repos::billing::UpsertSubscription {
        stripe_subscription_id: "sub_test123",
        stripe_customer_id: "cus_test",
        seats: 5,
        status: "active",
        currency: "usd",
        current_period_start: None,
        current_period_end: None,
        cancel_at_period_end: false,
    };
    overslash_db::repos::billing::upsert_org_subscription(&pool, org_id, params)
        .await
        .unwrap();

    let sub = overslash_db::repos::billing::get_org_subscription(&pool, org_id)
        .await
        .unwrap()
        .expect("subscription should exist");
    assert_eq!(sub.stripe_subscription_id, "sub_test123");
    assert_eq!(sub.seats, 5);
    assert_eq!(sub.status, "active");

    // Update status to canceled.
    overslash_db::repos::billing::update_subscription_status(
        &pool,
        "sub_test123",
        "canceled",
        5,
        None,
        None,
        false,
    )
    .await
    .unwrap();

    let sub = overslash_db::repos::billing::get_org_subscription(&pool, org_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sub.status, "canceled");
}

// ---------------------------------------------------------------------------
// Tests: POST /v1/billing/checkout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_create_checkout_returns_stripe_url() {
    let pool = common::test_pool().await;
    let (stripe_addr, stripe_state) = start_mock_stripe(vec![]).await;
    let (addr, client) = start_billing_api(pool.clone(), stripe_addr).await;
    let base = format!("http://{addr}");

    // Bootstrap org + admin session.
    let (_, _, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/billing/checkout"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "org_name": "My Team",
            "org_slug": "my-team-slug",
            "seats": 3,
            "currency": "usd"
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "checkout should succeed");
    let body: Value = resp.json().await.unwrap();

    // URL must come from Stripe's response (starts with checkout.stripe.com).
    assert!(
        body["url"]
            .as_str()
            .unwrap_or("")
            .starts_with("https://checkout.stripe.com/"),
        "url should be from Stripe response, got: {}",
        body["url"]
    );

    // Stripe mock should have received a checkout session creation request.
    let sessions = stripe_state.checkout_sessions.lock().await;
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["mode"], "subscription");
}

// ---------------------------------------------------------------------------
// Tests: Stripe webhook
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_webhook_checkout_completed_provisions_org() {
    let pool = common::test_pool().await;
    let sub_id = format!("sub_{}", Uuid::new_v4().simple());
    let sub_fixture = json!({
        "id": sub_id,
        "object": "subscription",
        "status": "active",
        "items": { "data": [{ "quantity": 4 }] },
        "current_period_start": 1700000000_i64,
        "current_period_end": 1702592000_i64,
        "cancel_at_period_end": false,
        "customer": "cus_webhook_test"
    });

    let (stripe_addr, _) = start_mock_stripe(vec![(sub_id.clone(), sub_fixture)]).await;
    let (addr, client) = start_billing_api(pool.clone(), stripe_addr).await;
    let base = format!("http://{addr}");

    // Bootstrap a user to own the pending checkout.
    let (_, user_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    // Insert a pending checkout directly in the DB.
    let session_id = format!("cs_wh_{}", Uuid::new_v4().simple());
    let org_slug = format!("webhook-org-{}", Uuid::new_v4().simple());
    overslash_db::repos::billing::insert_pending_checkout(
        &pool,
        &session_id,
        user_id,
        "Webhook Org",
        &org_slug,
        4,
        "usd",
    )
    .await
    .unwrap();

    // Build the webhook payload.
    let payload = serde_json::to_vec(&json!({
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": session_id,
                "object": "checkout.session",
                "status": "complete",
                "subscription": sub_id,
                "customer": "cus_webhook_test",
                "metadata": { "pending_checkout_id": session_id }
            }
        }
    }))
    .unwrap();

    let ts = 1_700_000_000_i64;
    let sig = stripe_sig("whsec_test", ts, &payload);

    let resp = client
        .post(format!("{base}/v1/webhooks/stripe"))
        .header("Stripe-Signature", sig)
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200, "webhook should be accepted");

    // Org should now exist.
    let org = overslash_db::repos::org::get_by_slug(&pool, &org_slug)
        .await
        .unwrap()
        .expect("org should have been provisioned");
    assert_eq!(org.name, "Webhook Org");

    // Pending checkout should be fulfilled.
    let pc = overslash_db::repos::billing::get_pending_checkout_any(&pool, &session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pc.fulfilled_org_id, Some(org.id));

    // Subscription should be inserted.
    let sub = overslash_db::repos::billing::get_org_subscription(&pool, org.id)
        .await
        .unwrap()
        .expect("subscription should be created");
    assert_eq!(sub.status, "active");
    assert_eq!(sub.seats, 4);

    drop(api_key);
}

#[tokio::test]
async fn test_webhook_checkout_completed_idempotent() {
    // Sending the same webhook twice should not error — second call is a no-op.
    let pool = common::test_pool().await;
    let sub_id = format!("sub_{}", Uuid::new_v4().simple());
    let sub_fixture = json!({
        "id": sub_id, "object": "subscription", "status": "active",
        "items": { "data": [{ "quantity": 2 }] },
        "current_period_start": 1700000000_i64, "current_period_end": 1702592000_i64,
        "cancel_at_period_end": false, "customer": "cus_idem"
    });
    let (stripe_addr, _) = start_mock_stripe(vec![(sub_id.clone(), sub_fixture)]).await;
    let (addr, client) = start_billing_api(pool.clone(), stripe_addr).await;
    let base = format!("http://{addr}");

    let (_, user_id, _, _) = common::bootstrap_org_identity(&base, &client).await;

    let session_id = format!("cs_idem_{}", Uuid::new_v4().simple());
    let org_slug = format!("idem-org-{}", Uuid::new_v4().simple());
    overslash_db::repos::billing::insert_pending_checkout(
        &pool,
        &session_id,
        user_id,
        "Idem Org",
        &org_slug,
        2,
        "usd",
    )
    .await
    .unwrap();

    let payload = serde_json::to_vec(&json!({
        "type": "checkout.session.completed",
        "data": { "object": {
            "id": session_id, "object": "checkout.session", "status": "complete",
            "subscription": sub_id, "customer": "cus_idem",
            "metadata": { "pending_checkout_id": session_id }
        }}
    }))
    .unwrap();

    let ts = 1_700_000_001_i64;
    let sig = stripe_sig("whsec_test", ts, &payload);

    // First delivery.
    let r1 = client
        .post(format!("{base}/v1/webhooks/stripe"))
        .header("Stripe-Signature", sig.clone())
        .header("Content-Type", "application/json")
        .body(payload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);

    // Second delivery (same payload, same sig) — idempotent.
    let r2 = client
        .post(format!("{base}/v1/webhooks/stripe"))
        .header("Stripe-Signature", sig)
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r2.status(),
        200,
        "second delivery must also succeed (idempotent)"
    );

    // Only one org.
    let org = overslash_db::repos::org::get_by_slug(&pool, &org_slug)
        .await
        .unwrap()
        .expect("org should exist");
    assert_eq!(org.name, "Idem Org");
}

#[tokio::test]
async fn test_webhook_bad_signature_rejected() {
    let pool = common::test_pool().await;
    let (stripe_addr, _) = start_mock_stripe(vec![]).await;
    let (addr, client) = start_billing_api(pool, stripe_addr).await;
    let base = format!("http://{addr}");

    let payload = b"{\"type\":\"checkout.session.completed\"}";
    let bad_sig = "t=1700000000,v1=badbadbadbad";

    let resp = client
        .post(format!("{base}/v1/webhooks/stripe"))
        .header("Stripe-Signature", bad_sig)
        .header("Content-Type", "application/json")
        .body(payload.as_ref())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400, "bad signature should be rejected");
}

#[tokio::test]
async fn test_webhook_subscription_updated() {
    let pool = common::test_pool().await;

    // First create an org and a subscription record.
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, _, _, _) = common::bootstrap_org_identity(&base, &client).await;

    let sub_id = format!("sub_{}", Uuid::new_v4().simple());
    overslash_db::repos::billing::upsert_org_subscription(
        &pool,
        org_id,
        overslash_db::repos::billing::UpsertSubscription {
            stripe_subscription_id: &sub_id,
            stripe_customer_id: "cus_upd",
            seats: 2,
            status: "active",
            currency: "eur",
            current_period_start: None,
            current_period_end: None,
            cancel_at_period_end: false,
        },
    )
    .await
    .unwrap();

    // Now deliver subscription.updated via the billing-enabled API.
    let (stripe_addr, _) = start_mock_stripe(vec![]).await;
    let (billing_addr, billing_client) = start_billing_api(pool.clone(), stripe_addr).await;
    let billing_base = format!("http://{billing_addr}");

    let payload = serde_json::to_vec(&json!({
        "type": "customer.subscription.updated",
        "data": { "object": {
            "id": sub_id,
            "object": "subscription",
            "status": "past_due",
            "items": { "data": [{ "quantity": 5 }] },
            "current_period_start": 1700000000_i64,
            "current_period_end": 1702592000_i64,
            "cancel_at_period_end": true,
            "customer": "cus_upd"
        }}
    }))
    .unwrap();

    let ts = 1_700_000_002_i64;
    let sig = stripe_sig("whsec_test", ts, &payload);

    let resp = billing_client
        .post(format!("{billing_base}/v1/webhooks/stripe"))
        .header("Stripe-Signature", sig)
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Subscription should be updated.
    let sub = overslash_db::repos::billing::get_org_subscription(&pool, org_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sub.status, "past_due");
    assert_eq!(sub.seats, 5);
    assert!(sub.cancel_at_period_end);
}

#[tokio::test]
async fn test_webhook_subscription_deleted() {
    let pool = common::test_pool().await;

    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, _, _, _) = common::bootstrap_org_identity(&base, &client).await;

    let sub_id = format!("sub_{}", Uuid::new_v4().simple());
    overslash_db::repos::billing::upsert_org_subscription(
        &pool,
        org_id,
        overslash_db::repos::billing::UpsertSubscription {
            stripe_subscription_id: &sub_id,
            stripe_customer_id: "cus_del",
            seats: 2,
            status: "active",
            currency: "usd",
            current_period_start: None,
            current_period_end: None,
            cancel_at_period_end: false,
        },
    )
    .await
    .unwrap();

    let (stripe_addr, _) = start_mock_stripe(vec![]).await;
    let (billing_addr, billing_client) = start_billing_api(pool.clone(), stripe_addr).await;
    let billing_base = format!("http://{billing_addr}");

    let payload = serde_json::to_vec(&json!({
        "type": "customer.subscription.deleted",
        "data": { "object": {
            "id": sub_id,
            "object": "subscription",
            "status": "canceled",
            "items": { "data": [{ "quantity": 2 }] },
            "current_period_start": 1700000000_i64,
            "current_period_end": 1702592000_i64,
            "cancel_at_period_end": false,
            "customer": "cus_del"
        }}
    }))
    .unwrap();

    let ts = 1_700_000_003_i64;
    let sig = stripe_sig("whsec_test", ts, &payload);

    let resp = billing_client
        .post(format!("{billing_base}/v1/webhooks/stripe"))
        .header("Stripe-Signature", sig)
        .header("Content-Type", "application/json")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let sub = overslash_db::repos::billing::get_org_subscription(&pool, org_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sub.status, "canceled");
}

// ---------------------------------------------------------------------------
// Tests: GET /v1/billing/checkout/{session_id}/status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_checkout_status_pending_then_fulfilled() {
    let pool = common::test_pool().await;
    let (stripe_addr, _) = start_mock_stripe(vec![]).await;
    let (addr, client) = start_billing_api(pool.clone(), stripe_addr).await;
    let base = format!("http://{addr}");

    let (org_id, user_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    let session_id = format!("cs_status_{}", Uuid::new_v4().simple());
    overslash_db::repos::billing::insert_pending_checkout(
        &pool,
        &session_id,
        user_id,
        "Status Org",
        "status-org-slug",
        2,
        "usd",
    )
    .await
    .unwrap();

    // Before fulfillment: status = "pending".
    let resp: Value = client
        .get(format!("{base}/v1/billing/checkout/{session_id}/status"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "pending");
    assert!(resp["redirect_to"].is_null());

    // Fulfill it.
    overslash_db::repos::billing::fulfill_pending_checkout(&pool, &session_id, org_id)
        .await
        .unwrap();

    // After fulfillment: status = "fulfilled" with redirect_to.
    let resp: Value = client
        .get(format!("{base}/v1/billing/checkout/{session_id}/status"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "fulfilled");
    assert!(resp["redirect_to"].as_str().is_some());
}

// ---------------------------------------------------------------------------
// Tests: config validation
// ---------------------------------------------------------------------------

#[test]
fn test_config_validate_env_catches_empty_string() {
    // Simulate CLOUD_BILLING=true with STRIPE_SECRET_KEY="" (empty string).
    // The validator must treat this the same as missing.
    unsafe {
        std::env::set_var("CLOUD_BILLING", "true");
        std::env::set_var("STRIPE_SECRET_KEY", "");
        std::env::set_var("STRIPE_WEBHOOK_SECRET", "");
        std::env::set_var("STRIPE_EUR_PRICE_ID", "price_eur");
        std::env::set_var("STRIPE_USD_PRICE_ID", "price_usd");
        std::env::set_var("DATABASE_URL", "postgres://localhost/test");
        std::env::set_var("SECRETS_ENCRYPTION_KEY", "a".repeat(64));
        std::env::set_var("SIGNING_KEY", "b".repeat(64));
    }

    let missing = overslash_api::config::Config::validate_env();

    unsafe {
        std::env::remove_var("CLOUD_BILLING");
        std::env::remove_var("STRIPE_SECRET_KEY");
        std::env::remove_var("STRIPE_WEBHOOK_SECRET");
        std::env::remove_var("STRIPE_EUR_PRICE_ID");
        std::env::remove_var("STRIPE_USD_PRICE_ID");
    }

    // Empty STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET must be flagged as missing.
    assert!(
        missing.contains(&"STRIPE_SECRET_KEY"),
        "empty STRIPE_SECRET_KEY should be treated as missing"
    );
    assert!(
        missing.contains(&"STRIPE_WEBHOOK_SECRET"),
        "empty STRIPE_WEBHOOK_SECRET should be treated as missing"
    );
    // Non-empty price IDs should not be flagged.
    assert!(
        !missing.contains(&"STRIPE_EUR_PRICE_ID"),
        "non-empty STRIPE_EUR_PRICE_ID should not be flagged"
    );
}

#[test]
fn test_config_validate_env_passes_when_all_set() {
    unsafe {
        std::env::set_var("CLOUD_BILLING", "true");
        std::env::set_var("STRIPE_SECRET_KEY", "sk_test_key");
        std::env::set_var("STRIPE_WEBHOOK_SECRET", "whsec_test");
        std::env::set_var("STRIPE_EUR_PRICE_ID", "price_eur");
        std::env::set_var("STRIPE_USD_PRICE_ID", "price_usd");
        std::env::set_var("DATABASE_URL", "postgres://localhost/test");
        std::env::set_var("SECRETS_ENCRYPTION_KEY", "a".repeat(64));
        std::env::set_var("SIGNING_KEY", "b".repeat(64));
    }

    let missing = overslash_api::config::Config::validate_env();

    unsafe {
        std::env::remove_var("CLOUD_BILLING");
        std::env::remove_var("STRIPE_SECRET_KEY");
        std::env::remove_var("STRIPE_WEBHOOK_SECRET");
        std::env::remove_var("STRIPE_EUR_PRICE_ID");
        std::env::remove_var("STRIPE_USD_PRICE_ID");
    }

    // Filter out always-required vars that might be missing in test env.
    let billing_missing: Vec<_> = missing.iter().filter(|k| k.starts_with("STRIPE")).collect();
    assert!(
        billing_missing.is_empty(),
        "no Stripe vars should be missing: {:?}",
        billing_missing
    );
}
