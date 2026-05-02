//! Stripe fake.
//!
//! Covers the surface Overslash's billing routes hit during e2e Checkout +
//! webhook reconciliation flows:
//!
//! - Customer create / delete (delete is the compensation path)
//! - Checkout Session create / expire / *simulated* completion
//! - Customer-portal session create + return-URL redirect
//! - Subscription fetch (the API calls back here from the webhook handler)
//! - Price list-by-lookup-key (used at API startup to resolve price IDs)
//! - Outbound webhook delivery with a real Stripe-Signature header (HMAC-SHA256
//!   over `<timestamp>.<body>`) using a configurable signing secret
//! - Refund + dispute event emission (`/__simulate/refund/...`, `/__simulate/dispute/...`)
//!   so billing-reconciliation paths can be exercised
//!
//! The webhook target URL is set at runtime via `POST /__admin/webhook-target`
//! because the API URL isn't known when the fake binary boots. The signing
//! secret can be set the same way (default: `whsec_e2e_fake`).

use axum::{
    Form, Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::{delete, get, post},
};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{Handle, bind, serve};

#[derive(Default)]
pub struct State_ {
    pub customers: HashMap<String, Value>,
    pub deleted_customers: Vec<String>,
    pub checkout_sessions: HashMap<String, Value>,
    pub expired_sessions: Vec<String>,
    pub completed_sessions: Vec<String>,
    pub portal_sessions: HashMap<String, Value>,
    pub subscriptions: HashMap<String, Value>,
    pub deliveries: Vec<Delivery>,
    pub webhook_url: Option<String>,
    pub signing_secret: String,
}

pub struct Delivery {
    pub event_type: String,
    pub status: u16,
    pub error: Option<String>,
}

pub type SharedState = Arc<Mutex<State_>>;

pub struct StripeHandle {
    pub handle: Handle,
    pub state: SharedState,
}

pub async fn start() -> StripeHandle {
    start_on("127.0.0.1:0").await
}

pub async fn start_on(bind_addr: &str) -> StripeHandle {
    start_with(bind_addr, "whsec_e2e_fake", None).await
}

/// Boot with explicit signing secret + (optional) preconfigured webhook
/// target. Useful for in-process tests that already know the API URL.
pub async fn start_with(
    bind_addr: &str,
    signing_secret: &str,
    webhook_url: Option<String>,
) -> StripeHandle {
    let (listener, addr, url) = bind(bind_addr).await.expect("bind stripe fake");
    let state: SharedState = Arc::new(Mutex::new(State_ {
        signing_secret: signing_secret.into(),
        webhook_url,
        ..Default::default()
    }));
    let app = router(state.clone(), url.clone());
    let handle = serve(listener, addr, url, app);
    StripeHandle { handle, state }
}

#[derive(Clone)]
struct AppCtx {
    state: SharedState,
    /// Public URL for the fake itself — used to build the simulated
    /// Checkout/portal URLs we hand back to clients.
    self_url: String,
}

pub fn router(state: SharedState, self_url: String) -> Router {
    let ctx = AppCtx { state, self_url };
    Router::new()
        .route("/v1/customers", post(create_customer))
        .route("/v1/customers/{id}", delete(delete_customer))
        .route("/v1/checkout/sessions", post(create_checkout_session))
        .route("/v1/checkout/sessions/{id}/expire", post(expire_session))
        .route("/v1/billing_portal/sessions", post(create_portal_session))
        .route("/v1/subscriptions/{id}", get(get_subscription))
        .route("/v1/prices", get(list_prices))
        // Simulated user-facing pages.
        .route("/__simulate/checkout/{id}", get(simulate_checkout_complete))
        .route("/__simulate/portal/{id}", get(simulate_portal_return))
        // Test-only triggers for downstream events.
        .route("/__simulate/refund/{session_id}", post(simulate_refund))
        .route(
            "/__simulate/dispute/{session_id}",
            post(simulate_dispute_created),
        )
        // Runtime config — set after the API URL is known.
        .route("/__admin/webhook-target", post(set_webhook_target))
        .route("/__admin/state", get(dump_state))
        .with_state(ctx)
}

// ---------------------------------------------------------------------------
// Stripe REST surface
// ---------------------------------------------------------------------------

async fn create_customer(
    State(ctx): State<AppCtx>,
    Form(params): Form<Vec<(String, String)>>,
) -> Json<Value> {
    let id = format!("cus_{}", Uuid::new_v4().simple());
    let email = pick(&params, "email").unwrap_or_default();
    let name = pick(&params, "name").unwrap_or_default();
    let obj = json!({
        "id": id,
        "object": "customer",
        "email": email,
        "name": name,
    });
    ctx.state.lock().await.customers.insert(id, obj.clone());
    Json(obj)
}

async fn delete_customer(State(ctx): State<AppCtx>, Path(id): Path<String>) -> Json<Value> {
    let mut s = ctx.state.lock().await;
    s.customers.remove(&id);
    s.deleted_customers.push(id.clone());
    Json(json!({ "id": id, "object": "customer", "deleted": true }))
}

async fn create_checkout_session(
    State(ctx): State<AppCtx>,
    Form(params): Form<Vec<(String, String)>>,
) -> Json<Value> {
    let id = format!("cs_{}", Uuid::new_v4().simple());
    let customer = pick(&params, "customer").unwrap_or_default();
    let mode = pick(&params, "mode").unwrap_or_else(|| "subscription".into());
    let success_url = pick(&params, "success_url").unwrap_or_default();
    let cancel_url = pick(&params, "cancel_url").unwrap_or_default();
    let quantity: i64 = pick(&params, "line_items[0][quantity]")
        .and_then(|v| v.parse().ok())
        .unwrap_or(2);
    let url = format!("{}/__simulate/checkout/{id}", ctx.self_url);
    let obj = json!({
        "id": id,
        "object": "checkout.session",
        "url": url,
        "status": "open",
        "mode": mode,
        "customer": customer,
        "success_url": success_url,
        "cancel_url": cancel_url,
        "line_items": { "data": [{ "quantity": quantity }] },
    });
    ctx.state
        .lock()
        .await
        .checkout_sessions
        .insert(id, obj.clone());
    Json(obj)
}

async fn expire_session(State(ctx): State<AppCtx>, Path(id): Path<String>) -> Json<Value> {
    let mut s = ctx.state.lock().await;
    if let Some(session) = s.checkout_sessions.get_mut(&id) {
        session["status"] = json!("expired");
    }
    s.expired_sessions.push(id.clone());
    Json(json!({ "id": id, "object": "checkout.session", "status": "expired" }))
}

async fn create_portal_session(
    State(ctx): State<AppCtx>,
    Form(params): Form<Vec<(String, String)>>,
) -> Json<Value> {
    let id = format!("bps_{}", Uuid::new_v4().simple());
    let customer = pick(&params, "customer").unwrap_or_default();
    let return_url = pick(&params, "return_url").unwrap_or_default();
    let url = format!("{}/__simulate/portal/{id}", ctx.self_url);
    let obj = json!({
        "id": id,
        "object": "billing_portal.session",
        "url": url,
        "customer": customer,
        "return_url": return_url,
    });
    ctx.state
        .lock()
        .await
        .portal_sessions
        .insert(id, obj.clone());
    Json(obj)
}

async fn get_subscription(
    State(ctx): State<AppCtx>,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let s = ctx.state.lock().await;
    s.subscriptions
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// Stripe `GET /v1/prices?lookup_keys[]=key`. Returns a single fake price
/// keyed off the lookup so the API's startup resolver can succeed.
async fn list_prices(Query(q): Query<HashMap<String, String>>) -> Json<Value> {
    let key = q
        .get("lookup_keys[]")
        .cloned()
        .unwrap_or_else(|| "missing".into());
    Json(json!({
        "object": "list",
        "data": [{
            "id": format!("price_for_{key}"),
            "object": "price",
            "lookup_key": key,
            "active": true,
        }],
        "has_more": false,
    }))
}

// ---------------------------------------------------------------------------
// Simulated user-facing flows
// ---------------------------------------------------------------------------

/// `GET /__simulate/checkout/{id}` — stand-in for the user clicking "Pay" on
/// the Stripe-hosted Checkout page. Persists a subscription, fires
/// `checkout.session.completed` to the configured webhook URL, then 302s to
/// the success URL with `{CHECKOUT_SESSION_ID}` substituted.
async fn simulate_checkout_complete(
    State(ctx): State<AppCtx>,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let (session, sub_id, customer_id, sub_obj) = {
        let mut s = ctx.state.lock().await;
        if !s.checkout_sessions.contains_key(&session_id) {
            return (StatusCode::NOT_FOUND, "checkout session not found").into_response();
        }
        let sub_id = format!("sub_{}", Uuid::new_v4().simple());
        let (customer_id, quantity) = {
            let session = &s.checkout_sessions[&session_id];
            let customer_id = session
                .get("customer")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let quantity = session
                .pointer("/line_items/data/0/quantity")
                .and_then(|v| v.as_i64())
                .unwrap_or(2);
            (customer_id, quantity)
        };
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let period_end = now + 30 * 24 * 60 * 60;
        let sub_obj = json!({
            "id": sub_id,
            "object": "subscription",
            "status": "active",
            "customer": customer_id,
            "items": { "data": [{ "quantity": quantity, "price": { "id": "price_e2e" } }] },
            "current_period_start": now,
            "current_period_end": period_end,
            "cancel_at_period_end": false,
        });
        s.subscriptions.insert(sub_id.clone(), sub_obj.clone());
        let session = s
            .checkout_sessions
            .get_mut(&session_id)
            .expect("session existed above");
        session["subscription"] = json!(sub_id);
        session["status"] = json!("complete");
        session["payment_status"] = json!("paid");
        let session_snapshot = session.clone();
        s.completed_sessions.push(session_id.clone());
        (session_snapshot, sub_id, customer_id, sub_obj)
    };

    let event = build_event(
        "checkout.session.completed",
        json!({
            "id": session_id,
            "object": "checkout.session",
            "customer": customer_id,
            "subscription": sub_id,
            "status": "complete",
            "payment_status": "paid",
        }),
    );
    deliver_webhook(&ctx.state, &event).await;

    // Real Stripe also fires customer.subscription.created on its own. Emit
    // it after checkout.session.completed so reconciliation paths see both.
    let sub_event = build_event("customer.subscription.created", sub_obj);
    deliver_webhook(&ctx.state, &sub_event).await;

    let success = session
        .get("success_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .replace("{CHECKOUT_SESSION_ID}", &session_id);
    if success.is_empty() {
        (StatusCode::OK, "checkout completed (no success_url set)").into_response()
    } else {
        Redirect::to(&success).into_response()
    }
}

/// `GET /__simulate/portal/{id}` — Stripe Customer Portal stand-in. Just 302s
/// straight to the configured `return_url`; tests that want to assert "user
/// landed back in dashboard from portal" use this round-trip.
async fn simulate_portal_return(
    State(ctx): State<AppCtx>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let return_url = {
        let s = ctx.state.lock().await;
        s.portal_sessions
            .get(&id)
            .and_then(|v| v.get("return_url"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    match return_url {
        Some(u) if !u.is_empty() => Redirect::to(&u).into_response(),
        _ => (StatusCode::NOT_FOUND, "portal session not found").into_response(),
    }
}

/// `POST /__simulate/refund/{session_id}` — emit `charge.refunded`.
async fn simulate_refund(
    State(ctx): State<AppCtx>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let (customer, subscription) = lookup_session(&ctx.state, &session_id)
        .await
        .ok_or(StatusCode::NOT_FOUND)?;
    let refund_id = format!("re_{}", Uuid::new_v4().simple());
    let charge_id = format!("ch_{}", Uuid::new_v4().simple());
    let event = build_event(
        "charge.refunded",
        json!({
            "id": charge_id,
            "object": "charge",
            "customer": customer,
            "refunded": true,
            "amount_refunded": 2000,
            "currency": "usd",
            "metadata": {
                "checkout_session_id": session_id,
                "subscription": subscription,
            },
            "refunds": {
                "data": [{
                    "id": refund_id,
                    "object": "refund",
                    "status": "succeeded",
                    "amount": 2000,
                }],
            },
        }),
    );
    deliver_webhook(&ctx.state, &event).await;
    Ok(Json(
        json!({ "delivered": "charge.refunded", "refund_id": refund_id }),
    ))
}

/// `POST /__simulate/dispute/{session_id}` — emit `charge.dispute.created`.
async fn simulate_dispute_created(
    State(ctx): State<AppCtx>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    let (customer, _subscription) = lookup_session(&ctx.state, &session_id)
        .await
        .ok_or(StatusCode::NOT_FOUND)?;
    let dispute_id = format!("dp_{}", Uuid::new_v4().simple());
    let event = build_event(
        "charge.dispute.created",
        json!({
            "id": dispute_id,
            "object": "dispute",
            "status": "warning_needs_response",
            "reason": "fraudulent",
            "amount": 2000,
            "currency": "usd",
            "customer": customer,
            "metadata": { "checkout_session_id": session_id },
        }),
    );
    deliver_webhook(&ctx.state, &event).await;
    Ok(Json(
        json!({ "delivered": "charge.dispute.created", "dispute_id": dispute_id }),
    ))
}

// ---------------------------------------------------------------------------
// Admin / introspection
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct WebhookTargetReq {
    url: String,
    #[serde(default)]
    signing_secret: Option<String>,
}

async fn set_webhook_target(
    State(ctx): State<AppCtx>,
    Json(req): Json<WebhookTargetReq>,
) -> Json<Value> {
    let mut s = ctx.state.lock().await;
    s.webhook_url = Some(req.url.clone());
    if let Some(sec) = req.signing_secret {
        s.signing_secret = sec;
    }
    Json(json!({ "ok": true, "webhook_url": req.url }))
}

async fn dump_state(State(ctx): State<AppCtx>) -> Json<Value> {
    let s = ctx.state.lock().await;
    Json(json!({
        "customers": s.customers.len(),
        "checkout_sessions": s.checkout_sessions.len(),
        "completed_sessions": s.completed_sessions,
        "expired_sessions": s.expired_sessions,
        "deleted_customers": s.deleted_customers,
        "subscriptions": s.subscriptions.keys().collect::<Vec<_>>(),
        "deliveries": s.deliveries.iter().map(|d| json!({
            "type": d.event_type,
            "status": d.status,
            "error": d.error,
        })).collect::<Vec<_>>(),
        "webhook_url": s.webhook_url,
    }))
}

// ---------------------------------------------------------------------------
// Webhook delivery
// ---------------------------------------------------------------------------

fn build_event(event_type: &str, data_object: Value) -> Value {
    let id = format!("evt_{}", Uuid::new_v4().simple());
    json!({
        "id": id,
        "object": "event",
        "type": event_type,
        "api_version": "2024-06-20",
        "created": OffsetDateTime::now_utc().unix_timestamp(),
        "data": { "object": data_object },
    })
}

/// Sign + POST the event to the configured webhook URL. Captures status
/// (and any transport error) into `state.deliveries` for assertions.
async fn deliver_webhook(state: &SharedState, event: &Value) {
    let (url, secret) = {
        let s = state.lock().await;
        (s.webhook_url.clone(), s.signing_secret.clone())
    };
    let event_type = event["type"].as_str().unwrap_or("").to_string();
    let Some(url) = url else {
        let mut s = state.lock().await;
        s.deliveries.push(Delivery {
            event_type,
            status: 0,
            error: Some("no webhook_url configured".into()),
        });
        return;
    };

    let body = serde_json::to_vec(event).expect("serialize event");
    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    let signature = sign_payload(&secret, timestamp, &body);

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Stripe-Signature", &signature)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await;

    let mut s = state.lock().await;
    match resp {
        Ok(r) => s.deliveries.push(Delivery {
            event_type,
            status: r.status().as_u16(),
            error: None,
        }),
        Err(e) => s.deliveries.push(Delivery {
            event_type,
            status: 0,
            error: Some(e.to_string()),
        }),
    }
}

/// Stripe-Signature header: `t=<unix>,v1=<hex_hmac_sha256(secret, "<t>.<body>")>`.
fn sign_payload(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let ts = timestamp.to_string();
    let mut signed = ts.as_bytes().to_vec();
    signed.push(b'.');
    signed.extend_from_slice(body);
    let mut mac: Hmac<Sha256> =
        Hmac::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(&signed);
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("t={ts},v1={sig}")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pick(params: &[(String, String)], key: &str) -> Option<String> {
    params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
}

async fn lookup_session(state: &SharedState, session_id: &str) -> Option<(String, String)> {
    let s = state.lock().await;
    let session = s.checkout_sessions.get(session_id)?;
    let customer = session
        .get("customer")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let subscription = session
        .get("subscription")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Some((customer, subscription))
}
