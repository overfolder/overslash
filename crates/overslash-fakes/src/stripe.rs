//! Minimal Stripe fake — enough to let the cloud-billing checkout flow round-
//! trip without hitting the real Stripe API. Only the endpoints actually
//! exercised by Overslash's billing routes are covered. A richer fake (signed
//! webhooks, customer-portal redirects) ships in a follow-on PR.

use axum::{Json, Router, response::Redirect, routing::post};
use serde_json::{Value, json};

use crate::{Handle, bind, serve};

pub async fn start() -> Handle {
    start_on("127.0.0.1:0").await
}

pub async fn start_on(bind_addr: &str) -> Handle {
    let (listener, addr, url) = bind(bind_addr).await.expect("bind stripe fake");
    let app = router();
    serve(listener, addr, url, app)
}

pub fn router() -> Router {
    Router::new()
        .route("/v1/checkout/sessions", post(create_checkout_session))
        .route("/v1/billing_portal/sessions", post(create_billing_portal))
}

async fn create_checkout_session() -> Json<Value> {
    Json(json!({
        "id": "cs_fake_123",
        "object": "checkout.session",
        "url": "http://localhost/billing/success?session_id=cs_fake_123",
        "status": "open",
    }))
}

async fn create_billing_portal() -> impl axum::response::IntoResponse {
    Redirect::temporary("http://localhost/billing/portal-stub")
}
