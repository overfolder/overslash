//! Cloud billing routes: Stripe Checkout, Customer Portal, subscription
//! reads and the Stripe webhook intake.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::repos::{billing, org as org_repo};

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{AdminAcl, AuthContext, ReqExt},
    routes::orgs::{provision_new_org_contents, redirect_for_org},
};

mod checkout;
mod config;
mod stripe_client;
mod webhook;

use checkout::{create_checkout, create_portal, get_checkout_status, get_subscription};
use config::{get_billing_config, get_geo};

// Called at startup from `lib.rs` to fail fast on a misconfigured Stripe
// lookup key, and exercised directly by `tests/billing.rs`.
pub use stripe_client::resolve_stripe_price_by_lookup_key;
pub use webhook::stripe_webhook;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/billing/config", get(get_billing_config))
        .route("/v1/billing/geo", get(get_geo))
        .route("/v1/billing/checkout", post(create_checkout))
        .route(
            "/v1/billing/checkout/{session_id}/status",
            get(get_checkout_status),
        )
        .route("/v1/billing/portal", post(create_portal))
        .route("/v1/orgs/{id}/subscription", get(get_subscription))
}

pub fn webhook_router() -> Router<AppState> {
    Router::new().route("/v1/webhooks/stripe", post(stripe_webhook))
}
