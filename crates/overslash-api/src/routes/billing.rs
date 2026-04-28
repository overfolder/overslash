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
    extractors::{AdminAcl, AuthContext},
    routes::orgs::{provision_new_org_contents, redirect_for_org},
};

/// EU member state ISO 3166-1 alpha-2 codes for EUR/USD detection.
const EU_COUNTRIES: &[&str] = &[
    "AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IE", "IT",
    "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK",
];

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

// ---------------------------------------------------------------------------
// Public config — exposed to the dashboard so it can render the right CTA
// ("Add org" goes to `/billing/new-team` when billing is on).
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct BillingConfigResponse {
    cloud_billing: bool,
}

/// GET /v1/billing/config — unauthenticated; the only field is the public
/// flag. Always returns true here (route is only mounted when billing is on).
async fn get_billing_config() -> Json<BillingConfigResponse> {
    Json(BillingConfigResponse {
        cloud_billing: true,
    })
}

// ---------------------------------------------------------------------------
// Geo
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct GeoResponse {
    currency: &'static str,
    base_price: u32,
}

/// GET /v1/billing/geo — unauthenticated; returns EUR or USD pricing based on
/// the `CF-IPCountry` header set by Cloudflare (falls back to USD).
async fn get_geo(headers: HeaderMap) -> Json<GeoResponse> {
    let country = headers
        .get("CF-IPCountry")
        .or_else(|| headers.get("X-Country-Code"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if EU_COUNTRIES.contains(&country) {
        Json(GeoResponse {
            currency: "eur",
            base_price: 15,
        })
    } else {
        Json(GeoResponse {
            currency: "usd",
            base_price: 20,
        })
    }
}

// ---------------------------------------------------------------------------
// Checkout
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateCheckoutRequest {
    org_name: String,
    org_slug: String,
    seats: u32,
    currency: String,
}

#[derive(Serialize)]
struct CheckoutResponse {
    url: String,
}

/// POST /v1/billing/checkout — create a Stripe Checkout Session for a new
/// Team org. Returns the Stripe-hosted URL to redirect the user to.
async fn create_checkout(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<CreateCheckoutRequest>,
) -> Result<Json<CheckoutResponse>> {
    let user_id = auth
        .user_id
        .ok_or_else(|| AppError::Unauthorized("multi-org session required".into()))?;

    if req.seats < 2 || req.seats > 20 {
        return Err(AppError::BadRequest(
            "seats must be between 2 and 20".into(),
        ));
    }

    let currency = match req.currency.to_lowercase().as_str() {
        "eur" => "eur",
        "usd" => "usd",
        _ => return Err(AppError::BadRequest("currency must be eur or usd".into())),
    };

    let slug = req.org_slug.trim();
    crate::routes::orgs::validate_slug_format_pub(slug)
        .map_err(|code| AppError::BadRequest(code.into()))?;

    // Reject slug before hitting Stripe if it's already taken.
    if org_repo::get_by_slug(&state.db, slug).await?.is_some() {
        return Err(AppError::Conflict("slug_taken".into()));
    }

    let stripe_key = state
        .config
        .stripe_secret_key
        .as_deref()
        .ok_or_else(|| AppError::Internal("billing not configured".into()))?;

    let price_id = if currency == "eur" {
        state
            .config
            .stripe_eur_price_id
            .as_deref()
            .ok_or_else(|| AppError::Internal("STRIPE_EUR_PRICE_ID not set".into()))?
    } else {
        state
            .config
            .stripe_usd_price_id
            .as_deref()
            .ok_or_else(|| AppError::Internal("STRIPE_USD_PRICE_ID not set".into()))?
    };

    // Find or create the Stripe Customer for this user.
    let customer_id = match billing::get_stripe_customer(&state.db, user_id).await? {
        Some(id) => id,
        None => {
            let user = overslash_db::repos::user::get_by_id(&state.db, user_id)
                .await?
                .ok_or_else(|| AppError::Unauthorized("user not found".into()))?;
            let cid = stripe_create_customer(
                &state.http_client,
                stripe_key,
                user.email.as_deref(),
                user.display_name.as_deref(),
                user_id,
                &state.config.stripe_api_base,
            )
            .await?;
            // If we can't persist the customer ID locally, the Stripe customer
            // would be orphaned — and on retry we'd create a second one,
            // breaking the "one Stripe Customer per user" invariant. Delete
            // the just-created customer (best-effort) and surface the error.
            //
            // Two failure modes: (a) Err from sqlx (transient DB issue,
            // constraint violation), and (b) Ok(false) — the UPDATE matched
            // zero rows because the user was deleted between auth and now.
            let persist_result = billing::set_stripe_customer(&state.db, user_id, &cid).await;
            let persist_failed = match &persist_result {
                Ok(true) => false,
                Ok(false) => {
                    tracing::error!(
                        user_id = %user_id,
                        customer_id = %cid,
                        "set_stripe_customer matched 0 rows (user vanished); deleting orphan"
                    );
                    true
                }
                Err(e) => {
                    tracing::error!(
                        user_id = %user_id,
                        customer_id = %cid,
                        error = %e,
                        "set_stripe_customer failed after Stripe customer create; deleting orphan"
                    );
                    true
                }
            };
            if persist_failed {
                if let Err(del_err) = stripe_delete_customer(
                    &state.http_client,
                    stripe_key,
                    &cid,
                    &state.config.stripe_api_base,
                )
                .await
                {
                    tracing::error!(
                        customer_id = %cid,
                        error = %del_err,
                        "stripe delete-customer compensation failed; orphan customer may exist"
                    );
                }
                return Err(match persist_result {
                    Err(e) => e.into(),
                    Ok(_) => AppError::NotFound("user not found".into()),
                });
            }
            cid
        }
    };

    // Build success/cancel URLs.
    let success_url = format!(
        "{}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
        state.config.dashboard_url.trim_end_matches('/')
    );
    let cancel_url = format!(
        "{}/billing/new-team",
        state.config.dashboard_url.trim_end_matches('/')
    );

    let (session_id, checkout_url) = stripe_create_checkout_session(
        &state.http_client,
        stripe_key,
        &customer_id,
        price_id,
        req.seats,
        &success_url,
        &cancel_url,
        &state.config.stripe_api_base,
    )
    .await?;

    // Store the pending checkout so the webhook can provision the org. If
    // the DB insert fails (transient connectivity glitch, etc.) the Stripe
    // session is already live — if the user paid, the webhook would find no
    // matching pending_checkout and the customer would be charged with
    // nothing provisioned. Compensate by expiring the Stripe session on
    // failure so the user can't pay it. Best-effort: if the expire call
    // also fails we still surface the original error to the user.
    if let Err(e) = billing::insert_pending_checkout(
        &state.db,
        &session_id,
        user_id,
        req.org_name.trim(),
        slug,
        req.seats as i32,
        currency,
    )
    .await
    {
        tracing::error!(
            session_id,
            error = %e,
            "insert_pending_checkout failed after Stripe session created; expiring session"
        );
        if let Err(expire_err) = stripe_expire_checkout_session(
            &state.http_client,
            stripe_key,
            &session_id,
            &state.config.stripe_api_base,
        )
        .await
        {
            tracing::error!(
                session_id,
                error = %expire_err,
                "stripe expire-session compensation failed; orphan session may exist"
            );
        }
        return Err(e.into());
    }

    Ok(Json(CheckoutResponse { url: checkout_url }))
}

// ---------------------------------------------------------------------------
// Checkout status
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct CheckoutStatusResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_to: Option<String>,
}

/// GET /v1/billing/checkout/{session_id}/status — polled by the success page.
async fn get_checkout_status(
    State(state): State<AppState>,
    auth: AuthContext,
    Path(session_id): Path<String>,
) -> Result<Json<CheckoutStatusResponse>> {
    let user_id = auth
        .user_id
        .ok_or_else(|| AppError::Unauthorized("multi-org session required".into()))?;

    let checkout = billing::get_pending_checkout_any(&state.db, &session_id)
        .await?
        .ok_or_else(|| AppError::NotFound("checkout not found".into()))?;

    // Callers can only poll their own checkout.
    if checkout.user_id != user_id {
        return Err(AppError::Forbidden("not your checkout".into()));
    }

    if let Some(org_id) = checkout.fulfilled_org_id {
        let org = org_repo::get_by_id(&state.db, org_id).await?;
        let redirect_to = org.as_ref().map(|o| redirect_for_org(&state, o));
        return Ok(Json(CheckoutStatusResponse {
            status: "fulfilled",
            org_id: Some(org_id),
            redirect_to,
        }));
    }

    Ok(Json(CheckoutStatusResponse {
        status: "pending",
        org_id: None,
        redirect_to: None,
    }))
}

// ---------------------------------------------------------------------------
// Customer Portal
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreatePortalRequest {
    org_id: Uuid,
}

#[derive(Serialize)]
struct PortalResponse {
    url: String,
}

/// POST /v1/billing/portal — create a Stripe Customer Portal session so the
/// user can manage seats, payment methods, and cancellation.
async fn create_portal(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(req): Json<CreatePortalRequest>,
) -> Result<Json<PortalResponse>> {
    let user_id = auth
        .user_id
        .ok_or_else(|| AppError::Unauthorized("multi-org session required".into()))?;

    let stripe_key = state
        .config
        .stripe_secret_key
        .as_deref()
        .ok_or_else(|| AppError::Internal("billing not configured".into()))?;

    // Verify there's an active subscription for this org.
    let sub = billing::get_org_subscription(&state.db, req.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("no subscription for this org".into()))?;

    // Verify the caller has a Stripe customer (they created the subscription).
    let customer_id = billing::get_stripe_customer(&state.db, user_id)
        .await?
        .ok_or_else(|| AppError::Forbidden("not the billing contact for this org".into()))?;

    if customer_id != sub.stripe_customer_id {
        return Err(AppError::Forbidden(
            "not the billing contact for this org".into(),
        ));
    }

    let return_url = format!("{}/org", state.config.dashboard_url.trim_end_matches('/'));
    let url = stripe_create_portal_session(
        &state.http_client,
        stripe_key,
        &customer_id,
        &return_url,
        &state.config.stripe_api_base,
    )
    .await?;

    Ok(Json(PortalResponse { url }))
}

// ---------------------------------------------------------------------------
// Subscription info
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct SubscriptionResponse {
    org_id: Uuid,
    plan: String,
    seats: i32,
    status: String,
    currency: String,
    current_period_end: Option<i64>,
    cancel_at_period_end: bool,
}

/// GET /v1/orgs/{id}/subscription — admin-only subscription status.
async fn get_subscription(
    AdminAcl(acl): AdminAcl,
    State(state): State<AppState>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<SubscriptionResponse>> {
    if acl.org_id != org_id {
        return Err(AppError::Forbidden("org mismatch".into()));
    }

    let sub = billing::get_org_subscription(&state.db, org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("no subscription".into()))?;

    Ok(Json(SubscriptionResponse {
        org_id: sub.org_id,
        plan: sub.plan,
        seats: sub.seats,
        status: sub.status,
        currency: sub.currency,
        current_period_end: sub.current_period_end.map(|t| t.unix_timestamp()),
        cancel_at_period_end: sub.cancel_at_period_end,
    }))
}

// ---------------------------------------------------------------------------
// Stripe webhook
// ---------------------------------------------------------------------------

/// POST /v1/webhooks/stripe — receives Stripe events. Signature verified
/// against STRIPE_WEBHOOK_SECRET using HMAC-SHA256 before processing.
pub async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode> {
    let webhook_secret = state
        .config
        .stripe_webhook_secret
        .as_deref()
        .ok_or_else(|| AppError::Internal("webhook secret not configured".into()))?;

    let sig_header = headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("missing Stripe-Signature".into()))?;

    verify_stripe_signature(webhook_secret, &body, sig_header)
        .map_err(|_| AppError::BadRequest("invalid webhook signature".into()))?;

    let event: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| AppError::BadRequest("invalid JSON".into()))?;

    let event_type = event["type"].as_str().unwrap_or("");
    let data = &event["data"]["object"];

    match event_type {
        "checkout.session.completed" => {
            handle_checkout_completed(&state, data).await?;
        }
        "customer.subscription.updated" => {
            handle_subscription_updated(&state, data).await?;
        }
        "customer.subscription.deleted" => {
            handle_subscription_deleted(&state, data).await?;
        }
        _ => {}
    }

    Ok(StatusCode::OK)
}

async fn handle_checkout_completed(state: &AppState, session: &serde_json::Value) -> Result<()> {
    let session_id = session["id"].as_str().unwrap_or("");
    let subscription_id = session["subscription"].as_str().unwrap_or("");
    let customer_id = session["customer"].as_str().unwrap_or("");

    if session_id.is_empty() || subscription_id.is_empty() || customer_id.is_empty() {
        tracing::warn!(
            session_id,
            "stripe webhook checkout.session.completed missing ids"
        );
        return Ok(());
    }

    // Use _any variant so late Stripe retries (after the 2h expiry window) still work.
    let checkout = match billing::get_pending_checkout_any(&state.db, session_id).await? {
        Some(c) => c,
        None => {
            tracing::warn!(
                session_id,
                "checkout.session.completed: no matching pending_checkout"
            );
            return Ok(());
        }
    };

    if checkout.fulfilled_org_id.is_some() {
        tracing::info!(session_id, "checkout already fulfilled; skipping");
        return Ok(());
    }

    // Create the org. A unique violation has two possible causes:
    //   (a) A retry of THIS webhook (same checkout, same user) — proceed
    //       with idempotent provisioning.
    //   (b) A slug collision with a DIFFERENT user's already-provisioned org
    //       — must NOT provision this user there or they'd become admin of
    //       someone else's org. Stripe already charged them; ACK the event,
    //       leave the pending checkout unfulfilled, and log loudly so an
    //       operator can refund.
    // Distinguished by checking whether the existing org has any identity
    // owned by this checkout's user_id.
    let org = match overslash_db::repos::org::create(
        &state.db,
        &checkout.org_name,
        &checkout.org_slug,
    )
    .await
    {
        Ok(o) => o,
        Err(sqlx::Error::Database(ref de)) if de.is_unique_violation() => {
            let existing = overslash_db::repos::org::get_by_slug(&state.db, &checkout.org_slug)
                .await?
                .ok_or_else(|| AppError::Internal("slug conflict but org not found".into()))?;
            let owns_existing = overslash_db::repos::identity::find_by_org_and_user(
                &state.db,
                existing.id,
                checkout.user_id,
            )
            .await?
            .is_some();
            if !owns_existing {
                tracing::error!(
                    session_id,
                    org_slug = %checkout.org_slug,
                    existing_org_id = %existing.id,
                    user_id = %checkout.user_id,
                    "slug collision: org exists for a different user; \
                     leaving checkout unfulfilled — operator must refund the charge"
                );
                return Ok(());
            }
            tracing::info!(
                session_id,
                org_slug = %checkout.org_slug,
                "checkout retry: org already exists for this user, continuing idempotent provision"
            );
            existing
        }
        Err(e) => return Err(AppError::from(e)),
    };

    // Provision identity, bootstrap, membership — but only if this org isn't
    // already provisioned for the user. `provision_new_org_contents` is NOT
    // idempotent (identity::create_with_email + membership::create both
    // collide on uniqueness on retry), so on a Stripe re-delivery we must
    // skip it. The (org_id, user_id) identity row is the ground-truth marker.
    //
    // Concurrent-delivery race: two webhook deliveries for the same event can
    // both pass this check before either inserts. The second `provision_new_org_contents`
    // call would 23505. Catch the unique-violation and treat it as success —
    // a sibling invocation already provisioned us.
    if overslash_db::repos::identity::find_by_org_and_user(&state.db, org.id, checkout.user_id)
        .await?
        .is_none()
    {
        match provision_new_org_contents(state, org.id, Some(checkout.user_id)).await {
            Ok(_) => {}
            Err(AppError::Database(sqlx::Error::Database(ref de))) if de.is_unique_violation() => {
                tracing::info!(
                    session_id,
                    org_id = %org.id,
                    "concurrent webhook delivery already provisioned org; continuing"
                );
            }
            Err(e) => return Err(e),
        }
    } else {
        tracing::info!(
            session_id,
            org_id = %org.id,
            "checkout retry: org already provisioned for user, skipping bootstrap"
        );
    }

    // Fetch subscription details from Stripe for seats/period info.
    let stripe_key = state.config.stripe_secret_key.as_deref().unwrap_or("");
    let sub_details = fetch_stripe_subscription(
        &state.http_client,
        stripe_key,
        subscription_id,
        &state.config.stripe_api_base,
    )
    .await?;

    let seats = sub_details
        .get("items")
        .and_then(|i| i["data"][0]["quantity"].as_i64())
        .unwrap_or(checkout.seats as i64) as i32;
    let status = sub_details["status"].as_str().unwrap_or("active");
    let period_start = sub_details["current_period_start"]
        .as_i64()
        .and_then(|ts| OffsetDateTime::from_unix_timestamp(ts).ok());
    let period_end = sub_details["current_period_end"]
        .as_i64()
        .and_then(|ts| OffsetDateTime::from_unix_timestamp(ts).ok());
    let cancel_at_period_end = sub_details["cancel_at_period_end"]
        .as_bool()
        .unwrap_or(false);

    billing::upsert_org_subscription(
        &state.db,
        org.id,
        billing::UpsertSubscription {
            stripe_subscription_id: subscription_id,
            stripe_customer_id: customer_id,
            seats,
            status,
            currency: &checkout.currency,
            current_period_start: period_start,
            current_period_end: period_end,
            cancel_at_period_end,
        },
    )
    .await?;

    billing::fulfill_pending_checkout(&state.db, session_id, org.id).await?;

    tracing::info!(
        session_id,
        org_id = %org.id,
        org_slug = %org.slug,
        "billing: checkout fulfilled, org provisioned"
    );
    Ok(())
}

async fn handle_subscription_updated(state: &AppState, sub: &serde_json::Value) -> Result<()> {
    let sub_id = sub["id"].as_str().unwrap_or("");
    let status = sub["status"].as_str().unwrap_or("active");
    let seats = sub["items"]["data"][0]["quantity"].as_i64().unwrap_or(2) as i32;
    let period_start = sub["current_period_start"]
        .as_i64()
        .and_then(|ts| OffsetDateTime::from_unix_timestamp(ts).ok());
    let period_end = sub["current_period_end"]
        .as_i64()
        .and_then(|ts| OffsetDateTime::from_unix_timestamp(ts).ok());
    let cancel_at_period_end = sub["cancel_at_period_end"].as_bool().unwrap_or(false);

    billing::update_subscription_status(
        &state.db,
        sub_id,
        status,
        seats,
        period_start,
        period_end,
        cancel_at_period_end,
    )
    .await?;
    Ok(())
}

async fn handle_subscription_deleted(state: &AppState, sub: &serde_json::Value) -> Result<()> {
    let sub_id = sub["id"].as_str().unwrap_or("");
    billing::cancel_subscription(&state.db, sub_id).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Stripe API helpers (uses reqwest + form encoding — no new dependencies)
// ---------------------------------------------------------------------------

async fn stripe_create_customer(
    client: &reqwest::Client,
    secret_key: &str,
    email: Option<&str>,
    name: Option<&str>,
    user_id: Uuid,
    api_base: &str,
) -> Result<String> {
    let mut params = vec![("metadata[user_id]", user_id.to_string())];
    if let Some(e) = email {
        params.push(("email", e.to_string()));
    }
    if let Some(n) = name {
        params.push(("name", n.to_string()));
    }

    let resp = client
        .post(format!("{api_base}/customers"))
        .basic_auth(secret_key, Option::<&str>::None)
        .form(&params)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("stripe customer create: {e}")))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!("stripe customer error: {body}")));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("stripe customer parse: {e}")))?;
    json["id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Internal("stripe customer: no id".into()))
}

#[allow(clippy::too_many_arguments)]
async fn stripe_create_checkout_session(
    client: &reqwest::Client,
    secret_key: &str,
    customer_id: &str,
    price_id: &str,
    seats: u32,
    success_url: &str,
    cancel_url: &str,
    api_base: &str,
) -> Result<(String, String)> {
    let seats_str = seats.to_string();
    let params = [
        ("mode", "subscription"),
        ("customer", customer_id),
        ("line_items[0][price]", price_id),
        ("line_items[0][quantity]", &seats_str),
        ("automatic_tax[enabled]", "true"),
        ("success_url", success_url),
        ("cancel_url", cancel_url),
    ];

    let resp = client
        .post(format!("{api_base}/checkout/sessions"))
        .basic_auth(secret_key, Option::<&str>::None)
        .form(&params)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("stripe checkout create: {e}")))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!("stripe checkout error: {body}")));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("stripe checkout parse: {e}")))?;
    let id = json["id"]
        .as_str()
        .ok_or_else(|| AppError::Internal("stripe checkout: no id".into()))?
        .to_string();
    let url = json["url"]
        .as_str()
        .ok_or_else(|| AppError::Internal("stripe checkout: no url".into()))?
        .to_string();
    Ok((id, url))
}

/// Resolve a Stripe lookup key to a literal price ID. Called at startup when
/// `cloud_billing` is enabled so a misconfigured deploy (typo in lookup key,
/// price not yet created in Stripe Dashboard, etc.) fails fast instead of at
/// first checkout. Returns the single matching active price's ID.
pub async fn resolve_stripe_price_by_lookup_key(
    client: &reqwest::Client,
    secret_key: &str,
    lookup_key: &str,
    api_base: &str,
) -> Result<String> {
    // Stripe wants `lookup_keys[]=<key>` as a repeated query param. URL-encode
    // the lookup key (it can contain characters like `_` which are safe, but
    // be defensive in case future operators pick something with reserved
    // characters).
    let encoded = urlencoding::encode(lookup_key);
    let url = format!("{api_base}/prices?lookup_keys[]={encoded}&active=true&limit=1");
    let resp = client
        .get(url)
        .basic_auth(secret_key, Option::<&str>::None)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("stripe price lookup: {e}")))?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!("stripe price lookup: {body}")));
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("stripe price parse: {e}")))?;
    let id = json["data"][0]["id"].as_str().ok_or_else(|| {
        AppError::Internal(format!(
            "no active Stripe price for lookup_key={lookup_key}"
        ))
    })?;
    Ok(id.to_string())
}

/// Delete a Stripe Customer — used to compensate when the local
/// `set_stripe_customer` insert fails after the customer has been created.
/// Without this, retrying the checkout would create a second orphan customer
/// in Stripe.
async fn stripe_delete_customer(
    client: &reqwest::Client,
    secret_key: &str,
    customer_id: &str,
    api_base: &str,
) -> Result<()> {
    let resp = client
        .delete(format!("{api_base}/customers/{customer_id}"))
        .basic_auth(secret_key, Option::<&str>::None)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("stripe delete customer: {e}")))?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "stripe delete customer error: {body}"
        )));
    }
    Ok(())
}

/// Expire a Stripe Checkout Session — used to compensate when the local
/// pending_checkouts insert fails after the session has been created. After
/// expiry the user's payment URL stops working, preventing a charge with no
/// matching local record.
async fn stripe_expire_checkout_session(
    client: &reqwest::Client,
    secret_key: &str,
    session_id: &str,
    api_base: &str,
) -> Result<()> {
    let resp = client
        .post(format!("{api_base}/checkout/sessions/{session_id}/expire"))
        .basic_auth(secret_key, Option::<&str>::None)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("stripe expire session: {e}")))?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "stripe expire session error: {body}"
        )));
    }
    Ok(())
}

async fn stripe_create_portal_session(
    client: &reqwest::Client,
    secret_key: &str,
    customer_id: &str,
    return_url: &str,
    api_base: &str,
) -> Result<String> {
    let params = [("customer", customer_id), ("return_url", return_url)];

    let resp = client
        .post(format!("{api_base}/billing_portal/sessions"))
        .basic_auth(secret_key, Option::<&str>::None)
        .form(&params)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("stripe portal create: {e}")))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!("stripe portal error: {body}")));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AppError::Internal(format!("stripe portal parse: {e}")))?;
    json["url"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Internal("stripe portal: no url".into()))
}

async fn fetch_stripe_subscription(
    client: &reqwest::Client,
    secret_key: &str,
    subscription_id: &str,
    api_base: &str,
) -> Result<serde_json::Value> {
    let resp = client
        .get(format!("{api_base}/subscriptions/{subscription_id}"))
        .basic_auth(secret_key, Option::<&str>::None)
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("stripe fetch subscription: {e}")))?;
    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(AppError::Internal(format!(
            "stripe subscription {subscription_id} error: {body}"
        )));
    }
    resp.json()
        .await
        .map_err(|e| AppError::Internal(format!("stripe subscription parse: {e}")))
}

// ---------------------------------------------------------------------------
// Webhook signature verification
// ---------------------------------------------------------------------------

/// Stripe's recommended replay-attack tolerance: reject events whose `t=`
/// timestamp is more than this many seconds away from server time. Matches
/// the default in the official Stripe libraries.
const STRIPE_TIMESTAMP_TOLERANCE_SECS: i64 = 5 * 60;

fn verify_stripe_signature(
    secret: &str,
    payload: &[u8],
    sig_header: &str,
) -> std::result::Result<(), ()> {
    verify_stripe_signature_at(
        secret,
        payload,
        sig_header,
        OffsetDateTime::now_utc().unix_timestamp(),
    )
}

/// Same as `verify_stripe_signature` but with an injectable "now" for tests.
fn verify_stripe_signature_at(
    secret: &str,
    payload: &[u8],
    sig_header: &str,
    now_unix: i64,
) -> std::result::Result<(), ()> {
    // Parse `t=...` and `v1=...` from the header (comma-separated key=value pairs).
    let mut timestamp: Option<&str> = None;
    let mut signatures: Vec<&str> = Vec::new();

    for part in sig_header.split(',') {
        if let Some(t) = part.trim().strip_prefix("t=") {
            timestamp = Some(t);
        } else if let Some(v) = part.trim().strip_prefix("v1=") {
            signatures.push(v);
        }
    }

    let t = timestamp.ok_or(())?;
    if signatures.is_empty() {
        return Err(());
    }

    // Reject events whose timestamp is too far from now in either direction.
    // This blocks replay attacks where an attacker captures a valid (signed)
    // payload and re-sends it later.
    let t_secs: i64 = t.parse().map_err(|_| ())?;
    if (now_unix - t_secs).abs() > STRIPE_TIMESTAMP_TOLERANCE_SECS {
        return Err(());
    }

    // signed_payload = "<timestamp>.<body>"
    let mut signed_payload = t.as_bytes().to_vec();
    signed_payload.push(b'.');
    signed_payload.extend_from_slice(payload);

    let mut mac: Hmac<Sha256> = Hmac::new_from_slice(secret.as_bytes()).map_err(|_| ())?;
    mac.update(&signed_payload);
    let expected = mac.finalize().into_bytes();
    let expected_hex = hex::encode(expected);

    // Constant-time comparison across all v1 signatures.
    let matches = signatures
        .iter()
        .any(|sig| constant_time_eq(sig.as_bytes(), expected_hex.as_bytes()));

    if matches { Ok(()) } else { Err(()) }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
