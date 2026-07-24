//! Stripe Checkout Session creation and polling, the Customer Portal
//! session endpoint, and the org subscription read.

use super::stripe_client::*;
use super::*;

// ---------------------------------------------------------------------------
// Checkout
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(super) struct CreateCheckoutRequest {
    org_name: String,
    org_slug: String,
    seats: u32,
    currency: String,
    /// When true, the checkout session opens a Stripe free trial
    /// (`subscription_data[trial_period_days]` = `trial_default_duration_days`):
    /// a card is still collected, but the first charge is deferred by the trial
    /// window. Drives the "Not sure. Trial for free for a month" toggle.
    #[serde(default)]
    trial: bool,
}

#[derive(Serialize)]
pub(super) struct CheckoutResponse {
    url: String,
}

/// POST /v1/billing/checkout — create a Stripe Checkout Session for a new
/// Team org. Returns the Stripe-hosted URL to redirect the user to.
pub(super) async fn create_checkout(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
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
    if org_repo::get_by_slug(state.db(&ext), slug).await?.is_some() {
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
    let customer_id = match billing::get_stripe_customer(state.db(&ext), user_id).await? {
        Some(id) => id,
        None => {
            let user = overslash_db::repos::user::get_by_id(state.db(&ext), user_id)
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
            let persist_result = billing::set_stripe_customer(state.db(&ext), user_id, &cid).await;
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

    // A self-serve trial collects a card but defers the first charge by
    // `trial_default_duration_days` (Stripe emits status='trialing' until then).
    let trial_period_days = if req.trial {
        Some(state.config.trial_default_duration_days)
    } else {
        None
    };

    let (session_id, checkout_url) = stripe_create_checkout_session(
        &state.http_client,
        stripe_key,
        &customer_id,
        price_id,
        req.seats,
        &success_url,
        &cancel_url,
        &state.config.stripe_api_base,
        trial_period_days,
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
        state.db(&ext),
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
pub(super) struct CheckoutStatusResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    org_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_to: Option<String>,
}

/// GET /v1/billing/checkout/{session_id}/status — polled by the success page.
pub(super) async fn get_checkout_status(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    Path(session_id): Path<String>,
) -> Result<Json<CheckoutStatusResponse>> {
    let user_id = auth
        .user_id
        .ok_or_else(|| AppError::Unauthorized("multi-org session required".into()))?;

    let checkout = billing::get_pending_checkout_any(state.db(&ext), &session_id)
        .await?
        .ok_or_else(|| AppError::NotFound("checkout not found".into()))?;

    // Callers can only poll their own checkout.
    if checkout.user_id != user_id {
        return Err(AppError::Forbidden("not your checkout".into()));
    }

    if let Some(org_id) = checkout.fulfilled_org_id {
        let org = org_repo::get_by_id(state.db(&ext), org_id).await?;
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
pub(super) struct CreatePortalRequest {
    org_id: Uuid,
}

#[derive(Serialize)]
pub(super) struct PortalResponse {
    url: String,
}

/// POST /v1/billing/portal — create a Stripe Customer Portal session so the
/// user can manage seats, payment methods, and cancellation.
pub(super) async fn create_portal(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
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
    let sub = billing::get_org_subscription(state.db(&ext), req.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("no subscription for this org".into()))?;

    // Verify the caller has a Stripe customer (they created the subscription).
    let customer_id = billing::get_stripe_customer(state.db(&ext), user_id)
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
pub(super) struct SubscriptionResponse {
    org_id: Uuid,
    plan: String,
    seats: i32,
    status: String,
    currency: String,
    current_period_end: Option<i64>,
    cancel_at_period_end: bool,
}

/// GET /v1/orgs/{id}/subscription — admin-only subscription status.
pub(super) async fn get_subscription(
    AdminAcl(acl): AdminAcl,
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    Path(org_id): Path<Uuid>,
) -> Result<Json<SubscriptionResponse>> {
    if acl.org_id != org_id {
        return Err(AppError::Forbidden("org mismatch".into()));
    }

    // Free-unlimited orgs have no Stripe subscription row by design. Return a
    // synthetic body so the dashboard can render a "Courtesy plan" badge in
    // place of the billing controls.
    if state
        .free_unlimited_cache(&ext)
        .is_free_unlimited(state.db(&ext), org_id)
        .await
    {
        return Ok(Json(SubscriptionResponse {
            org_id,
            plan: "free_unlimited".into(),
            seats: 0,
            status: "active".into(),
            currency: String::new(),
            current_period_end: None,
            cancel_at_period_end: false,
        }));
    }

    // Instance-admin-managed trial orgs (plan='trial') have no Stripe row.
    // Return a synthetic body so the dashboard renders the trial banner and
    // days-remaining. `trialing` while active, `trial_expired` once past the
    // window (enforcement is banner-only — see DECISIONS D25).
    use crate::services::billing_tier::TrialStatus;
    match state
        .free_unlimited_cache(&ext)
        .trial_status(state.db(&ext), org_id, OffsetDateTime::now_utc())
        .await
    {
        TrialStatus::Active { ends_at } => {
            return Ok(Json(SubscriptionResponse {
                org_id,
                plan: "trial".into(),
                seats: 0,
                status: "trialing".into(),
                currency: String::new(),
                current_period_end: Some(ends_at.unix_timestamp()),
                cancel_at_period_end: false,
            }));
        }
        TrialStatus::Expired { ends_at } => {
            return Ok(Json(SubscriptionResponse {
                org_id,
                plan: "trial".into(),
                seats: 0,
                status: "trial_expired".into(),
                currency: String::new(),
                current_period_end: Some(ends_at.unix_timestamp()),
                cancel_at_period_end: false,
            }));
        }
        TrialStatus::None => {}
    }

    let sub = billing::get_org_subscription(state.db(&ext), org_id)
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
