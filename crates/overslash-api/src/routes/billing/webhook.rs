//! `POST /v1/webhooks/stripe` — Stripe event intake, the per-event
//! handlers it dispatches to, and HMAC-SHA256 signature verification.

use super::stripe_client::*;
use super::*;

// ---------------------------------------------------------------------------
// Stripe webhook
// ---------------------------------------------------------------------------

/// POST /v1/webhooks/stripe — receives Stripe events. Signature verified
/// against STRIPE_WEBHOOK_SECRET using HMAC-SHA256 before processing.
pub async fn stripe_webhook(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
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
    let event_id = event["id"].as_str().unwrap_or("");

    // Reject signed-but-malformed events without an `id` up front. Stripe
    // always sets `evt_...`; falling through with the empty string would
    // funnel every such event to the same `(stripe_event_id, kind) = ("", …)`
    // idempotency key and silently drop the second one on the UNIQUE.
    if event_id.is_empty() {
        tracing::warn!(event_type, "stripe webhook missing event id");
        return Err(AppError::BadRequest("missing event id".into()));
    }

    match event_type {
        "checkout.session.completed" => {
            handle_checkout_completed(&state, &ext, data).await?;
        }
        "customer.subscription.updated" => {
            handle_subscription_updated(&state, &ext, data).await?;
        }
        "customer.subscription.deleted" => {
            handle_subscription_deleted(&state, &ext, data).await?;
            crate::services::billing_email::send_subscription_canceled(
                &state, &ext, event_id, data,
            )
            .await;
        }
        "invoice.payment_succeeded" => {
            if matches!(
                crate::services::billing_email::send_invoice_paid(&state, &ext, event_id, data)
                    .await,
                crate::services::billing_email::SendOutcome::Retryable,
            ) {
                // Webhook ordering race: known customer, but
                // checkout.session.completed hasn't yet provisioned the
                // org_subscriptions row. Stripe re-delivers on 5xx; the
                // claim row was released so the next retry can proceed.
                return Err(AppError::Internal(
                    "subscription not yet provisioned for known customer; awaiting checkout.session.completed".into(),
                ));
            }
        }
        "invoice.payment_failed" => {
            if matches!(
                crate::services::billing_email::send_invoice_payment_failed(
                    &state, &ext, event_id, data,
                )
                .await,
                crate::services::billing_email::SendOutcome::Retryable,
            ) {
                return Err(AppError::Internal(
                    "subscription not yet provisioned for known customer; awaiting checkout.session.completed".into(),
                ));
            }
        }
        _ => {}
    }

    Ok(StatusCode::OK)
}

async fn handle_checkout_completed(
    state: &AppState,
    ext: &axum::http::Extensions,
    session: &serde_json::Value,
) -> Result<()> {
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
    let checkout = match billing::get_pending_checkout_any(state.db(ext), session_id).await? {
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
        state.db(ext),
        &checkout.org_name,
        &checkout.org_slug,
        "standard",
    )
    .await
    {
        Ok(o) => o,
        Err(sqlx::Error::Database(ref de)) if de.is_unique_violation() => {
            let existing = overslash_db::repos::org::get_by_slug(state.db(ext), &checkout.org_slug)
                .await?
                .ok_or_else(|| AppError::Internal("slug conflict but org not found".into()))?;
            let owns_existing = overslash_db::repos::identity::find_by_org_and_user(
                state.db(ext),
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
    if overslash_db::repos::identity::find_by_org_and_user(state.db(ext), org.id, checkout.user_id)
        .await?
        .is_none()
    {
        match provision_new_org_contents(state, ext, org.id, Some(checkout.user_id)).await {
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
        state.db(ext),
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

    billing::fulfill_pending_checkout(state.db(ext), session_id, org.id).await?;

    tracing::info!(
        session_id,
        org_id = %org.id,
        org_slug = %org.slug,
        "billing: checkout fulfilled, org provisioned"
    );
    Ok(())
}

async fn handle_subscription_updated(
    state: &AppState,
    ext: &axum::http::Extensions,
    sub: &serde_json::Value,
) -> Result<()> {
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
        state.db(ext),
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

async fn handle_subscription_deleted(
    state: &AppState,
    ext: &axum::http::Extensions,
    sub: &serde_json::Value,
) -> Result<()> {
    let sub_id = sub["id"].as_str().unwrap_or("");
    billing::cancel_subscription(state.db(ext), sub_id).await?;
    Ok(())
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
