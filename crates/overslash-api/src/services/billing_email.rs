//! Billing transactional emails: receipt, dunning, cancellation. Fired from
//! the Stripe webhook dispatch in `routes/billing.rs`. **Exempt from
//! unsubscribe by policy** (TODO.md §1.1) — these senders never consult
//! `users.welcome_emails_unsubscribed_at`, never mint
//! `email_unsubscribe_tokens`, and never set RFC 8058 `List-Unsubscribe`
//! headers.
//!
//! Idempotency is enforced by `billing_email_log` keyed on
//! `(stripe_event_id, kind)`: insert-first via [`billing_email_log::try_claim`],
//! render + send, then stamp `sent_at`. A Stripe re-delivery hits the UNIQUE
//! and silently no-ops. A transient mailer failure leaves `sent_at` NULL —
//! the row is the audit signal for manual replay; we deliberately don't
//! delete it on failure so the next webhook retry doesn't double-send.
//!
//! All public entry points return `()` so the webhook handler can't
//! accidentally propagate failure into a 5xx (which would re-trigger the
//! non-idempotent side effects in `handle_subscription_deleted` etc.).

use std::collections::HashMap;

use overslash_core::email::{
    EmailMessage, INVOICE_PAID_HTML, INVOICE_PAID_SUBJECT, INVOICE_PAYMENT_FAILED_HTML,
    INVOICE_PAYMENT_FAILED_SUBJECT, SUBSCRIPTION_CANCELED_HTML, SUBSCRIPTION_CANCELED_SUBJECT,
    render,
};
use overslash_db::repos::{billing as billing_repo, billing_email_log, org as org_repo};
use serde_json::Value;
use time::OffsetDateTime;
use time::macros::format_description;
use uuid::Uuid;

use crate::AppState;

const KIND_INVOICE_PAID: &str = "invoice_paid";
const KIND_INVOICE_PAYMENT_FAILED: &str = "invoice_payment_failed";
const KIND_SUBSCRIPTION_CANCELED: &str = "subscription_canceled";

/// Send the receipt on `invoice.payment_succeeded`. Best-effort: any failure
/// (no matching user, mailer down, etc.) is logged at `warn` and swallowed.
pub async fn send_invoice_paid(state: &AppState, event_id: &str, invoice: &Value) {
    let Some(customer_id) = invoice["customer"].as_str() else {
        tracing::warn!(event_id, "invoice_paid: missing customer id on payload");
        return;
    };

    let Some(ctx) = resolve_context(state, customer_id, KIND_INVOICE_PAID).await else {
        return;
    };

    let Some(log_id) = claim(state, event_id, KIND_INVOICE_PAID, ctx.user_id).await else {
        return;
    };

    let amount_minor = invoice["amount_paid"].as_i64().unwrap_or(0);
    let currency = invoice["currency"].as_str().unwrap_or(&ctx.currency);
    let invoice_number = invoice["number"].as_str().unwrap_or("");
    let period_end_display = unix_to_date(invoice["period_end"].as_i64())
        .or_else(|| ctx.current_period_end.and_then(format_date))
        .unwrap_or_else(|| "—".to_string());
    let hosted_invoice_url = invoice["hosted_invoice_url"].as_str().unwrap_or("");
    let billing_portal_url = state.config.dashboard_url_for("/org/billing");

    let mut params: HashMap<String, Value> = HashMap::new();
    params.insert("org_name".into(), Value::String(ctx.org_name.clone()));
    params.insert(
        "amount_display".into(),
        Value::String(format_money(amount_minor, currency)),
    );
    params.insert(
        "currency_upper".into(),
        Value::String(currency.to_uppercase()),
    );
    if !invoice_number.is_empty() {
        params.insert(
            "invoice_number".into(),
            Value::String(invoice_number.into()),
        );
    }
    params.insert(
        "period_end_display".into(),
        Value::String(period_end_display),
    );
    params.insert(
        "hosted_invoice_url".into(),
        Value::String(hosted_invoice_url.to_string()),
    );
    params.insert(
        "billing_portal_url".into(),
        Value::String(billing_portal_url),
    );

    deliver(
        state,
        log_id,
        event_id,
        KIND_INVOICE_PAID,
        ctx.email,
        INVOICE_PAID_SUBJECT,
        render(INVOICE_PAID_HTML, &params),
    )
    .await;
}

/// Send the dunning email on `invoice.payment_failed`.
pub async fn send_invoice_payment_failed(state: &AppState, event_id: &str, invoice: &Value) {
    let Some(customer_id) = invoice["customer"].as_str() else {
        tracing::warn!(
            event_id,
            "invoice_payment_failed: missing customer id on payload"
        );
        return;
    };

    let Some(ctx) = resolve_context(state, customer_id, KIND_INVOICE_PAYMENT_FAILED).await else {
        return;
    };

    let Some(log_id) = claim(state, event_id, KIND_INVOICE_PAYMENT_FAILED, ctx.user_id).await
    else {
        return;
    };

    let amount_minor = invoice["amount_due"].as_i64().unwrap_or(0);
    let currency = invoice["currency"].as_str().unwrap_or(&ctx.currency);
    let attempt_count = invoice["attempt_count"].as_i64().unwrap_or(1);
    let next_attempt_display = unix_to_date(invoice["next_payment_attempt"].as_i64());
    let billing_portal_url = state.config.dashboard_url_for("/org/billing");

    let mut params: HashMap<String, Value> = HashMap::new();
    params.insert("org_name".into(), Value::String(ctx.org_name.clone()));
    params.insert(
        "amount_display".into(),
        Value::String(format_money(amount_minor, currency)),
    );
    params.insert(
        "currency_upper".into(),
        Value::String(currency.to_uppercase()),
    );
    params.insert(
        "attempt_count".into(),
        Value::String(attempt_count.to_string()),
    );
    if let Some(s) = next_attempt_display {
        params.insert("next_attempt_display".into(), Value::String(s));
    }
    params.insert(
        "billing_portal_url".into(),
        Value::String(billing_portal_url),
    );

    deliver(
        state,
        log_id,
        event_id,
        KIND_INVOICE_PAYMENT_FAILED,
        ctx.email,
        INVOICE_PAYMENT_FAILED_SUBJECT,
        render(INVOICE_PAYMENT_FAILED_HTML, &params),
    )
    .await;
}

/// Send the cancellation notice on `customer.subscription.deleted`. Invoked
/// AFTER the DB `cancel_subscription` so we read the final state.
pub async fn send_subscription_canceled(state: &AppState, event_id: &str, sub: &Value) {
    let Some(customer_id) = sub["customer"].as_str() else {
        tracing::warn!(
            event_id,
            "subscription_canceled: missing customer id on payload"
        );
        return;
    };

    let Some(ctx) = resolve_context(state, customer_id, KIND_SUBSCRIPTION_CANCELED).await else {
        return;
    };

    let Some(log_id) = claim(state, event_id, KIND_SUBSCRIPTION_CANCELED, ctx.user_id).await else {
        return;
    };

    // current_period_end on the deleted subscription is the access cutoff. If
    // the row's `current_period_end` was never set (free trial canceled
    // immediately, exotic states), fall back to the event payload.
    let access_until_display = ctx
        .current_period_end
        .and_then(format_date)
        .or_else(|| unix_to_date(sub["current_period_end"].as_i64()));
    let billing_portal_url = state.config.dashboard_url_for("/org/billing");

    let mut params: HashMap<String, Value> = HashMap::new();
    params.insert("org_name".into(), Value::String(ctx.org_name.clone()));
    if let Some(s) = access_until_display {
        params.insert("access_until_display".into(), Value::String(s));
    }
    params.insert(
        "billing_portal_url".into(),
        Value::String(billing_portal_url),
    );

    deliver(
        state,
        log_id,
        event_id,
        KIND_SUBSCRIPTION_CANCELED,
        ctx.email,
        SUBSCRIPTION_CANCELED_SUBJECT,
        render(SUBSCRIPTION_CANCELED_HTML, &params),
    )
    .await;
}

struct BillingContext {
    user_id: Uuid,
    email: String,
    org_name: String,
    currency: String,
    current_period_end: Option<OffsetDateTime>,
}

/// Resolve recipient + org context from a Stripe customer id. Logs and
/// returns `None` for the silent-skip cases: unknown customer, no email on
/// the user row, missing org_subscription row, missing org row.
async fn resolve_context(
    state: &AppState,
    customer_id: &str,
    kind: &'static str,
) -> Option<BillingContext> {
    let user = match billing_repo::get_user_by_stripe_customer(&state.db, customer_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            tracing::warn!(
                kind,
                customer_id,
                "billing email: no user for stripe_customer_id"
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(kind, customer_id, error = %e, "billing email: user lookup failed");
            return None;
        }
    };
    let (user_id, email_opt, _display_name) = user;
    let email = match email_opt.filter(|s| !s.is_empty()) {
        Some(e) => e,
        None => {
            tracing::warn!(kind, %user_id, "billing email: user has no email on file");
            return None;
        }
    };

    let sub = match billing_repo::get_org_subscription_by_customer(&state.db, customer_id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            tracing::warn!(
                kind,
                customer_id,
                "billing email: no org_subscription for customer"
            );
            return None;
        }
        Err(e) => {
            tracing::warn!(kind, customer_id, error = %e, "billing email: subscription lookup failed");
            return None;
        }
    };

    let org = match org_repo::get_by_id(&state.db, sub.org_id).await {
        Ok(Some(o)) => o,
        Ok(None) => {
            tracing::warn!(kind, org_id = %sub.org_id, "billing email: org row missing");
            return None;
        }
        Err(e) => {
            tracing::warn!(kind, org_id = %sub.org_id, error = %e, "billing email: org lookup failed");
            return None;
        }
    };

    Some(BillingContext {
        user_id,
        email,
        org_name: org.name,
        currency: sub.currency,
        current_period_end: sub.current_period_end,
    })
}

async fn claim(
    state: &AppState,
    event_id: &str,
    kind: &'static str,
    user_id: Uuid,
) -> Option<Uuid> {
    match billing_email_log::try_claim(&state.db, event_id, kind, user_id).await {
        Ok(Some(id)) => Some(id),
        Ok(None) => {
            // Already handled — Stripe retry. Silent.
            None
        }
        Err(e) => {
            tracing::warn!(kind, event_id, error = %e, "billing email: claim failed");
            None
        }
    }
}

async fn deliver(
    state: &AppState,
    log_id: Uuid,
    event_id: &str,
    kind: &'static str,
    to: String,
    subject: &str,
    html: String,
) {
    // Billing emails carry NO `List-Unsubscribe` header — exempt by policy.
    let msg = EmailMessage {
        from: String::new(),
        to,
        subject: subject.to_string(),
        html,
        reply_to: None,
        headers: HashMap::new(),
    };

    if let Err(e) = state.mailer.send(msg).await {
        // Leave sent_at NULL so an operator can manually replay. We do NOT
        // delete the claim row — Stripe will retry this exact event id, and
        // we want the next retry to also be a no-op (the user can be reached
        // some other way; double-sending a receipt is worse than not sending).
        tracing::warn!(kind, event_id, %log_id, error = %e, "billing email send failed");
        return;
    }

    if let Err(e) = billing_email_log::mark_sent(&state.db, log_id).await {
        tracing::warn!(kind, event_id, %log_id, error = %e, "billing email: mark_sent failed");
    }
}

/// `4000` USD → `$40.00`. EUR/GBP use locale symbols; anything else falls
/// back to plain `<amount> <CCY>` (e.g. `40.00 SEK`). Kept narrow on purpose
/// — a real localization story is post-launch.
fn format_money(amount_minor: i64, currency: &str) -> String {
    let major = amount_minor as f64 / 100.0;
    match currency.to_uppercase().as_str() {
        "USD" | "CAD" | "AUD" | "NZD" => format!("${major:.2}"),
        "EUR" => format!("€{major:.2}"),
        "GBP" => format!("£{major:.2}"),
        other => format!("{major:.2} {other}"),
    }
}

fn unix_to_date(ts: Option<i64>) -> Option<String> {
    let dt = OffsetDateTime::from_unix_timestamp(ts?).ok()?;
    format_date(dt)
}

/// `2026-05-12`. ISO 8601 keeps the email locale-agnostic; we don't try to
/// guess the recipient's date-format preference.
fn format_date(dt: OffsetDateTime) -> Option<String> {
    let fmt = format_description!("[year]-[month]-[day]");
    dt.date().format(&fmt).ok()
}
