//! Welcome / first-login email. Categorized as **non-transactional** per
//! TODO.md §1.1 (billing receipts and approval-class email are transactional
//! and exempt from `welcome_emails_unsubscribed_at`; welcome is not).
//!
//! Fired from `provision_root_contents` (root signup) and the corp-org JIT
//! provisioning branch of `provision_org_subdomain`, after the new `users`
//! row is in place. The send is gated on `users.welcome_email_sent_at IS NULL`
//! so the function is naturally idempotent — callers don't need to track
//! "is this a fresh user" themselves. This matters for corp-org JIT: a
//! returning member signing in again (or a second-IdP add) re-enters the
//! same code path with the existing user_id and must not be re-welcomed.
//!
//! All errors are swallowed (logged at `warn`) so a transient mailer failure
//! never blocks the auth callback. Welcome email is best-effort; the user
//! can always trigger product onboarding manually from the dashboard.

use std::collections::HashMap;

use overslash_core::email::{
    EmailMessage, WELCOME_TEMPLATE_HTML, WELCOME_TEMPLATE_SUBJECT, render,
};
use overslash_db::repos::{email_unsubscribe_token, user as user_repo};
use serde_json::Value;
use uuid::Uuid;

use crate::AppState;

/// Send the welcome email if the user hasn't already received it and hasn't
/// already unsubscribed. Best-effort: every failure mode (user lookup, token
/// mint, mailer send, mark-sent) is logged at `warn` and swallowed so the
/// auth callback that triggered the send never fails on transient email
/// trouble.
///
/// * `user_id` — recipient.
/// * `org_id_for_audit` — captured into the unsubscribe-token row so the
///   redemption endpoint can audit in the correct org (root → personal org;
///   corp JIT → the corp org).
/// * `dashboard_url` — absolute URL the recipient should land on from the
///   email's CTA. The caller composes this from the per-org redirect helper
///   in `auth.rs` so personal vs corp subdomains are routed correctly.
pub async fn send_if_due(
    state: &AppState,
    user_id: Uuid,
    org_id_for_audit: Uuid,
    dashboard_url: String,
) {
    let user = match user_repo::get_by_id(&state.db, user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            tracing::warn!(%user_id, "welcome email skipped: user not found");
            return;
        }
        Err(e) => {
            tracing::warn!(%user_id, error = %e, "welcome email skipped: user lookup failed");
            return;
        }
    };

    if user.welcome_email_sent_at.is_some() {
        return;
    }
    if user.welcome_emails_unsubscribed_at.is_some() {
        // Defensive: a fresh user can't normally be unsubscribed, but if
        // they are (e.g. a re-attached existing user), respect the choice
        // and still mark sent so we don't keep checking.
        let _ = user_repo::mark_welcome_sent(&state.db, user_id).await;
        return;
    }
    let Some(email) = user.email.as_deref().filter(|s| !s.is_empty()) else {
        tracing::warn!(%user_id, "welcome email skipped: user has no email");
        return;
    };
    let display_name = user
        .display_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("there");

    let token_row = match email_unsubscribe_token::create(
        &state.db,
        user_id,
        org_id_for_audit,
        "welcome",
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(%user_id, error = %e, "welcome email skipped: token mint failed");
            return;
        }
    };

    let api_base = state.config.public_url.trim_end_matches('/');
    let unsubscribe_url = format!("{api_base}/v1/unsubscribe?token={}", token_row.token);

    let mut params: HashMap<String, Value> = HashMap::new();
    params.insert(
        "display_name".into(),
        Value::String(display_name.to_string()),
    );
    params.insert("dashboard_url".into(), Value::String(dashboard_url.clone()));
    params.insert(
        "unsubscribe_url".into(),
        Value::String(unsubscribe_url.clone()),
    );
    let html = render(WELCOME_TEMPLATE_HTML, &params);

    // RFC 8058 List-Unsubscribe + List-Unsubscribe-Post so Gmail's native
    // "Unsubscribe" button calls the one-click POST without a confirmation.
    let mut headers = HashMap::new();
    headers.insert(
        "List-Unsubscribe".to_string(),
        format!("<{unsubscribe_url}>"),
    );
    headers.insert(
        "List-Unsubscribe-Post".to_string(),
        "List-Unsubscribe=One-Click".to_string(),
    );

    let msg = EmailMessage {
        from: String::new(), // ResendMailer falls back to default_from
        to: email.to_string(),
        subject: WELCOME_TEMPLATE_SUBJECT.to_string(),
        html,
        reply_to: None,
        headers,
    };

    if let Err(e) = state.mailer.send(msg).await {
        tracing::warn!(%user_id, token = %token_row.token, error = %e, "welcome email send failed");
        // The token row we just minted is now orphaned: `welcome_email_sent_at`
        // is still NULL so the next provisioning retry would mint a fresh
        // token, leaving this one as accumulated garbage with a still-valid
        // unsubscribe blast radius. Drop it. Failure of the cleanup is
        // itself best-effort (logged) — we already swallowed the send error.
        if let Err(del_err) = email_unsubscribe_token::delete(&state.db, token_row.token).await {
            tracing::warn!(%user_id, token = %token_row.token, error = %del_err, "welcome email: cleanup of orphan token failed");
        }
        return;
    }

    if let Err(e) = user_repo::mark_welcome_sent(&state.db, user_id).await {
        tracing::warn!(%user_id, error = %e, "welcome email sent but mark_welcome_sent failed");
    }
}
