//! Public one-click unsubscribe endpoints. Mounted outside the rate-limit
//! and auth layers because email clients (and recipients clicking from
//! their inbox) have no session cookie.
//!
//! - `GET  /v1/unsubscribe?token=<uuid>` — browser click. Marks the user
//!   unsubscribed and renders a minimal HTML confirmation page.
//! - `POST /v1/unsubscribe?token=<uuid>` — RFC 8058
//!   `List-Unsubscribe-Post: List-Unsubscribe=One-Click`. Same effect,
//!   returns `204 No Content`.
//!
//! Both are idempotent: a second click leaves the user in the same final
//! state. Only the *first* redemption flips `welcome_emails_unsubscribed_at`
//! and writes an audit row; replays (email scanners, re-clicks) are no-ops
//! on user state so an old token can't silently re-unsubscribe a user who
//! has since re-subscribed via `/account`. The GET path also renders a
//! distinct "already used" page on replays so the response can't lie
//! about the user's current state. Unknown / malformed tokens return
//! `404` on GET and `204` on POST — RFC 8058 §3.1 recommends POST stay
//! opaque so an attacker probing tokens can't distinguish hit from miss.

use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::{email_unsubscribe_token, user as user_repo};
use overslash_db::scopes::OrgScope;
use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/unsubscribe", get(unsubscribe_get))
        .route("/v1/unsubscribe", post(unsubscribe_post))
}

#[derive(Debug, Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

/// Possible outcomes of redeeming an unsubscribe token. The GET handler
/// renders different copy per variant so a replayed click on a re-subscribed
/// user no longer falsely tells them "You've been unsubscribed."
#[derive(Debug, Clone, Copy)]
enum RedeemOutcome {
    /// First redemption — user pref + audit row were just written.
    Applied,
    /// Token resolved but was already redeemed (email scanner / re-click /
    /// prefetch). User state was deliberately not touched.
    Replayed,
    /// No row for this token. GET surfaces this as 404; POST swallows it
    /// per RFC 8058 §3.1 opacity.
    NotFound,
}

/// HTML response shown on the first redemption — the user *just* got
/// unsubscribed. Plain and self-contained so it renders identically
/// regardless of whether the apex serves the dashboard SPA.
fn applied_html() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Unsubscribed — Overslash</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: #f5f5f7; color: #383a42; }
  .wrap { max-width: 480px; margin: 80px auto; padding: 32px; background: #ffffff; border: 1px solid #e8e8ee; border-radius: 12px; }
  h1 { margin: 0 0 8px 0; font-size: 20px; color: #17191c; }
  p { margin: 0 0 12px 0; line-height: 1.5; font-size: 15px; }
  .muted { color: #737580; font-size: 13px; }
</style>
</head>
<body>
  <div class="wrap">
    <h1>You've been unsubscribed.</h1>
    <p>You won't receive product or welcome emails from Overslash anymore.</p>
    <p class="muted">Billing receipts and other transactional emails are exempt and will continue to be sent for any active subscription.</p>
    <p class="muted">You can re-enable product emails any time from your account preferences.</p>
  </div>
</body>
</html>"#,
    )
}

/// HTML response shown when the token was already redeemed. We intentionally
/// avoid asserting the user's current state here (they may have re-subscribed
/// since), and point them at the authoritative control in the dashboard.
fn replay_html() -> Html<&'static str> {
    Html(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Link already used — Overslash</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: #f5f5f7; color: #383a42; }
  .wrap { max-width: 480px; margin: 80px auto; padding: 32px; background: #ffffff; border: 1px solid #e8e8ee; border-radius: 12px; }
  h1 { margin: 0 0 8px 0; font-size: 20px; color: #17191c; }
  p { margin: 0 0 12px 0; line-height: 1.5; font-size: 15px; }
  .muted { color: #737580; font-size: 13px; }
</style>
</head>
<body>
  <div class="wrap">
    <h1>This link has already been used.</h1>
    <p>No changes were made to your email preferences.</p>
    <p class="muted">To change them, sign in and open your account settings.</p>
  </div>
</body>
</html>"#,
    )
}

async fn unsubscribe_get(State(state): State<AppState>, Query(q): Query<TokenQuery>) -> Response {
    let Some(token) = q.token.as_deref().and_then(|s| Uuid::parse_str(s).ok()) else {
        return (StatusCode::NOT_FOUND, "unknown token").into_response();
    };
    match apply_unsubscribe(&state, token).await {
        Ok(RedeemOutcome::Applied) => applied_html().into_response(),
        Ok(RedeemOutcome::Replayed) => replay_html().into_response(),
        Ok(RedeemOutcome::NotFound) => (StatusCode::NOT_FOUND, "unknown token").into_response(),
        Err(()) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "unsubscribe failed; please try again or update your preferences from the dashboard.",
        )
            .into_response(),
    }
}

async fn unsubscribe_post(
    State(state): State<AppState>,
    Query(q): Query<TokenQuery>,
) -> StatusCode {
    // RFC 8058 §3.1: stay opaque on POST so probes can't enumerate valid
    // tokens. Always 204 unless we hit a real server-side error — the
    // hit-vs-miss-vs-replay distinction is irrelevant here.
    let Some(token) = q.token.as_deref().and_then(|s| Uuid::parse_str(s).ok()) else {
        return StatusCode::NO_CONTENT;
    };
    match apply_unsubscribe(&state, token).await {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(()) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Shared redemption path. Returns:
/// * `Applied` — first redemption, user pref flipped + audit written.
/// * `Replayed` — token row exists but was already redeemed; user state
///   intentionally left untouched (a previously-unsubscribed user may have
///   re-subscribed via `/account`).
/// * `NotFound` — no row for this token.
async fn apply_unsubscribe(state: &AppState, token: Uuid) -> Result<RedeemOutcome, ()> {
    let row = match email_unsubscribe_token::find(&state.db, token).await {
        Ok(Some(r)) => r,
        Ok(None) => return Ok(RedeemOutcome::NotFound),
        Err(e) => {
            tracing::error!(%token, error = %e, "unsubscribe: token lookup failed");
            return Err(());
        }
    };
    let was_first_redeem = match email_unsubscribe_token::mark_redeemed(&state.db, token).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(%token, error = %e, "unsubscribe: mark_redeemed failed");
            return Err(());
        }
    };
    // Replayed clicks (email scanners, re-clicks from inbox, prefetchers)
    // leave the user's state untouched: this prevents an old token from
    // silently re-unsubscribing a user who has since re-subscribed via the
    // `/account` toggle. The GET handler renders different copy for the
    // replay branch so the response doesn't lie about the user's state.
    if !was_first_redeem {
        return Ok(RedeemOutcome::Replayed);
    }
    if let Err(e) =
        user_repo::set_welcome_unsubscribed(&state.db, row.user_id, Some(OffsetDateTime::now_utc()))
            .await
    {
        tracing::error!(user_id = %row.user_id, %token, error = %e, "unsubscribe: set_welcome_unsubscribed failed");
        return Err(());
    }
    let scope = OrgScope::new(row.org_id, state.db.clone());
    if let Err(e) = scope
        .log_audit(AuditEntry {
            org_id: row.org_id,
            identity_id: None,
            action: "email.unsubscribed",
            resource_type: Some("user"),
            resource_id: Some(row.user_id),
            detail: json!({ "purpose": row.purpose, "via": "one_click_token" }),
            description: Some("Welcome / product emails unsubscribed via one-click link"),
            ip_address: None,
        })
        .await
    {
        tracing::warn!(user_id = %row.user_id, %token, error = %e, "unsubscribe: audit log failed");
    }
    Ok(RedeemOutcome::Applied)
}
