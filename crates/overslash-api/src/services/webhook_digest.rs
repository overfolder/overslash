//! Daily webhook DLQ digest. Once per UTC day at [`DIGEST_HOUR_UTC`], every
//! API replica enters `run_once`; for each org with terminal webhook failures
//! (`delivered_at IS NULL AND attempts >= 5`) in the last 24 hours, the
//! winner of the `webhook_digest_runs` claim sends one email per admin user
//! (skipping admins who flipped `users.webhook_digest_unsubscribed_at`).
//!
//! Per-admin failures are swallowed and logged (welcome's pattern). Empty
//! digest → no claim, silent. The claim row also prevents double-send across
//! replicas: only the winner of `INSERT … ON CONFLICT DO NOTHING RETURNING`
//! sends; losers see a `false` claim and move on.
//!
//! No dashboard surface exists for webhook failures yet (TODO §2.1, launch+1),
//! so this email *is* the surface — the CTA links to the dashboard root.
//!
//! See migration 069 for the schema and the approved plan
//! (`launch-webhook-dlq-digest-robust-platypus.md`) for the design rationale.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;

use overslash_core::email::{
    EmailMessage, Mailer, WEBHOOK_DIGEST_TEMPLATE_HTML, WEBHOOK_DIGEST_TEMPLATE_SUBJECT, render,
};
use overslash_db::repos::membership::{MembershipRow, ROLE_ADMIN};
use overslash_db::repos::webhook::DigestEndpointSummary;
use overslash_db::repos::{email_unsubscribe_token, membership, org, user, webhook_digest_run};
use overslash_db::scopes::SystemScope;
use serde_json::Value;
use sqlx::PgPool;
use time::format_description::well_known::Rfc3339;
use time::{Date, Duration, OffsetDateTime, Time};
use uuid::Uuid;

/// UTC wall-clock hour the daily send fires at. Picked so that "last 24h"
/// covers a natural workday for both EU and US org admins.
pub const DIGEST_HOUR_UTC: u8 = 13;

/// Window the digest reports on. Matches the daily cadence so the window
/// rolls forward exactly when the next digest fires.
pub const DIGEST_WINDOW: Duration = Duration::hours(24);

/// Background task that wakes once per UTC day at [`DIGEST_HOUR_UTC`] and
/// runs the digest pass. Designed to be `tokio::spawn`ed exactly once per
/// API replica from `lib.rs` next to the other periodic loops; the claim
/// row in `webhook_digest_runs` makes co-running replicas safe.
pub async fn spawn_digest_loop(pool: PgPool, mailer: Arc<dyn Mailer>, public_url: String) {
    loop {
        let now = OffsetDateTime::now_utc();
        let anchor = next_anchor(now, DIGEST_HOUR_UTC);
        let until: std::time::Duration = (anchor - now)
            .try_into()
            .unwrap_or(std::time::Duration::ZERO);
        tokio::time::sleep(until).await;
        let start = std::time::Instant::now();
        let today = OffsetDateTime::now_utc().date();
        match run_once(&pool, mailer.as_ref(), &public_url, today).await {
            Ok(n) => {
                let status = if n == 0 { "noop" } else { "ok" };
                overslash_metrics::background::record_tick(
                    "webhook_digest",
                    status,
                    start.elapsed(),
                );
                overslash_metrics::background::set_last_success("webhook_digest");
            }
            Err(e) => {
                tracing::error!(error = %e, "webhook_digest pass failed");
                overslash_metrics::background::record_tick(
                    "webhook_digest",
                    "err",
                    start.elapsed(),
                );
            }
        }
    }
}

/// Next instant at `hour_utc:00:00` UTC strictly after `now`. If today's
/// anchor has already passed, returns tomorrow's.
fn next_anchor(now: OffsetDateTime, hour_utc: u8) -> OffsetDateTime {
    let today = now.replace_time(Time::from_hms(hour_utc, 0, 0).expect("hour < 24"));
    if today > now {
        today
    } else {
        today + Duration::days(1)
    }
}

/// One pass over every org with terminal failures in the last
/// [`DIGEST_WINDOW`]. Returns the number of orgs whose digest pipeline ran
/// (claim won and the per-admin loop entered) — this includes orgs where
/// every admin was unsubscribed or every send failed, since the work was
/// attempted. It does *not* include orgs whose claim was released because
/// the failures disappeared mid-pass or because the org has no admins.
/// Exposed for tests so they can drive a deterministic run without sleeping.
pub async fn run_once(
    pool: &PgPool,
    mailer: &dyn Mailer,
    public_url: &str,
    today: Date,
) -> Result<u64, sqlx::Error> {
    let system = SystemScope::new_internal(pool.clone());
    let since = OffsetDateTime::now_utc() - DIGEST_WINDOW;
    let candidates = system
        .list_org_ids_with_webhook_terminal_failures(since)
        .await?;

    let mut sent_orgs: u64 = 0;
    for org_id in candidates {
        let won = match webhook_digest_run::try_claim(pool, org_id, today).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(%org_id, error = %e, "webhook digest: claim failed");
                continue;
            }
        };
        if !won {
            continue;
        }

        match send_for_org(pool, mailer, public_url, &system, org_id, today, since).await {
            Ok(SendOutcome::Sent {
                endpoint_count,
                admin_count,
            }) => {
                tracing::info!(
                    %org_id,
                    endpoint_count,
                    admin_count,
                    "webhook digest sent"
                );
                sent_orgs += 1;
            }
            Ok(SendOutcome::NoFailures) => {
                tracing::info!(%org_id, "webhook digest: failures cleared before send; claim released");
            }
            Ok(SendOutcome::NoAdmins) => {
                // The claim row would block tomorrow's retry if we kept it.
                // Release so the next tick (or tomorrow's pass) can revisit
                // an org that has since added an admin.
                if let Err(e) = webhook_digest_run::release(pool, org_id, today).await {
                    tracing::warn!(%org_id, error = %e, "webhook digest: release after no-admins failed");
                }
                tracing::warn!(%org_id, "webhook digest: org has no admins; skipped");
            }
            Err(e) => {
                // Release the claim so a future tick (today or tomorrow's
                // 13:00 anchor) can retry. Otherwise a transient DB error
                // mid-send would lock this org out for the rest of the day
                // even though no email actually went out.
                if let Err(rel_err) = webhook_digest_run::release(pool, org_id, today).await {
                    tracing::warn!(%org_id, error = %rel_err, "webhook digest: release after send_for_org err failed");
                }
                tracing::error!(%org_id, error = %e, "webhook digest: send_for_org failed; claim released");
            }
        }
    }
    Ok(sent_orgs)
}

enum SendOutcome {
    /// Claim held, summaries non-empty, per-admin loop ran. Counters
    /// describe how many endpoints surfaced and how many emails were
    /// dispatched (the latter can be 0 if every admin was unsubscribed
    /// or every mailer.send failed).
    Sent {
        endpoint_count: usize,
        admin_count: usize,
    },
    /// Claim held but the failures had already cleared. Caller-side path
    /// already released the claim so the next pass can re-evaluate.
    NoFailures,
    /// Claim held but the org has no admins to email. Caller releases the
    /// claim so the next pass can revisit if an admin is added.
    NoAdmins,
}

async fn send_for_org(
    pool: &PgPool,
    mailer: &dyn Mailer,
    public_url: &str,
    system: &SystemScope,
    org_id: Uuid,
    today: Date,
    since: OffsetDateTime,
) -> Result<SendOutcome, sqlx::Error> {
    let summaries = system
        .summarize_webhook_terminal_failures_for_org(org_id, since)
        .await?;
    if summaries.is_empty() {
        // Lost the race to clear the failures? Release so the slot can be
        // re-attempted (the next pass will simply skip the org as a
        // non-candidate, which is correct).
        let _ = webhook_digest_run::release(pool, org_id, today).await;
        return Ok(SendOutcome::NoFailures);
    }

    let memberships = membership::list_for_org(pool, org_id).await?;
    let admins: Vec<MembershipRow> = memberships
        .into_iter()
        .filter(|m| m.role == ROLE_ADMIN)
        .collect();
    if admins.is_empty() {
        return Ok(SendOutcome::NoAdmins);
    }

    let org_row = org::get_by_id(pool, org_id).await?;
    let org_name = org_row
        .as_ref()
        .map(|o| o.name.clone())
        .unwrap_or_else(|| "your org".to_string());

    let rows_html = render_rows_html(&summaries);
    let endpoint_count = summaries.len();
    let dashboard_url = public_url.trim_end_matches('/').to_string();

    let mut sent: usize = 0;
    for admin in &admins {
        let user = match user::get_by_id(pool, admin.user_id).await? {
            Some(u) => u,
            None => continue,
        };
        if user.webhook_digest_unsubscribed_at.is_some() {
            continue;
        }
        let Some(email) = user.email.as_deref().filter(|s| !s.is_empty()) else {
            continue;
        };

        let token_row = match email_unsubscribe_token::create(
            pool,
            user.id,
            org_id,
            "webhook_digest",
        )
        .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(user_id = %user.id, error = %e, "webhook digest: token mint failed");
                continue;
            }
        };

        let unsubscribe_url = format!(
            "{}/v1/unsubscribe?token={}",
            public_url.trim_end_matches('/'),
            token_row.token
        );

        let mut params: HashMap<String, Value> = HashMap::new();
        params.insert("org_name".into(), Value::String(html_escape(&org_name)));
        params.insert(
            "endpoint_count".into(),
            Value::String(endpoint_count.to_string()),
        );
        params.insert("rows_html".into(), Value::String(rows_html.clone()));
        params.insert("dashboard_url".into(), Value::String(dashboard_url.clone()));
        params.insert(
            "unsubscribe_url".into(),
            Value::String(unsubscribe_url.clone()),
        );
        let html = render(WEBHOOK_DIGEST_TEMPLATE_HTML, &params);

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
            from: String::new(),
            to: email.to_string(),
            subject: WEBHOOK_DIGEST_TEMPLATE_SUBJECT.to_string(),
            html,
            reply_to: None,
            headers,
        };

        if let Err(e) = mailer.send(msg).await {
            tracing::warn!(
                user_id = %user.id,
                token = %token_row.token,
                error = %e,
                "webhook digest: send failed"
            );
            // Orphan-token cleanup mirrors welcome: the mailer never
            // delivered, so the token's unsubscribe blast radius (one
            // ghost email no one received) is pointless garbage.
            if let Err(del_err) = email_unsubscribe_token::delete(pool, token_row.token).await {
                tracing::warn!(
                    user_id = %user.id,
                    token = %token_row.token,
                    error = %del_err,
                    "webhook digest: cleanup of orphan token failed"
                );
            }
            continue;
        }
        sent += 1;
    }

    Ok(SendOutcome::Sent {
        endpoint_count,
        admin_count: sent,
    })
}

fn render_rows_html(summaries: &[DigestEndpointSummary]) -> String {
    let mut out = String::with_capacity(summaries.len() * 256);
    for s in summaries {
        let last = match (s.last_status_code, s.last_error_excerpt.as_deref()) {
            (Some(code), Some(body)) if !body.is_empty() => {
                format!("{code} — {}", html_escape(body))
            }
            (Some(code), _) => code.to_string(),
            (None, Some(body)) if !body.is_empty() => html_escape(body),
            _ => "no response".to_string(),
        };
        let first = s
            .first_failure_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::from("—"));
        let _ = write!(
            out,
            "<tr>\
               <td style=\"padding: 8px 8px; border-bottom: 1px solid #f0f0f5; vertical-align: top;\">\
                 <div style=\"font-family: ui-monospace, SFMono-Regular, Menlo, monospace; color: #17191c; word-break: break-all;\">{url}</div>\
                 <div style=\"font-size: 11px; color: #737580; margin-top: 4px;\">First failure: {first}</div>\
               </td>\
               <td align=\"right\" style=\"padding: 8px 8px; border-bottom: 1px solid #f0f0f5; vertical-align: top; color: #17191c;\">{count}</td>\
               <td style=\"padding: 8px 8px; border-bottom: 1px solid #f0f0f5; vertical-align: top; color: #737580; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-word;\">{last}</td>\
             </tr>",
            url = html_escape(&s.url),
            first = html_escape(&first),
            count = s.attempt_count,
            last = last,
        );
    }
    out
}

/// Local HTML-escape so the service is self-contained (the dashboard's
/// `routes::connect_gate::html_escape` does the same job for HTML pages).
fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn next_anchor_jumps_to_tomorrow_when_past() {
        // 14:00 UTC — today's 13:00 has passed.
        let now = datetime!(2026-05-12 14:00:00 UTC);
        let anchor = next_anchor(now, 13);
        assert_eq!(anchor, datetime!(2026-05-13 13:00:00 UTC));
    }

    #[test]
    fn next_anchor_stays_today_when_earlier() {
        let now = datetime!(2026-05-12 09:30:00 UTC);
        let anchor = next_anchor(now, 13);
        assert_eq!(anchor, datetime!(2026-05-12 13:00:00 UTC));
    }

    #[test]
    fn next_anchor_jumps_when_exactly_at_hour() {
        // Boundary: exactly at the anchor should jump to tomorrow so we don't
        // immediately re-fire the loop in a tight cycle.
        let now = datetime!(2026-05-12 13:00:00 UTC);
        let anchor = next_anchor(now, 13);
        assert_eq!(anchor, datetime!(2026-05-13 13:00:00 UTC));
    }

    #[test]
    fn html_escape_neutralizes_angle_brackets() {
        assert_eq!(
            html_escape("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;"
        );
    }
}
