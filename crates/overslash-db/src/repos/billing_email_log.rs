//! `billing_email_log` — idempotency + audit log for billing transactional
//! emails (receipt, dunning, cancellation). Pattern: the webhook handler
//! claims an event-kind pair with [`try_claim`] before rendering or sending;
//! a Stripe re-delivery of the same event id finds the row already present
//! (UNIQUE conflict) and returns `Ok(None)` so the second attempt is silently
//! a no-op. [`mark_sent`] stamps `sent_at` only after the mailer call returns
//! Ok — rows with `sent_at IS NULL` are claimed-but-not-yet-delivered and
//! provide the manual-replay signal during incidents. See migration 070.
//!
//! Billing emails are exempt from `welcome_emails_unsubscribed_at` by policy
//! (TODO.md §1.1) — this table never consults the unsubscribe state.

use sqlx::PgPool;
use uuid::Uuid;

/// Claim `(stripe_event_id, kind)` for sending. Returns the new log row id on
/// first call; returns `Ok(None)` if a row already exists for this pair
/// (Stripe retry — the prior delivery already handled the send).
///
/// `INSERT ... ON CONFLICT DO NOTHING RETURNING id` is the atomic-claim
/// idiom: a concurrent retry that lost the race sees zero rows returned
/// without raising an error, so callers don't have to translate
/// `UniqueViolation` themselves.
pub async fn try_claim(
    pool: &PgPool,
    stripe_event_id: &str,
    kind: &str,
    user_id: Uuid,
) -> Result<Option<Uuid>, sqlx::Error> {
    let row = sqlx::query!(
        "INSERT INTO billing_email_log (stripe_event_id, kind, user_id)
         VALUES ($1, $2, $3)
         ON CONFLICT (stripe_event_id, kind) DO NOTHING
         RETURNING id",
        stripe_event_id,
        kind,
        user_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.id))
}

/// Stamp `sent_at = now()`. Called once, only after the mailer returns Ok.
pub async fn mark_sent(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE billing_email_log SET sent_at = now() WHERE id = $1",
        id,
    )
    .execute(pool)
    .await?;
    Ok(())
}
