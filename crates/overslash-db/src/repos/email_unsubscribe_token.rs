//! `email_unsubscribe_tokens` — one row per outgoing non-transactional email
//! (today: welcome only). The `token` is the unguessable UUID embedded in
//! the email's `List-Unsubscribe` header and visible footer link. Redemption
//! is idempotent at the row level: the first click stamps `redeemed_at`;
//! subsequent clicks find the row already redeemed. The caller gates the
//! user-state flip on first redemption only — a replayed click does not
//! re-unsubscribe a user who has since re-subscribed elsewhere. See
//! migration 068.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EmailUnsubscribeTokenRow {
    pub token: Uuid,
    pub user_id: Uuid,
    /// Captured at mint time so the redemption endpoint can write an audit
    /// row in the correct org without re-deriving from membership (root →
    /// personal org; corp JIT → the corp org).
    pub org_id: Uuid,
    /// `'welcome'` today; extension hook for future non-transactional kinds.
    /// A DB CHECK keeps the allowed set explicit.
    pub purpose: String,
    pub created_at: OffsetDateTime,
    pub redeemed_at: Option<OffsetDateTime>,
}

/// Mint a fresh token row. The DB default for `token` produces a UUID v4 with
/// ~122 bits of entropy, which is sufficient for an unsubscribe-only blast
/// radius (worst case: someone unsubscribes someone else).
pub async fn create(
    pool: &PgPool,
    user_id: Uuid,
    org_id: Uuid,
    purpose: &str,
) -> Result<EmailUnsubscribeTokenRow, sqlx::Error> {
    sqlx::query_as!(
        EmailUnsubscribeTokenRow,
        "INSERT INTO email_unsubscribe_tokens (user_id, org_id, purpose)
         VALUES ($1, $2, $3)
         RETURNING token, user_id, org_id, purpose, created_at, redeemed_at",
        user_id,
        org_id,
        purpose,
    )
    .fetch_one(pool)
    .await
}

pub async fn find(
    pool: &PgPool,
    token: Uuid,
) -> Result<Option<EmailUnsubscribeTokenRow>, sqlx::Error> {
    sqlx::query_as!(
        EmailUnsubscribeTokenRow,
        "SELECT token, user_id, org_id, purpose, created_at, redeemed_at
         FROM email_unsubscribe_tokens WHERE token = $1",
        token,
    )
    .fetch_optional(pool)
    .await
}

/// Stamp `redeemed_at = now()`. Idempotent: re-redeeming is allowed so a
/// second click from the same email link returns success but doesn't
/// re-trigger user-state changes. Returns `true` on first redemption,
/// `false` if already redeemed — callers use this to gate the user-pref
/// flip + audit write to the first redemption only.
pub async fn mark_redeemed(pool: &PgPool, token: Uuid) -> Result<bool, sqlx::Error> {
    let res = sqlx::query!(
        "UPDATE email_unsubscribe_tokens
         SET redeemed_at = now()
         WHERE token = $1 AND redeemed_at IS NULL",
        token,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Drop a freshly-minted token when the mailer send that was supposed to
/// deliver it fails. Without this, a transient mailer error leaves an
/// orphaned-but-valid unsubscribe row behind, and the next welcome retry
/// (the call site does not mark `welcome_email_sent_at` on send failure)
/// would mint yet another. Treat as best-effort: callers swallow the
/// error since the orphan is harmless (worst case: someone unsubscribes
/// from a never-delivered email).
pub async fn delete(pool: &PgPool, token: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM email_unsubscribe_tokens WHERE token = $1",
        token
    )
    .execute(pool)
    .await?;
    Ok(())
}
