//! `email_unsubscribe_tokens` — one row per outgoing non-transactional email
//! (today: welcome only). The `token` is the unguessable UUID embedded in
//! the email's `List-Unsubscribe` header and visible footer link. Redemption
//! is idempotent: the first click stamps `redeemed_at`; subsequent clicks
//! find the row already redeemed and are accepted as a no-op while the
//! caller still re-asserts the user's unsubscribe state, so the final
//! observable result is the same. See migration 067.

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
/// second click from the same email link leaves the user in the same final
/// state. Returns `true` on first redemption, `false` if already redeemed
/// (caller still flips the user pref to keep behavior idempotent).
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
