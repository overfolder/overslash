//! `magic_link_tokens` — one row per passwordless email sign-in link.
//!
//! Only the SHA-256 hash of the raw token is stored; the raw value lives only
//! in the emailed URL. Verification is single-use: [`consume`] stamps
//! `redeemed_at` in the same UPDATE that claims an unexpired, unredeemed row,
//! so a double-click or replay finds nothing to claim. See migration 078.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MagicLinkTokenRow {
    pub id: Uuid,
    pub token_hash: Vec<u8>,
    /// Normalized (trimmed + lowercased) address the link was minted for.
    pub email: String,
    /// Already-sanitized post-login redirect, carried across the email bounce.
    pub next_path: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub redeemed_at: Option<OffsetDateTime>,
}

/// Mint a token row. `token_hash` is `sha256(raw_token)` — the raw token is
/// never persisted. `ttl_secs` sets `expires_at = now() + ttl`.
pub async fn create(
    pool: &PgPool,
    token_hash: &[u8],
    email: &str,
    next_path: Option<&str>,
    ttl_secs: i64,
) -> Result<MagicLinkTokenRow, sqlx::Error> {
    sqlx::query_as!(
        MagicLinkTokenRow,
        "INSERT INTO magic_link_tokens (token_hash, email, next_path, expires_at)
         VALUES ($1, $2, $3, now() + make_interval(secs => $4))
         RETURNING id, token_hash, email, next_path, created_at, expires_at, redeemed_at",
        token_hash,
        email,
        next_path,
        ttl_secs as f64,
    )
    .fetch_one(pool)
    .await
}

/// Atomically claim a token: stamp `redeemed_at` iff the row exists, hasn't
/// been redeemed, and hasn't expired. Returns the row on a successful claim,
/// `None` for invalid / expired / already-used. The single-statement UPDATE
/// closes the double-click and replay races.
pub async fn consume(
    pool: &PgPool,
    token_hash: &[u8],
) -> Result<Option<MagicLinkTokenRow>, sqlx::Error> {
    sqlx::query_as!(
        MagicLinkTokenRow,
        "UPDATE magic_link_tokens
         SET redeemed_at = now()
         WHERE token_hash = $1 AND redeemed_at IS NULL AND expires_at > now()
         RETURNING id, token_hash, email, next_path, created_at, expires_at, redeemed_at",
        token_hash,
    )
    .fetch_optional(pool)
    .await
}

/// Drop a freshly-minted token when the mailer send fails, so a transient
/// error doesn't leave a valid-but-undelivered login link behind. Best-effort:
/// callers swallow the error (an orphaned hashed token is harmless and expires
/// on its own).
pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!("DELETE FROM magic_link_tokens WHERE id = $1", id)
        .execute(pool)
        .await?;
    Ok(())
}
