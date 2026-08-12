//! `call_results` — the full output of a call whose compact rendering was cropped.
//!
//! Written only when a `verbose: false` render actually truncated, so this is a
//! working-set store for one agent turn, not history. History lives in the audit
//! log. See migration 111 for why the body is encrypted rather than JSONB, and
//! why a `download_tokens` row must name exactly one byte source.
//!
//! Reads are deliberately *not* `OrgScope`-based: redemption arrives at
//! `GET /v1/downloads/{token}` with no authenticated principal at all, and
//! builds its scope *from* the token row. Same reason [`super::download_token`]
//! is a plain repo.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CallResultRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub service_key: Option<String>,
    pub action_key: Option<String>,
    /// AES-256-GCM blob over the serialized `ActionResult`.
    pub body_ciphertext: Vec<u8>,
    pub status_code: i32,
    pub content_type: Option<String>,
    /// Plaintext size. Cleartext so a Descriptor can be built without decrypting.
    pub body_bytes: i64,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

pub struct NewCallResult<'a> {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub service_key: Option<&'a str>,
    pub action_key: Option<&'a str>,
    pub body_ciphertext: &'a [u8],
    pub status_code: i32,
    pub content_type: Option<&'a str>,
    pub body_bytes: i64,
    pub ttl_secs: i64,
}

/// Store one result. `expires_at = now() + ttl_secs`.
pub async fn create(pool: &PgPool, r: NewCallResult<'_>) -> Result<CallResultRow, sqlx::Error> {
    sqlx::query_as!(
        CallResultRow,
        "INSERT INTO call_results (
             org_id, identity_id, service_key, action_key,
             body_ciphertext, status_code, content_type, body_bytes, expires_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                 now() + make_interval(secs => $9))
         RETURNING id, org_id, identity_id, service_key, action_key,
                   body_ciphertext, status_code, content_type, body_bytes,
                   created_at, expires_at",
        r.org_id,
        r.identity_id,
        r.service_key,
        r.action_key,
        r.body_ciphertext,
        r.status_code,
        r.content_type,
        r.body_bytes,
        r.ttl_secs as f64,
    )
    .fetch_one(pool)
    .await
}

/// Load a result for a token redemption. Filters on `expires_at` here as well as
/// on the token: the token's expiry is clamped to the result's at mint time, but
/// checking both means a result pruned early can't be served by a token that
/// happens to outlive it.
pub async fn get_unexpired(pool: &PgPool, id: Uuid) -> Result<Option<CallResultRow>, sqlx::Error> {
    sqlx::query_as!(
        CallResultRow,
        "SELECT id, org_id, identity_id, service_key, action_key,
                body_ciphertext, status_code, content_type, body_bytes,
                created_at, expires_at
         FROM call_results
         WHERE id = $1 AND expires_at > now()",
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Drop expired rows. The `ON DELETE CASCADE` on `download_tokens.call_result_id`
/// reaps the tokens pointing at them, so this needs no ordering against
/// [`super::download_token::prune_expired`].
pub async fn prune_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let r = sqlx::query!("DELETE FROM call_results WHERE expires_at < now()")
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}
