use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct SecretRequestRow {
    pub id: String,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub secret_name: String,
    pub requested_by: Uuid,
    pub reason: Option<String>,
    pub token_hash: Vec<u8>,
    pub expires_at: OffsetDateTime,
    pub fulfilled_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &PgPool,
    id: &str,
    org_id: Uuid,
    identity_id: Uuid,
    secret_name: &str,
    requested_by: Uuid,
    reason: Option<&str>,
    token_hash: &[u8],
    expires_at: OffsetDateTime,
) -> Result<SecretRequestRow, sqlx::Error> {
    sqlx::query_as!(
        SecretRequestRow,
        "INSERT INTO secret_requests (id, org_id, identity_id, secret_name, requested_by, reason, token_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING id, org_id, identity_id, secret_name, requested_by, reason, token_hash, expires_at, fulfilled_at, created_at",
        id,
        org_id,
        identity_id,
        secret_name,
        requested_by,
        reason,
        token_hash,
        expires_at,
    )
    .fetch_one(pool)
    .await
}

pub async fn get(pool: &PgPool, id: &str) -> Result<Option<SecretRequestRow>, sqlx::Error> {
    sqlx::query_as!(
        SecretRequestRow,
        "SELECT id, org_id, identity_id, secret_name, requested_by, reason, token_hash, expires_at, fulfilled_at, created_at
         FROM secret_requests WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Atomically mark fulfilled. Returns false if already fulfilled.
pub async fn mark_fulfilled(pool: &PgPool, id: &str) -> Result<bool, sqlx::Error> {
    let r = sqlx::query!(
        "UPDATE secret_requests SET fulfilled_at = now() WHERE id = $1 AND fulfilled_at IS NULL",
        id,
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}
