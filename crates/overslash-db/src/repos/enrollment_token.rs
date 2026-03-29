use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct EnrollmentTokenRow {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub org_id: Uuid,
    pub token_hash: String,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

/// Insert a new enrollment token. `token_hash` is the SHA-256 hex digest of the raw token.
/// `ttl_secs` controls how far in the future `expires_at` is set.
pub async fn create(
    pool: &PgPool,
    identity_id: Uuid,
    org_id: Uuid,
    token_hash: &str,
    ttl_secs: i64,
) -> Result<EnrollmentTokenRow, sqlx::Error> {
    sqlx::query_as::<_, EnrollmentTokenRow>(
        "INSERT INTO enrollment_tokens (identity_id, org_id, token_hash, expires_at)
         VALUES ($1, $2, $3, now() + make_interval(secs => $4))
         RETURNING id, identity_id, org_id, token_hash, expires_at, consumed_at, created_at",
    )
    .bind(identity_id)
    .bind(org_id)
    .bind(token_hash)
    .bind(ttl_secs as f64)
    .fetch_one(pool)
    .await
}

/// Find an unconsumed token by its hash. Returns `None` if no matching row exists.
pub async fn find_by_hash(
    pool: &PgPool,
    token_hash: &str,
) -> Result<Option<EnrollmentTokenRow>, sqlx::Error> {
    sqlx::query_as::<_, EnrollmentTokenRow>(
        "SELECT id, identity_id, org_id, token_hash, expires_at, consumed_at, created_at
         FROM enrollment_tokens WHERE token_hash = $1",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await
}

/// Atomically consume a token: sets `consumed_at = now()` only if it has not already been consumed.
/// Returns `true` if a row was updated (i.e. the token was successfully consumed).
pub async fn consume(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE enrollment_tokens SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
