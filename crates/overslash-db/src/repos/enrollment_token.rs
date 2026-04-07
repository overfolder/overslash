use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct EnrollmentTokenRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub token_hash: String,
    pub token_prefix: String,
    pub expires_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
}

pub(crate) async fn create(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    token_hash: &str,
    token_prefix: &str,
    expires_at: OffsetDateTime,
    created_by: Option<Uuid>,
) -> Result<EnrollmentTokenRow, sqlx::Error> {
    sqlx::query_as!(
        EnrollmentTokenRow,
        "INSERT INTO enrollment_tokens (org_id, identity_id, token_hash, token_prefix, expires_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, org_id, identity_id, token_hash, token_prefix, expires_at, used_at, created_by, created_at",
        org_id,
        identity_id,
        token_hash,
        token_prefix,
        expires_at,
        created_by,
    )
    .fetch_one(pool)
    .await
}

pub(crate) async fn find_by_prefix(
    pool: &PgPool,
    prefix: &str,
) -> Result<Option<EnrollmentTokenRow>, sqlx::Error> {
    sqlx::query_as!(
        EnrollmentTokenRow,
        "SELECT id, org_id, identity_id, token_hash, token_prefix, expires_at, used_at, created_by, created_at
         FROM enrollment_tokens WHERE token_prefix = $1 AND used_at IS NULL",
        prefix,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn mark_used(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE enrollment_tokens SET used_at = now() WHERE id = $1 AND used_at IS NULL",
        id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub(crate) async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<EnrollmentTokenRow>, sqlx::Error> {
    sqlx::query_as!(
        EnrollmentTokenRow,
        "SELECT id, org_id, identity_id, token_hash, token_prefix, expires_at, used_at, created_by, created_at
         FROM enrollment_tokens WHERE org_id = $1 AND used_at IS NULL AND expires_at > now()
         ORDER BY created_at DESC",
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub(crate) async fn revoke(pool: &PgPool, id: Uuid, org_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE enrollment_tokens SET used_at = now() WHERE id = $1 AND org_id = $2 AND used_at IS NULL",
        id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
