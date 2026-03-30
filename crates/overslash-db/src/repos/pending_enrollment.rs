use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct PendingEnrollmentRow {
    pub id: Uuid,
    pub suggested_name: String,
    pub platform: Option<String>,
    pub metadata: serde_json::Value,
    pub status: String,
    pub approval_token: String,
    pub poll_token_hash: String,
    pub poll_token_prefix: String,
    pub org_id: Option<Uuid>,
    pub identity_id: Option<Uuid>,
    pub api_key_hash: Option<String>,
    pub api_key_prefix: Option<String>,
    pub approved_by: Option<Uuid>,
    pub final_name: Option<String>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    pub resolved_at: Option<OffsetDateTime>,
}

#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &PgPool,
    suggested_name: &str,
    platform: Option<&str>,
    metadata: serde_json::Value,
    approval_token: &str,
    poll_token_hash: &str,
    poll_token_prefix: &str,
    expires_at: OffsetDateTime,
) -> Result<PendingEnrollmentRow, sqlx::Error> {
    sqlx::query_as::<_, PendingEnrollmentRow>(
        "INSERT INTO pending_enrollments (suggested_name, platform, metadata, approval_token, poll_token_hash, poll_token_prefix, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, suggested_name, platform, metadata, status, approval_token, poll_token_hash, poll_token_prefix,
                   org_id, identity_id, api_key_hash, api_key_prefix, approved_by, final_name,
                   expires_at, created_at, resolved_at",
    )
    .bind(suggested_name)
    .bind(platform)
    .bind(metadata)
    .bind(approval_token)
    .bind(poll_token_hash)
    .bind(poll_token_prefix)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

pub async fn find_by_poll_prefix(
    pool: &PgPool,
    prefix: &str,
) -> Result<Option<PendingEnrollmentRow>, sqlx::Error> {
    sqlx::query_as::<_, PendingEnrollmentRow>(
        "SELECT id, suggested_name, platform, metadata, status, approval_token, poll_token_hash, poll_token_prefix,
                org_id, identity_id, api_key_hash, api_key_prefix, approved_by, final_name,
                expires_at, created_at, resolved_at
         FROM pending_enrollments WHERE poll_token_prefix = $1",
    )
    .bind(prefix)
    .fetch_optional(pool)
    .await
}

pub async fn find_by_approval_token(
    pool: &PgPool,
    token: &str,
) -> Result<Option<PendingEnrollmentRow>, sqlx::Error> {
    sqlx::query_as::<_, PendingEnrollmentRow>(
        "SELECT id, suggested_name, platform, metadata, status, approval_token, poll_token_hash, poll_token_prefix,
                org_id, identity_id, api_key_hash, api_key_prefix, approved_by, final_name,
                expires_at, created_at, resolved_at
         FROM pending_enrollments WHERE approval_token = $1",
    )
    .bind(token)
    .fetch_optional(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn approve(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
    identity_id: Uuid,
    api_key_hash: &str,
    api_key_prefix: &str,
    approved_by: Uuid,
    final_name: &str,
) -> Result<Option<PendingEnrollmentRow>, sqlx::Error> {
    sqlx::query_as::<_, PendingEnrollmentRow>(
        "UPDATE pending_enrollments
         SET status = 'approved', org_id = $2, identity_id = $3, api_key_hash = $4, api_key_prefix = $5,
             approved_by = $6, final_name = $7, resolved_at = now()
         WHERE id = $1 AND status = 'pending'
         RETURNING id, suggested_name, platform, metadata, status, approval_token, poll_token_hash, poll_token_prefix,
                   org_id, identity_id, api_key_hash, api_key_prefix, approved_by, final_name,
                   expires_at, created_at, resolved_at",
    )
    .bind(id)
    .bind(org_id)
    .bind(identity_id)
    .bind(api_key_hash)
    .bind(api_key_prefix)
    .bind(approved_by)
    .bind(final_name)
    .fetch_optional(pool)
    .await
}

pub async fn deny(pool: &PgPool, id: Uuid) -> Result<Option<PendingEnrollmentRow>, sqlx::Error> {
    sqlx::query_as::<_, PendingEnrollmentRow>(
        "UPDATE pending_enrollments
         SET status = 'denied', resolved_at = now()
         WHERE id = $1 AND status = 'pending'
         RETURNING id, suggested_name, platform, metadata, status, approval_token, poll_token_hash, poll_token_prefix,
                   org_id, identity_id, api_key_hash, api_key_prefix, approved_by, final_name,
                   expires_at, created_at, resolved_at",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

pub async fn expire_stale(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE pending_enrollments SET status = 'expired', resolved_at = now()
         WHERE status = 'pending' AND expires_at < now()",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
