use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct ApprovalRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub action_summary: String,
    pub action_detail: Option<serde_json::Value>,
    pub permission_keys: Vec<String>,
    pub status: String,
    pub resolved_at: Option<OffsetDateTime>,
    pub resolved_by: Option<String>,
    pub remember: bool,
    pub token: String,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

pub struct CreateApproval<'a> {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub action_summary: &'a str,
    pub action_detail: Option<serde_json::Value>,
    pub permission_keys: &'a [String],
    pub token: &'a str,
    pub expires_at: OffsetDateTime,
}

pub async fn create(pool: &PgPool, input: &CreateApproval<'_>) -> Result<ApprovalRow, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "INSERT INTO approvals (org_id, identity_id, action_summary, action_detail, permission_keys, token, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, org_id, identity_id, action_summary, action_detail, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at",
        input.org_id,
        input.identity_id,
        input.action_summary,
        input.action_detail.clone() as Option<serde_json::Value>,
        input.permission_keys,
        input.token,
        input.expires_at,
    )
    .fetch_one(pool)
    .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "SELECT id, org_id, identity_id, action_summary, action_detail, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at
         FROM approvals WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn get_by_token(pool: &PgPool, token: &str) -> Result<Option<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "SELECT id, org_id, identity_id, action_summary, action_detail, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at
         FROM approvals WHERE token = $1",
        token,
    )
    .fetch_optional(pool)
    .await
}

/// Atomically resolve a pending approval. Returns None if not pending.
pub async fn resolve(
    pool: &PgPool,
    id: Uuid,
    status: &str,
    resolved_by: &str,
    remember: bool,
) -> Result<Option<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "UPDATE approvals SET status = $2, resolved_at = now(), resolved_by = $3, remember = $4
         WHERE id = $1 AND status = 'pending'
         RETURNING id, org_id, identity_id, action_summary, action_detail, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at",
        id,
        status,
        resolved_by,
        remember,
    )
    .fetch_optional(pool)
    .await
}

pub async fn list_pending_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ApprovalRow>, sqlx::Error> {
    sqlx::query_as!(
        ApprovalRow,
        "SELECT id, org_id, identity_id, action_summary, action_detail, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at
         FROM approvals WHERE org_id = $1 AND status = 'pending' ORDER BY created_at DESC",
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn expire_stale(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE approvals SET status = 'expired', resolved_at = now(), resolved_by = 'system'
         WHERE status = 'pending' AND expires_at < now()",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
