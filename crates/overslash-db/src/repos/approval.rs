use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

const APPROVAL_COLUMNS: &str = "id, org_id, identity_id, action_summary, action_detail, permission_keys, status, resolved_at, resolved_by, remember, token, expires_at, created_at, gap_identity_id, can_be_handled_by, grant_to";

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
    pub gap_identity_id: Option<Uuid>,
    pub can_be_handled_by: Vec<Uuid>,
    pub grant_to: Option<Uuid>,
}

pub struct CreateApproval<'a> {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub action_summary: &'a str,
    pub action_detail: Option<serde_json::Value>,
    pub permission_keys: &'a [String],
    pub token: &'a str,
    pub expires_at: OffsetDateTime,
    pub gap_identity_id: Option<Uuid>,
    pub can_be_handled_by: Vec<Uuid>,
}

pub async fn create(pool: &PgPool, input: &CreateApproval<'_>) -> Result<ApprovalRow, sqlx::Error> {
    let query = format!(
        "INSERT INTO approvals (org_id, identity_id, action_summary, action_detail, permission_keys, token, expires_at, gap_identity_id, can_be_handled_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING {APPROVAL_COLUMNS}"
    );
    sqlx::query_as::<_, ApprovalRow>(&query)
        .bind(input.org_id)
        .bind(input.identity_id)
        .bind(input.action_summary)
        .bind(&input.action_detail)
        .bind(input.permission_keys)
        .bind(input.token)
        .bind(input.expires_at)
        .bind(input.gap_identity_id)
        .bind(&input.can_be_handled_by)
        .fetch_one(pool)
        .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<ApprovalRow>, sqlx::Error> {
    let query = format!("SELECT {APPROVAL_COLUMNS} FROM approvals WHERE id = $1");
    sqlx::query_as::<_, ApprovalRow>(&query)
        .bind(id)
        .fetch_optional(pool)
        .await
}

pub async fn get_by_token(pool: &PgPool, token: &str) -> Result<Option<ApprovalRow>, sqlx::Error> {
    let query = format!("SELECT {APPROVAL_COLUMNS} FROM approvals WHERE token = $1");
    sqlx::query_as::<_, ApprovalRow>(&query)
        .bind(token)
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
    grant_to: Option<Uuid>,
) -> Result<Option<ApprovalRow>, sqlx::Error> {
    let query = format!(
        "UPDATE approvals SET status = $2, resolved_at = now(), resolved_by = $3, remember = $4, grant_to = $5
         WHERE id = $1 AND status = 'pending'
         RETURNING {APPROVAL_COLUMNS}"
    );
    sqlx::query_as::<_, ApprovalRow>(&query)
        .bind(id)
        .bind(status)
        .bind(resolved_by)
        .bind(remember)
        .bind(grant_to)
        .fetch_optional(pool)
        .await
}

pub async fn list_pending_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<ApprovalRow>, sqlx::Error> {
    let query = format!(
        "SELECT {APPROVAL_COLUMNS} FROM approvals WHERE org_id = $1 AND status = 'pending' ORDER BY created_at DESC"
    );
    sqlx::query_as::<_, ApprovalRow>(&query)
        .bind(org_id)
        .fetch_all(pool)
        .await
}

/// List approvals scoped by the caller's identity.
pub async fn list_pending_scoped(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    scope: &str,
) -> Result<Vec<ApprovalRow>, sqlx::Error> {
    let sql = match scope {
        "mine" => format!(
            "SELECT {APPROVAL_COLUMNS} FROM approvals
             WHERE org_id = $1 AND status = 'pending' AND identity_id = $2
             ORDER BY created_at DESC"
        ),
        "actionable" => format!(
            "SELECT {APPROVAL_COLUMNS} FROM approvals
             WHERE org_id = $1 AND status = 'pending' AND $2 = ANY(can_be_handled_by)
             ORDER BY created_at DESC"
        ),
        _ => format!(
            // "all" — union of mine and actionable
            "SELECT {APPROVAL_COLUMNS} FROM approvals
             WHERE org_id = $1 AND status = 'pending' AND (identity_id = $2 OR $2 = ANY(can_be_handled_by))
             ORDER BY created_at DESC"
        ),
    };
    sqlx::query_as::<_, ApprovalRow>(&sql)
        .bind(org_id)
        .bind(identity_id)
        .fetch_all(pool)
        .await
}

pub async fn expire_stale(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE approvals SET status = 'expired', resolved_at = now(), resolved_by = 'system'
         WHERE status = 'pending' AND expires_at < now()",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
