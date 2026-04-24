//! Execution lifecycle: once an approval is `allowed`, a pending `executions`
//! row is created. The row transitions through `pending → executing → executed`
//! (or `failed`, `cancelled`, `expired`) and is triggered by an explicit
//! `POST /v1/approvals/{id}/execute`.
//!
//! The unique index on `approval_id` and the `status='pending' AND expires_at > now()`
//! guard on `claim_for_execution` together enforce at-most-one replay per approval,
//! even under user+agent races.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct ExecutionRow {
    pub id: Uuid,
    pub approval_id: Uuid,
    pub org_id: Uuid,
    pub status: String,
    pub remember: bool,
    pub remember_keys: Option<Vec<String>>,
    pub remember_rule_ttl: Option<OffsetDateTime>,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub triggered_by: Option<String>,
    pub started_at: Option<OffsetDateTime>,
    pub completed_at: Option<OffsetDateTime>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

pub(crate) async fn create_pending(
    pool: &PgPool,
    org_id: Uuid,
    approval_id: Uuid,
    remember: bool,
    remember_keys: Option<&[String]>,
    remember_rule_ttl: Option<OffsetDateTime>,
    expires_at: OffsetDateTime,
) -> Result<ExecutionRow, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "INSERT INTO executions (approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, expires_at)
         VALUES ($1, $2, 'pending', $3, $4, $5, $6)
         RETURNING id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at",
        approval_id,
        org_id,
        remember,
        remember_keys as Option<&[String]>,
        remember_rule_ttl,
        expires_at,
    )
    .fetch_one(pool)
    .await
}

/// Atomically claim a pending execution for replay. Returns `Some(row)` on
/// win (status was 'pending' AND not yet expired), `None` on any other state.
/// The caller must inspect the current row via `find_by_approval` to produce
/// a specific error.
pub(crate) async fn claim_for_execution(
    pool: &PgPool,
    org_id: Uuid,
    approval_id: Uuid,
    triggered_by: &str,
) -> Result<Option<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "UPDATE executions
            SET status = 'executing',
                triggered_by = $3,
                started_at = now()
          WHERE approval_id = $1
            AND org_id = $2
            AND status = 'pending'
            AND expires_at > now()
          RETURNING id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at",
        approval_id,
        org_id,
        triggered_by,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn finalize_executed(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    result: &serde_json::Value,
) -> Result<Option<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "UPDATE executions
            SET status = 'executed',
                result = $3,
                completed_at = now()
          WHERE id = $1
            AND org_id = $2
            AND status = 'executing'
          RETURNING id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at",
        id,
        org_id,
        result,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn finalize_failed(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    error: &str,
) -> Result<Option<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "UPDATE executions
            SET status = 'failed',
                error = $3,
                completed_at = now()
          WHERE id = $1
            AND org_id = $2
            AND status = 'executing'
          RETURNING id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at",
        id,
        org_id,
        error,
    )
    .fetch_optional(pool)
    .await
}

/// Transition a pending execution to cancelled. Returns the updated row on
/// success, `None` if the row was not pending (already executing / terminal).
pub(crate) async fn cancel_if_pending(
    pool: &PgPool,
    org_id: Uuid,
    approval_id: Uuid,
) -> Result<Option<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "UPDATE executions
            SET status = 'cancelled',
                completed_at = now()
          WHERE approval_id = $1
            AND org_id = $2
            AND status = 'pending'
          RETURNING id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at",
        approval_id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn find_by_approval(
    pool: &PgPool,
    org_id: Uuid,
    approval_id: Uuid,
) -> Result<Option<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "SELECT id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at
         FROM executions
         WHERE approval_id = $1 AND org_id = $2",
        approval_id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn find_by_approval_ids(
    pool: &PgPool,
    org_id: Uuid,
    approval_ids: &[Uuid],
) -> Result<Vec<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "SELECT id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at
         FROM executions
         WHERE org_id = $1 AND approval_id = ANY($2)",
        org_id,
        approval_ids,
    )
    .fetch_all(pool)
    .await
}

/// Cross-org maintenance: transition pending executions that have passed their
/// 15-minute deadline to `expired`. Exposed via `SystemScope`.
pub(crate) async fn expire_stale(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE executions
            SET status = 'expired',
                completed_at = now(),
                error = 'expired_before_execution'
          WHERE status = 'pending' AND expires_at < now()",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Cross-org maintenance: reap `executing` rows that have been in flight far
/// longer than any legitimate replay — the API likely crashed mid-call.
/// Exposed via `SystemScope`.
pub(crate) async fn expire_orphaned_executing(
    pool: &PgPool,
    grace_secs: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE executions
            SET status = 'failed',
                error = 'orphaned',
                completed_at = now()
          WHERE status = 'executing'
            AND started_at IS NOT NULL
            AND started_at < now() - make_interval(secs => $1)",
        grace_secs as f64,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
