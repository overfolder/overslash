//! `pending_mcp_elicitations` — coordination state for the SSE elicitation
//! flow. The originator pod inserts a row when it upgrades a tools/call to
//! SSE; the pod that receives the elicitation response (which may be a
//! different replica behind the load balancer) drives resolve+call against
//! the underlying approval and writes the final response into the row. The
//! originator polls until the row reaches a terminal status, then emits the
//! result on its SSE stream.

use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct PendingElicitationRow {
    pub elicit_id: String,
    pub session_id: Uuid,
    pub agent_identity_id: Uuid,
    pub approval_id: Uuid,
    pub status: String,
    pub final_response: Option<Value>,
    pub created_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
}

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_CLAIMED: &str = "claimed";
pub const STATUS_COMPLETED: &str = "completed";
pub const STATUS_FAILED: &str = "failed";
pub const STATUS_CANCELLED: &str = "cancelled";

pub async fn insert(
    pool: &PgPool,
    elicit_id: &str,
    session_id: Uuid,
    agent_identity_id: Uuid,
    approval_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO pending_mcp_elicitations
           (elicit_id, session_id, agent_identity_id, approval_id)
         VALUES ($1, $2, $3, $4)",
        elicit_id,
        session_id,
        agent_identity_id,
        approval_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get(
    pool: &PgPool,
    elicit_id: &str,
) -> Result<Option<PendingElicitationRow>, sqlx::Error> {
    sqlx::query_as!(
        PendingElicitationRow,
        "SELECT elicit_id, session_id, agent_identity_id, approval_id,
                status, final_response, created_at, completed_at
           FROM pending_mcp_elicitations
          WHERE elicit_id = $1",
        elicit_id,
    )
    .fetch_optional(pool)
    .await
}

/// Atomically claim a pending row so only one receiver pod drives the
/// resolve+call. Returns the row on success, `None` if the row is missing or
/// already non-pending. The receiver runs the work outside the transaction
/// and then calls `complete` / `fail`.
pub async fn claim(
    pool: &PgPool,
    elicit_id: &str,
) -> Result<Option<PendingElicitationRow>, sqlx::Error> {
    sqlx::query_as!(
        PendingElicitationRow,
        "UPDATE pending_mcp_elicitations
            SET status = $2
          WHERE elicit_id = $1 AND status = $3
         RETURNING elicit_id, session_id, agent_identity_id, approval_id,
                   status, final_response, created_at, completed_at",
        elicit_id,
        STATUS_CLAIMED,
        STATUS_PENDING,
    )
    .fetch_optional(pool)
    .await
}

/// Terminal write from the receiver pod. Gated on a live status so a row
/// already cancelled by the originator's timeout (or an admin disconnect)
/// stays cancelled — otherwise an unconditional UPDATE would race the
/// `claimed → cancelled` flip and let a late receiver overwrite the row to
/// `completed`, leaving the SSE stream and DB inconsistent.
pub async fn complete(
    pool: &PgPool,
    elicit_id: &str,
    final_response: &Value,
) -> Result<u64, sqlx::Error> {
    let r = sqlx::query!(
        "UPDATE pending_mcp_elicitations
            SET status = $2, final_response = $3, completed_at = now()
          WHERE elicit_id = $1 AND status IN ($4, $5)",
        elicit_id,
        STATUS_COMPLETED,
        final_response,
        STATUS_CLAIMED,
        STATUS_PENDING,
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

pub async fn fail(
    pool: &PgPool,
    elicit_id: &str,
    final_response: &Value,
) -> Result<u64, sqlx::Error> {
    let r = sqlx::query!(
        "UPDATE pending_mcp_elicitations
            SET status = $2, final_response = $3, completed_at = now()
          WHERE elicit_id = $1 AND status IN ($4, $5)",
        elicit_id,
        STATUS_FAILED,
        final_response,
        STATUS_CLAIMED,
        STATUS_PENDING,
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

pub async fn cancel(pool: &PgPool, elicit_id: &str) -> Result<(), sqlx::Error> {
    // Cancellable from either `pending` (originator timeout / disconnect) or
    // `claimed` (receiver decided not to resolve, e.g. user clicked decline /
    // cancel on the elicitation form). Already-terminal rows are left as-is.
    sqlx::query!(
        "UPDATE pending_mcp_elicitations
            SET status = $2, completed_at = now()
          WHERE elicit_id = $1 AND status IN ($3, $4)",
        elicit_id,
        STATUS_CANCELLED,
        STATUS_PENDING,
        STATUS_CLAIMED,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Cancel every in-flight elicitation tied to a given agent. Used by the
/// disconnect handler so re-initialize drift (the client's `last_session_id`
/// was rewritten between elicitation-start and disconnect) doesn't orphan
/// rows that no longer match the current session id.
pub async fn cancel_for_agent(pool: &PgPool, agent_identity_id: Uuid) -> Result<u64, sqlx::Error> {
    let r = sqlx::query!(
        "UPDATE pending_mcp_elicitations
            SET status = $2, completed_at = now()
          WHERE agent_identity_id = $1 AND status IN ($3, $4)",
        agent_identity_id,
        STATUS_CANCELLED,
        STATUS_PENDING,
        STATUS_CLAIMED,
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

/// Periodic cleanup — drop rows older than `older_than_secs`.
pub async fn purge_older_than(pool: &PgPool, older_than_secs: i64) -> Result<u64, sqlx::Error> {
    let r = sqlx::query!(
        "DELETE FROM pending_mcp_elicitations
          WHERE created_at < now() - make_interval(secs => $1)",
        older_than_secs as f64,
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}
