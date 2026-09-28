//! `mcp_url_elicitations` — carries a 2025-era MCP client's answer to a
//! URL-mode `elicitation/create` from whichever replica receives it to the
//! replica holding the tool call's SSE stream. See migration 126.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct UrlElicitationRow {
    pub elicit_id: String,
    pub agent_identity_id: Uuid,
    /// `accept` / `decline` / `cancel`, or `None` while unanswered.
    pub action: Option<String>,
    pub created_at: OffsetDateTime,
    pub answered_at: Option<OffsetDateTime>,
}

pub async fn insert(
    pool: &PgPool,
    elicit_id: &str,
    agent_identity_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO mcp_url_elicitations (elicit_id, agent_identity_id) VALUES ($1, $2)",
        elicit_id,
        agent_identity_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get(pool: &PgPool, elicit_id: &str) -> Result<Option<UrlElicitationRow>, sqlx::Error> {
    sqlx::query_as!(
        UrlElicitationRow,
        "SELECT elicit_id, agent_identity_id, action, created_at, answered_at
           FROM mcp_url_elicitations WHERE elicit_id = $1",
        elicit_id,
    )
    .fetch_optional(pool)
    .await
}

/// Record the client's answer. Only the first answer counts; returns whether
/// this one was recorded. `action` must be one of the three MCP actions —
/// anything else is stored as `cancel`, the "no answer" outcome.
pub async fn answer(pool: &PgPool, elicit_id: &str, action: &str) -> Result<bool, sqlx::Error> {
    let action = match action {
        "accept" | "decline" => action,
        _ => "cancel",
    };
    let r = sqlx::query!(
        "UPDATE mcp_url_elicitations SET action = $2, answered_at = now()
          WHERE elicit_id = $1 AND action IS NULL",
        elicit_id,
        action,
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Delete rows older than `older_than_secs`. Nothing reads a row once the
/// stream that opened it has finished, which is bounded by the elicitation
/// timeout, so any retention past that is only for debugging.
pub async fn purge(pool: &PgPool, older_than_secs: i64) -> Result<u64, sqlx::Error> {
    let r = sqlx::query!(
        "DELETE FROM mcp_url_elicitations
          WHERE created_at < now() - make_interval(secs => $1)",
        older_than_secs as f64,
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}
