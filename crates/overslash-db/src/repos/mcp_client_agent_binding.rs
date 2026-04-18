//! Per-(user, MCP client) → agent identity binding.
//!
//! Populated by the OAuth consent step (`POST /oauth/consent/finish`) and read
//! by `/oauth/authorize` to skip consent on repeat logins. The uniqueness
//! constraint on `(user_identity_id, client_id)` makes `upsert` safe to call
//! on every consent submission.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct McpClientAgentBindingRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub user_identity_id: Uuid,
    pub client_id: String,
    pub agent_identity_id: Uuid,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub async fn get_for(
    pool: &PgPool,
    user_identity_id: Uuid,
    client_id: &str,
) -> Result<Option<McpClientAgentBindingRow>, sqlx::Error> {
    sqlx::query_as!(
        McpClientAgentBindingRow,
        "SELECT id, org_id, user_identity_id, client_id, agent_identity_id,
                created_at, updated_at
           FROM mcp_client_agent_bindings
          WHERE user_identity_id = $1 AND client_id = $2",
        user_identity_id,
        client_id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn upsert(
    pool: &PgPool,
    org_id: Uuid,
    user_identity_id: Uuid,
    client_id: &str,
    agent_identity_id: Uuid,
) -> Result<McpClientAgentBindingRow, sqlx::Error> {
    sqlx::query_as!(
        McpClientAgentBindingRow,
        "INSERT INTO mcp_client_agent_bindings
           (org_id, user_identity_id, client_id, agent_identity_id)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_identity_id, client_id)
           DO UPDATE SET agent_identity_id = EXCLUDED.agent_identity_id,
                         updated_at = now()
         RETURNING id, org_id, user_identity_id, client_id, agent_identity_id,
                   created_at, updated_at",
        org_id,
        user_identity_id,
        client_id,
        agent_identity_id,
    )
    .fetch_one(pool)
    .await
}

pub async fn list_for_user(
    pool: &PgPool,
    user_identity_id: Uuid,
) -> Result<Vec<McpClientAgentBindingRow>, sqlx::Error> {
    sqlx::query_as!(
        McpClientAgentBindingRow,
        "SELECT id, org_id, user_identity_id, client_id, agent_identity_id,
                created_at, updated_at
           FROM mcp_client_agent_bindings
          WHERE user_identity_id = $1
          ORDER BY updated_at DESC",
        user_identity_id,
    )
    .fetch_all(pool)
    .await
}
