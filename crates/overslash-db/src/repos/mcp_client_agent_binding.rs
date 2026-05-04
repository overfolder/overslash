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
    pub elicitation_enabled: bool,
    pub auto_call_on_approve: bool,
}

pub async fn get_for(
    pool: &PgPool,
    user_identity_id: Uuid,
    client_id: &str,
) -> Result<Option<McpClientAgentBindingRow>, sqlx::Error> {
    sqlx::query_as!(
        McpClientAgentBindingRow,
        "SELECT id, org_id, user_identity_id, client_id, agent_identity_id,
                created_at, updated_at, elicitation_enabled, auto_call_on_approve
           FROM mcp_client_agent_bindings
          WHERE user_identity_id = $1 AND client_id = $2",
        user_identity_id,
        client_id,
    )
    .fetch_optional(pool)
    .await
}

/// Look up the binding by the agent identity. Returns the most-recently-
/// updated row when an agent is bound by multiple users (rare; the common
/// case is one binding per agent because consent mints a fresh agent
/// per-user).
pub async fn get_by_agent_identity(
    pool: &PgPool,
    agent_identity_id: Uuid,
) -> Result<Option<McpClientAgentBindingRow>, sqlx::Error> {
    sqlx::query_as!(
        McpClientAgentBindingRow,
        "SELECT id, org_id, user_identity_id, client_id, agent_identity_id,
                created_at, updated_at, elicitation_enabled, auto_call_on_approve
           FROM mcp_client_agent_bindings
          WHERE agent_identity_id = $1
          ORDER BY updated_at DESC
          LIMIT 1",
        agent_identity_id,
    )
    .fetch_optional(pool)
    .await
}

/// Lookup keyed on the (agent, client) pair. Distinct from
/// `get_by_agent_identity` (which returns the most-recently-updated row
/// across whichever clients are bound to the agent) because in a
/// multi-client-per-agent setup the calling client and the latest binding
/// can be different — eligibility checks must query against the *calling*
/// client.
pub async fn get_for_agent_and_client(
    pool: &PgPool,
    agent_identity_id: Uuid,
    client_id: &str,
) -> Result<Option<McpClientAgentBindingRow>, sqlx::Error> {
    sqlx::query_as!(
        McpClientAgentBindingRow,
        "SELECT id, org_id, user_identity_id, client_id, agent_identity_id,
                created_at, updated_at, elicitation_enabled, auto_call_on_approve
           FROM mcp_client_agent_bindings
          WHERE agent_identity_id = $1 AND client_id = $2
          ORDER BY updated_at DESC
          LIMIT 1",
        agent_identity_id,
        client_id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn set_elicitation_enabled(
    pool: &PgPool,
    binding_id: Uuid,
    enabled: bool,
) -> Result<Option<McpClientAgentBindingRow>, sqlx::Error> {
    sqlx::query_as!(
        McpClientAgentBindingRow,
        "UPDATE mcp_client_agent_bindings
            SET elicitation_enabled = $2,
                updated_at = now()
          WHERE id = $1
         RETURNING id, org_id, user_identity_id, client_id, agent_identity_id,
                   created_at, updated_at, elicitation_enabled, auto_call_on_approve",
        binding_id,
        enabled,
    )
    .fetch_optional(pool)
    .await
}

/// Apply the elicitation toggle to *every* binding for this agent. The
/// dashboard surfaces a single per-agent toggle, so the change has to fan
/// out — otherwise the eligibility check (which is keyed on the calling
/// client's binding) would read a stale flag for any client other than
/// the most-recently-updated one. Returns rows_affected.
pub async fn set_elicitation_enabled_for_agent(
    pool: &PgPool,
    agent_identity_id: Uuid,
    enabled: bool,
) -> Result<u64, sqlx::Error> {
    let r = sqlx::query!(
        "UPDATE mcp_client_agent_bindings
            SET elicitation_enabled = $2,
                updated_at = now()
          WHERE agent_identity_id = $1",
        agent_identity_id,
        enabled,
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

/// Fan-out the auto-call-on-approve toggle across every binding for the
/// agent — same rationale as `set_elicitation_enabled_for_agent`: the
/// eligibility check at resolve time is keyed on whichever binding is
/// most-recently-updated, so a per-client write would let stale flags
/// drive auto-call decisions for the agent's other clients.
pub async fn set_auto_call_on_approve_for_agent(
    pool: &PgPool,
    agent_identity_id: Uuid,
    enabled: bool,
) -> Result<u64, sqlx::Error> {
    let r = sqlx::query!(
        "UPDATE mcp_client_agent_bindings
            SET auto_call_on_approve = $2,
                updated_at = now()
          WHERE agent_identity_id = $1",
        agent_identity_id,
        enabled,
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected())
}

/// Delete every binding for this agent. The reauth flow lets a single user
/// stack multiple `(client_id)` bindings under one agent, so the DELETE can
/// match more than one row — return them all so the caller can audit each
/// removed `client_id` and the cancellation key (`agent_identity_id`) covers
/// every dropped session.
pub async fn delete_by_agent_identity(
    pool: &PgPool,
    agent_identity_id: Uuid,
) -> Result<Vec<McpClientAgentBindingRow>, sqlx::Error> {
    sqlx::query_as!(
        McpClientAgentBindingRow,
        "DELETE FROM mcp_client_agent_bindings
          WHERE agent_identity_id = $1
         RETURNING id, org_id, user_identity_id, client_id, agent_identity_id,
                   created_at, updated_at, elicitation_enabled, auto_call_on_approve",
        agent_identity_id,
    )
    .fetch_all(pool)
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
                   created_at, updated_at, elicitation_enabled, auto_call_on_approve",
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
                created_at, updated_at, elicitation_enabled, auto_call_on_approve
           FROM mcp_client_agent_bindings
          WHERE user_identity_id = $1
          ORDER BY updated_at DESC",
        user_identity_id,
    )
    .fetch_all(pool)
    .await
}
