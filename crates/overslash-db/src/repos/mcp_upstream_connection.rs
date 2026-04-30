//! `mcp_upstream_connections` — one row per (identity, upstream MCP resource).
//! Tracks the DCR'd client_id at the upstream AS and the connection's
//! current status. Tokens live in `mcp_upstream_tokens`, keyed by `id`.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct McpUpstreamConnectionRow {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub org_id: Uuid,
    pub upstream_resource: String,
    pub upstream_client_id: String,
    pub status: String,
    pub created_at: OffsetDateTime,
    pub last_refreshed_at: Option<OffsetDateTime>,
}

crate::repos::impl_org_owned!(McpUpstreamConnectionRow);

pub const STATUS_PENDING_AUTH: &str = "pending_auth";
pub const STATUS_READY: &str = "ready";
pub const STATUS_REVOKED: &str = "revoked";
pub const STATUS_ERROR: &str = "error";

pub struct UpsertMcpUpstreamConnection<'a> {
    pub identity_id: Uuid,
    pub org_id: Uuid,
    pub upstream_resource: &'a str,
    pub upstream_client_id: &'a str,
}

/// Insert or update the (identity, upstream_resource) connection row,
/// resetting status to `pending_auth`. Used when a new flow is initiated;
/// the callback flips status to `ready` once a token lands.
pub async fn upsert_pending(
    pool: &PgPool,
    input: &UpsertMcpUpstreamConnection<'_>,
) -> Result<McpUpstreamConnectionRow, sqlx::Error> {
    sqlx::query_as!(
        McpUpstreamConnectionRow,
        "INSERT INTO mcp_upstream_connections
            (identity_id, org_id, upstream_resource, upstream_client_id, status)
         VALUES ($1, $2, $3, $4, 'pending_auth')
         ON CONFLICT (identity_id, upstream_resource) DO UPDATE
           SET upstream_client_id = EXCLUDED.upstream_client_id,
               status = 'pending_auth'
         RETURNING id, identity_id, org_id, upstream_resource, upstream_client_id,
                   status, created_at, last_refreshed_at",
        input.identity_id,
        input.org_id,
        input.upstream_resource,
        input.upstream_client_id,
    )
    .fetch_one(pool)
    .await
}

pub async fn get(
    pool: &PgPool,
    identity_id: Uuid,
    upstream_resource: &str,
) -> Result<Option<McpUpstreamConnectionRow>, sqlx::Error> {
    sqlx::query_as!(
        McpUpstreamConnectionRow,
        "SELECT id, identity_id, org_id, upstream_resource, upstream_client_id,
                status, created_at, last_refreshed_at
           FROM mcp_upstream_connections
          WHERE identity_id = $1 AND upstream_resource = $2",
        identity_id,
        upstream_resource,
    )
    .fetch_optional(pool)
    .await
}

pub async fn get_by_id(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<McpUpstreamConnectionRow>, sqlx::Error> {
    sqlx::query_as!(
        McpUpstreamConnectionRow,
        "SELECT id, identity_id, org_id, upstream_resource, upstream_client_id,
                status, created_at, last_refreshed_at
           FROM mcp_upstream_connections
          WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn list_for_identity(
    pool: &PgPool,
    identity_id: Uuid,
) -> Result<Vec<McpUpstreamConnectionRow>, sqlx::Error> {
    sqlx::query_as!(
        McpUpstreamConnectionRow,
        "SELECT id, identity_id, org_id, upstream_resource, upstream_client_id,
                status, created_at, last_refreshed_at
           FROM mcp_upstream_connections
          WHERE identity_id = $1
          ORDER BY created_at DESC",
        identity_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn mark_ready(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE mcp_upstream_connections
            SET status = 'ready', last_refreshed_at = now()
          WHERE id = $1",
        id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_revoked(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE mcp_upstream_connections SET status = 'revoked' WHERE id = $1",
        id,
    )
    .execute(pool)
    .await?;
    Ok(())
}
