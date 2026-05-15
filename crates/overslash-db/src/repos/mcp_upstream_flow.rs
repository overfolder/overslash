//! `mcp_upstream_flows` — in-progress nested-OAuth flows. The opaque base62
//! `id` is both the URL short-id and the OAuth `state` parameter sent to the
//! upstream AS. The row is the trusted source of identity, resource, PKCE
//! verifier, and TTL — never trust state-encoded data.
//!
//! Single-use is enforced via `consumed_at` on an atomic
//! `UPDATE … WHERE consumed_at IS NULL RETURNING …` (see [`consume`]).
//! Concurrent clicks of the same short URL: the first transaction wins;
//! the second receives `Ok(None)` and the gate/callback returns 410.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct McpUpstreamFlowRow {
    pub id: String,
    pub identity_id: Uuid,
    pub org_id: Uuid,
    pub upstream_resource: String,
    pub upstream_client_id: String,
    pub upstream_as_issuer: String,
    pub upstream_token_endpoint: String,
    pub upstream_authorize_url: String,
    pub pkce_code_verifier: String,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub created_ip: Option<String>,
    pub created_user_agent: Option<String>,
}

pub struct CreateMcpUpstreamFlow<'a> {
    pub id: &'a str,
    pub identity_id: Uuid,
    pub org_id: Uuid,
    pub upstream_resource: &'a str,
    pub upstream_client_id: &'a str,
    pub upstream_as_issuer: &'a str,
    pub upstream_token_endpoint: &'a str,
    pub upstream_authorize_url: &'a str,
    pub pkce_code_verifier: &'a str,
    pub expires_at: OffsetDateTime,
    pub created_ip: Option<&'a str>,
    pub created_user_agent: Option<&'a str>,
}

pub async fn create(
    pool: &PgPool,
    input: &CreateMcpUpstreamFlow<'_>,
) -> Result<McpUpstreamFlowRow, sqlx::Error> {
    sqlx::query_as!(
        McpUpstreamFlowRow,
        "INSERT INTO mcp_upstream_flows
            (id, identity_id, org_id, upstream_resource, upstream_client_id,
             upstream_as_issuer, upstream_token_endpoint,
             upstream_authorize_url, pkce_code_verifier, expires_at,
             created_ip, created_user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         RETURNING id, identity_id, org_id, upstream_resource, upstream_client_id,
                   upstream_as_issuer, upstream_token_endpoint,
                   upstream_authorize_url, pkce_code_verifier, expires_at,
                   consumed_at, created_at, created_ip, created_user_agent",
        input.id,
        input.identity_id,
        input.org_id,
        input.upstream_resource,
        input.upstream_client_id,
        input.upstream_as_issuer,
        input.upstream_token_endpoint,
        input.upstream_authorize_url,
        input.pkce_code_verifier,
        input.expires_at,
        input.created_ip,
        input.created_user_agent,
    )
    .fetch_one(pool)
    .await
}

/// Fetch a flow by id without consuming it. Used by the gate to render the
/// pre-redirect page (multi-org switch / login prompt / mismatch). The gate
/// must NOT consume — only the callback consumes.
pub async fn get_by_id(pool: &PgPool, id: &str) -> Result<Option<McpUpstreamFlowRow>, sqlx::Error> {
    sqlx::query_as!(
        McpUpstreamFlowRow,
        "SELECT id, identity_id, org_id, upstream_resource, upstream_client_id,
                upstream_as_issuer, upstream_token_endpoint,
                upstream_authorize_url, pkce_code_verifier, expires_at,
                consumed_at, created_at, created_ip, created_user_agent
           FROM mcp_upstream_flows WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Atomically claim a flow for completion. Returns `Some(row)` to the
/// winning caller and `None` if the flow is missing, expired, or already
/// consumed. The row's `consumed_at` is filled with `now()` on success.
pub async fn consume(pool: &PgPool, id: &str) -> Result<Option<McpUpstreamFlowRow>, sqlx::Error> {
    sqlx::query_as!(
        McpUpstreamFlowRow,
        "UPDATE mcp_upstream_flows
            SET consumed_at = now()
          WHERE id = $1
            AND consumed_at IS NULL
            AND expires_at > now()
          RETURNING id, identity_id, org_id, upstream_resource, upstream_client_id,
                    upstream_as_issuer, upstream_token_endpoint,
                    upstream_authorize_url, pkce_code_verifier, expires_at,
                    consumed_at, created_at, created_ip, created_user_agent",
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Find the most recent active (non-expired, non-consumed) flow for the
/// given (identity, upstream_resource). Used by the boot/ensure path so
/// re-running boot returns the same authorize URL rather than minting a
/// fresh row each time.
pub async fn find_active_for(
    pool: &PgPool,
    identity_id: Uuid,
    upstream_resource: &str,
) -> Result<Option<McpUpstreamFlowRow>, sqlx::Error> {
    sqlx::query_as!(
        McpUpstreamFlowRow,
        "SELECT id, identity_id, org_id, upstream_resource, upstream_client_id,
                upstream_as_issuer, upstream_token_endpoint,
                upstream_authorize_url, pkce_code_verifier, expires_at,
                consumed_at, created_at, created_ip, created_user_agent
           FROM mcp_upstream_flows
          WHERE identity_id = $1
            AND upstream_resource = $2
            AND consumed_at IS NULL
            AND expires_at > now()
          ORDER BY created_at DESC
          LIMIT 1",
        identity_id,
        upstream_resource,
    )
    .fetch_optional(pool)
    .await
}

/// Best-effort cleanup of expired & unconsumed flows. Called periodically.
pub async fn delete_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM mcp_upstream_flows
          WHERE expires_at < now() AND consumed_at IS NULL",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
