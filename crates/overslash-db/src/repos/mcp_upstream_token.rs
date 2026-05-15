//! `mcp_upstream_tokens` — versioned, encrypted-at-rest tokens issued by
//! upstream MCP authorization servers. Multiple rows per connection allowed
//! for rotation; the active row is the unique one with `superseded_at IS NULL`
//! (enforced by `idx_mcp_upstream_tokens_current`).
//!
//! Encryption (AES-256-GCM) is performed by route handlers in
//! `crates/overslash-api/src/routes/oauth_upstream.rs` using the shared
//! `crates/overslash-core/src/crypto.rs` primitive. Ciphertexts here include
//! the random nonce prefix produced by `crypto::encrypt`.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct McpUpstreamTokenRow {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub access_token_ciphertext: Vec<u8>,
    pub refresh_token_ciphertext: Option<Vec<u8>>,
    pub access_token_expires_at: Option<OffsetDateTime>,
    pub scope: Option<String>,
    pub created_at: OffsetDateTime,
    pub superseded_at: Option<OffsetDateTime>,
}

pub struct InsertMcpUpstreamToken<'a> {
    pub connection_id: Uuid,
    pub access_token_ciphertext: &'a [u8],
    pub refresh_token_ciphertext: Option<&'a [u8]>,
    pub access_token_expires_at: Option<OffsetDateTime>,
    pub scope: Option<&'a str>,
}

/// Insert a new token as the current row for `connection_id`, atomically
/// superseding any prior current row. The unique partial index
/// `idx_mcp_upstream_tokens_current` guarantees there is at most one
/// non-superseded row per connection at any time.
pub async fn insert_current(
    pool: &PgPool,
    input: &InsertMcpUpstreamToken<'_>,
) -> Result<McpUpstreamTokenRow, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query!(
        "UPDATE mcp_upstream_tokens
            SET superseded_at = now()
          WHERE connection_id = $1 AND superseded_at IS NULL",
        input.connection_id,
    )
    .execute(&mut *tx)
    .await?;
    let inserted = sqlx::query_as!(
        McpUpstreamTokenRow,
        "INSERT INTO mcp_upstream_tokens
            (connection_id, access_token_ciphertext, refresh_token_ciphertext,
             access_token_expires_at, scope)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, connection_id, access_token_ciphertext,
                   refresh_token_ciphertext, access_token_expires_at, scope,
                   created_at, superseded_at",
        input.connection_id,
        input.access_token_ciphertext,
        input.refresh_token_ciphertext,
        input.access_token_expires_at,
        input.scope,
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(inserted)
}

/// Fetch the current (non-superseded) token for a connection.
pub async fn get_current(
    pool: &PgPool,
    connection_id: Uuid,
) -> Result<Option<McpUpstreamTokenRow>, sqlx::Error> {
    sqlx::query_as!(
        McpUpstreamTokenRow,
        "SELECT id, connection_id, access_token_ciphertext,
                refresh_token_ciphertext, access_token_expires_at, scope,
                created_at, superseded_at
           FROM mcp_upstream_tokens
          WHERE connection_id = $1 AND superseded_at IS NULL",
        connection_id,
    )
    .fetch_optional(pool)
    .await
}

/// Mark all tokens for a connection as superseded. Called on revoke.
pub async fn supersede_all(pool: &PgPool, connection_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE mcp_upstream_tokens
            SET superseded_at = coalesce(superseded_at, now())
          WHERE connection_id = $1",
        connection_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}
