use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct McpRefreshTokenRow {
    pub id: Uuid,
    pub client_id: String,
    pub identity_id: Uuid,
    pub org_id: Uuid,
    pub hash: Vec<u8>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub replaced_by_id: Option<Uuid>,
}

pub struct CreateMcpRefreshToken<'a> {
    pub client_id: &'a str,
    pub identity_id: Uuid,
    pub org_id: Uuid,
    pub hash: &'a [u8],
    pub expires_at: OffsetDateTime,
}

pub async fn create(
    pool: &PgPool,
    input: &CreateMcpRefreshToken<'_>,
) -> Result<McpRefreshTokenRow, sqlx::Error> {
    sqlx::query_as!(
        McpRefreshTokenRow,
        "INSERT INTO mcp_refresh_tokens
           (client_id, identity_id, org_id, hash, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, client_id, identity_id, org_id, hash,
                   created_at, expires_at, revoked_at, replaced_by_id",
        input.client_id,
        input.identity_id,
        input.org_id,
        input.hash,
        input.expires_at,
    )
    .fetch_one(pool)
    .await
}

pub async fn get_by_hash(
    pool: &PgPool,
    hash: &[u8],
) -> Result<Option<McpRefreshTokenRow>, sqlx::Error> {
    sqlx::query_as!(
        McpRefreshTokenRow,
        "SELECT id, client_id, identity_id, org_id, hash,
                created_at, expires_at, revoked_at, replaced_by_id
           FROM mcp_refresh_tokens
          WHERE hash = $1",
        hash,
    )
    .fetch_optional(pool)
    .await
}

/// Atomically rotate a refresh token: mark the presented row as revoked +
/// replaced-by, and insert the freshly minted one. Returns the new row.
pub async fn rotate(
    pool: &PgPool,
    presented_id: Uuid,
    new: &CreateMcpRefreshToken<'_>,
) -> Result<McpRefreshTokenRow, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let inserted = sqlx::query_as!(
        McpRefreshTokenRow,
        "INSERT INTO mcp_refresh_tokens
           (client_id, identity_id, org_id, hash, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, client_id, identity_id, org_id, hash,
                   created_at, expires_at, revoked_at, replaced_by_id",
        new.client_id,
        new.identity_id,
        new.org_id,
        new.hash,
        new.expires_at,
    )
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query!(
        "UPDATE mcp_refresh_tokens
            SET revoked_at = now(), replaced_by_id = $2
          WHERE id = $1",
        presented_id,
        inserted.id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(inserted)
}

/// Revoke a single token by ID. Idempotent.
pub async fn revoke_by_id(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE mcp_refresh_tokens
            SET revoked_at = coalesce(revoked_at, now())
          WHERE id = $1",
        id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Revoke every token connected to `start_id` via `replaced_by_id` links —
/// both forward (newer tokens minted from the start) and backward (older
/// tokens the start replaced). Called on refresh-token replay detection.
pub async fn revoke_chain_from(pool: &PgPool, start_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "WITH RECURSIVE chain(id, replaced_by_id) AS (
             SELECT id, replaced_by_id FROM mcp_refresh_tokens WHERE id = $1
             UNION
             SELECT t.id, t.replaced_by_id
               FROM mcp_refresh_tokens t
               JOIN chain c ON t.id = c.replaced_by_id OR t.replaced_by_id = c.id
         )
         UPDATE mcp_refresh_tokens
            SET revoked_at = coalesce(revoked_at, now())
          WHERE id IN (SELECT id FROM chain)",
        start_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Revoke every outstanding refresh token bound to a client.
/// Called when the org-admin revokes the client record.
pub async fn revoke_all_for_client(pool: &PgPool, client_id: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE mcp_refresh_tokens
            SET revoked_at = coalesce(revoked_at, now())
          WHERE client_id = $1 AND revoked_at IS NULL",
        client_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
