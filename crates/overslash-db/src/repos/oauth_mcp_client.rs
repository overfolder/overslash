use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct OauthMcpClientRow {
    pub id: Uuid,
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub created_at: OffsetDateTime,
    pub last_seen_at: Option<OffsetDateTime>,
    pub created_ip: Option<String>,
    pub created_user_agent: Option<String>,
    pub is_revoked: bool,
}

pub struct CreateOauthMcpClient<'a> {
    pub client_id: &'a str,
    pub client_name: Option<&'a str>,
    pub redirect_uris: &'a [String],
    pub software_id: Option<&'a str>,
    pub software_version: Option<&'a str>,
    pub created_ip: Option<&'a str>,
    pub created_user_agent: Option<&'a str>,
}

pub async fn create(
    pool: &PgPool,
    input: &CreateOauthMcpClient<'_>,
) -> Result<OauthMcpClientRow, sqlx::Error> {
    sqlx::query_as!(
        OauthMcpClientRow,
        "INSERT INTO oauth_mcp_clients
             (client_id, client_name, redirect_uris, software_id, software_version,
              created_ip, created_user_agent)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           RETURNING id, client_id, client_name, redirect_uris,
                     software_id, software_version, created_at, last_seen_at,
                     created_ip, created_user_agent, is_revoked",
        input.client_id,
        input.client_name,
        input.redirect_uris,
        input.software_id,
        input.software_version,
        input.created_ip,
        input.created_user_agent,
    )
    .fetch_one(pool)
    .await
}

pub async fn get_by_client_id(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<OauthMcpClientRow>, sqlx::Error> {
    sqlx::query_as!(
        OauthMcpClientRow,
        "SELECT id, client_id, client_name, redirect_uris,
                software_id, software_version, created_at, last_seen_at,
                created_ip, created_user_agent, is_revoked
           FROM oauth_mcp_clients
          WHERE client_id = $1",
        client_id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn list_all(pool: &PgPool) -> Result<Vec<OauthMcpClientRow>, sqlx::Error> {
    sqlx::query_as!(
        OauthMcpClientRow,
        "SELECT id, client_id, client_name, redirect_uris,
                software_id, software_version, created_at, last_seen_at,
                created_ip, created_user_agent, is_revoked
           FROM oauth_mcp_clients
          ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
}

pub async fn mark_seen(pool: &PgPool, client_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE oauth_mcp_clients SET last_seen_at = now() WHERE client_id = $1",
        client_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn revoke(pool: &PgPool, client_id: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE oauth_mcp_clients SET is_revoked = true WHERE client_id = $1",
        client_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
