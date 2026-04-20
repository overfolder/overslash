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

#[derive(Debug)]
pub struct UserBoundClient {
    pub client: OauthMcpClientRow,
    pub agent_identity_id: Uuid,
    pub binding_updated_at: OffsetDateTime,
}

// List clients that are bound to this user via `mcp_client_agent_bindings`.
// Unlike `list_all` (admin-only), this filters to the caller's own clients
// so the dashboard can surface a per-user MCP Clients section without
// requiring admin privileges.
pub async fn list_bound_to_user(
    pool: &PgPool,
    user_identity_id: Uuid,
) -> Result<Vec<UserBoundClient>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"SELECT c.id            AS "id!",
                  c.client_id     AS "client_id!",
                  c.client_name,
                  c.redirect_uris AS "redirect_uris!",
                  c.software_id,
                  c.software_version,
                  c.created_at    AS "created_at!",
                  c.last_seen_at,
                  c.created_ip,
                  c.created_user_agent,
                  c.is_revoked    AS "is_revoked!",
                  b.agent_identity_id AS "agent_identity_id!",
                  b.updated_at        AS "binding_updated_at!"
             FROM oauth_mcp_clients c
             JOIN mcp_client_agent_bindings b ON b.client_id = c.client_id
            WHERE b.user_identity_id = $1
         ORDER BY b.updated_at DESC"#,
        user_identity_id,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| UserBoundClient {
            client: OauthMcpClientRow {
                id: r.id,
                client_id: r.client_id,
                client_name: r.client_name,
                redirect_uris: r.redirect_uris,
                software_id: r.software_id,
                software_version: r.software_version,
                created_at: r.created_at,
                last_seen_at: r.last_seen_at,
                created_ip: r.created_ip,
                created_user_agent: r.created_user_agent,
                is_revoked: r.is_revoked,
            },
            agent_identity_id: r.agent_identity_id,
            binding_updated_at: r.binding_updated_at,
        })
        .collect())
}

// Does this user own a binding to this client? Used to authorize the
// user-scoped revoke endpoint — only clients the caller has enrolled can
// be revoked by that caller.
pub async fn user_has_binding(
    pool: &PgPool,
    user_identity_id: Uuid,
    client_id: &str,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT 1 AS one FROM mcp_client_agent_bindings
          WHERE user_identity_id = $1 AND client_id = $2 LIMIT 1",
        user_identity_id,
        client_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
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

#[derive(Debug)]
pub struct SimilarBoundClient {
    pub client: OauthMcpClientRow,
    pub agent_identity_id: Uuid,
}

// `IS NOT DISTINCT FROM` handles the common case where one or both sides are
// NULL — a client that re-registers without software_id should still match
// a previous registration that also had no software_id.
pub async fn find_similar_for_user(
    pool: &PgPool,
    user_identity_id: Uuid,
    client_name: Option<&str>,
    software_id: Option<&str>,
) -> Result<Option<SimilarBoundClient>, sqlx::Error> {
    let row = sqlx::query!(
        r#"SELECT c.id            AS "id!",
                  c.client_id     AS "client_id!",
                  c.client_name,
                  c.redirect_uris AS "redirect_uris!",
                  c.software_id,
                  c.software_version,
                  c.created_at    AS "created_at!",
                  c.last_seen_at,
                  c.created_ip,
                  c.created_user_agent,
                  c.is_revoked    AS "is_revoked!",
                  b.agent_identity_id AS "agent_identity_id!"
             FROM oauth_mcp_clients c
             JOIN mcp_client_agent_bindings b ON b.client_id = c.client_id
            WHERE b.user_identity_id = $1
              AND c.is_revoked = false
              AND c.client_name IS NOT DISTINCT FROM $2
              AND c.software_id IS NOT DISTINCT FROM $3
         ORDER BY b.updated_at DESC
            LIMIT 1"#,
        user_identity_id,
        client_name,
        software_id,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| SimilarBoundClient {
        client: OauthMcpClientRow {
            id: r.id,
            client_id: r.client_id,
            client_name: r.client_name,
            redirect_uris: r.redirect_uris,
            software_id: r.software_id,
            software_version: r.software_version,
            created_at: r.created_at,
            last_seen_at: r.last_seen_at,
            created_ip: r.created_ip,
            created_user_agent: r.created_user_agent,
            is_revoked: r.is_revoked,
        },
        agent_identity_id: r.agent_identity_id,
    }))
}
