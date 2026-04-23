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

#[derive(Debug)]
pub struct SimilarBoundClient {
    pub client: OauthMcpClientRow,
    pub agent_identity_id: Uuid,
}

// Match on `client_name` + `software_id` with `IS NOT DISTINCT FROM` so a
// client re-registering with the same identity (even without software_id)
// still pairs with its previous binding. A caller with **both** fields
// NULL is treated as anonymous — returning early with `None` — because
// matching NULL-to-NULL would collapse every metadata-less client the
// user has ever enrolled into the most recent one and silently rebind
// distinct clients to the same agent.
// Does this user already have a (non-revoked) binding to this agent via
// any MCP client? Used to authorize a reauth: the user can only rebind
// a re-registered MCP client to an agent they'd previously enrolled
// some MCP client against.
pub async fn user_has_binding_to_agent(
    pool: &PgPool,
    user_identity_id: Uuid,
    agent_identity_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT 1 AS one
           FROM mcp_client_agent_bindings b
           JOIN oauth_mcp_clients c ON c.client_id = b.client_id
          WHERE b.user_identity_id = $1
            AND b.agent_identity_id = $2
            AND c.is_revoked = false
          LIMIT 1",
        user_identity_id,
        agent_identity_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

pub async fn find_similar_for_user(
    pool: &PgPool,
    user_identity_id: Uuid,
    client_name: Option<&str>,
    software_id: Option<&str>,
) -> Result<Option<SimilarBoundClient>, sqlx::Error> {
    if client_name.is_none() && software_id.is_none() {
        return Ok(None);
    }
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
