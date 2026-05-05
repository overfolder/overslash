//! `oauth_connection_flows` — in-progress HTTP-OAuth flows that are not yet
//! consumed by the user click. The opaque base62 `id` is the URL short-id
//! used in `https://app.overslash.com/connect-authorize?id=…`. The row is
//! the trusted source of identity, expiry, PKCE verifier, and the raw
//! provider authorize URL.
//!
//! Mirrors `mcp_upstream_flow` for the upstream-MCP path. We keep the two
//! tables separate for now (HTTP-OAuth has no DCR, no upstream-AS issuer,
//! and binds to `oauth_provider` rather than an arbitrary resource URL).
//! Consolidation is fair follow-up work if the second handler grows the
//! itch.
//!
//! Single-use is enforced via `consumed_at`. Concurrent clicks of the
//! same URL: first wins, second sees `Ok(None)`. The `/v1/oauth/callback`
//! security boundary is unchanged and still keys off the colon-segmented
//! `state` parameter — `consumed_at` is purely the gate's UX flag.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct OauthConnectionFlowRow {
    pub id: String,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub actor_identity_id: Uuid,
    pub provider_key: String,
    pub byoc_credential_id: Option<Uuid>,
    pub scopes: Vec<String>,
    pub pkce_code_verifier: Option<String>,
    pub upstream_authorize_url: String,
    pub expires_at: OffsetDateTime,
    pub consumed_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub created_ip: Option<String>,
    pub created_user_agent: Option<String>,
}

pub struct CreateOauthConnectionFlow<'a> {
    pub id: &'a str,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub actor_identity_id: Uuid,
    pub provider_key: &'a str,
    pub byoc_credential_id: Option<Uuid>,
    pub scopes: &'a [String],
    pub pkce_code_verifier: Option<&'a str>,
    pub upstream_authorize_url: &'a str,
    pub expires_at: OffsetDateTime,
    pub created_ip: Option<&'a str>,
    pub created_user_agent: Option<&'a str>,
}

pub async fn create(
    pool: &PgPool,
    input: &CreateOauthConnectionFlow<'_>,
) -> Result<OauthConnectionFlowRow, sqlx::Error> {
    sqlx::query_as!(
        OauthConnectionFlowRow,
        "INSERT INTO oauth_connection_flows
            (id, org_id, identity_id, actor_identity_id, provider_key,
             byoc_credential_id, scopes, pkce_code_verifier,
             upstream_authorize_url, expires_at,
             created_ip, created_user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
         RETURNING id, org_id, identity_id, actor_identity_id, provider_key,
                   byoc_credential_id, scopes, pkce_code_verifier,
                   upstream_authorize_url, expires_at, consumed_at,
                   created_at, created_ip, created_user_agent",
        input.id,
        input.org_id,
        input.identity_id,
        input.actor_identity_id,
        input.provider_key,
        input.byoc_credential_id,
        input.scopes,
        input.pkce_code_verifier,
        input.upstream_authorize_url,
        input.expires_at,
        input.created_ip,
        input.created_user_agent,
    )
    .fetch_one(pool)
    .await
}

/// Fetch a flow by id without consuming it. The gate uses this to render
/// the pre-redirect page (login bounce, mismatch HTML). Only the gate's
/// successful-redirect path consumes — see [`consume`].
pub async fn get_by_id(
    pool: &PgPool,
    id: &str,
) -> Result<Option<OauthConnectionFlowRow>, sqlx::Error> {
    sqlx::query_as!(
        OauthConnectionFlowRow,
        "SELECT id, org_id, identity_id, actor_identity_id, provider_key,
                byoc_credential_id, scopes, pkce_code_verifier,
                upstream_authorize_url, expires_at, consumed_at,
                created_at, created_ip, created_user_agent
           FROM oauth_connection_flows WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Atomically claim a flow for the gate redirect. Returns `Some(row)` to
/// the winning caller and `None` if missing, expired, or already consumed.
pub async fn consume(
    pool: &PgPool,
    id: &str,
) -> Result<Option<OauthConnectionFlowRow>, sqlx::Error> {
    sqlx::query_as!(
        OauthConnectionFlowRow,
        "UPDATE oauth_connection_flows
            SET consumed_at = now()
          WHERE id = $1
            AND consumed_at IS NULL
            AND expires_at > now()
          RETURNING id, org_id, identity_id, actor_identity_id, provider_key,
                    byoc_credential_id, scopes, pkce_code_verifier,
                    upstream_authorize_url, expires_at, consumed_at,
                    created_at, created_ip, created_user_agent",
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Best-effort cleanup of expired & unconsumed flows. Call periodically.
pub async fn delete_expired(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM oauth_connection_flows
          WHERE expires_at < now() AND consumed_at IS NULL",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
