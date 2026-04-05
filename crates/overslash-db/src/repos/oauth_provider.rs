use sqlx::PgPool;
use time::OffsetDateTime;

#[derive(Debug, sqlx::FromRow)]
pub struct OAuthProviderRow {
    pub key: String,
    pub display_name: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub client_id_pattern: Option<String>,
    pub supports_pkce: bool,
    pub supports_refresh: bool,
    pub extra_auth_params: serde_json::Value,
    /// `client_secret_post` (form body) or `client_secret_basic` (HTTP Basic Auth header).
    pub token_auth_method: String,
    pub is_builtin: bool,
    pub issuer_url: Option<String>,
    pub jwks_uri: Option<String>,
    pub created_at: OffsetDateTime,
}

pub async fn get_by_key(pool: &PgPool, key: &str) -> Result<Option<OAuthProviderRow>, sqlx::Error> {
    sqlx::query_as!(
        OAuthProviderRow,
        "SELECT key, display_name, authorization_endpoint, token_endpoint, revocation_endpoint,
                userinfo_endpoint, client_id_pattern, supports_pkce, supports_refresh,
                extra_auth_params, token_auth_method, is_builtin, issuer_url, jwks_uri, created_at
         FROM oauth_providers WHERE key = $1",
        key,
    )
    .fetch_optional(pool)
    .await
}

pub async fn list_all(pool: &PgPool) -> Result<Vec<OAuthProviderRow>, sqlx::Error> {
    sqlx::query_as!(
        OAuthProviderRow,
        "SELECT key, display_name, authorization_endpoint, token_endpoint, revocation_endpoint,
                userinfo_endpoint, client_id_pattern, supports_pkce, supports_refresh,
                extra_auth_params, token_auth_method, is_builtin, issuer_url, jwks_uri, created_at
         FROM oauth_providers ORDER BY display_name",
    )
    .fetch_all(pool)
    .await
}

/// Create a custom (non-builtin) OAuth provider, typically from OIDC discovery.
#[allow(clippy::too_many_arguments)]
pub async fn create_custom(
    pool: &PgPool,
    key: &str,
    display_name: &str,
    authorization_endpoint: &str,
    token_endpoint: &str,
    revocation_endpoint: Option<&str>,
    userinfo_endpoint: Option<&str>,
    issuer_url: Option<&str>,
    jwks_uri: Option<&str>,
    supports_pkce: bool,
    supports_refresh: bool,
    token_auth_method: &str,
) -> Result<OAuthProviderRow, sqlx::Error> {
    sqlx::query_as!(
        OAuthProviderRow,
        "INSERT INTO oauth_providers (key, display_name, authorization_endpoint, token_endpoint,
                revocation_endpoint, userinfo_endpoint, issuer_url, jwks_uri,
                supports_pkce, supports_refresh, token_auth_method, is_builtin, extra_auth_params)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false, '{}'::jsonb)
         ON CONFLICT (key) DO UPDATE SET
            display_name = EXCLUDED.display_name,
            authorization_endpoint = EXCLUDED.authorization_endpoint,
            token_endpoint = EXCLUDED.token_endpoint,
            revocation_endpoint = EXCLUDED.revocation_endpoint,
            userinfo_endpoint = EXCLUDED.userinfo_endpoint,
            issuer_url = EXCLUDED.issuer_url,
            jwks_uri = EXCLUDED.jwks_uri,
            supports_pkce = EXCLUDED.supports_pkce,
            supports_refresh = EXCLUDED.supports_refresh,
            token_auth_method = EXCLUDED.token_auth_method
         RETURNING key, display_name, authorization_endpoint, token_endpoint, revocation_endpoint,
                   userinfo_endpoint, client_id_pattern, supports_pkce, supports_refresh,
                   extra_auth_params, token_auth_method, is_builtin, issuer_url, jwks_uri, created_at",
        key,
        display_name,
        authorization_endpoint,
        token_endpoint,
        revocation_endpoint,
        userinfo_endpoint,
        issuer_url,
        jwks_uri,
        supports_pkce,
        supports_refresh,
        token_auth_method,
    )
    .fetch_one(pool)
    .await
}
