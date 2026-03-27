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
    pub created_at: OffsetDateTime,
}

pub async fn get_by_key(pool: &PgPool, key: &str) -> Result<Option<OAuthProviderRow>, sqlx::Error> {
    sqlx::query_as::<_, OAuthProviderRow>(
        "SELECT key, display_name, authorization_endpoint, token_endpoint, revocation_endpoint,
                userinfo_endpoint, client_id_pattern, supports_pkce, supports_refresh,
                extra_auth_params, token_auth_method, is_builtin, created_at
         FROM oauth_providers WHERE key = $1",
    )
    .bind(key)
    .fetch_optional(pool)
    .await
}

pub async fn list_all(pool: &PgPool) -> Result<Vec<OAuthProviderRow>, sqlx::Error> {
    sqlx::query_as::<_, OAuthProviderRow>(
        "SELECT key, display_name, authorization_endpoint, token_endpoint, revocation_endpoint,
                userinfo_endpoint, client_id_pattern, supports_pkce, supports_refresh,
                extra_auth_params, token_auth_method, is_builtin, created_at
         FROM oauth_providers ORDER BY display_name",
    )
    .fetch_all(pool)
    .await
}
