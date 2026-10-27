//! Per-org opt-in letting org OAuth App Credentials serve Overslash-managed
//! sign-in for a provider. Absent row = sign-in keeps the built-in env app.

use sqlx::PgPool;
use uuid::Uuid;

/// Public because `overslash_api::services::org_signin` resolves sign-in
/// credentials pre-auth, before any `OrgScope` exists.
pub async fn is_enabled(
    pool: &PgPool,
    org_id: Uuid,
    provider_key: &str,
) -> Result<bool, sqlx::Error> {
    let found = sqlx::query_scalar!(
        "SELECT EXISTS(SELECT 1 FROM org_oauth_signin_overrides WHERE org_id = $1 AND provider_key = $2)",
        org_id,
        provider_key,
    )
    .fetch_one(pool)
    .await?;
    Ok(found.unwrap_or(false))
}

pub(crate) async fn list_by_org(pool: &PgPool, org_id: Uuid) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar!(
        "SELECT provider_key FROM org_oauth_signin_overrides WHERE org_id = $1",
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub(crate) async fn set(
    pool: &PgPool,
    org_id: Uuid,
    provider_key: &str,
    enabled: bool,
) -> Result<(), sqlx::Error> {
    if enabled {
        sqlx::query!(
            "INSERT INTO org_oauth_signin_overrides (org_id, provider_key) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
            org_id,
            provider_key,
        )
        .execute(pool)
        .await?;
    } else {
        sqlx::query!(
            "DELETE FROM org_oauth_signin_overrides WHERE org_id = $1 AND provider_key = $2",
            org_id,
            provider_key,
        )
        .execute(pool)
        .await?;
    }
    Ok(())
}
