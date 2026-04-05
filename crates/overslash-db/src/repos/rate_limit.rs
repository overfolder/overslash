use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct RateLimitRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    pub scope: String,
    pub max_requests: i32,
    pub window_seconds: i32,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl_org_owned!(RateLimitRow);

/// Upsert a rate limit config. Uses scope + org + identity/group to determine uniqueness.
pub async fn upsert(
    pool: &PgPool,
    org_id: Uuid,
    scope: &str,
    identity_id: Option<Uuid>,
    group_id: Option<Uuid>,
    max_requests: i32,
    window_seconds: i32,
) -> Result<RateLimitRow, sqlx::Error> {
    // Use the appropriate unique index for conflict resolution based on scope.
    // We do a two-step approach: try update, then insert if no rows updated.
    // This avoids complex ON CONFLICT with partial indexes.
    let existing = match scope {
        "org" => {
            sqlx::query_as!(
                RateLimitRow,
                "UPDATE rate_limits SET max_requests = $2, window_seconds = $3, updated_at = now()
                 WHERE org_id = $1 AND scope = 'org'
                 RETURNING id, org_id, identity_id, group_id, scope, max_requests, window_seconds, created_at, updated_at",
                org_id, max_requests, window_seconds,
            )
            .fetch_optional(pool)
            .await?
        }
        "group" => {
            sqlx::query_as!(
                RateLimitRow,
                "UPDATE rate_limits SET max_requests = $3, window_seconds = $4, updated_at = now()
                 WHERE org_id = $1 AND group_id = $2 AND scope = 'group'
                 RETURNING id, org_id, identity_id, group_id, scope, max_requests, window_seconds, created_at, updated_at",
                org_id, group_id, max_requests, window_seconds,
            )
            .fetch_optional(pool)
            .await?
        }
        "user" | "identity_cap" => {
            sqlx::query_as!(
                RateLimitRow,
                "UPDATE rate_limits SET max_requests = $3, window_seconds = $4, updated_at = now()
                 WHERE org_id = $1 AND identity_id = $2 AND scope = $5
                 RETURNING id, org_id, identity_id, group_id, scope, max_requests, window_seconds, created_at, updated_at",
                org_id, identity_id, max_requests, window_seconds, scope,
            )
            .fetch_optional(pool)
            .await?
        }
        _ => None,
    };

    if let Some(row) = existing {
        return Ok(row);
    }

    sqlx::query_as!(
        RateLimitRow,
        "INSERT INTO rate_limits (org_id, identity_id, group_id, scope, max_requests, window_seconds)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, org_id, identity_id, group_id, scope, max_requests, window_seconds, created_at, updated_at",
        org_id, identity_id, group_id, scope, max_requests, window_seconds,
    )
    .fetch_one(pool)
    .await
}

/// Get the rate limit for a specific identity (scope = 'user' or 'identity_cap').
pub async fn get_for_identity(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    scope: &str,
) -> Result<Option<RateLimitRow>, sqlx::Error> {
    sqlx::query_as!(
        RateLimitRow,
        "SELECT id, org_id, identity_id, group_id, scope, max_requests, window_seconds, created_at, updated_at
         FROM rate_limits
         WHERE org_id = $1 AND identity_id = $2 AND scope = $3",
        org_id, identity_id, scope,
    )
    .fetch_optional(pool)
    .await
}

/// Get the most permissive group rate limit across the given groups.
/// Returns the group config with the highest max_requests.
pub async fn get_most_permissive_for_groups(
    pool: &PgPool,
    org_id: Uuid,
    group_ids: &[Uuid],
) -> Result<Option<RateLimitRow>, sqlx::Error> {
    sqlx::query_as!(
        RateLimitRow,
        "SELECT id, org_id, identity_id, group_id, scope, max_requests, window_seconds, created_at, updated_at
         FROM rate_limits
         WHERE org_id = $1 AND scope = 'group' AND group_id = ANY($2)
         ORDER BY max_requests DESC
         LIMIT 1",
        org_id, group_ids,
    )
    .fetch_optional(pool)
    .await
}

/// Get the org-wide default rate limit.
pub async fn get_org_default(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Option<RateLimitRow>, sqlx::Error> {
    sqlx::query_as!(
        RateLimitRow,
        "SELECT id, org_id, identity_id, group_id, scope, max_requests, window_seconds, created_at, updated_at
         FROM rate_limits
         WHERE org_id = $1 AND scope = 'org'",
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// List all rate limit configs for an org.
pub async fn list_by_org(pool: &PgPool, org_id: Uuid) -> Result<Vec<RateLimitRow>, sqlx::Error> {
    sqlx::query_as!(
        RateLimitRow,
        "SELECT id, org_id, identity_id, group_id, scope, max_requests, window_seconds, created_at, updated_at
         FROM rate_limits
         WHERE org_id = $1
         ORDER BY scope, created_at",
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// Delete a rate limit config.
pub async fn delete(pool: &PgPool, id: Uuid, org_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM rate_limits WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
