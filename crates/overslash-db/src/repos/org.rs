use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct OrgRow {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub subagent_idle_timeout_secs: i32,
    pub subagent_archive_retention_days: i32,
    pub is_personal: bool,
    pub plan: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Insert a new org. `plan` must be one of the values allowed by the
/// `orgs.plan` CHECK constraint (today: `'standard'` or `'free_unlimited'`).
/// Most callers pass `"standard"`; the instance-admin path passes
/// `"free_unlimited"` to skip Stripe.
pub async fn create(
    pool: &PgPool,
    name: &str,
    slug: &str,
    plan: &str,
) -> Result<OrgRow, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "INSERT INTO orgs (name, slug, plan) VALUES ($1, $2, $3)
         RETURNING id, name, slug, subagent_idle_timeout_secs, subagent_archive_retention_days, is_personal, plan, created_at, updated_at",
        name,
        slug,
        plan,
    )
    .fetch_one(pool)
    .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "SELECT id, name, slug, subagent_idle_timeout_secs, subagent_archive_retention_days, is_personal, plan, created_at, updated_at
         FROM orgs WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Read just the `plan` field for an org. Used by the rate-limit hot path
/// to decide whether to bypass limits without dragging the full `OrgRow`
/// shape into the cache. Returns `None` if the org doesn't exist.
pub async fn get_plan(pool: &PgPool, id: Uuid) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query!("SELECT plan FROM orgs WHERE id = $1", id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.plan))
}

/// Read just the `approval_auto_bubble_secs` setting for an org.
/// Returns `None` if the org doesn't exist.
pub async fn get_approval_auto_bubble_secs(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<i32>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT approval_auto_bubble_secs FROM orgs WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.approval_auto_bubble_secs))
}

/// Update the `approval_auto_bubble_secs` setting for an org.
pub async fn set_approval_auto_bubble_secs(
    pool: &PgPool,
    id: Uuid,
    secs: i32,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET approval_auto_bubble_secs = $2, updated_at = now() WHERE id = $1",
        id,
        secs,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Read the `allow_user_templates` setting for an org.
pub async fn get_allow_user_templates(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<bool>, sqlx::Error> {
    let row = sqlx::query!("SELECT allow_user_templates FROM orgs WHERE id = $1", id,)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.allow_user_templates))
}

/// Update the `allow_user_templates` setting for an org.
pub async fn set_allow_user_templates(
    pool: &PgPool,
    id: Uuid,
    allow: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET allow_user_templates = $2, updated_at = now() WHERE id = $1",
        id,
        allow,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Read the `global_templates_enabled` setting for an org.
pub async fn get_global_templates_enabled(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<bool>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT global_templates_enabled FROM orgs WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.global_templates_enabled))
}

/// Update the `global_templates_enabled` setting for an org.
pub async fn set_global_templates_enabled(
    pool: &PgPool,
    id: Uuid,
    enabled: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET global_templates_enabled = $2, updated_at = now() WHERE id = $1",
        id,
        enabled,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Read the `allow_unsigned_secret_provide` setting for an org.
pub async fn get_allow_unsigned_secret_provide(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<bool>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT allow_unsigned_secret_provide FROM orgs WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.allow_unsigned_secret_provide))
}

/// Update the `allow_unsigned_secret_provide` setting for an org.
pub async fn set_allow_unsigned_secret_provide(
    pool: &PgPool,
    id: Uuid,
    allow: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE orgs SET allow_unsigned_secret_provide = $2, updated_at = now() WHERE id = $1",
        id,
        allow,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Atomically update template settings and return the new values.
pub async fn update_template_settings(
    pool: &PgPool,
    id: Uuid,
    allow_user_templates: Option<bool>,
    global_templates_enabled: Option<bool>,
) -> Result<Option<(bool, bool)>, sqlx::Error> {
    let row = sqlx::query!(
        "UPDATE orgs SET \
         allow_user_templates = COALESCE($2, allow_user_templates), \
         global_templates_enabled = COALESCE($3, global_templates_enabled), \
         updated_at = now() \
         WHERE id = $1 \
         RETURNING allow_user_templates, global_templates_enabled",
        id,
        allow_user_templates,
        global_templates_enabled,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| (r.allow_user_templates, r.global_templates_enabled)))
}

pub async fn get_by_slug(pool: &PgPool, slug: &str) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "SELECT id, name, slug, subagent_idle_timeout_secs, subagent_archive_retention_days, is_personal, plan, created_at, updated_at
         FROM orgs WHERE slug = $1",
        slug,
    )
    .fetch_optional(pool)
    .await
}

/// Update an org's sub-agent cleanup configuration. Bounds validated by caller.
pub async fn update_subagent_cleanup_config(
    pool: &PgPool,
    id: Uuid,
    idle_timeout_secs: i32,
    archive_retention_days: i32,
) -> Result<Option<OrgRow>, sqlx::Error> {
    sqlx::query_as!(
        OrgRow,
        "UPDATE orgs
         SET subagent_idle_timeout_secs = $2,
             subagent_archive_retention_days = $3,
             updated_at = now()
         WHERE id = $1
         RETURNING id, name, slug, subagent_idle_timeout_secs, subagent_archive_retention_days, is_personal, plan, created_at, updated_at",
        id,
        idle_timeout_secs,
        archive_retention_days,
    )
    .fetch_optional(pool)
    .await
}
