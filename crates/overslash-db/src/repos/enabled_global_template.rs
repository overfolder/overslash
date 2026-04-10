use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct EnabledGlobalTemplateRow {
    pub org_id: Uuid,
    pub template_key: String,
    pub enabled_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
}

/// Mark a global template as enabled for an org. No-op if already enabled.
pub async fn enable(
    pool: &PgPool,
    org_id: Uuid,
    template_key: &str,
    enabled_by: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO enabled_global_templates (org_id, template_key, enabled_by)
         VALUES ($1, $2, $3)
         ON CONFLICT (org_id, template_key) DO NOTHING",
        org_id,
        template_key,
        enabled_by,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Remove a global template from the enabled list for an org.
pub async fn disable(pool: &PgPool, org_id: Uuid, template_key: &str) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM enabled_global_templates WHERE org_id = $1 AND template_key = $2",
        org_id,
        template_key,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// List all enabled global template keys for an org (for filtering).
pub async fn list_enabled_keys(pool: &PgPool, org_id: Uuid) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT template_key FROM enabled_global_templates WHERE org_id = $1 ORDER BY template_key",
        org_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.template_key).collect())
}

/// Check if a specific global template is enabled for an org.
pub async fn is_enabled(
    pool: &PgPool,
    org_id: Uuid,
    template_key: &str,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT 1 as _exists FROM enabled_global_templates WHERE org_id = $1 AND template_key = $2",
        org_id,
        template_key,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}
