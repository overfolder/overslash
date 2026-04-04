use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct PermissionRuleRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub action_pattern: String,
    pub effect: String,
    pub expires_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

pub async fn create(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    action_pattern: &str,
    effect: &str,
    expires_at: Option<OffsetDateTime>,
) -> Result<PermissionRuleRow, sqlx::Error> {
    sqlx::query_as::<_, PermissionRuleRow>(
        "INSERT INTO permission_rules (org_id, identity_id, action_pattern, effect, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, org_id, identity_id, action_pattern, effect, expires_at, created_at",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(action_pattern)
    .bind(effect)
    .bind(expires_at)
    .fetch_one(pool)
    .await
}

pub async fn list_by_identity(
    pool: &PgPool,
    identity_id: Uuid,
) -> Result<Vec<PermissionRuleRow>, sqlx::Error> {
    sqlx::query_as::<_, PermissionRuleRow>(
        "SELECT id, org_id, identity_id, action_pattern, effect, expires_at, created_at
         FROM permission_rules WHERE identity_id = $1 ORDER BY created_at",
    )
    .bind(identity_id)
    .fetch_all(pool)
    .await
}

pub async fn delete(pool: &PgPool, id: Uuid, org_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM permission_rules WHERE id = $1 AND org_id = $2")
        .bind(id)
        .bind(org_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}
