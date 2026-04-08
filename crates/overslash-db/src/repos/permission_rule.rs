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

pub(crate) async fn create(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    action_pattern: &str,
    effect: &str,
    expires_at: Option<OffsetDateTime>,
) -> Result<PermissionRuleRow, sqlx::Error> {
    sqlx::query_as!(
        PermissionRuleRow,
        "INSERT INTO permission_rules (org_id, identity_id, action_pattern, effect, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, org_id, identity_id, action_pattern, effect, expires_at, created_at",
        org_id,
        identity_id,
        action_pattern,
        effect,
        expires_at,
    )
    .fetch_one(pool)
    .await
}

pub(crate) async fn list_by_identity(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<Vec<PermissionRuleRow>, sqlx::Error> {
    sqlx::query_as!(
        PermissionRuleRow,
        "SELECT id, org_id, identity_id, action_pattern, effect, expires_at, created_at
         FROM permission_rules
         WHERE org_id = $1 AND identity_id = $2
           AND (expires_at IS NULL OR expires_at > now())
         ORDER BY created_at",
        org_id,
        identity_id,
    )
    .fetch_all(pool)
    .await
}

pub(crate) async fn list_by_identities(
    pool: &PgPool,
    org_id: Uuid,
    identity_ids: &[Uuid],
) -> Result<Vec<PermissionRuleRow>, sqlx::Error> {
    sqlx::query_as!(
        PermissionRuleRow,
        "SELECT id, org_id, identity_id, action_pattern, effect, expires_at, created_at
         FROM permission_rules
         WHERE org_id = $1 AND identity_id = ANY($2)
           AND (expires_at IS NULL OR expires_at > now())
         ORDER BY created_at",
        org_id,
        identity_ids,
    )
    .fetch_all(pool)
    .await
}

pub(crate) async fn get_by_id(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<Option<PermissionRuleRow>, sqlx::Error> {
    sqlx::query_as!(
        PermissionRuleRow,
        "SELECT id, org_id, identity_id, action_pattern, effect, expires_at, created_at
         FROM permission_rules WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn delete(pool: &PgPool, org_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM permission_rules WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
