use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct AuditRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Option<Uuid>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub detail: serde_json::Value,
    pub ip_address: Option<String>,
    pub created_at: OffsetDateTime,
}

pub async fn log(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    action: &str,
    resource_type: Option<&str>,
    resource_id: Option<Uuid>,
    detail: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (org_id, identity_id, action, resource_type, resource_id, detail)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(detail)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn query_by_org(
    pool: &PgPool,
    org_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<AuditRow>, sqlx::Error> {
    sqlx::query_as::<_, AuditRow>(
        "SELECT id, org_id, identity_id, action, resource_type, resource_id, detail, ip_address, created_at
         FROM audit_log WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(org_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
}
