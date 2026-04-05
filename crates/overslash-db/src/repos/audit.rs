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
    pub description: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: OffsetDateTime,
}

pub struct AuditEntry<'a> {
    pub org_id: Uuid,
    pub identity_id: Option<Uuid>,
    pub action: &'a str,
    pub resource_type: Option<&'a str>,
    pub resource_id: Option<Uuid>,
    pub detail: serde_json::Value,
    pub description: Option<&'a str>,
    pub ip_address: Option<&'a str>,
}

pub async fn log(pool: &PgPool, entry: &AuditEntry<'_>) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO audit_log (org_id, identity_id, action, resource_type, resource_id, detail, description, ip_address)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        entry.org_id,
        entry.identity_id,
        entry.action,
        entry.resource_type,
        entry.resource_id,
        entry.detail,
        entry.description,
        entry.ip_address,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub struct AuditFilter {
    pub org_id: Uuid,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub identity_id: Option<Uuid>,
    pub since: Option<OffsetDateTime>,
    pub until: Option<OffsetDateTime>,
    pub limit: i64,
    pub offset: i64,
}

pub async fn query_filtered(
    pool: &PgPool,
    filter: &AuditFilter,
) -> Result<Vec<AuditRow>, sqlx::Error> {
    sqlx::query_as!(
        AuditRow,
        "SELECT id, org_id, identity_id, action, resource_type, resource_id, detail, description, ip_address, created_at
         FROM audit_log
         WHERE org_id = $1
           AND ($2::text IS NULL OR action = $2)
           AND ($3::text IS NULL OR resource_type = $3)
           AND ($4::uuid IS NULL OR identity_id = $4)
           AND ($5::timestamptz IS NULL OR created_at >= $5)
           AND ($6::timestamptz IS NULL OR created_at <= $6)
         ORDER BY created_at DESC
         LIMIT $7 OFFSET $8",
        filter.org_id,
        filter.action,
        filter.resource_type,
        filter.identity_id,
        filter.since,
        filter.until,
        filter.limit,
        filter.offset,
    )
    .fetch_all(pool)
    .await
}
