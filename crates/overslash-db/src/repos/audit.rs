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
    /// Set when the request was made via `X-Overslash-As` impersonation.
    /// Records the service-account identity that performed the impersonation;
    /// `identity_id` is the effective (impersonated) identity.
    pub impersonated_by_identity_id: Option<Uuid>,
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

/// Insert an audit row. `impersonated_by_identity_id` is passed separately
/// so callers (handlers) never need to set it — `OrgScope::log_audit`
/// injects it automatically from the scope's impersonation context.
pub(crate) async fn log(
    pool: &PgPool,
    entry: &AuditEntry<'_>,
    impersonated_by_identity_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO audit_log (org_id, identity_id, action, resource_type, resource_id, detail, description, ip_address, impersonated_by_identity_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        entry.org_id,
        entry.identity_id,
        entry.action,
        entry.resource_type,
        entry.resource_id,
        entry.detail,
        entry.description,
        entry.ip_address,
        impersonated_by_identity_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Clone)]
pub struct AuditFilter {
    pub org_id: Uuid,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub identity_id: Option<Uuid>,
    pub since: Option<OffsetDateTime>,
    pub until: Option<OffsetDateTime>,
    /// Free-text substring matched (case-insensitive) against `action`,
    /// `description`, and the joined identity name. Powers the audit log
    /// search bar.
    pub q: Option<String>,
    /// Exact match on `audit_log.id`. Used by the dashboard deep-link
    /// (`/audit?event=<uuid>`) to confirm a target event exists outside the
    /// active filter set.
    pub event_id: Option<Uuid>,
    /// Match a UUID across the row id, actor id, resource id, and the JSONB
    /// `detail` keys `execution_id` / `replayed_from_approval`. Powers the
    /// `uuid =` search bar key.
    pub uuid: Option<Uuid>,
    pub limit: i64,
    pub offset: i64,
}

pub(crate) async fn query_filtered(
    pool: &PgPool,
    filter: &AuditFilter,
) -> Result<Vec<AuditRow>, sqlx::Error> {
    // Build a `%term%` pattern once so the query plan can short-circuit when
    // q is None. The LEFT JOIN keeps rows whose identity has been deleted.
    let like = filter.q.as_deref().map(|q| format!("%{q}%"));
    sqlx::query_as!(
        AuditRow,
        "SELECT a.id, a.org_id, a.identity_id, a.action, a.resource_type, a.resource_id, a.detail, a.description, a.ip_address, a.created_at, a.impersonated_by_identity_id
         FROM audit_log a
         LEFT JOIN identities i ON i.id = a.identity_id AND i.org_id = a.org_id
         WHERE a.org_id = $1
           AND ($2::text IS NULL OR a.action = $2)
           AND ($3::text IS NULL OR a.resource_type = $3)
           AND ($4::uuid IS NULL OR a.identity_id = $4)
           AND ($5::timestamptz IS NULL OR a.created_at >= $5)
           AND ($6::timestamptz IS NULL OR a.created_at <= $6)
           AND ($7::text IS NULL
                OR a.action ILIKE $7
                OR a.description ILIKE $7
                OR i.name ILIKE $7)
           AND ($8::uuid IS NULL OR a.id = $8)
           AND ($9::uuid IS NULL
                OR a.id = $9
                OR a.identity_id = $9
                OR a.resource_id = $9
                OR CASE WHEN a.detail->>'execution_id' ~ '^[0-9a-fA-F-]{36}$'
                        THEN (a.detail->>'execution_id')::uuid = $9
                        ELSE FALSE END
                OR CASE WHEN a.detail->>'replayed_from_approval' ~ '^[0-9a-fA-F-]{36}$'
                        THEN (a.detail->>'replayed_from_approval')::uuid = $9
                        ELSE FALSE END)
         ORDER BY a.created_at DESC
         LIMIT $10 OFFSET $11",
        filter.org_id,
        filter.action,
        filter.resource_type,
        filter.identity_id,
        filter.since,
        filter.until,
        like,
        filter.event_id,
        filter.uuid,
        filter.limit,
        filter.offset,
    )
    .fetch_all(pool)
    .await
}
