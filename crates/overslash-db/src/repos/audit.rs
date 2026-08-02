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
    /// System-derived metadata tags (`sql:write`, `table:wh/orders`,
    /// `service:metabase`, `outcome:error`, …). Searchable via
    /// `GET /v1/audit?tag=`. Empty for events outside the action/approval
    /// path — see `log_tagged`.
    pub tags: Vec<String>,
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
    log_tagged(pool, entry, impersonated_by_identity_id, &[]).await
}

/// Insert an audit row carrying system-derived metadata tags.
///
/// Kept separate from [`log`] — and taking the tags as an argument rather than
/// a field on [`AuditEntry`] — because tags are minted on exactly one code
/// path (the gated action call and the approval lifecycle around it) while
/// `AuditEntry` is constructed at over a hundred sites. A field would have
/// meant `tags: vec![]` at every one of them to say nothing.
pub(crate) async fn log_tagged(
    pool: &PgPool,
    entry: &AuditEntry<'_>,
    impersonated_by_identity_id: Option<Uuid>,
    tags: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO audit_log (org_id, identity_id, action, resource_type, resource_id, detail, description, ip_address, impersonated_by_identity_id, tags)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        entry.org_id,
        entry.identity_id,
        entry.action,
        entry.resource_type,
        entry.resource_id,
        entry.detail,
        entry.description,
        entry.ip_address,
        impersonated_by_identity_id,
        tags,
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Clone, Default)]
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
    // ── Per-column `~` (contains) + `=` (match) filters. Each powers a
    // search-bar key; substrings are matched case-insensitively (ILIKE).
    /// Substring on `action`. Powers `event ~`.
    pub action_contains: Option<String>,
    /// Substring on `resource_type`. Powers `resource ~`.
    pub resource_type_contains: Option<String>,
    /// Exact / substring on `description`. Powers `description =` / `~`.
    pub description: Option<String>,
    pub description_contains: Option<String>,
    /// Exact / substring on `ip_address`. Powers `ip =` / `~`.
    pub ip_address: Option<String>,
    pub ip_address_contains: Option<String>,
    /// Substring on the joined actor identity name. Powers `agent ~` /
    /// `user ~` / `identity ~`.
    pub identity_name_contains: Option<String>,
    /// Restrict the actor's identity kind (e.g. `['user']` or
    /// `['agent','sub_agent']`). Scopes the kind split for `agent`/`user`.
    pub identity_kinds: Option<Vec<String>>,
    /// Owning user (root of the actor's identity chain). Matches rows where the
    /// actor *is* this user (acting directly) or is one of the user's agents
    /// (`identities.owner_id`). Powers the `user =` search bar key — a wider
    /// match than the exact-actor `identity_id`, consistent with the audit
    /// table's "User" column.
    pub owner_user_id: Option<Uuid>,
    /// Substring (case-insensitive) on the owning user's name — the actor's own
    /// name when they are a user, else their `owner_id`'s name. Powers `user ~`.
    pub owner_user_contains: Option<String>,
    /// Upstream result of execution events, matched against the normalized
    /// `detail.is_error` flag written by the action executors. `Some(true)`
    /// returns executions whose upstream reported failure (MCP `is_error`
    /// envelope, upstream HTTP >= 400); `Some(false)` returns executions that
    /// carry the flag and succeeded — rows without the flag (non-execution
    /// events, pre-flag history) match neither. Powers the `result =` key.
    pub is_error: Option<bool>,
    /// Require **all** of these metadata tags on the row (`tags @> $n`).
    /// AND rather than OR because tags narrow along independent axes — a
    /// `service:metabase` + `sql:write` filter means "writes against
    /// Metabase", which OR would turn into a far larger set. Powers `tag =`.
    pub tags: Option<Vec<String>>,
    /// Substring (case-insensitive) against any one tag. Powers `tag ~`, which
    /// is how you find `table:warehouse/orders` without knowing the db label.
    pub tag_contains: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

pub(crate) async fn query_filtered(
    pool: &PgPool,
    filter: &AuditFilter,
) -> Result<Vec<AuditRow>, sqlx::Error> {
    // Build `%term%` patterns once so the query plan can short-circuit when a
    // filter is None. The LEFT JOIN keeps rows whose identity has been deleted.
    let like = filter.q.as_deref().map(|q| format!("%{q}%"));
    let action_like = filter.action_contains.as_deref().map(|q| format!("%{q}%"));
    let resource_like = filter
        .resource_type_contains
        .as_deref()
        .map(|q| format!("%{q}%"));
    let desc_like = filter
        .description_contains
        .as_deref()
        .map(|q| format!("%{q}%"));
    let ip_like = filter
        .ip_address_contains
        .as_deref()
        .map(|q| format!("%{q}%"));
    let name_like = filter
        .identity_name_contains
        .as_deref()
        .map(|q| format!("%{q}%"));
    let owner_name_like = filter
        .owner_user_contains
        .as_deref()
        .map(|q| format!("%{q}%"));
    let kinds = filter.identity_kinds.as_deref();
    let tags = filter.tags.as_deref();
    let tag_like = filter.tag_contains.as_deref().map(|q| format!("%{q}%"));
    sqlx::query_as!(
        AuditRow,
        "SELECT a.id, a.org_id, a.identity_id, a.action, a.resource_type, a.resource_id, a.detail, a.description, a.ip_address, a.created_at, a.impersonated_by_identity_id, a.tags
         FROM audit_log a
         LEFT JOIN identities i ON i.id = a.identity_id AND i.org_id = a.org_id
         LEFT JOIN identities owner ON owner.id = i.owner_id AND owner.org_id = a.org_id
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
           AND ($12::text IS NULL OR a.action ILIKE $12)
           AND ($13::text IS NULL OR a.resource_type ILIKE $13)
           AND ($14::text IS NULL OR a.description = $14)
           AND ($15::text IS NULL OR a.description ILIKE $15)
           AND ($16::text IS NULL OR a.ip_address = $16)
           AND ($17::text IS NULL OR a.ip_address ILIKE $17)
           AND ($18::text IS NULL OR i.name ILIKE $18)
           AND ($19::text[] IS NULL OR i.kind = ANY($19))
           AND ($20::uuid IS NULL OR a.identity_id = $20 OR i.owner_id = $20)
           AND ($21::text IS NULL
                OR (i.kind = 'user' AND i.name ILIKE $21)
                OR owner.name ILIKE $21)
           AND ($22::boolean IS NULL
                OR ($22 AND a.detail->>'is_error' = 'true')
                OR (NOT $22 AND a.detail->>'is_error' = 'false'))
           -- Containment (not overlap): every requested tag must be present.
           -- Uses idx_audit_log_tags.
           AND ($23::text[] IS NULL OR a.tags @> $23)
           -- No index for this one; it rides the org/created_at scan alongside
           -- the other ILIKE filters.
           AND ($24::text IS NULL
                OR EXISTS (SELECT 1 FROM unnest(a.tags) t WHERE t ILIKE $24))
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
        action_like,
        resource_like,
        filter.description,
        desc_like,
        filter.ip_address,
        ip_like,
        name_like,
        kinds,
        filter.owner_user_id,
        owner_name_like,
        filter.is_error,
        tags,
        tag_like,
    )
    .fetch_all(pool)
    .await
}
