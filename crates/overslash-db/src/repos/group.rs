use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

// ── Row types ────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
pub struct GroupRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub description: String,
    pub allow_raw_http: bool,
    pub is_system: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl_org_owned!(GroupRow);

#[derive(Debug, sqlx::FromRow)]
pub struct GroupGrantRow {
    pub id: Uuid,
    pub group_id: Uuid,
    pub service_instance_id: Uuid,
    pub access_level: String,
    pub auto_approve_reads: bool,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, sqlx::FromRow)]
pub struct GroupGrantDetailRow {
    pub id: Uuid,
    pub group_id: Uuid,
    pub service_instance_id: Uuid,
    pub service_name: String,
    pub access_level: String,
    pub auto_approve_reads: bool,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, sqlx::FromRow)]
pub struct IdentityGroupRow {
    pub identity_id: Uuid,
    pub group_id: Uuid,
    pub assigned_at: OffsetDateTime,
}

/// A grant with service name, used for ceiling checks.
#[derive(Debug, sqlx::FromRow)]
pub struct UserCeilingGrantRow {
    pub service_instance_id: Uuid,
    pub service_name: String,
    pub template_key: String,
    pub access_level: String,
    pub auto_approve_reads: bool,
}

/// Aggregated ceiling data for a user.
pub struct UserCeiling {
    pub allow_raw_http: bool,
    pub grants: Vec<UserCeilingGrantRow>,
}

// ── Group CRUD ───────────────────────────────────────────────────────

pub(crate) async fn create(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    description: &str,
    allow_raw_http: bool,
) -> Result<GroupRow, sqlx::Error> {
    sqlx::query_as!(
        GroupRow,
        "INSERT INTO groups (org_id, name, description, allow_raw_http)
         VALUES ($1, $2, $3, $4)
         RETURNING id, org_id, name, description, allow_raw_http, is_system, created_at, updated_at",
        org_id,
        name,
        description,
        allow_raw_http,
    )
    .fetch_one(pool)
    .await
}

pub(crate) async fn get_by_id(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<Option<GroupRow>, sqlx::Error> {
    sqlx::query_as!(
        GroupRow,
        "SELECT id, org_id, name, description, allow_raw_http, is_system, created_at, updated_at
         FROM groups WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn list_by_org(pool: &PgPool, org_id: Uuid) -> Result<Vec<GroupRow>, sqlx::Error> {
    sqlx::query_as!(
        GroupRow,
        "SELECT id, org_id, name, description, allow_raw_http, is_system, created_at, updated_at
         FROM groups WHERE org_id = $1 ORDER BY name",
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub(crate) async fn update(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
    name: &str,
    description: &str,
    allow_raw_http: bool,
) -> Result<Option<GroupRow>, sqlx::Error> {
    sqlx::query_as!(
        GroupRow,
        "UPDATE groups SET name = $3, description = $4, allow_raw_http = $5, updated_at = now()
         WHERE id = $1 AND org_id = $2
         RETURNING id, org_id, name, description, allow_raw_http, is_system, created_at, updated_at",
        id,
        org_id,
        name,
        description,
        allow_raw_http,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn delete(pool: &PgPool, id: Uuid, org_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM groups WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

// ── Grants ───────────────────────────────────────────────────────────

pub(crate) async fn add_grant(
    pool: &PgPool,
    org_id: Uuid,
    group_id: Uuid,
    service_instance_id: Uuid,
    access_level: &str,
    auto_approve_reads: bool,
) -> Result<Option<GroupGrantRow>, sqlx::Error> {
    sqlx::query_as!(
        GroupGrantRow,
        "INSERT INTO group_grants (group_id, service_instance_id, access_level, auto_approve_reads)
         SELECT $1, $2, $3, $4
         WHERE EXISTS (SELECT 1 FROM groups WHERE id = $1 AND org_id = $5)
           AND EXISTS (SELECT 1 FROM service_instances WHERE id = $2 AND org_id = $5)
         RETURNING id, group_id, service_instance_id, access_level, auto_approve_reads, created_at",
        group_id,
        service_instance_id,
        access_level,
        auto_approve_reads,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn list_grants(
    pool: &PgPool,
    org_id: Uuid,
    group_id: Uuid,
) -> Result<Vec<GroupGrantDetailRow>, sqlx::Error> {
    sqlx::query_as!(
        GroupGrantDetailRow,
        "SELECT gg.id, gg.group_id, gg.service_instance_id,
                si.name AS service_name,
                gg.access_level, gg.auto_approve_reads, gg.created_at
         FROM group_grants gg
         JOIN service_instances si ON si.id = gg.service_instance_id
         JOIN groups g ON g.id = gg.group_id
         WHERE gg.group_id = $1 AND g.org_id = $2
         ORDER BY si.name",
        group_id,
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub(crate) async fn remove_grant(
    pool: &PgPool,
    org_id: Uuid,
    grant_id: Uuid,
    group_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM group_grants
         WHERE id = $1 AND group_id = $2
           AND EXISTS (SELECT 1 FROM groups WHERE id = $2 AND org_id = $3)",
        grant_id,
        group_id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

// ── Identity ↔ Group membership ──────────────────────────────────────

pub(crate) async fn assign_identity(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    group_id: Uuid,
) -> Result<Option<IdentityGroupRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityGroupRow,
        "INSERT INTO identity_groups (identity_id, group_id)
         SELECT $1, $2
         WHERE EXISTS (SELECT 1 FROM groups WHERE id = $2 AND org_id = $3)
           AND EXISTS (SELECT 1 FROM identities WHERE id = $1 AND org_id = $3)
         RETURNING identity_id, group_id, assigned_at",
        identity_id,
        group_id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn unassign_identity(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    group_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM identity_groups
         WHERE identity_id = $1 AND group_id = $2
           AND EXISTS (SELECT 1 FROM groups WHERE id = $2 AND org_id = $3)",
        identity_id,
        group_id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub(crate) async fn list_groups_for_identity(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<Vec<GroupRow>, sqlx::Error> {
    sqlx::query_as!(
        GroupRow,
        "SELECT g.id, g.org_id, g.name, g.description, g.allow_raw_http, g.is_system, g.created_at, g.updated_at
         FROM groups g
         JOIN identity_groups ig ON ig.group_id = g.id
         JOIN identities i ON i.id = ig.identity_id
         WHERE ig.identity_id = $1 AND g.org_id = $2 AND i.org_id = $2
         ORDER BY g.name",
        identity_id,
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub(crate) async fn list_identity_ids_in_group(
    pool: &PgPool,
    org_id: Uuid,
    group_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT ig.identity_id
         FROM identity_groups ig
         JOIN groups g ON g.id = ig.group_id
         WHERE ig.group_id = $1 AND g.org_id = $2",
        group_id,
        org_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.identity_id).collect())
}

pub(crate) async fn count_members_in_group(
    pool: &PgPool,
    org_id: Uuid,
    group_id: Uuid,
) -> Result<i64, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS count
         FROM identity_groups ig
         JOIN groups g ON g.id = ig.group_id
         WHERE ig.group_id = $1 AND g.org_id = $2",
        group_id,
        org_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.count.unwrap_or(0))
}

/// Find the system group named "Everyone" for an org.
pub(crate) async fn find_everyone_group(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Option<GroupRow>, sqlx::Error> {
    sqlx::query_as!(
        GroupRow,
        "SELECT id, org_id, name, description, allow_raw_http, is_system, created_at, updated_at
         FROM groups WHERE org_id = $1 AND name = 'Everyone' AND is_system = true",
        org_id,
    )
    .fetch_optional(pool)
    .await
}

// ── Ceiling queries (hot path) ───────────────────────────────────────

/// Get the aggregated group ceiling for a user, bounded by `org_id`.
/// Returns all grants across all groups the user belongs to (within the org),
/// plus the OR of `allow_raw_http` across those groups. The user identity, the
/// groups, and the granted service instances must all live in the same org —
/// rows from any other tenant are excluded at the SQL boundary.
pub(crate) async fn get_ceiling_for_user(
    pool: &PgPool,
    org_id: Uuid,
    user_identity_id: Uuid,
) -> Result<UserCeiling, sqlx::Error> {
    // Check if the user has allow_raw_http on any group, bounded by org.
    let raw_http_row = sqlx::query!(
        "SELECT COALESCE(bool_or(g.allow_raw_http), false) AS allow_raw_http
         FROM groups g
         JOIN identity_groups ig ON ig.group_id = g.id
         JOIN identities i ON i.id = ig.identity_id
         WHERE ig.identity_id = $1 AND g.org_id = $2 AND i.org_id = $2",
        user_identity_id,
        org_id,
    )
    .fetch_one(pool)
    .await?;

    let allow_raw_http = raw_http_row.allow_raw_http.unwrap_or(false);

    // Get all grants across all groups, bounded by org on the user, the
    // group, and the service instance.
    let grants = sqlx::query_as!(
        UserCeilingGrantRow,
        "SELECT gg.service_instance_id, si.name AS service_name,
                si.template_key, gg.access_level, gg.auto_approve_reads
         FROM group_grants gg
         JOIN identity_groups ig ON ig.group_id = gg.group_id
         JOIN identities i ON i.id = ig.identity_id
         JOIN groups g ON g.id = gg.group_id
         JOIN service_instances si ON si.id = gg.service_instance_id
         WHERE ig.identity_id = $1
           AND i.org_id = $2
           AND g.org_id = $2
           AND si.org_id = $2",
        user_identity_id,
        org_id,
    )
    .fetch_all(pool)
    .await?;

    Ok(UserCeiling {
        allow_raw_http,
        grants,
    })
}

/// Get service instance IDs visible to a user through their group memberships,
/// bounded by `org_id`.
pub(crate) async fn get_visible_service_ids(
    pool: &PgPool,
    org_id: Uuid,
    user_identity_id: Uuid,
) -> Result<Vec<Uuid>, sqlx::Error> {
    let rows = sqlx::query!(
        "SELECT DISTINCT gg.service_instance_id
         FROM group_grants gg
         JOIN identity_groups ig ON ig.group_id = gg.group_id
         JOIN identities i ON i.id = ig.identity_id
         JOIN groups g ON g.id = gg.group_id
         JOIN service_instances si ON si.id = gg.service_instance_id
         WHERE ig.identity_id = $1
           AND i.org_id = $2
           AND g.org_id = $2
           AND si.org_id = $2",
        user_identity_id,
        org_id,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.service_instance_id).collect())
}
