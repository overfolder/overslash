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
    pub is_system: bool,
    /// `'everyone'`, `'admins'`, or `'self'` for system groups; `NULL` for
    /// admin-created groups.
    pub system_kind: Option<String>,
    /// Set iff `system_kind = 'self'` — the user-identity this Myself group
    /// belongs to.
    pub owner_identity_id: Option<Uuid>,
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
    /// DEPRECATED — mirror of `auto_approve_level != "none"`, kept only to
    /// feed the API's compat alias. Never branch on it.
    pub auto_approve_reads: bool,
    /// `"none" | "read" | "write" | "admin"` — how far up the ladder actions
    /// skip Layer 2. Bounded by `access_level` (DB `CHECK`).
    pub auto_approve_level: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, sqlx::FromRow)]
pub struct GroupGrantDetailRow {
    pub id: Uuid,
    pub group_id: Uuid,
    pub service_instance_id: Uuid,
    pub service_name: String,
    pub access_level: String,
    /// DEPRECATED — mirror of `auto_approve_level != "none"`, kept only to
    /// feed the API's compat alias. Never branch on it.
    pub auto_approve_reads: bool,
    /// `"none" | "read" | "write" | "admin"` — how far up the ladder actions
    /// skip Layer 2. Bounded by `access_level` (DB `CHECK`).
    pub auto_approve_level: String,
    pub created_at: OffsetDateTime,
}

/// Reverse view of a group grant: a group that a given service is assigned to.
#[derive(Debug, sqlx::FromRow)]
pub struct ServiceGroupRow {
    pub grant_id: Uuid,
    pub service_instance_id: Uuid,
    pub group_id: Uuid,
    pub group_name: String,
    /// `'everyone'`, `'admins'`, or `'self'` for system groups; `None` otherwise.
    /// Lets the dashboard render Myself grants as a clean "Myself" label without
    /// leaking the storage-form name `Myself: <email> (<id8>)`.
    pub system_kind: Option<String>,
    pub access_level: String,
    /// DEPRECATED — mirror of `auto_approve_level != "none"`, kept only to
    /// feed the API's compat alias. Never branch on it.
    pub auto_approve_reads: bool,
    /// `"none" | "read" | "write" | "admin"` — how far up the ladder actions
    /// skip Layer 2. Bounded by `access_level` (DB `CHECK`).
    pub auto_approve_level: String,
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
    /// DEPRECATED — mirror of `auto_approve_level != "none"`, kept only to
    /// feed the API's compat alias. Never branch on it.
    pub auto_approve_reads: bool,
    /// `"none" | "read" | "write" | "admin"` — how far up the ladder actions
    /// skip Layer 2. Bounded by `access_level` (DB `CHECK`).
    pub auto_approve_level: String,
}

/// Aggregated ceiling data for a user.
pub struct UserCeiling {
    pub grants: Vec<UserCeilingGrantRow>,
}

// ── Group CRUD ───────────────────────────────────────────────────────

pub(crate) async fn create(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    description: &str,
) -> Result<GroupRow, sqlx::Error> {
    sqlx::query_as!(
        GroupRow,
        "INSERT INTO groups (org_id, name, description)
         VALUES ($1, $2, $3)
         RETURNING id, org_id, name, description, is_system, system_kind, owner_identity_id, created_at, updated_at",
        org_id,
        name,
        description,
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
        "SELECT id, org_id, name, description, is_system, system_kind, owner_identity_id, created_at, updated_at
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
        "SELECT id, org_id, name, description, is_system, system_kind, owner_identity_id, created_at, updated_at
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
) -> Result<Option<GroupRow>, sqlx::Error> {
    sqlx::query_as!(
        GroupRow,
        "UPDATE groups SET name = $3, description = $4, updated_at = now()
         WHERE id = $1 AND org_id = $2
         RETURNING id, org_id, name, description, is_system, system_kind, owner_identity_id, created_at, updated_at",
        id,
        org_id,
        name,
        description,
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
    auto_approve_level: &str,
) -> Result<Option<GroupGrantRow>, sqlx::Error> {
    // `auto_approve_reads` is written from the level so the deprecated column
    // stays coherent for anything still reading it; the level is the truth.
    sqlx::query_as!(
        GroupGrantRow,
        "INSERT INTO group_grants
             (group_id, service_instance_id, access_level, auto_approve_reads, auto_approve_level)
         SELECT $1, $2, $3, $4::text <> 'none', $4
         WHERE EXISTS (SELECT 1 FROM groups WHERE id = $1 AND org_id = $5)
           AND EXISTS (SELECT 1 FROM service_instances WHERE id = $2 AND org_id = $5)
         RETURNING id, group_id, service_instance_id, access_level,
                   auto_approve_reads, auto_approve_level, created_at",
        group_id,
        service_instance_id,
        access_level,
        auto_approve_level,
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
                gg.access_level, gg.auto_approve_reads, gg.auto_approve_level,
                gg.created_at
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

/// List the groups granting access to a single service instance, with the
/// grant metadata. Used by the service detail view to surface "who can use
/// this service" without forcing the caller to walk groups individually.
pub(crate) async fn list_groups_for_service(
    pool: &PgPool,
    org_id: Uuid,
    service_instance_id: Uuid,
) -> Result<Vec<ServiceGroupRow>, sqlx::Error> {
    sqlx::query_as!(
        ServiceGroupRow,
        "SELECT gg.id AS grant_id,
                gg.service_instance_id,
                gg.group_id,
                g.name AS group_name,
                g.system_kind,
                gg.access_level,
                gg.auto_approve_reads,
                gg.auto_approve_level
         FROM group_grants gg
         JOIN groups g ON g.id = gg.group_id
         JOIN service_instances si ON si.id = gg.service_instance_id
         WHERE gg.service_instance_id = $1
           AND g.org_id = $2
           AND si.org_id = $2
         ORDER BY g.name",
        service_instance_id,
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// Batch variant: list groups for many services in a single query. Used by
/// the services list to annotate each row with its assigned groups without
/// incurring N+1.
pub(crate) async fn list_groups_for_services(
    pool: &PgPool,
    org_id: Uuid,
    service_instance_ids: &[Uuid],
) -> Result<Vec<ServiceGroupRow>, sqlx::Error> {
    if service_instance_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as!(
        ServiceGroupRow,
        "SELECT gg.id AS grant_id,
                gg.service_instance_id,
                gg.group_id,
                g.name AS group_name,
                g.system_kind,
                gg.access_level,
                gg.auto_approve_reads,
                gg.auto_approve_level
         FROM group_grants gg
         JOIN groups g ON g.id = gg.group_id
         JOIN service_instances si ON si.id = gg.service_instance_id
         WHERE gg.service_instance_id = ANY($1)
           AND g.org_id = $2
           AND si.org_id = $2
         ORDER BY g.name",
        service_instance_ids,
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

/// Fetch a single grant by id, scoped to its group and org. The PATCH path
/// needs the *current* pair to decide whether a partial update would leave
/// `auto_approve_level` above `access_level`, which a COALESCE-only UPDATE
/// can't see.
pub(crate) async fn get_grant(
    pool: &PgPool,
    org_id: Uuid,
    grant_id: Uuid,
    group_id: Uuid,
) -> Result<Option<GroupGrantRow>, sqlx::Error> {
    sqlx::query_as!(
        GroupGrantRow,
        "SELECT gg.id, gg.group_id, gg.service_instance_id, gg.access_level,
                gg.auto_approve_reads, gg.auto_approve_level, gg.created_at
         FROM group_grants gg
         JOIN groups g ON g.id = gg.group_id
         WHERE gg.id = $1 AND gg.group_id = $2 AND g.org_id = $3",
        grant_id,
        group_id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// Partial-update a grant. Each field is optional; `None` leaves that column
/// untouched (`COALESCE`). Returns `None` when the grant id doesn't belong to
/// a group in this org — same scoping shape as `add_grant` / `remove_grant`.
pub(crate) async fn update_grant(
    pool: &PgPool,
    org_id: Uuid,
    grant_id: Uuid,
    group_id: Uuid,
    access_level: Option<&str>,
    auto_approve_level: Option<&str>,
) -> Result<Option<GroupGrantRow>, sqlx::Error> {
    sqlx::query_as!(
        GroupGrantRow,
        "UPDATE group_grants
            SET access_level       = COALESCE($4, access_level),
                auto_approve_level = COALESCE($5, auto_approve_level),
                auto_approve_reads = COALESCE($5::text, auto_approve_level) <> 'none'
          WHERE id = $1 AND group_id = $2
            AND EXISTS (SELECT 1 FROM groups WHERE id = $2 AND org_id = $3)
        RETURNING id, group_id, service_instance_id, access_level,
                  auto_approve_reads, auto_approve_level, created_at",
        grant_id,
        group_id,
        org_id,
        access_level,
        auto_approve_level,
    )
    .fetch_optional(pool)
    .await
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
        "SELECT g.id, g.org_id, g.name, g.description, g.is_system, g.system_kind, g.owner_identity_id, g.created_at, g.updated_at
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

/// Check whether an identity is a member of the system "Admins" group of an org.
pub(crate) async fn is_identity_in_admins(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT 1 AS one
         FROM identity_groups ig
         JOIN groups g ON g.id = ig.group_id
         WHERE ig.identity_id = $1
           AND g.org_id = $2
           AND g.system_kind = 'admins'
         LIMIT 1",
        identity_id,
        org_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

/// Find the system "Everyone" group for an org.
pub(crate) async fn find_everyone_group(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Option<GroupRow>, sqlx::Error> {
    sqlx::query_as!(
        GroupRow,
        "SELECT id, org_id, name, description, is_system, system_kind, owner_identity_id, created_at, updated_at
         FROM groups WHERE org_id = $1 AND system_kind = 'everyone'",
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// Find the Myself group for a specific user-identity in an org, if one exists.
pub(crate) async fn find_self_group(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<Option<GroupRow>, sqlx::Error> {
    sqlx::query_as!(
        GroupRow,
        "SELECT id, org_id, name, description, is_system, system_kind, owner_identity_id, created_at, updated_at
         FROM groups
         WHERE org_id = $1 AND system_kind = 'self' AND owner_identity_id = $2",
        org_id,
        identity_id,
    )
    .fetch_optional(pool)
    .await
}

/// Ensure a Myself group exists for the given user-identity, creating it (and
/// adding the user as the sole member) if missing. Returns the group id.
///
/// Idempotent: safe to call repeatedly. Caller is responsible for verifying
/// that `identity_id` refers to a `kind = 'user'` identity in `org_id`.
pub(crate) async fn ensure_self_group(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    label: &str,
) -> Result<Uuid, sqlx::Error> {
    if let Some(existing) = find_self_group(pool, org_id, identity_id).await? {
        return Ok(existing.id);
    }

    let mut tx = pool.begin().await?;

    // Suffix the name with the first 8 chars of the identity uuid so the
    // `(org_id, name)` unique constraint on `groups` cannot collide between
    // two users in the same org who happen to share an email or display name
    // (`identities.email`/`name` are not unique per migration 043). The
    // dashboard hides this suffix behind the "Myself" label.
    let unique_name = format!(
        "Myself: {label} ({})",
        &identity_id.simple().to_string()[..8]
    );
    let row = sqlx::query!(
        "INSERT INTO groups (org_id, name, description, is_system, system_kind, owner_identity_id)
         VALUES ($1, $2, 'Personal services and Layer-1 grants for this user', true, 'self', $3)
         ON CONFLICT (org_id, owner_identity_id) WHERE system_kind = 'self'
         DO NOTHING
         RETURNING id",
        org_id,
        unique_name,
        identity_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let group_id = match row {
        Some(r) => r.id,
        None => {
            // A concurrent caller won the insert race — pick up theirs.
            sqlx::query!(
                "SELECT id FROM groups
                 WHERE org_id = $1 AND system_kind = 'self' AND owner_identity_id = $2",
                org_id,
                identity_id,
            )
            .fetch_one(&mut *tx)
            .await?
            .id
        }
    };

    sqlx::query!(
        "INSERT INTO identity_groups (identity_id, group_id) VALUES ($1, $2)
         ON CONFLICT DO NOTHING",
        identity_id,
        group_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(group_id)
}

/// Insert a `group_grants` row pointing the given user's Myself group at the
/// given service instance. Defaults: `access_level='admin'`,
/// `auto_approve_level='read'` — reads run unattended, writes and deletes on
/// the user's own services still file an approval. Raising the default would
/// silently hand every agent unattended deletes on everything its owner owns.
/// Idempotent on the `(group_id, service_instance_id)` unique key.
///
/// Caller is responsible for ensuring `service_instance_id` belongs to the same
/// `org_id` and is owned by `identity_id`.
pub(crate) async fn grant_to_self_group(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    service_instance_id: Uuid,
    label: &str,
) -> Result<(), sqlx::Error> {
    let group_id = ensure_self_group(pool, org_id, identity_id, label).await?;
    sqlx::query!(
        "INSERT INTO group_grants
             (group_id, service_instance_id, access_level, auto_approve_reads, auto_approve_level)
         VALUES ($1, $2, 'admin', true, 'read')
         ON CONFLICT (group_id, service_instance_id) DO NOTHING",
        group_id,
        service_instance_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

// ── Ceiling queries (hot path) ───────────────────────────────────────

/// Get the aggregated group ceiling for a user, bounded by `org_id`.
/// Returns all grants across all groups the user belongs to (within the org).
/// The user identity, the groups, and the granted service instances must all
/// live in the same org — rows from any other tenant are excluded at the SQL
/// boundary.
///
/// Raw HTTP access is no longer a separate boolean: the org's system-managed
/// `http` service instance is included in `grants` whenever the user's groups
/// have a grant on it.
pub(crate) async fn get_ceiling_for_user(
    pool: &PgPool,
    org_id: Uuid,
    user_identity_id: Uuid,
) -> Result<UserCeiling, sqlx::Error> {
    // Get all grants across all groups, bounded by org on the user, the
    // group, and the service instance.
    let grants = sqlx::query_as!(
        UserCeilingGrantRow,
        "SELECT gg.service_instance_id, si.name AS service_name,
                si.template_key, gg.access_level, gg.auto_approve_reads,
                gg.auto_approve_level
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

    Ok(UserCeiling { grants })
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

/// `true` when the caller's ceiling user has group-granted access to any
/// service instance currently bound to `connection_id`. Used by the OAuth
/// re-auth helper to allow a cross-user upgrade-URL mint without taking
/// the `validate_on_behalf_of` path (which is for the agent-acting-for-
/// owner-user case, not the user-A-reaches-user-B-via-group case).
///
/// Mirrors the EXISTS clause in `service_instance::resolve_by_name`
/// step 5, but pivots on the connection rather than the name — multiple
/// instances may share a connection in theory, and any group-granted
/// path among them authorises the upgrade.
pub(crate) async fn caller_has_group_access_to_connection(
    pool: &PgPool,
    org_id: Uuid,
    caller_ceiling_user_id: Uuid,
    connection_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT EXISTS (
             SELECT 1
             FROM group_grants gg
             JOIN identity_groups ig ON ig.group_id = gg.group_id
             JOIN identities i ON i.id = ig.identity_id
             JOIN groups g ON g.id = gg.group_id
             JOIN service_instances si ON si.id = gg.service_instance_id
             WHERE ig.identity_id = $1
               AND i.org_id = $2
               AND g.org_id = $2
               AND si.org_id = $2
               AND si.connection_id = $3
         ) AS \"has_access!\"",
        caller_ceiling_user_id,
        org_id,
        connection_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.has_access)
}
