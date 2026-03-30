use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

// --- Row types ---

#[derive(Debug, sqlx::FromRow)]
pub struct AclRoleRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub slug: String,
    pub description: String,
    pub is_builtin: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, sqlx::FromRow)]
pub struct AclGrantRow {
    pub id: Uuid,
    pub role_id: Uuid,
    pub resource_type: String,
    pub action: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, sqlx::FromRow)]
pub struct AclRoleAssignmentRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub role_id: Uuid,
    pub assigned_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
}

// --- Roles ---

pub async fn create_role(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    slug: &str,
    description: &str,
    is_builtin: bool,
) -> Result<AclRoleRow, sqlx::Error> {
    sqlx::query_as::<_, AclRoleRow>(
        "INSERT INTO acl_roles (org_id, name, slug, description, is_builtin)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, org_id, name, slug, description, is_builtin, created_at, updated_at",
    )
    .bind(org_id)
    .bind(name)
    .bind(slug)
    .bind(description)
    .bind(is_builtin)
    .fetch_one(pool)
    .await
}

pub async fn get_role(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
) -> Result<Option<AclRoleRow>, sqlx::Error> {
    sqlx::query_as::<_, AclRoleRow>(
        "SELECT id, org_id, name, slug, description, is_builtin, created_at, updated_at
         FROM acl_roles WHERE id = $1 AND org_id = $2",
    )
    .bind(id)
    .bind(org_id)
    .fetch_optional(pool)
    .await
}

pub async fn list_roles_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<AclRoleRow>, sqlx::Error> {
    sqlx::query_as::<_, AclRoleRow>(
        "SELECT id, org_id, name, slug, description, is_builtin, created_at, updated_at
         FROM acl_roles WHERE org_id = $1 ORDER BY is_builtin DESC, name ASC",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
}

pub async fn update_role(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
    name: &str,
    description: &str,
) -> Result<Option<AclRoleRow>, sqlx::Error> {
    sqlx::query_as::<_, AclRoleRow>(
        "UPDATE acl_roles SET name = $3, description = $4, updated_at = now()
         WHERE id = $1 AND org_id = $2 AND is_builtin = false
         RETURNING id, org_id, name, slug, description, is_builtin, created_at, updated_at",
    )
    .bind(id)
    .bind(org_id)
    .bind(name)
    .bind(description)
    .fetch_optional(pool)
    .await
}

pub async fn delete_role(pool: &PgPool, id: Uuid, org_id: Uuid) -> Result<bool, sqlx::Error> {
    let result =
        sqlx::query("DELETE FROM acl_roles WHERE id = $1 AND org_id = $2 AND is_builtin = false")
            .bind(id)
            .bind(org_id)
            .execute(pool)
            .await?;
    Ok(result.rows_affected() > 0)
}

// --- Grants ---

pub async fn list_grants_by_role(
    pool: &PgPool,
    role_id: Uuid,
) -> Result<Vec<AclGrantRow>, sqlx::Error> {
    sqlx::query_as::<_, AclGrantRow>(
        "SELECT id, role_id, resource_type, action, created_at
         FROM acl_grants WHERE role_id = $1 ORDER BY resource_type, action",
    )
    .bind(role_id)
    .fetch_all(pool)
    .await
}

/// Replace all grants for a role. Deletes existing grants and inserts new ones in a transaction.
pub async fn set_grants(
    pool: &PgPool,
    role_id: Uuid,
    grants: &[(String, String)], // (resource_type, action) pairs
) -> Result<Vec<AclGrantRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    sqlx::query("DELETE FROM acl_grants WHERE role_id = $1")
        .bind(role_id)
        .execute(&mut *tx)
        .await?;

    let mut result = Vec::with_capacity(grants.len());
    for (resource_type, action) in grants {
        let row = sqlx::query_as::<_, AclGrantRow>(
            "INSERT INTO acl_grants (role_id, resource_type, action)
             VALUES ($1, $2, $3)
             RETURNING id, role_id, resource_type, action, created_at",
        )
        .bind(role_id)
        .bind(resource_type)
        .bind(action)
        .fetch_one(&mut *tx)
        .await?;
        result.push(row);
    }

    tx.commit().await?;
    Ok(result)
}

// --- Assignments ---

pub async fn assign_role(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    role_id: Uuid,
    assigned_by: Option<Uuid>,
) -> Result<AclRoleAssignmentRow, sqlx::Error> {
    sqlx::query_as::<_, AclRoleAssignmentRow>(
        "INSERT INTO acl_role_assignments (org_id, identity_id, role_id, assigned_by)
         VALUES ($1, $2, $3, $4)
         RETURNING id, org_id, identity_id, role_id, assigned_by, created_at",
    )
    .bind(org_id)
    .bind(identity_id)
    .bind(role_id)
    .bind(assigned_by)
    .fetch_one(pool)
    .await
}

pub async fn revoke_assignment(pool: &PgPool, id: Uuid, org_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM acl_role_assignments WHERE id = $1 AND org_id = $2")
        .bind(id)
        .bind(org_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn list_assignments_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<AclRoleAssignmentRow>, sqlx::Error> {
    sqlx::query_as::<_, AclRoleAssignmentRow>(
        "SELECT id, org_id, identity_id, role_id, assigned_by, created_at
         FROM acl_role_assignments WHERE org_id = $1 ORDER BY created_at",
    )
    .bind(org_id)
    .fetch_all(pool)
    .await
}

pub async fn list_roles_for_identity(
    pool: &PgPool,
    identity_id: Uuid,
) -> Result<Vec<AclRoleRow>, sqlx::Error> {
    sqlx::query_as::<_, AclRoleRow>(
        "SELECT r.id, r.org_id, r.name, r.slug, r.description, r.is_builtin, r.created_at, r.updated_at
         FROM acl_roles r
         INNER JOIN acl_role_assignments a ON a.role_id = r.id
         WHERE a.identity_id = $1
         ORDER BY r.name",
    )
    .bind(identity_id)
    .fetch_all(pool)
    .await
}

// --- Permission checking ---

/// Check if an identity has a specific permission via any of their assigned roles.
/// `manage` on a resource implies read, write, and delete.
pub async fn check_permission(
    pool: &PgPool,
    identity_id: Uuid,
    resource_type: &str,
    action: &str,
) -> Result<bool, sqlx::Error> {
    // If action is read/write/delete, also accept manage
    let row = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
            SELECT 1 FROM acl_role_assignments a
            INNER JOIN acl_grants g ON g.role_id = a.role_id
            WHERE a.identity_id = $1
              AND g.resource_type = $2
              AND (g.action = $3 OR g.action = 'manage')
        )",
    )
    .bind(identity_id)
    .bind(resource_type)
    .bind(action)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Check if an identity has any role assignments at all.
/// Used for backward compatibility — identities with no assignments are allowed through.
pub async fn has_any_assignments(pool: &PgPool, identity_id: Uuid) -> Result<bool, sqlx::Error> {
    let row = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM acl_role_assignments WHERE identity_id = $1)",
    )
    .bind(identity_id)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Check if an identity is an org-admin (has org-admin role assigned).
pub async fn is_org_admin(pool: &PgPool, identity_id: Uuid) -> Result<bool, sqlx::Error> {
    let row = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
            SELECT 1 FROM acl_role_assignments a
            INNER JOIN acl_roles r ON r.id = a.role_id
            WHERE a.identity_id = $1 AND r.slug = 'org-admin'
        )",
    )
    .bind(identity_id)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Check if an org has at least one admin.
pub async fn has_any_admin(pool: &PgPool, org_id: Uuid) -> Result<bool, sqlx::Error> {
    let row = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
            SELECT 1 FROM acl_role_assignments a
            INNER JOIN acl_roles r ON r.id = a.role_id
            WHERE a.org_id = $1 AND r.slug = 'org-admin'
        )",
    )
    .bind(org_id)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

// --- Bootstrap ---

/// Idempotently create the 3 built-in roles for an org and seed their grants.
/// Returns the org-admin role ID (for assigning to the first user).
pub async fn ensure_builtin_roles(pool: &PgPool, org_id: Uuid) -> Result<Uuid, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Create roles (or get existing)
    let admin_role = upsert_builtin_role(
        &mut tx,
        org_id,
        "Org Admin",
        "org-admin",
        "Full access to all org resources and settings",
    )
    .await?;

    let member_role = upsert_builtin_role(
        &mut tx,
        org_id,
        "Member",
        "member",
        "Read and write access to core resources",
    )
    .await?;

    let readonly_role = upsert_builtin_role(
        &mut tx,
        org_id,
        "Read Only",
        "read-only",
        "Read-only access to most resources",
    )
    .await?;

    // Seed admin grants: manage on all
    let all_resources = [
        "services",
        "connections",
        "secrets",
        "agents",
        "approvals",
        "audit_logs",
        "webhooks",
        "org_settings",
        "acl",
    ];
    for rt in &all_resources {
        upsert_grant(&mut tx, admin_role, rt, "manage").await?;
    }

    // Seed member grants
    let member_rw = ["services", "connections", "secrets", "agents", "approvals"];
    for rt in &member_rw {
        upsert_grant(&mut tx, member_role, rt, "read").await?;
        upsert_grant(&mut tx, member_role, rt, "write").await?;
    }
    upsert_grant(&mut tx, member_role, "audit_logs", "read").await?;
    upsert_grant(&mut tx, member_role, "webhooks", "read").await?;

    // Seed read-only grants
    let readonly_resources = [
        "services",
        "connections",
        "secrets",
        "agents",
        "approvals",
        "audit_logs",
        "webhooks",
    ];
    for rt in &readonly_resources {
        upsert_grant(&mut tx, readonly_role, rt, "read").await?;
    }

    tx.commit().await?;
    Ok(admin_role)
}

async fn upsert_builtin_role(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    name: &str,
    slug: &str,
    description: &str,
) -> Result<Uuid, sqlx::Error> {
    let row = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO acl_roles (org_id, name, slug, description, is_builtin)
         VALUES ($1, $2, $3, $4, true)
         ON CONFLICT (org_id, slug) DO UPDATE SET name = EXCLUDED.name
         RETURNING id",
    )
    .bind(org_id)
    .bind(name)
    .bind(slug)
    .bind(description)
    .fetch_one(&mut **tx)
    .await?;
    Ok(row)
}

async fn upsert_grant(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    role_id: Uuid,
    resource_type: &str,
    action: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO acl_grants (role_id, resource_type, action)
         VALUES ($1, $2, $3)
         ON CONFLICT DO NOTHING",
    )
    .bind(role_id)
    .bind(resource_type)
    .bind(action)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Get all effective permissions for an identity as a list of (resource_type, action) pairs.
pub async fn effective_permissions(
    pool: &PgPool,
    identity_id: Uuid,
) -> Result<Vec<(String, String)>, sqlx::Error> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT DISTINCT g.resource_type, g.action
         FROM acl_role_assignments a
         INNER JOIN acl_grants g ON g.role_id = a.role_id
         WHERE a.identity_id = $1
         ORDER BY g.resource_type, g.action",
    )
    .bind(identity_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}
