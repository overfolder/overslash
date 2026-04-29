use sqlx::PgPool;
use uuid::Uuid;

/// Bootstrap system assets for a new org: overslash service instance, Everyone + Admins groups,
/// and default group grants. Idempotent — safe to call if assets already exist.
///
/// If `creator_identity_id` is provided, that user is added to both Everyone and Admins groups
/// and gets a Myself group created.
pub async fn bootstrap_org(
    pool: &PgPool,
    org_id: Uuid,
    creator_identity_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    // 1. Create the overslash service instance (system, org-level)
    let svc = sqlx::query!(
        "INSERT INTO service_instances (org_id, name, template_source, template_key, status, is_system)
         VALUES ($1, 'overslash', 'global', 'overslash', 'active', true)
         ON CONFLICT (org_id, name) WHERE owner_identity_id IS NULL DO NOTHING
         RETURNING id",
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let svc_id = match svc {
        Some(row) => row.id,
        None => {
            // Already existed — fetch it
            sqlx::query!(
                "SELECT id FROM service_instances WHERE org_id = $1 AND name = 'overslash' AND is_system = true",
                org_id,
            )
            .fetch_one(&mut *tx)
            .await?
            .id
        }
    };

    // 2. Create Everyone group (allow_raw_http = true for backward compat).
    // Tagged with system_kind = 'everyone' so lookups don't depend on the localized name.
    let everyone = sqlx::query!(
        "INSERT INTO groups (org_id, name, description, is_system, system_kind, allow_raw_http)
         VALUES ($1, 'Everyone', 'All users in this organization', true, 'everyone', true)
         ON CONFLICT (org_id, name) DO UPDATE SET system_kind = 'everyone'
         RETURNING id",
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let everyone_id = match everyone {
        Some(row) => row.id,
        None => {
            sqlx::query!(
                "SELECT id FROM groups WHERE org_id = $1 AND system_kind = 'everyone'",
                org_id,
            )
            .fetch_one(&mut *tx)
            .await?
            .id
        }
    };

    // 3. Create Admins group
    let admins = sqlx::query!(
        "INSERT INTO groups (org_id, name, description, is_system, system_kind, allow_raw_http)
         VALUES ($1, 'Admins', 'Organization administrators', true, 'admins', true)
         ON CONFLICT (org_id, name) DO UPDATE SET system_kind = 'admins'
         RETURNING id",
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let admins_id = match admins {
        Some(row) => row.id,
        None => {
            sqlx::query!(
                "SELECT id FROM groups WHERE org_id = $1 AND system_kind = 'admins'",
                org_id,
            )
            .fetch_one(&mut *tx)
            .await?
            .id
        }
    };

    // 4. Grant Everyone write access to overslash
    sqlx::query!(
        "INSERT INTO group_grants (group_id, service_instance_id, access_level)
         VALUES ($1, $2, 'write')
         ON CONFLICT (group_id, service_instance_id) DO NOTHING",
        everyone_id,
        svc_id,
    )
    .execute(&mut *tx)
    .await?;

    // 5. Grant Admins admin access to overslash
    sqlx::query!(
        "INSERT INTO group_grants (group_id, service_instance_id, access_level)
         VALUES ($1, $2, 'admin')
         ON CONFLICT (group_id, service_instance_id) DO NOTHING",
        admins_id,
        svc_id,
    )
    .execute(&mut *tx)
    .await?;

    // 6. Add creator to both groups + ensure their Myself group
    if let Some(user_id) = creator_identity_id {
        sqlx::query!(
            "INSERT INTO identity_groups (identity_id, group_id)
             VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
            user_id,
            everyone_id,
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(
            "INSERT INTO identity_groups (identity_id, group_id)
             VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
            user_id,
            admins_id,
        )
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    // Myself group runs in its own short transaction (post-commit) so a missing
    // identity row (e.g. tests calling bootstrap_org with creator_identity_id=None
    // expectations) doesn't roll back the org-level setup.
    if let Some(user_id) = creator_identity_id {
        ensure_myself_group_for_identity(pool, org_id, user_id).await?;
    }

    Ok(())
}

/// Bootstrap a user's per-org membership: join the Everyone group and create
/// their Myself group. Idempotent.
///
/// Replaces the previous narrower `add_to_everyone_group` — call this from any
/// code path that creates a `kind = 'user'` identity in an org.
pub async fn bootstrap_user_in_org(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO identity_groups (identity_id, group_id)
         SELECT $1, g.id FROM groups g
         WHERE g.org_id = $2 AND g.system_kind = 'everyone'
         ON CONFLICT DO NOTHING",
        identity_id,
        org_id,
    )
    .execute(pool)
    .await?;

    ensure_myself_group_for_identity(pool, org_id, identity_id).await?;
    Ok(())
}

/// Look up the identity's `email`/`name` to label the Myself group, then
/// delegate to `repos::group::ensure_self_group`.
async fn ensure_myself_group_for_identity(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<(), sqlx::Error> {
    let row = sqlx::query!(
        "SELECT email, name FROM identities WHERE id = $1 AND org_id = $2 AND kind = 'user'",
        identity_id,
        org_id,
    )
    .fetch_optional(pool)
    .await?;

    let label = row
        .as_ref()
        .and_then(|r| r.email.clone().or_else(|| Some(r.name.clone())))
        .unwrap_or_else(|| identity_id.to_string());

    crate::repos::group::ensure_self_group(pool, org_id, identity_id, &label).await?;
    Ok(())
}
