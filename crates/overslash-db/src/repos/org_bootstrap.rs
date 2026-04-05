use sqlx::PgPool;
use uuid::Uuid;

/// Bootstrap system assets for a new org: overslash service instance, Everyone + Admins groups,
/// and default group grants. Idempotent — safe to call if assets already exist.
///
/// If `creator_identity_id` is provided, that user is added to both Everyone and Admins groups.
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

    // 2. Create Everyone group (allow_raw_http = true for backward compat)
    let everyone = sqlx::query!(
        "INSERT INTO groups (org_id, name, description, is_system, allow_raw_http)
         VALUES ($1, 'Everyone', 'All users in this organization', true, true)
         ON CONFLICT (org_id, name) DO NOTHING
         RETURNING id",
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let everyone_id = match everyone {
        Some(row) => row.id,
        None => sqlx::query!(
            "SELECT id FROM groups WHERE org_id = $1 AND name = 'Everyone' AND is_system = true",
            org_id,
        )
        .fetch_one(&mut *tx)
        .await?
        .id,
    };

    // 3. Create Admins group
    let admins = sqlx::query!(
        "INSERT INTO groups (org_id, name, description, is_system, allow_raw_http)
         VALUES ($1, 'Admins', 'Organization administrators', true, true)
         ON CONFLICT (org_id, name) DO NOTHING
         RETURNING id",
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let admins_id =
        match admins {
            Some(row) => row.id,
            None => sqlx::query!(
                "SELECT id FROM groups WHERE org_id = $1 AND name = 'Admins' AND is_system = true",
                org_id,
            )
            .fetch_one(&mut *tx)
            .await?
            .id,
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

    // 6. Add creator to both groups
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
    Ok(())
}

/// Add a user to the Everyone group for their org. No-op if already a member.
pub async fn add_to_everyone_group(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO identity_groups (identity_id, group_id)
         SELECT $1, g.id FROM groups g
         WHERE g.org_id = $2 AND g.name = 'Everyone' AND g.is_system = true
         ON CONFLICT DO NOTHING",
        identity_id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}
