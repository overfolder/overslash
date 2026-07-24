use sqlx::PgPool;
use uuid::Uuid;

use super::{IdentityRow, ORG_SERVICE_EXTERNAL_ID};

/// Insert or remove `identity_id` from the org's `Admins` system group inside
/// an existing transaction. This is the single primitive that every
/// admin-granting path routes through ([`set_is_org_admin`] for one identity,
/// [`set_org_member_admin`] for a whole membership) so the group-grant ACL path
/// can never drift from the `is_org_admin` fast-path flag.
async fn sync_admins_group_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    identity_id: Uuid,
    value: bool,
) -> Result<(), sqlx::Error> {
    if value {
        sqlx::query!(
            "INSERT INTO identity_groups (identity_id, group_id)
             SELECT $1, g.id FROM groups g
             WHERE g.org_id = $2 AND g.system_kind = 'admins'
             ON CONFLICT DO NOTHING",
            identity_id,
            org_id,
        )
        .execute(&mut **tx)
        .await?;
    } else {
        sqlx::query!(
            "DELETE FROM identity_groups
             WHERE identity_id = $1
               AND group_id IN (
                 SELECT id FROM groups
                 WHERE org_id = $2 AND system_kind = 'admins'
               )",
            identity_id,
            org_id,
        )
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Toggle the `is_org_admin` flag on a single User identity. The DB CHECK
/// constraint rejects the call if `id` is not a User. Also keeps the `Admins`
/// system-group membership in sync (via [`sync_admins_group_tx`]) so the
/// group-grant ACL path stays consistent with the `is_org_admin` fast-path flag.
pub async fn set_is_org_admin(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    value: bool,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let result = sqlx::query!(
        "UPDATE identities SET is_org_admin = $3, updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org_id,
        value,
    )
    .execute(&mut *tx)
    .await?;
    sync_admins_group_tx(&mut tx, org_id, id, value).await?;
    tx.commit().await?;
    Ok(result.rows_affected() > 0)
}

/// Outcome of [`set_org_member_admin`].
pub enum SetOrgMemberAdminOutcome {
    /// Role change applied. `changed` is false when the member was already in
    /// the requested state (idempotent no-op) — the caller can still treat it
    /// as success.
    Updated { changed: bool },
    /// No `user_org_memberships` row for this `(org, user)`.
    NotFound,
    /// Refused: demoting this member would leave the org with zero admins.
    LastAdmin,
}

/// Promote or demote an existing org member to/from org admin, atomically.
///
/// "Real" admin authorization requires BOTH the `user_org_memberships.role`
/// (used for the last-admin guard and display) AND the per-identity
/// `is_org_admin` flag + `Admins`-group membership that `AdminAcl`/`OrgAcl`
/// actually read (see `extractors.rs`). This helper is the single source of
/// truth that keeps all three in lock-step for every user-kind identity of the
/// `(org, user)` — a human may hold more than one identity in an org after
/// signing in through a second IdP, and each carries its own flag/group state.
///
/// Guards the last-admin invariant: refuses to demote the final admin (mirror
/// of [`super::remove_user_from_org`]). Locks all admin membership rows in `user_id`
/// order so concurrent role changes serialise instead of deadlocking. A
/// self-demotion of the sole admin is refused by the same guard.
pub async fn set_org_member_admin(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    make_admin: bool,
) -> Result<SetOrgMemberAdminOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Lock every admin membership row of the org in deterministic order so
    // concurrent promotions/demotions serialise instead of deadlocking, and so
    // the last-admin count below is a consistent snapshot.
    let admin_user_ids: Vec<Uuid> = sqlx::query_scalar!(
        "SELECT user_id FROM user_org_memberships
         WHERE org_id = $1 AND role = 'admin'
         ORDER BY user_id FOR UPDATE",
        org_id,
    )
    .fetch_all(&mut *tx)
    .await?;

    // Lock the target membership row (existence check).
    let existing_role: Option<String> = sqlx::query_scalar!(
        "SELECT role FROM user_org_memberships
         WHERE user_id = $1 AND org_id = $2 FOR UPDATE",
        user_id,
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let Some(existing_role) = existing_role else {
        return Ok(SetOrgMemberAdminOutcome::NotFound);
    };

    let is_admin_now = admin_user_ids.contains(&user_id);
    if !make_admin && is_admin_now && admin_user_ids.len() <= 1 {
        return Ok(SetOrgMemberAdminOutcome::LastAdmin);
    }

    let new_role = if make_admin {
        crate::repos::membership::ROLE_ADMIN
    } else {
        crate::repos::membership::ROLE_MEMBER
    };
    let changed = existing_role != new_role;

    // 1. Membership role (drives the last-admin guard + display).
    sqlx::query!(
        "UPDATE user_org_memberships SET role = $3
         WHERE user_id = $1 AND org_id = $2",
        user_id,
        org_id,
        new_role,
    )
    .execute(&mut *tx)
    .await?;

    // 2+3. The per-identity flag + Admins-group membership for EVERY user-kind
    // identity of this human in the org — the authorization surface the ACL
    // extractor reads. Route each through the shared group primitive so the two
    // never drift.
    let identity_ids: Vec<Uuid> = sqlx::query_scalar!(
        "SELECT id FROM identities
         WHERE org_id = $2 AND user_id = $1 AND kind = 'user'",
        user_id,
        org_id,
    )
    .fetch_all(&mut *tx)
    .await?;

    sqlx::query!(
        "UPDATE identities SET is_org_admin = $3, updated_at = now()
         WHERE org_id = $2 AND user_id = $1 AND kind = 'user'",
        user_id,
        org_id,
        make_admin,
    )
    .execute(&mut *tx)
    .await?;

    for id in identity_ids {
        sync_admins_group_tx(&mut tx, org_id, id, make_admin).await?;
    }

    tx.commit().await?;
    Ok(SetOrgMemberAdminOutcome::Updated { changed })
}

/// Resolve (or create) the well-known "org-service" Agent for an org.
///
/// All API keys minted from the dashboard's Org Settings → Service keys
/// section bind to this single shared identity. The first call inserts
/// a row with `external_id = ORG_SERVICE_EXTERNAL_ID`, points its
/// `owner_id` at itself, and attaches it to the org's Admins group;
/// subsequent calls return the existing row.
///
/// **Self-ownership is intentional.** The standard agent layout
/// (`Agent.owner_id → User`) routes ACL ceiling lookups through the
/// owner's group memberships. We don't want this agent's authority to
/// be anchored to any individual admin User (it would die when that
/// admin is offboarded), so we make it self-owned. `get_ceiling_for_user`
/// joins on `identity_groups` directly and does not require the input
/// to be a User, so feeding it the agent's own id makes its Admins
/// membership the authoritative ceiling source.
///
/// We don't use `set_is_org_admin` here because the DB CHECK
/// `identities_is_org_admin_only_user` rejects `is_org_admin=true` on
/// non-User identities. Membership in the Admins group via `identity_groups`
/// is what `resolve_identity_access` reads to compute the agent's
/// AccessLevel, so the impersonation cap at the auth layer treats it as
/// admin-level when an impersonate-capable key is presented.
///
/// Returns `(row, created)` so the caller can emit a one-time
/// `org_service_agent.created` audit row.
pub async fn get_or_create_org_service_agent(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<(IdentityRow, bool), sqlx::Error> {
    let mut tx = pool.begin().await?;

    // ON CONFLICT DO NOTHING returns no row if a parallel writer already
    // inserted, so a SELECT fallback covers the race. The UNIQUE(org_id,
    // external_id) index is the single source of truth either way.
    let inserted = sqlx::query_as!(
        IdentityRow,
        "INSERT INTO identities (org_id, name, kind, external_id, auto_call_on_approve)
         VALUES ($1, 'org-service', 'agent', $2,
                 (SELECT NOT default_deferred_execution FROM orgs WHERE id = $1))
         ON CONFLICT (org_id, external_id) DO NOTHING
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
        org_id,
        ORG_SERVICE_EXTERNAL_ID,
    )
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(agent) = inserted {
        let agent = sqlx::query_as!(
            IdentityRow,
            "UPDATE identities SET owner_id = id, updated_at = now()
             WHERE id = $1
             RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
            agent.id,
        )
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query!(
            "INSERT INTO identity_groups (identity_id, group_id)
             SELECT $1, g.id FROM groups g
             WHERE g.org_id = $2 AND g.system_kind = 'admins'
             ON CONFLICT DO NOTHING",
            agent.id,
            org_id,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok((agent, true));
    }

    let agent = sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at
         FROM identities
         WHERE org_id = $1 AND external_id = $2",
        org_id,
        ORG_SERVICE_EXTERNAL_ID,
    )
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((agent, false))
}
