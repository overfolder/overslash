use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Reason an identity was archived. Stored in `archived_reason`.
pub const ARCHIVED_REASON_IDLE_TIMEOUT: &str = "idle_timeout";

/// `external_id` reserved for the per-org Agent that owns "service keys"
/// minted from Org Settings. The colon-prefixed namespace cannot collide
/// with IdP-issued subjects (IdP subs come from per-provider strings
/// without that namespace).
pub const ORG_SERVICE_EXTERNAL_ID: &str = "overslash:org-service";

#[derive(Debug, sqlx::FromRow)]
pub struct IdentityRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub kind: String,
    pub external_id: Option<String>,
    pub email: Option<String>,
    pub metadata: serde_json::Value,
    pub parent_id: Option<Uuid>,
    pub depth: i32,
    pub owner_id: Option<Uuid>,
    pub inherit_permissions: bool,
    pub last_active_at: OffsetDateTime,
    pub archived_at: Option<OffsetDateTime>,
    pub archived_reason: Option<String>,
    pub preferences: serde_json::Value,
    pub is_org_admin: bool,
    pub user_id: Option<Uuid>,
    pub auto_call_on_approve: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

super::impl_org_owned!(IdentityRow);

pub async fn create(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    kind: &str,
    external_id: Option<&str>,
) -> Result<IdentityRow, sqlx::Error> {
    // `auto_call_on_approve` is seeded from the inverse of
    // `orgs.default_deferred_execution`: when the org has flipped its policy
    // to deferred-by-default, a new agent is born with auto-call OFF. The
    // value is meaningless for `user`-kind rows but storing it uniformly
    // avoids branching here.
    sqlx::query_as!(
        IdentityRow,
        "INSERT INTO identities (org_id, name, kind, external_id, auto_call_on_approve)
         VALUES ($1, $2, $3, $4, (SELECT NOT default_deferred_execution FROM orgs WHERE id = $1))
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
        org_id,
        name,
        kind,
        external_id,
    )
    .fetch_one(pool)
    .await
}

pub async fn create_with_email(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    kind: &str,
    external_id: Option<&str>,
    email: Option<&str>,
    metadata: serde_json::Value,
) -> Result<IdentityRow, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "INSERT INTO identities (org_id, name, kind, external_id, email, metadata, auto_call_on_approve)
         VALUES ($1, $2, $3, $4, $5, $6, (SELECT NOT default_deferred_execution FROM orgs WHERE id = $1))
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
        org_id,
        name,
        kind,
        external_id,
        email,
        metadata,
    )
    .fetch_one(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn create_with_parent(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    kind: &str,
    external_id: Option<&str>,
    parent_id: Uuid,
    depth: i32,
    owner_id: Uuid,
    inherit_permissions: bool,
) -> Result<IdentityRow, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "INSERT INTO identities (org_id, name, kind, external_id, parent_id, depth, owner_id, inherit_permissions, auto_call_on_approve)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, (SELECT NOT default_deferred_execution FROM orgs WHERE id = $1))
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
        org_id,
        name,
        kind,
        external_id,
        parent_id,
        depth,
        owner_id,
        inherit_permissions,
    )
    .fetch_one(pool)
    .await
}

/// Cross-org user lookup by email. Used exclusively by the login bootstrap
/// path, where the org is not yet known. All in-org callers must instead go
/// through `OrgScope::get_identity` (which is bounded by `self.org_id()`).
/// Surfaced on `SystemScope::find_user_identity_by_email`.
pub(crate) async fn find_user_by_email_global(
    pool: &PgPool,
    email: &str,
) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at
         FROM identities WHERE email = $1 AND kind = 'user'",
        email,
    )
    .fetch_optional(pool)
    .await
}

/// Look up a user-kind identity by its IdP subject within an org. Used by
/// the org-subdomain login path to detect returning users before deciding
/// whether to auto-provision.
pub async fn find_user_by_external_id_in_org(
    pool: &PgPool,
    org_id: Uuid,
    external_id: &str,
) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at
         FROM identities WHERE org_id = $1 AND external_id = $2 AND kind = 'user'",
        org_id,
        external_id,
    )
    .fetch_optional(pool)
    .await
}

/// Find the user-kind `identities` row for a specific `(org_id, user_id)`
/// pair. At most one row exists (partial UNIQUE from migration 040). Used by
/// the multi-org switch flow to resolve `sub` for the new JWT.
pub async fn find_by_org_and_user(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at
         FROM identities WHERE org_id = $1 AND user_id = $2 AND kind = 'user'",
        org_id,
        user_id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn get_by_id(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at
         FROM identities WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn count_by_org(pool: &PgPool, org_id: Uuid) -> Result<i64, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS count FROM identities WHERE org_id = $1",
        org_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.count.unwrap_or(0))
}

pub(crate) async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at
         FROM identities WHERE org_id = $1 ORDER BY created_at",
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn list_children(
    pool: &PgPool,
    org_id: Uuid,
    parent_id: Uuid,
) -> Result<Vec<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at
         FROM identities WHERE parent_id = $1 AND org_id = $2 ORDER BY created_at",
        parent_id,
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_ancestor_chain(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
) -> Result<Vec<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        r#"WITH RECURSIVE chain AS (
            SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at,
                   1 AS _depth
            FROM identities WHERE id = $1 AND org_id = $2
            UNION ALL
            SELECT i.id, i.org_id, i.name, i.kind, i.external_id, i.email, i.metadata,
                   i.parent_id, i.depth, i.owner_id, i.inherit_permissions,
                   i.last_active_at, i.archived_at, i.archived_reason, i.preferences,
                   i.is_org_admin, i.user_id, i.auto_call_on_approve,
                   i.created_at, i.updated_at, c._depth + 1
            FROM identities i
            INNER JOIN chain c ON i.id = c.parent_id
            WHERE c._depth < 50 AND i.org_id = $2
        )
        SELECT id as "id!", org_id as "org_id!", name as "name!", kind as "kind!",
               external_id, email, metadata as "metadata!",
               parent_id, depth as "depth!", owner_id,
               inherit_permissions as "inherit_permissions!",
               last_active_at as "last_active_at!",
               archived_at, archived_reason,
               preferences as "preferences!",
               is_org_admin as "is_org_admin!",
               user_id,
               auto_call_on_approve as "auto_call_on_approve!",
               created_at as "created_at!", updated_at as "updated_at!"
        FROM chain ORDER BY depth ASC"#,
        identity_id,
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// Update an identity's profile (name, metadata) on subsequent login.
pub async fn update_profile(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    name: &str,
    metadata: serde_json::Value,
) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "UPDATE identities SET name = $3, metadata = $4, updated_at = now()
         WHERE id = $1 AND org_id = $2
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
        id,
        org_id,
        name,
        metadata,
    )
    .fetch_optional(pool)
    .await
}

/// Toggle the `is_org_admin` flag on a User identity. The DB CHECK constraint
/// rejects the call if `id` is not a User. Also keeps the `Admins` system group
/// membership in sync so the group-grant ACL path stays consistent with the
/// Attach (or detach) this identity's human pointer. Used by the multi-org
/// provisioning path when an existing identity needs to be promoted from
/// the legacy NULL-user_id shape. Writes are scoped by `(id, org_id)` to
/// avoid cross-tenant drift.
pub async fn set_user_id(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    user_id: Option<Uuid>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE identities SET user_id = $3, updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org_id,
        user_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// fast-path flag.
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
    if value {
        sqlx::query!(
            "INSERT INTO identity_groups (identity_id, group_id)
             SELECT $1, g.id FROM groups g
             WHERE g.org_id = $2 AND g.system_kind = 'admins'
             ON CONFLICT DO NOTHING",
            id,
            org_id,
        )
        .execute(&mut *tx)
        .await?;
    } else {
        sqlx::query!(
            "DELETE FROM identity_groups
             WHERE identity_id = $1
               AND group_id IN (
                 SELECT id FROM groups
                 WHERE org_id = $2 AND system_kind = 'admins'
               )",
            id,
            org_id,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(result.rows_affected() > 0)
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

/// Toggle the per-agent `auto_call_on_approve` flag. Default for new
/// identities is TRUE; flipping to FALSE puts the agent in "deferred
/// execution" mode where the resolver/agent must call `POST
/// /v1/approvals/{id}/call` explicitly after approve.
pub async fn set_auto_call_on_approve(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    value: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE identities SET auto_call_on_approve = $3, updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org_id,
        value,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn set_inherit_permissions(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    inherit: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE identities SET inherit_permissions = $3, updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org_id,
        inherit,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub(crate) async fn delete(pool: &PgPool, org_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM identities WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub(crate) async fn rename(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
    name: &str,
) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "UPDATE identities SET name = $3, updated_at = now()
         WHERE id = $1 AND org_id = $2
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
        id,
        org_id,
        name,
    )
    .fetch_optional(pool)
    .await
}

/// Move parameters for `apply_patch`. The caller resolves owner ids from the
/// `IdentityKind` (Agent vs SubAgent), but the new `depth` is computed
/// **inside** the transaction from the parent row that's been locked
/// `FOR UPDATE`, so a concurrent move of the parent can't race in a stale
/// depth.
#[derive(Debug, Clone, Copy)]
pub struct MoveTo {
    pub parent_id: Uuid,
    pub new_owner_id: Uuid,
    pub descendant_owner_id: Uuid,
}

/// All optional patches to apply to an identity, atomically.
#[derive(Debug, Default)]
pub struct PatchIdentity<'a> {
    pub name: Option<&'a str>,
    pub move_to: Option<MoveTo>,
    pub inherit_permissions: Option<bool>,
}

/// Outcome of `apply_patch`. `Cycle` indicates the requested move would
/// have placed the identity under one of its own descendants — refused
/// inside the transaction so two concurrent moves can't sneak past an
/// out-of-band cycle check.
pub enum ApplyPatchOutcome {
    Updated(Box<IdentityRow>),
    NotFound,
    ParentNotFound,
    Cycle,
}

/// Maximum recursive descent for both the cycle check and the descendant
/// `depth`/`owner_id` cascade. Matches `get_ancestor_chain`'s bound.
/// Defence-in-depth so a leftover cycle (e.g. from a manual SQL fixup) can't
/// loop forever inside a recursive CTE.
const MAX_TREE_DEPTH: i32 = 50;

/// Apply rename + move + inherit toggle in a single transaction so the
/// patch is atomic. The transaction holds `FOR UPDATE` on **both** the
/// moved row and (when moving) the new parent, in id-sorted order to avoid
/// deadlocks. The cycle check and depth lookup happen inside the lock so
/// no concurrent move can poison the result.
pub(crate) async fn apply_patch(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
    patch: PatchIdentity<'_>,
) -> Result<ApplyPatchOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Lock the moved row + (when moving) the new parent in id-sorted order.
    // This serialises any pair of concurrent moves that touch the same two
    // rows and prevents a lock-acquisition deadlock.
    if let Some(mv) = patch.move_to.as_ref() {
        let mut to_lock = [id, mv.parent_id];
        to_lock.sort();
        sqlx::query!(
            "SELECT id FROM identities WHERE id = ANY($1) AND org_id = $2 ORDER BY id FOR UPDATE",
            &to_lock[..],
            org_id,
        )
        .fetch_all(&mut *tx)
        .await?;
    } else {
        sqlx::query!(
            "SELECT id FROM identities WHERE id = $1 AND org_id = $2 FOR UPDATE",
            id,
            org_id,
        )
        .fetch_optional(&mut *tx)
        .await?;
    }

    // Re-read the moved row's depth under the lock.
    let current = sqlx::query!(
        "SELECT depth FROM identities WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(current) = current else {
        return Ok(ApplyPatchOutcome::NotFound);
    };

    if let Some(name) = patch.name {
        sqlx::query!(
            "UPDATE identities SET name = $3, updated_at = now()
             WHERE id = $1 AND org_id = $2",
            id,
            org_id,
            name,
        )
        .execute(&mut *tx)
        .await?;
    }

    if let Some(MoveTo {
        parent_id,
        new_owner_id,
        descendant_owner_id,
    }) = patch.move_to
    {
        // Re-read the parent's depth under the lock. Outside the tx its
        // value could have changed under our feet (a concurrent move of the
        // parent itself), so don't trust the route's pre-tx read.
        // Parent may have been concurrently deleted between the route's
        // pre-check and the apply_patch transaction starting, even though
        // we tried to lock it above (the `FOR UPDATE` lock-set returns
        // fewer rows when one of the ids is gone). Surface that as a
        // domain outcome rather than a 500.
        let Some(parent) = sqlx::query!(
            "SELECT depth FROM identities WHERE id = $1 AND org_id = $2",
            parent_id,
            org_id,
        )
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(ApplyPatchOutcome::ParentNotFound);
        };
        let new_depth = parent.depth + 1;
        let depth_delta = new_depth - current.depth;

        // Cycle guard, also under the lock and bounded so a pre-existing
        // cycle can't loop the planner forever. Walk parent_id → root and
        // refuse if we ever see `id`.
        let cycle = sqlx::query!(
            r#"WITH RECURSIVE chain(id, parent_id, lvl) AS (
                SELECT id, parent_id, 1 FROM identities WHERE id = $1 AND org_id = $2
                UNION ALL
                SELECT i.id, i.parent_id, c.lvl + 1
                FROM identities i
                INNER JOIN chain c ON i.id = c.parent_id
                WHERE i.org_id = $2 AND c.lvl < $3
            )
            SELECT 1 as "hit!" FROM chain WHERE id = $4 LIMIT 1"#,
            parent_id,
            org_id,
            MAX_TREE_DEPTH,
            id,
        )
        .fetch_optional(&mut *tx)
        .await?;
        if cycle.is_some() {
            return Ok(ApplyPatchOutcome::Cycle);
        }

        sqlx::query!(
            "UPDATE identities SET parent_id = $3, depth = $4, owner_id = $5, updated_at = now()
             WHERE id = $1 AND org_id = $2",
            id,
            org_id,
            parent_id,
            new_depth,
            new_owner_id,
        )
        .execute(&mut *tx)
        .await?;
        // Bounded recursive CTE — defends against a corrupt cycle slipping
        // past the check above.
        sqlx::query!(
            r#"WITH RECURSIVE subtree(id, lvl) AS (
                SELECT id, 1 FROM identities WHERE parent_id = $1
                UNION ALL
                SELECT i.id, s.lvl + 1
                FROM identities i
                INNER JOIN subtree s ON i.parent_id = s.id
                WHERE s.lvl < $4
            )
            UPDATE identities SET
                depth = depth + $2,
                owner_id = CASE WHEN kind = 'sub_agent' THEN $3 ELSE owner_id END,
                updated_at = now()
            WHERE id IN (SELECT id FROM subtree)"#,
            id,
            depth_delta,
            descendant_owner_id,
            MAX_TREE_DEPTH,
        )
        .execute(&mut *tx)
        .await?;
    }

    if let Some(inherit) = patch.inherit_permissions {
        sqlx::query!(
            "UPDATE identities SET inherit_permissions = $3, updated_at = now()
             WHERE id = $1 AND org_id = $2",
            id,
            org_id,
            inherit,
        )
        .execute(&mut *tx)
        .await?;
    }

    let row = sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at
         FROM identities WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(ApplyPatchOutcome::Updated(Box::new(row)))
}

/// Move an identity to a new parent and recursively update its descendants.
///
/// All descendants have their `depth` shifted by the same delta as the moved
/// node, and any sub_agent descendants get their `owner_id` rewritten to
/// `descendant_owner_id` (the User at the top of the new chain). This keeps
/// the SubAgent.owner_id invariant after a move that crosses owner chains.
pub(crate) async fn move_under(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
    parent_id: Uuid,
    new_depth: i32,
    new_owner_id: Uuid,
    descendant_owner_id: Uuid,
) -> Result<Option<IdentityRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Fetch current depth so we can shift descendants by the delta.
    let current = sqlx::query!(
        "SELECT depth FROM identities WHERE id = $1 AND org_id = $2 FOR UPDATE",
        id,
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(current) = current else {
        return Ok(None);
    };
    let depth_delta = new_depth - current.depth;

    let row = sqlx::query_as!(
        IdentityRow,
        "UPDATE identities SET parent_id = $3, depth = $4, owner_id = $5, updated_at = now()
         WHERE id = $1 AND org_id = $2
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
        id,
        org_id,
        parent_id,
        new_depth,
        new_owner_id,
    )
    .fetch_one(&mut *tx)
    .await?;

    // Shift all descendants' depth and rewrite sub_agent owner_id.
    sqlx::query!(
        r#"WITH RECURSIVE subtree AS (
            SELECT id FROM identities WHERE parent_id = $1
            UNION ALL
            SELECT i.id FROM identities i
            INNER JOIN subtree s ON i.parent_id = s.id
        )
        UPDATE identities SET
            depth = depth + $2,
            owner_id = CASE WHEN kind = 'sub_agent' THEN $3 ELSE owner_id END,
            updated_at = now()
        WHERE id IN (SELECT id FROM subtree)"#,
        id,
        depth_delta,
        descendant_owner_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Some(row))
}

/// Outcome of an attempt to delete a leaf identity.
pub enum DeleteLeafOutcome {
    Deleted,
    NotFound,
    HasChildren,
}

/// Atomically delete an identity only if it has no children.
///
/// The parent row is locked `FOR UPDATE` for the duration of the transaction,
/// which forces any concurrent FK-checking INSERT (which needs at least
/// `FOR KEY SHARE`) to block until we commit. This closes the TOCTOU race
/// where a child could be inserted between a separate count and delete and
/// then be silently cascade-deleted.
pub(crate) async fn delete_leaf(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
) -> Result<DeleteLeafOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let exists = sqlx::query!(
        "SELECT id FROM identities WHERE id = $1 AND org_id = $2 FOR UPDATE",
        id,
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if exists.is_none() {
        return Ok(DeleteLeafOutcome::NotFound);
    }

    // Only *live* children block deletion. Archived children (e.g.
    // idle-cleanup'd sub-agents in their retention window) are
    // semantically gone from the user's perspective and would cascade-
    // delete with the parent via the FK anyway, so they must not block
    // an admin's intentional delete. Add the `org_id` filter for
    // defence-in-depth even though the FOR UPDATE on the parent row
    // already gates cross-tenant access.
    let child = sqlx::query!(
        "SELECT 1 as exists FROM identities
         WHERE parent_id = $1 AND org_id = $2 AND archived_at IS NULL
         LIMIT 1",
        id,
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if child.is_some() {
        return Ok(DeleteLeafOutcome::HasChildren);
    }

    sqlx::query!(
        "DELETE FROM identities WHERE id = $1 AND org_id = $2",
        id,
        org_id
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(DeleteLeafOutcome::Deleted)
}

/// Stamp `last_active_at = now()` for a sub-agent. Used by the auth middleware
/// after each authenticated request to keep idle-cleanup tracking current.
/// Returns Ok(()) even if the row doesn't exist or is already archived; this
/// is fire-and-forget and shouldn't surface errors to the request path.
pub(crate) async fn touch_last_active(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE identities SET last_active_at = now()
         WHERE id = $1 AND org_id = $2 AND archived_at IS NULL",
        id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Phase 1: archive idle sub-agents.
///
/// A sub-agent is archived when:
///   - it is `kind = 'sub_agent'`,
///   - it is not already archived,
///   - its `last_active_at` is older than the org's `subagent_idle_timeout_secs`,
///   - and **no live (un-archived) child identity** exists. Parents wait for
///     their entire descendant subtree to drain before they themselves archive.
///
/// Within a single transaction we:
///   1. Mark identities as archived (`archived_at = now()`, `archived_reason = 'idle_timeout'`).
///   2. Auto-revoke their API keys, tagged so `restore` can resurrect them.
///   3. Expire any pending approvals attached to them.
///
/// Returns the number of identities archived in this pass. Multiple passes may
/// be needed to drain a deep tree (children archive first, then parents next pass).
pub async fn archive_idle_subagents(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;

    let archived_ids: Vec<Uuid> = sqlx::query_scalar!(
        r#"UPDATE identities AS i
           SET archived_at = now(), archived_reason = $1, updated_at = now()
           FROM orgs o
           WHERE i.org_id = o.id
             AND i.kind = 'sub_agent'
             AND i.archived_at IS NULL
             AND i.last_active_at < now() - make_interval(secs => o.subagent_idle_timeout_secs)
             AND NOT EXISTS (
                 SELECT 1 FROM identities c
                 WHERE c.parent_id = i.id AND c.archived_at IS NULL
             )
           RETURNING i.id"#,
        ARCHIVED_REASON_IDLE_TIMEOUT,
    )
    .fetch_all(&mut *tx)
    .await?;

    if archived_ids.is_empty() {
        tx.commit().await?;
        return Ok(0);
    }

    super::api_key::revoke_by_identity_ids_with_reason(
        &mut *tx,
        &archived_ids,
        super::api_key::REVOKED_REASON_IDENTITY_ARCHIVED,
    )
    .await?;

    sqlx::query!(
        "UPDATE approvals SET status = 'expired', resolved_at = now(), resolved_by = 'system'
         WHERE identity_id = ANY($1) AND status = 'pending'",
        &archived_ids,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(archived_ids.len() as u64)
}

/// Phase 2: hard-delete sub-agents that have been archived past the org retention window.
///
/// Skip parents that still have any child rows in the DB (archived or not) — the
/// FK CASCADE would otherwise wipe active descendants. Children purge first;
/// the parent is eligible on a subsequent pass once they're gone.
pub async fn purge_archived_subagents(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        r#"DELETE FROM identities i
           USING orgs o
           WHERE i.org_id = o.id
             AND i.kind = 'sub_agent'
             AND i.archived_at IS NOT NULL
             AND i.archived_at < now() - make_interval(days => o.subagent_archive_retention_days)
             AND NOT EXISTS (SELECT 1 FROM identities c WHERE c.parent_id = i.id)"#,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Result of a restore attempt.
pub enum RestoreOutcome {
    /// Restored successfully. Returns the unarchived identity row and the count
    /// of API keys that were resurrected.
    Restored {
        identity: Box<IdentityRow>,
        api_keys_resurrected: u64,
    },
    /// Identity exists but is not archived; no-op.
    NotArchived,
    /// Identity exists, was archived, but is past its retention window —
    /// either already purged or about to be. Cannot restore.
    PastRetention,
    /// The identity's parent is itself archived. Restoring would create a live
    /// child under an archived parent and block the parent's purge forever.
    ParentArchived,
    /// Identity does not exist (or wrong org).
    NotFound,
}

/// Restore an archived sub-agent and resurrect its auto-revoked API keys.
/// Only works if the identity is still within the org's retention window AND
/// its parent is not itself archived.
///
/// All checks happen inside a single transaction with `FOR UPDATE` row locks
/// on the identity AND its parent (if any), so:
///   - a concurrent purge can't delete the row mid-restore, and
///   - a concurrent archive can't archive the parent between our check and
///     our UPDATE (TOCTOU race).
pub(crate) async fn restore(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<RestoreOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Lock the identity row + read its retention window. FOR UPDATE prevents
    // a concurrent purge from deleting it while we decide.
    let row = sqlx::query!(
        r#"SELECT i.archived_at, i.parent_id,
                  o.subagent_archive_retention_days
           FROM identities i JOIN orgs o ON i.org_id = o.id
           WHERE i.id = $1 AND i.org_id = $2
           FOR UPDATE OF i"#,
        id,
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        tx.commit().await?;
        return Ok(RestoreOutcome::NotFound);
    };

    let Some(archived_at) = row.archived_at else {
        tx.commit().await?;
        return Ok(RestoreOutcome::NotArchived);
    };

    let retention = time::Duration::days(row.subagent_archive_retention_days as i64);
    if OffsetDateTime::now_utc() - archived_at > retention {
        tx.commit().await?;
        return Ok(RestoreOutcome::PastRetention);
    }

    // Lock the parent row (if any) and verify it's not archived. The lock
    // blocks a concurrent archive_idle_subagents pass from sneaking in between
    // this check and our UPDATE below.
    if let Some(parent_id) = row.parent_id {
        let parent = sqlx::query_scalar!(
            "SELECT archived_at FROM identities WHERE id = $1 FOR UPDATE",
            parent_id,
        )
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(Some(_parent_archived_at)) = parent {
            tx.commit().await?;
            return Ok(RestoreOutcome::ParentArchived);
        }
    }

    // Unarchive
    let identity = sqlx::query_as!(
        IdentityRow,
        "UPDATE identities
         SET archived_at = NULL, archived_reason = NULL, last_active_at = now(), updated_at = now()
         WHERE id = $1
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at",
        id,
    )
    .fetch_one(&mut *tx)
    .await?;

    // Resurrect any keys we revoked during archive (manually-revoked keys untouched)
    let api_keys_resurrected = super::api_key::unrevoke_by_identity_id_and_reason(
        &mut *tx,
        id,
        super::api_key::REVOKED_REASON_IDENTITY_ARCHIVED,
    )
    .await?;

    tx.commit().await?;
    Ok(RestoreOutcome::Restored {
        identity: Box::new(identity),
        api_keys_resurrected,
    })
}
