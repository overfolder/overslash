use sqlx::PgPool;
use uuid::Uuid;

use super::{IdentityRow, MAX_TREE_DEPTH};

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
