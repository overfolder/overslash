use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::repos::api_key;

use super::{ARCHIVED_REASON_IDLE_TIMEOUT, ARCHIVED_REASON_MANUAL, IdentityRow, MAX_TREE_DEPTH};

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

    api_key::revoke_by_identity_ids_with_reason(
        &mut *tx,
        &archived_ids,
        api_key::REVOKED_REASON_IDENTITY_ARCHIVED,
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

/// Outcome of an on-demand cascade archive.
pub struct ArchiveOutcome {
    /// The root identity row, reflecting the archived state (whether it was
    /// archived by this call or was already archived).
    pub identity: Box<IdentityRow>,
    /// Number of rows newly archived in this call (0 on an idempotent re-archive).
    pub archived_count: u64,
}

/// Cascade-archive an identity and its entire descendant subtree in one
/// transaction. Mirrors `archive_idle_subagents` (revoke keys + expire pending
/// approvals for everything archived), but:
///   - targets a single `id` plus all its descendants (recursive CTE over
///     `parent_id` within `org_id`), so we never leave a live child under an
///     archived parent (overfolder's cascade-delete semantics); and
///   - accepts ANY kind (user/agent/sub_agent) — overfolder archives user
///     identities too (e.g. on ghost-merge/delete).
///
/// Returns `Ok(None)` when `id` doesn't exist in this org (drives a 404).
/// Idempotent: re-archiving an already-archived root is a no-op success with
/// `archived_count: 0`.
///
/// No `FOR UPDATE` locks: archive is monotonic (only ever sets `archived_at`,
/// never clears it) and the `archived_at IS NULL` guard makes a double-archive a
/// no-op, so concurrent passes converge. The cascade is a snapshot of the
/// subtree at CTE-eval time (a child grafted on mid-transaction by `move_under`
/// is caught by the next archive call or the idle sweep, not this one).
///
/// Known asymmetry: `restore` is `sub_agent`-only and refuses to revive a child
/// under an archived parent, so a cascade-archived user/agent subtree cannot be
/// fully undone via the current `/restore` endpoint. Archive is one-way for
/// non-sub_agent subtrees; a symmetric "cascade restore" is future work.
pub(crate) async fn archive_identity(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    reason: Option<&str>,
) -> Result<Option<ArchiveOutcome>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let outcome = archive_identity_tx(&mut tx, org_id, id, reason).await?;
    tx.commit().await?;
    Ok(outcome)
}

/// Transaction-scoped body of [`archive_identity`]. Factored out so callers that
/// need to compose archiving with other writes in the same transaction (e.g.
/// `remove_user_from_org`, which also drops the org membership) can reuse the
/// cascade without nesting transactions. The caller owns the commit.
pub(crate) async fn archive_identity_tx(
    tx: &mut sqlx::PgConnection,
    org_id: Uuid,
    id: Uuid,
    reason: Option<&str>,
) -> Result<Option<ArchiveOutcome>, sqlx::Error> {
    // Collect the root + all descendants (root seeded at lvl 0 so it's always
    // included, even with no children). Bounded by MAX_TREE_DEPTH as a
    // defence-in-depth against a leftover cycle.
    let subtree_ids: Vec<Uuid> = sqlx::query_scalar!(
        r#"WITH RECURSIVE subtree(id, lvl) AS (
            SELECT id, 0 FROM identities WHERE id = $1 AND org_id = $2
            UNION ALL
            SELECT i.id, s.lvl + 1
            FROM identities i
            INNER JOIN subtree s ON i.parent_id = s.id
            WHERE i.org_id = $2 AND s.lvl < $3
        )
        SELECT id AS "id!" FROM subtree"#,
        id,
        org_id,
        MAX_TREE_DEPTH,
    )
    .fetch_all(&mut *tx)
    .await?;

    if subtree_ids.is_empty() {
        // Root id not found in this org.
        return Ok(None);
    }

    let archived_ids: Vec<Uuid> = sqlx::query_scalar!(
        r#"UPDATE identities
           SET archived_at = now(), archived_reason = $2, updated_at = now()
           WHERE id = ANY($1) AND archived_at IS NULL
           RETURNING id"#,
        &subtree_ids,
        reason,
    )
    .fetch_all(&mut *tx)
    .await?;

    if !archived_ids.is_empty() {
        api_key::revoke_by_identity_ids_with_reason(
            &mut *tx,
            &archived_ids,
            api_key::REVOKED_REASON_IDENTITY_ARCHIVED,
        )
        .await?;

        sqlx::query!(
            "UPDATE approvals SET status = 'expired', resolved_at = now(), resolved_by = 'system'
             WHERE identity_id = ANY($1) AND status = 'pending'",
            &archived_ids,
        )
        .execute(&mut *tx)
        .await?;
    }

    // Re-read the root inside the tx so the returned row reflects the archived
    // state in both the just-archived and already-archived cases.
    let root = sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at
         FROM identities WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_one(&mut *tx)
    .await?;

    Ok(Some(ArchiveOutcome {
        identity: Box::new(root),
        archived_count: archived_ids.len() as u64,
    }))
}

/// Outcome of an admin attempt to remove a human user from an org.
pub enum RemoveUserOutcome {
    /// User evicted: subtree archived, membership dropped, identity detached.
    Removed {
        user_id: Uuid,
        archived_count: u64,
        was_admin: bool,
    },
    /// No identity with this id in this org.
    NotFound,
    /// The target identity isn't a user-kind identity (or has no linked user).
    NotApplicable,
    /// The target is the org's only admin; removing them would orphan the org.
    LastAdmin,
}

/// Remove a human user from an org: cascade-archive their identity subtree
/// (revoking API keys + expiring approvals via [`archive_identity_tx`]), drop
/// the `user_org_memberships` row, and detach the archived identity from the
/// user so the `(org_id, user_id)` slot frees up for a future re-invite.
///
/// All in one transaction so a half-removal (membership gone but identity still
/// live, or vice-versa) can never commit — the codebase treats "membership
/// without a matching live user identity" as an invariant violation.
///
/// Locks the org's admin membership rows in `user_id` order (deterministic, so
/// concurrent removals serialise instead of deadlocking) and refuses to remove
/// the last admin. The caller (route layer) separately refuses self-removal.
pub(crate) async fn remove_user_from_org(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<RemoveUserOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Lock the target row first for a clean existence/kind check.
    let target = sqlx::query!(
        "SELECT kind, user_id FROM identities WHERE id = $1 AND org_id = $2 FOR UPDATE",
        id,
        org_id,
    )
    .fetch_optional(&mut *tx)
    .await?;

    let Some(target) = target else {
        return Ok(RemoveUserOutcome::NotFound);
    };
    if target.kind != "user" {
        return Ok(RemoveUserOutcome::NotApplicable);
    }
    let Some(user_id) = target.user_id else {
        return Ok(RemoveUserOutcome::NotApplicable);
    };

    // Lock all admin rows in deterministic order; guard the last admin.
    let admin_user_ids: Vec<Uuid> = sqlx::query_scalar!(
        "SELECT user_id FROM user_org_memberships
         WHERE org_id = $1 AND role = 'admin'
         ORDER BY user_id FOR UPDATE",
        org_id,
    )
    .fetch_all(&mut *tx)
    .await?;

    let was_admin = admin_user_ids.contains(&user_id);
    if was_admin && admin_user_ids.len() <= 1 {
        return Ok(RemoveUserOutcome::LastAdmin);
    }

    // Cascade-archive the subtree (revokes keys, expires approvals).
    let outcome = archive_identity_tx(&mut tx, org_id, id, Some(ARCHIVED_REASON_MANUAL)).await?;
    let archived_count = outcome.map(|o| o.archived_count).unwrap_or(0);

    // Drop the org membership.
    sqlx::query!(
        "DELETE FROM user_org_memberships WHERE user_id = $1 AND org_id = $2",
        user_id,
        org_id,
    )
    .execute(&mut *tx)
    .await?;

    // Detach the archived identity from the user so the partial unique index
    // `(org_id, user_id) WHERE user_id IS NOT NULL AND kind = 'user'` no longer
    // holds the slot — otherwise re-inviting the same human into this org would
    // collide with this tombstone row.
    sqlx::query!(
        "UPDATE identities SET user_id = NULL, updated_at = now()
         WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(RemoveUserOutcome::Removed {
        user_id,
        archived_count,
        was_admin,
    })
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
    let api_keys_resurrected = api_key::unrevoke_by_identity_id_and_reason(
        &mut *tx,
        id,
        api_key::REVOKED_REASON_IDENTITY_ARCHIVED,
    )
    .await?;

    tx.commit().await?;
    Ok(RestoreOutcome::Restored {
        identity: Box::new(identity),
        api_keys_resurrected,
    })
}
