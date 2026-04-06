use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Reason an identity was archived. Stored in `archived_reason`.
pub const ARCHIVED_REASON_IDLE_TIMEOUT: &str = "idle_timeout";

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
    sqlx::query_as!(
        IdentityRow,
        "INSERT INTO identities (org_id, name, kind, external_id) VALUES ($1, $2, $3, $4)
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, created_at, updated_at",
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
        "INSERT INTO identities (org_id, name, kind, external_id, email, metadata)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, created_at, updated_at",
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
) -> Result<IdentityRow, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "INSERT INTO identities (org_id, name, kind, external_id, parent_id, depth, owner_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, created_at, updated_at",
        org_id,
        name,
        kind,
        external_id,
        parent_id,
        depth,
        owner_id,
    )
    .fetch_one(pool)
    .await
}

pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, created_at, updated_at
         FROM identities WHERE email = $1 AND kind = 'user'",
        email,
    )
    .fetch_optional(pool)
    .await
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, created_at, updated_at
         FROM identities WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn count_by_org(pool: &PgPool, org_id: Uuid) -> Result<i64, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT COUNT(*) AS count FROM identities WHERE org_id = $1",
        org_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.count.unwrap_or(0))
}

pub async fn list_by_org(pool: &PgPool, org_id: Uuid) -> Result<Vec<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, created_at, updated_at
         FROM identities WHERE org_id = $1 ORDER BY created_at",
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn list_children(
    pool: &PgPool,
    parent_id: Uuid,
) -> Result<Vec<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, created_at, updated_at
         FROM identities WHERE parent_id = $1 ORDER BY created_at",
        parent_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_ancestor_chain(
    pool: &PgPool,
    identity_id: Uuid,
) -> Result<Vec<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        r#"WITH RECURSIVE chain AS (
            SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, created_at, updated_at,
                   1 AS _depth
            FROM identities WHERE id = $1
            UNION ALL
            SELECT i.id, i.org_id, i.name, i.kind, i.external_id, i.email, i.metadata,
                   i.parent_id, i.depth, i.owner_id, i.inherit_permissions,
                   i.last_active_at, i.archived_at, i.archived_reason,
                   i.created_at, i.updated_at, c._depth + 1
            FROM identities i
            INNER JOIN chain c ON i.id = c.parent_id
            WHERE c._depth < 50
        )
        SELECT id as "id!", org_id as "org_id!", name as "name!", kind as "kind!",
               external_id, email, metadata as "metadata!",
               parent_id, depth as "depth!", owner_id,
               inherit_permissions as "inherit_permissions!",
               last_active_at as "last_active_at!",
               archived_at, archived_reason,
               created_at as "created_at!", updated_at as "updated_at!"
        FROM chain ORDER BY depth ASC"#,
        identity_id,
    )
    .fetch_all(pool)
    .await
}

pub async fn get_names_by_ids(
    pool: &PgPool,
    ids: &[Uuid],
) -> Result<Vec<(Uuid, String)>, sqlx::Error> {
    let rows = sqlx::query!("SELECT id, name FROM identities WHERE id = ANY($1)", ids,)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|r| (r.id, r.name)).collect())
}

/// Update an identity's profile (name, metadata) on subsequent login.
pub async fn update_profile(
    pool: &PgPool,
    id: Uuid,
    name: &str,
    metadata: serde_json::Value,
) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "UPDATE identities SET name = $2, metadata = $3, updated_at = now() WHERE id = $1
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, created_at, updated_at",
        id,
        name,
        metadata,
    )
    .fetch_optional(pool)
    .await
}

pub async fn set_inherit_permissions(
    pool: &PgPool,
    id: Uuid,
    inherit: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE identities SET inherit_permissions = $2, updated_at = now() WHERE id = $1",
        id,
        inherit,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn delete(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!("DELETE FROM identities WHERE id = $1", id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Stamp `last_active_at = now()` for a sub-agent. Used by the auth middleware
/// after each authenticated request to keep idle-cleanup tracking current.
/// Returns Ok(()) even if the row doesn't exist or is already archived; this
/// is fire-and-forget and shouldn't surface errors to the request path.
pub async fn touch_last_active(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE identities SET last_active_at = now() WHERE id = $1 AND archived_at IS NULL",
        id,
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
    /// Identity does not exist (or wrong org).
    NotFound,
}

/// Restore an archived sub-agent and resurrect its auto-revoked API keys.
/// Only works if the identity is still within the org's retention window.
pub async fn restore(pool: &PgPool, id: Uuid) -> Result<RestoreOutcome, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Look up the identity + its org's retention window in a single read
    let row = sqlx::query!(
        r#"SELECT i.archived_at,
                  o.subagent_archive_retention_days
           FROM identities i JOIN orgs o ON i.org_id = o.id
           WHERE i.id = $1"#,
        id,
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

    // Unarchive
    let identity = sqlx::query_as!(
        IdentityRow,
        "UPDATE identities
         SET archived_at = NULL, archived_reason = NULL, last_active_at = now(), updated_at = now()
         WHERE id = $1
         RETURNING id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, created_at, updated_at",
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
