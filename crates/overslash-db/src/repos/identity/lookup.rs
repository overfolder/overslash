use sqlx::PgPool;
use uuid::Uuid;

use super::IdentityRow;

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

/// Cross-org list of *pending invitations* addressed to `email` — the
/// invitee-side counterpart of `routes/org_invites.rs`'s admin listing.
/// Surfaced on `SystemScope::list_pending_invitations_for_email`.
///
/// "Pending" is the never-joined predicate: `external_id IS NULL` (no IdP
/// subject has ever claimed the row) *and* `user_id IS NULL` (no human is
/// attached). Both are needed — an invite accepted in-app links a user
/// without ever minting an `external_id` for that org.
///
/// Identities auto-created as a side effect of name-based impersonation are
/// excluded: nobody invited that person, so surfacing the org to them would
/// leak its existence. Same rule as `org_invites::is_pending_invite`.
///
/// Case-insensitive, matching `find_user_by_email_in_org` — `identities.email`
/// carries no lower-case CHECK, so historical rows can be mixed-case.
pub(crate) async fn list_pending_invites_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Vec<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at
         FROM identities
         WHERE kind = 'user' AND lower(email) = lower($1)
           AND archived_at IS NULL
           AND external_id IS NULL
           AND user_id IS NULL
           AND metadata->>'provisioned_by' IS DISTINCT FROM 'impersonation'
         ORDER BY created_at ASC",
        email,
    )
    .fetch_all(pool)
    .await
}

/// Look up a live user-kind identity by email **within one org**. Backs both
/// name-based impersonation (`X-Overslash-As: alice@acme.com`) and the
/// adopt-by-email branch of the login path, which is what makes a
/// pre-created identity and a first sign-in converge on the same row.
///
/// Case-insensitive on both sides: `identities.email` has no lower-case
/// CHECK (unlike the old `org_invites.email`), so historical rows can carry
/// mixed casing. Archived rows are excluded — an archived member must be
/// restored deliberately, not silently reanimated by an inbound header.
///
/// `created_at ASC` makes the pick deterministic: migration 043 dropped the
/// uniqueness of `(org_id, email)`, so duplicates can exist and the oldest
/// row is the one carrying the history.
pub async fn find_user_by_email_in_org(
    pool: &PgPool,
    org_id: Uuid,
    email: &str,
) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at
         FROM identities
         WHERE org_id = $1 AND kind = 'user' AND lower(email) = lower($2)
           AND archived_at IS NULL
         ORDER BY created_at ASC
         LIMIT 1",
        org_id,
        email,
    )
    .fetch_optional(pool)
    .await
}

/// Look up a live child identity by name under `parent_id`. Backs the agent
/// path segments of an `X-Overslash-As` target (`alice@acme.com/henry/...`).
///
/// Names are not unique among siblings, so this resolves to the oldest live
/// match rather than erroring — a caller naming `henry` twice must land on
/// the same agent every time, and the oldest row is the one that accumulated
/// the permissions and audit history.
pub async fn find_child_by_name(
    pool: &PgPool,
    org_id: Uuid,
    parent_id: Uuid,
    name: &str,
) -> Result<Option<IdentityRow>, sqlx::Error> {
    sqlx::query_as!(
        IdentityRow,
        "SELECT id, org_id, name, kind, external_id, email, metadata, parent_id, depth, owner_id, inherit_permissions, last_active_at, archived_at, archived_reason, preferences, is_org_admin, user_id, auto_call_on_approve, created_at, updated_at
         FROM identities
         WHERE org_id = $1 AND parent_id = $2 AND name = $3
           AND archived_at IS NULL
         ORDER BY created_at ASC
         LIMIT 1",
        org_id,
        parent_id,
        name,
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
/// pair. At most one row exists — `identities_org_user_unique`, the partial
/// UNIQUE migration 040 was designed around and 115 finally created. Used by
/// the multi-org switch flow to resolve `sub` for the new JWT.
///
/// The bound matters: this is `fetch_optional`, which takes the first row and
/// discards the rest, so duplicates would not surface as an error here — they
/// would quietly make the caller's answer depend on planner order.
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
