//! Directory groups: what an external directory says exists, what it says
//! about a human, and the admin-owned edge that turns the second into Layer 1
//! group membership.
//!
//! The three tables are deliberately separate from `groups` / `identity_groups`.
//! A directory group is not a ceiling — it carries no grants, no rate limit
//! and no service visibility — and keeping sync-owned membership in its own
//! table is what lets [`replace_memberships_for_identity`] reconcile
//! *authoritatively* without ever being able to touch an assignment an admin
//! made by hand. See `docs/design/directory-group-sync.md`.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// A group as an external directory reports it.
pub struct DirectoryGroupRow {
    pub id: Uuid,
    pub org_id: Uuid,
    /// The IdP config whose login produced this row. `None` for sources that
    /// do not ride a login (Google Admin SDK, SCIM) once those land.
    pub idp_config_id: Option<Uuid>,
    /// `'oidc_claim'` today; widened as new sources arrive.
    pub source: String,
    /// The claim value, verbatim — a name from Okta, an object GUID from Entra.
    pub external_id: String,
    /// Last label seen. Equals `external_id` for a bare-string claim.
    pub display_name: String,
    pub first_seen_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
}

/// A directory group plus the counts the dashboard lists it with.
pub struct DirectoryGroupSummaryRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub idp_config_id: Option<Uuid>,
    pub source: String,
    pub external_id: String,
    pub display_name: String,
    pub first_seen_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    /// Humans the directory currently places in this group.
    pub member_count: i64,
    /// Overslash groups this directory group currently feeds.
    pub mapped_group_ids: Vec<Uuid>,
}

/// One member of a group, tagged with how they got there.
pub struct GroupMemberOriginRow {
    pub identity_id: Uuid,
    /// `true` when an `identity_groups` row exists — an admin put them here.
    pub direct: bool,
    /// The directory groups routing this human into the group. Empty when the
    /// membership is purely manual.
    pub via_directory_group_ids: Vec<Uuid>,
}

// ── Directory groups ─────────────────────────────────────────────────

/// Record that `external_id` exists, refreshing its label and `last_seen_at`.
///
/// Idempotent: a login that reports the same groups again is a no-op beyond
/// the timestamp, which is what makes it safe to call on every sign-in.
pub(crate) async fn upsert(
    pool: &PgPool,
    org_id: Uuid,
    idp_config_id: Option<Uuid>,
    source: &str,
    external_id: &str,
    display_name: &str,
) -> Result<DirectoryGroupRow, sqlx::Error> {
    sqlx::query_as!(
        DirectoryGroupRow,
        "INSERT INTO directory_groups
             (org_id, idp_config_id, source, external_id, display_name)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (org_id, source, external_id) DO UPDATE
             SET display_name = EXCLUDED.display_name,
                 idp_config_id = EXCLUDED.idp_config_id,
                 last_seen_at = now()
         RETURNING id, org_id, idp_config_id, source, external_id, display_name,
                   first_seen_at, last_seen_at",
        org_id,
        idp_config_id,
        source,
        external_id,
        display_name,
    )
    .fetch_one(pool)
    .await
}

/// Every directory group discovered in this org, with member and mapping counts.
pub(crate) async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<DirectoryGroupSummaryRow>, sqlx::Error> {
    sqlx::query_as!(
        DirectoryGroupSummaryRow,
        r#"SELECT dg.id, dg.org_id, dg.idp_config_id, dg.source, dg.external_id,
                  dg.display_name, dg.first_seen_at, dg.last_seen_at,
                  (SELECT count(*) FROM identity_directory_groups idg
                    WHERE idg.directory_group_id = dg.id) AS "member_count!",
                  COALESCE(
                      (SELECT array_agg(gds.group_id)
                         FROM group_directory_sources gds
                        WHERE gds.directory_group_id = dg.id),
                      '{}'
                  ) AS "mapped_group_ids!"
             FROM directory_groups dg
            WHERE dg.org_id = $1
            ORDER BY dg.display_name"#,
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// Look up a directory group by id, bounded to this org.
pub(crate) async fn get_by_id(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<Option<DirectoryGroupRow>, sqlx::Error> {
    sqlx::query_as!(
        DirectoryGroupRow,
        "SELECT id, org_id, idp_config_id, source, external_id, display_name,
                first_seen_at, last_seen_at
           FROM directory_groups WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

// ── Sync-owned membership ────────────────────────────────────────────

/// Reconcile one identity's directory membership to exactly `directory_group_ids`.
///
/// Authoritative, and scoped two ways so that authority stays narrow:
///
/// * **By table.** It writes only `identity_directory_groups`, so no manual
///   `identity_groups` assignment is reachable from here at all.
/// * **By source.** Deletions are confined to rows whose directory group
///   carries this `(idp_config_id, source)` pair, so an org running two IdPs
///   does not have the second login revoke what the first established.
///
/// Returns `(added, removed)` directory group ids so the caller can decide
/// whether the login is worth an audit row.
pub(crate) async fn replace_memberships_for_identity(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    idp_config_id: Option<Uuid>,
    source: &str,
    directory_group_ids: &[Uuid],
) -> Result<(Vec<Uuid>, Vec<Uuid>), sqlx::Error> {
    let mut tx = pool.begin().await?;

    let removed = sqlx::query_scalar!(
        "DELETE FROM identity_directory_groups idg
          USING directory_groups dg
          WHERE idg.directory_group_id = dg.id
            AND idg.identity_id = $1
            AND dg.org_id = $2
            AND dg.source = $3
            AND dg.idp_config_id IS NOT DISTINCT FROM $4
            AND NOT (idg.directory_group_id = ANY($5))
          RETURNING idg.directory_group_id",
        identity_id,
        org_id,
        source,
        idp_config_id,
        directory_group_ids,
    )
    .fetch_all(&mut *tx)
    .await?;

    // `ON CONFLICT DO NOTHING` keeps `synced_at` as the moment the human first
    // entered the group, rather than resetting it on every login.
    let added = sqlx::query_scalar!(
        "INSERT INTO identity_directory_groups (identity_id, directory_group_id)
         SELECT $1, dg.id
           FROM directory_groups dg
          WHERE dg.id = ANY($2) AND dg.org_id = $3
         ON CONFLICT DO NOTHING
         RETURNING directory_group_id",
        identity_id,
        directory_group_ids,
        org_id,
    )
    .fetch_all(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok((added, removed))
}

// ── Admin-owned mapping ──────────────────────────────────────────────

/// Map a directory group into an Overslash group.
///
/// Both ids are checked against `org_id` in the SELECT that feeds the INSERT,
/// so a row id from another tenant inserts nothing and returns `false`.
/// Rejecting *system* groups is the handler's job — it is a policy rule, not a
/// tenancy one.
pub(crate) async fn add_source(
    pool: &PgPool,
    org_id: Uuid,
    group_id: Uuid,
    directory_group_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "INSERT INTO group_directory_sources (group_id, directory_group_id)
         SELECT g.id, dg.id
           FROM groups g
           JOIN directory_groups dg ON dg.id = $2 AND dg.org_id = $3
          WHERE g.id = $1 AND g.org_id = $3
         ON CONFLICT DO NOTHING",
        group_id,
        directory_group_id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Unmap a directory group. Revocation is immediate: the next ceiling read
/// stops traversing this edge.
pub(crate) async fn remove_source(
    pool: &PgPool,
    org_id: Uuid,
    group_id: Uuid,
    directory_group_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM group_directory_sources gds
          USING groups g
          WHERE gds.group_id = g.id
            AND gds.group_id = $1
            AND gds.directory_group_id = $2
            AND g.org_id = $3",
        group_id,
        directory_group_id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// The directory groups feeding one Overslash group.
pub(crate) async fn list_sources_for_group(
    pool: &PgPool,
    org_id: Uuid,
    group_id: Uuid,
) -> Result<Vec<DirectoryGroupRow>, sqlx::Error> {
    sqlx::query_as!(
        DirectoryGroupRow,
        "SELECT dg.id, dg.org_id, dg.idp_config_id, dg.source, dg.external_id,
                dg.display_name, dg.first_seen_at, dg.last_seen_at
           FROM directory_groups dg
           JOIN group_directory_sources gds ON gds.directory_group_id = dg.id
          WHERE gds.group_id = $1 AND dg.org_id = $2
          ORDER BY dg.display_name",
        group_id,
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// Members of a group, each tagged with whether they are there directly, via a
/// directory group, or both.
///
/// The dashboard needs the distinction to suppress "remove" on a derived row —
/// hand-removing someone the directory keeps asserting would silently reappear
/// at their next login.
pub(crate) async fn list_members_with_origin(
    pool: &PgPool,
    org_id: Uuid,
    group_id: Uuid,
) -> Result<Vec<GroupMemberOriginRow>, sqlx::Error> {
    sqlx::query_as!(
        GroupMemberOriginRow,
        r#"SELECT i.id AS "identity_id!",
                  bool_or(m.direct) AS "direct!",
                  COALESCE(
                      array_agg(m.directory_group_id)
                          FILTER (WHERE m.directory_group_id IS NOT NULL),
                      '{}'
                  ) AS "via_directory_group_ids!"
             FROM (
                 SELECT ig.identity_id, true AS direct, NULL::uuid AS directory_group_id
                   FROM identity_groups ig
                  WHERE ig.group_id = $1
                 UNION ALL
                 SELECT idg.identity_id, false AS direct, gds.directory_group_id
                   FROM group_directory_sources gds
                   JOIN identity_directory_groups idg
                     ON idg.directory_group_id = gds.directory_group_id
                  WHERE gds.group_id = $1
             ) m
             JOIN identities i ON i.id = m.identity_id AND i.org_id = $2
            GROUP BY i.id"#,
        group_id,
        org_id,
    )
    .fetch_all(pool)
    .await
}

/// `true` when this group's membership for `identity_id` comes only from a
/// directory — i.e. there is no `identity_groups` row to delete. The member
/// endpoint turns this into a 409 that points the admin at unmapping.
pub(crate) async fn membership_is_directory_only(
    pool: &PgPool,
    org_id: Uuid,
    group_id: Uuid,
    identity_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        r#"SELECT
              EXISTS (SELECT 1 FROM identity_groups ig
                       WHERE ig.group_id = $1 AND ig.identity_id = $2) AS "direct!",
              EXISTS (SELECT 1
                        FROM group_directory_sources gds
                        JOIN identity_directory_groups idg
                          ON idg.directory_group_id = gds.directory_group_id
                        JOIN identities i ON i.id = idg.identity_id AND i.org_id = $3
                       WHERE gds.group_id = $1 AND idg.identity_id = $2) AS "derived!""#,
        group_id,
        identity_id,
        org_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(!row.direct && row.derived)
}
