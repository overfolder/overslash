//! Instance-wide reads and writes behind the Instance Admin panel (`/instance`).
//!
//! Everything here crosses org boundaries on purpose, so every caller must be
//! gated by `InstanceAdminAuth`. The org listing returns tenancy and billing
//! facts only (plan, trial, member count, activity) and never anything inside
//! an org: no secrets, connections, approvals or member identities.

use sqlx::{PgConnection, PgPool};
use time::OffsetDateTime;
use uuid::Uuid;

// ── Orgs ────────────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
pub struct InstanceOrgRow {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub plan: String,
    pub trial_ends_at: Option<OffsetDateTime>,
    pub is_personal: bool,
    pub created_at: OffsetDateTime,
    pub member_count: i64,
    /// Latest of any member's session activity and any API key use in the org.
    pub last_activity_at: Option<OffsetDateTime>,
}

/// Every org on the instance, newest first. Personal orgs are left out unless
/// `include_personal`: on a cloud instance they outnumber team orgs by far and
/// are never billed, so the panel hides them by default.
pub async fn list_orgs(
    pool: &PgPool,
    include_personal: bool,
) -> Result<Vec<InstanceOrgRow>, sqlx::Error> {
    sqlx::query_as!(
        InstanceOrgRow,
        r#"SELECT o.id, o.name, o.slug, o.plan, o.trial_ends_at, o.is_personal, o.created_at,
                  (SELECT COUNT(*) FROM user_org_memberships m WHERE m.org_id = o.id) AS "member_count!",
                  GREATEST(
                      (SELECT MAX(s.last_seen_at) FROM user_sessions s WHERE s.org_id = o.id),
                      (SELECT MAX(k.last_used_at) FROM api_keys k WHERE k.org_id = o.id)
                  ) AS last_activity_at
             FROM orgs o
            WHERE $1 OR NOT o.is_personal
            ORDER BY o.created_at DESC, o.id"#,
        include_personal,
    )
    .fetch_all(pool)
    .await
}

// ── Instance admins ─────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
pub struct InstanceAdminRow {
    pub user_id: Uuid,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub overslash_idp_provider: Option<String>,
    /// NULL = granted out-of-band (psql bootstrap, or before migration 140).
    pub granted_at: Option<OffsetDateTime>,
    pub granted_by_email: Option<String>,
    pub last_seen_at: Option<OffsetDateTime>,
}

pub async fn list_admins(pool: &PgPool) -> Result<Vec<InstanceAdminRow>, sqlx::Error> {
    sqlx::query_as!(
        InstanceAdminRow,
        r#"SELECT u.id AS user_id, u.email, u.display_name, u.overslash_idp_provider,
                  u.instance_admin_granted_at AS granted_at,
                  g.email AS "granted_by_email?",
                  (SELECT MAX(s.last_seen_at) FROM user_sessions s WHERE s.user_id = u.id) AS last_seen_at
             FROM users u
             LEFT JOIN users g ON g.id = u.instance_admin_granted_by
            WHERE u.is_instance_admin
            ORDER BY u.instance_admin_granted_at NULLS FIRST, u.created_at"#,
    )
    .fetch_all(pool)
    .await
}

#[derive(Debug, sqlx::FromRow)]
pub struct UserSearchRow {
    pub id: Uuid,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub overslash_idp_provider: Option<String>,
    pub is_instance_admin: bool,
    /// One org the user belongs to, for the "signs in only through X" reason
    /// shown next to an org-only (ineligible) user.
    pub any_org_name: Option<String>,
}

/// Case-insensitive substring search over email and display name. `q` is
/// matched literally: LIKE wildcards in it are escaped.
pub async fn search_users(
    pool: &PgPool,
    q: &str,
    limit: i64,
) -> Result<Vec<UserSearchRow>, sqlx::Error> {
    let escaped = q
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let pattern = format!("%{escaped}%");
    sqlx::query_as!(
        UserSearchRow,
        r#"SELECT u.id, u.email, u.display_name, u.overslash_idp_provider, u.is_instance_admin,
                  (SELECT o.name FROM user_org_memberships m JOIN orgs o ON o.id = m.org_id
                    WHERE m.user_id = u.id AND NOT o.is_personal
                    ORDER BY m.created_at LIMIT 1) AS "any_org_name?"
             FROM users u
            WHERE u.email ILIKE $1 OR u.display_name ILIKE $1
            ORDER BY (u.overslash_idp_provider IS NULL), u.email
            LIMIT $2"#,
        pattern,
        limit,
    )
    .fetch_all(pool)
    .await
}

#[derive(Debug, PartialEq, Eq)]
pub enum GrantOutcome {
    Granted,
    AlreadyAdmin,
    NotFound,
    /// The user has no root-domain (Overslash IdP) login, so the
    /// `users_instance_admin_requires_overslash_idp` CHECK forbids the flag.
    NotEligible,
}

pub async fn grant(
    conn: &mut PgConnection,
    user_id: Uuid,
    granted_by: Uuid,
) -> Result<GrantOutcome, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT is_instance_admin, overslash_idp_provider FROM users WHERE id = $1 FOR UPDATE",
        user_id,
    )
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        return Ok(GrantOutcome::NotFound);
    };
    if row.is_instance_admin {
        return Ok(GrantOutcome::AlreadyAdmin);
    }
    if row.overslash_idp_provider.is_none() {
        return Ok(GrantOutcome::NotEligible);
    }
    sqlx::query!(
        "UPDATE users
            SET is_instance_admin = true,
                instance_admin_granted_at = now(),
                instance_admin_granted_by = $2,
                updated_at = now()
          WHERE id = $1",
        user_id,
        granted_by,
    )
    .execute(&mut *conn)
    .await?;
    Ok(GrantOutcome::Granted)
}

#[derive(Debug, PartialEq, Eq)]
pub enum RevokeOutcome {
    Revoked,
    NotAdmin,
    /// Revoking would leave the instance with no admin at all.
    LastAdmin,
}

/// Clear the flag unless the user is the last instance admin. Every admin row
/// is locked first, so two admins revoking each other at once can't both
/// pass the count check and leave the instance with none.
pub async fn revoke(conn: &mut PgConnection, user_id: Uuid) -> Result<RevokeOutcome, sqlx::Error> {
    let admins: Vec<Uuid> =
        sqlx::query_scalar!("SELECT id FROM users WHERE is_instance_admin ORDER BY id FOR UPDATE")
            .fetch_all(&mut *conn)
            .await?;
    if !admins.contains(&user_id) {
        return Ok(RevokeOutcome::NotAdmin);
    }
    if admins.len() <= 1 {
        return Ok(RevokeOutcome::LastAdmin);
    }
    sqlx::query!(
        "UPDATE users
            SET is_instance_admin = false,
                instance_admin_granted_at = NULL,
                instance_admin_granted_by = NULL,
                updated_at = now()
          WHERE id = $1",
        user_id,
    )
    .execute(&mut *conn)
    .await?;
    Ok(RevokeOutcome::Revoked)
}

// ── Instance audit ──────────────────────────────────────────────────────

pub struct InstanceAuditEntry<'a> {
    pub actor_user_id: Uuid,
    pub action: &'a str,
    /// The org acted on, if any. Its slug is snapshotted at write time.
    pub org_id: Option<Uuid>,
    pub detail: serde_json::Value,
    pub ip_address: Option<&'a str>,
}

/// Write one instance-audit row. The actor's email and the org's slug are
/// resolved inside the INSERT so the row keeps them after either is deleted.
pub async fn log<'e, E>(executor: E, entry: &InstanceAuditEntry<'_>) -> Result<(), sqlx::Error>
where
    E: sqlx::PgExecutor<'e>,
{
    sqlx::query!(
        "INSERT INTO instance_audit_log (actor_user_id, actor_email, action, org_id, org_slug, detail, ip_address)
         SELECT $1,
                COALESCE((SELECT email FROM users WHERE id = $1), ''),
                $2, $3,
                (SELECT slug FROM orgs WHERE id = $3),
                $4, $5",
        entry.actor_user_id,
        entry.action,
        entry.org_id,
        entry.detail,
        entry.ip_address,
    )
    .execute(executor)
    .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct InstanceAuditRow {
    pub id: Uuid,
    pub actor_user_id: Option<Uuid>,
    pub actor_email: String,
    pub action: String,
    pub org_id: Option<Uuid>,
    pub org_slug: Option<String>,
    pub detail: serde_json::Value,
    pub ip_address: Option<String>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Default, Clone)]
pub struct InstanceAuditFilter {
    /// Exact actor email, case-insensitive.
    pub admin: Option<String>,
    /// Exact action name.
    pub action: Option<String>,
    /// Exact org slug (as recorded at write time).
    pub org: Option<String>,
    /// Keyset cursor: rows strictly older than `(created_at, id)`.
    pub before: Option<(OffsetDateTime, Uuid)>,
    /// Inclusive lower bound on `created_at`.
    pub since: Option<OffsetDateTime>,
    /// Exclusive upper bound on `created_at`.
    pub until: Option<OffsetDateTime>,
}

pub async fn list_audit(
    pool: &PgPool,
    filter: &InstanceAuditFilter,
    limit: i64,
) -> Result<Vec<InstanceAuditRow>, sqlx::Error> {
    let (before_at, before_id) = filter.before.unzip();
    sqlx::query_as!(
        InstanceAuditRow,
        "SELECT id, actor_user_id, actor_email, action, org_id, org_slug, detail, ip_address, created_at
           FROM instance_audit_log
          WHERE ($1::text IS NULL OR lower(actor_email) = lower($1))
            AND ($2::text IS NULL OR action = $2)
            AND ($3::text IS NULL OR org_slug = $3)
            AND ($4::timestamptz IS NULL OR (created_at, id) < ($4, $5::uuid))
            AND ($6::timestamptz IS NULL OR created_at >= $6)
            AND ($7::timestamptz IS NULL OR created_at < $7)
          ORDER BY created_at DESC, id DESC
          LIMIT $8",
        filter.admin.as_deref(),
        filter.action.as_deref(),
        filter.org.as_deref(),
        before_at,
        before_id,
        filter.since,
        filter.until,
        limit,
    )
    .fetch_all(pool)
    .await
}
