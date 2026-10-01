//! `user_sessions` — one row per dashboard sign-in (migration 130).
//!
//! The session JWT's `jti` is this row's id. A session is live iff its row
//! exists, is unrevoked and is unexpired; the API checks that on every
//! request carrying a session cookie. Every revocation is an UPDATE that
//! returns the ids it touched, so the caller can drop them from the
//! validation cache.
//!
//! User-level, not org-level: one human's sessions span every org they
//! belong to, so these take a raw pool like `repos::user`.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

/// Why a session ended (`revoked_reason`).
pub mod reason {
    pub const LOGOUT: &str = "logout";
    pub const REPLACED: &str = "replaced";
    pub const TERMINATED: &str = "terminated";
    pub const TERMINATED_BY_OTHER: &str = "terminated_by_other_session";
    pub const IDENTITY_CHANGED: &str = "identity_changed";
    pub const MEMBER_REMOVED: &str = "member_removed";
    pub const IDENTITY_ARCHIVED: &str = "identity_archived";
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserSessionRow {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub identity_id: Uuid,
    pub org_id: Uuid,
    pub created_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub revoked_reason: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

impl UserSessionRow {
    pub fn is_live(&self, now: OffsetDateTime) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// A live session as the account page lists it, with its org's display name.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserSessionListing {
    pub id: Uuid,
    pub org_id: Uuid,
    pub org_name: String,
    pub created_at: OffsetDateTime,
    pub last_seen_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}

pub struct NewUserSession<'a> {
    pub user_id: Option<Uuid>,
    pub identity_id: Uuid,
    pub org_id: Uuid,
    pub ttl_secs: i64,
    pub user_agent: Option<&'a str>,
    pub ip_address: Option<&'a str>,
}

pub async fn create(pool: &PgPool, s: NewUserSession<'_>) -> Result<UserSessionRow, sqlx::Error> {
    sqlx::query_as!(
        UserSessionRow,
        "INSERT INTO user_sessions
            (user_id, identity_id, org_id, expires_at, user_agent, ip_address)
         VALUES ($1, $2, $3, now() + make_interval(secs => $4), $5, $6)
         RETURNING id, user_id, identity_id, org_id, created_at, last_seen_at,
                   expires_at, revoked_at, revoked_reason, user_agent, ip_address",
        s.user_id,
        s.identity_id,
        s.org_id,
        s.ttl_secs as f64,
        s.user_agent,
        s.ip_address,
    )
    .fetch_one(pool)
    .await
}

pub async fn get(pool: &PgPool, id: Uuid) -> Result<Option<UserSessionRow>, sqlx::Error> {
    sqlx::query_as!(
        UserSessionRow,
        "SELECT id, user_id, identity_id, org_id, created_at, last_seen_at,
                expires_at, revoked_at, revoked_reason, user_agent, ip_address
         FROM user_sessions WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Point a live session at another org/identity of the same human (switch
/// org, org creation, consent re-scope) and restart its lifetime, as the
/// fresh cookie does. `None` when the row is not live or belongs to someone
/// else — the caller then starts a new session instead.
pub async fn rescope(
    pool: &PgPool,
    id: Uuid,
    user_id: Uuid,
    identity_id: Uuid,
    org_id: Uuid,
    ttl_secs: i64,
) -> Result<Option<UserSessionRow>, sqlx::Error> {
    sqlx::query_as!(
        UserSessionRow,
        "UPDATE user_sessions
         SET identity_id = $3, org_id = $4, last_seen_at = now(),
             expires_at = now() + make_interval(secs => $5)
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now()
         RETURNING id, user_id, identity_id, org_id, created_at, last_seen_at,
                   expires_at, revoked_at, revoked_reason, user_agent, ip_address",
        id,
        user_id,
        identity_id,
        org_id,
        ttl_secs as f64,
    )
    .fetch_optional(pool)
    .await
}

pub async fn touch(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE user_sessions SET last_seen_at = now() WHERE id = $1",
        id
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Live sessions of one human, newest activity first.
pub async fn list_live_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<UserSessionListing>, sqlx::Error> {
    sqlx::query_as!(
        UserSessionListing,
        "SELECT s.id, s.org_id, o.name AS org_name, s.created_at, s.last_seen_at,
                s.expires_at, s.user_agent, s.ip_address
         FROM user_sessions s JOIN orgs o ON o.id = s.org_id
         WHERE s.user_id = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
         ORDER BY s.last_seen_at DESC, s.created_at DESC",
        user_id,
    )
    .fetch_all(pool)
    .await
}

/// Revoke one session. `owner` restricts it to that human's sessions (the
/// self-service path); `None` is the server-side path (logout, replace).
/// Returns whether a live row was revoked.
pub async fn revoke(
    pool: &PgPool,
    id: Uuid,
    owner: Option<Uuid>,
    reason: &str,
) -> Result<bool, sqlx::Error> {
    let n = sqlx::query!(
        "UPDATE user_sessions SET revoked_at = now(), revoked_reason = $3
         WHERE id = $1 AND revoked_at IS NULL
           AND ($2::uuid IS NULL OR user_id = $2)",
        id,
        owner,
        reason,
    )
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Revoke every live session of a human, optionally sparing one (the
/// caller's own, for "terminate all other sessions"). Returns the revoked ids.
pub async fn revoke_all_for_user(
    pool: &PgPool,
    user_id: Uuid,
    except: Option<Uuid>,
    reason: &str,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar!(
        "UPDATE user_sessions SET revoked_at = now(), revoked_reason = $3
         WHERE user_id = $1 AND revoked_at IS NULL
           AND ($2::uuid IS NULL OR id <> $2)
         RETURNING id",
        user_id,
        except,
        reason,
    )
    .fetch_all(pool)
    .await
}

/// Revoke every live session currently scoped to one of `identity_ids` in
/// `org_id` — an admin removing or archiving a member. Sessions the same
/// human holds in other orgs are not this org's to end. Returns the revoked
/// ids.
///
/// Takes any executor so a state change can revoke inside its own
/// transaction: an admin removal or email rewrite that commits without its
/// revocation would, on retry, find nothing left to trigger one.
pub async fn revoke_for_identities<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    org_id: Uuid,
    identity_ids: &[Uuid],
    reason: &str,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar!(
        "UPDATE user_sessions SET revoked_at = now(), revoked_reason = $3
         WHERE org_id = $1 AND identity_id = ANY($2) AND revoked_at IS NULL
         RETURNING id",
        org_id,
        identity_ids,
        reason,
    )
    .fetch_all(executor)
    .await
}

/// Every session id (live or not) ever scoped to one of `identity_ids` in
/// `org_id` — what to evict from the validation cache after a revocation that
/// ran inside someone else's transaction.
pub async fn ids_for_identities(
    pool: &PgPool,
    org_id: Uuid,
    identity_ids: &[Uuid],
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar!(
        "SELECT id FROM user_sessions WHERE org_id = $1 AND identity_id = ANY($2)",
        org_id,
        identity_ids,
    )
    .fetch_all(pool)
    .await
}

/// Delete rows that stopped mattering `retention_secs` ago (expired or
/// revoked). Kept that long so the audit trail's session ids still resolve.
pub async fn purge_stale(pool: &PgPool, retention_secs: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query!(
        "DELETE FROM user_sessions
         WHERE LEAST(revoked_at, expires_at) < now() - make_interval(secs => $1)",
        retention_secs as f64,
    )
    .execute(pool)
    .await?
    .rows_affected())
}
