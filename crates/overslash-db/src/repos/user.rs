//! `users` — one row per human, independent of any org. PR 4 will start
//! populating `overslash_idp_provider`/`overslash_idp_subject` and
//! `personal_org_id` on login; for now the repo just models the schema.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct UserRow {
    pub id: Uuid,
    /// Last email the IdP returned for this user. Informational — NOT unique,
    /// never used as the lookup key at login time. See `docs/design/multi_org_auth.md`.
    pub email: Option<String>,
    pub display_name: Option<String>,
    /// `'google'`, `'github'`, etc. NULL for org-only users (those who only
    /// authenticate via a per-org IdP and have no root-domain login).
    pub overslash_idp_provider: Option<String>,
    /// The IdP's stable subject. NULL together with `overslash_idp_provider`.
    pub overslash_idp_subject: Option<String>,
    /// Set only for Overslash-backed users. A personal org is auto-created on
    /// first root-level login and is always 1-member.
    pub personal_org_id: Option<Uuid>,
    /// Operator-granted flag (set only via psql). The single elevated
    /// capability today is creating new orgs with `plan='free_unlimited'`
    /// via `POST /v1/orgs/free-unlimited`. A CHECK constraint requires
    /// `overslash_idp_provider IS NOT NULL` whenever this is true.
    pub is_instance_admin: bool,
    /// Stamped after the welcome / first-login email is successfully sent.
    /// Send sites gate on `IS NULL` so re-entered provisioning paths
    /// (corp-org returning member, second-IdP add) never double-send.
    pub welcome_email_sent_at: Option<OffsetDateTime>,
    /// `NULL` = subscribed to non-transactional email; non-null = unsubscribed.
    /// Set by the one-click unsubscribe link or the `/account` toggle. Billing
    /// (transactional) email ignores this column by policy.
    pub welcome_emails_unsubscribed_at: Option<OffsetDateTime>,
    /// Per-category opt-out for the daily webhook DLQ digest. Independent of
    /// `welcome_emails_unsubscribed_at` so opting out of the product welcome
    /// doesn't silence webhook failure alerts (and vice versa).
    pub webhook_digest_unsubscribed_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub async fn get_by_id(pool: &PgPool, id: Uuid) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as!(
        UserRow,
        "SELECT id, email, display_name, overslash_idp_provider, overslash_idp_subject, personal_org_id, is_instance_admin, welcome_email_sent_at, welcome_emails_unsubscribed_at, webhook_digest_unsubscribed_at, created_at, updated_at
         FROM users WHERE id = $1",
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Lightweight fetch used by the `InstanceAdminAuth` extractor on every
/// request that gates on the flag. Returns `false` when the user doesn't
/// exist (matches the extractor's "not an admin" semantics).
pub async fn is_instance_admin(pool: &PgPool, user_id: Uuid) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!("SELECT is_instance_admin FROM users WHERE id = $1", user_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.is_instance_admin).unwrap_or(false))
}

/// Operator-only setter, exposed for tests and any future internal tooling.
/// **No HTTP route uses this.** The CHECK constraint
/// `users_instance_admin_requires_overslash_idp` will reject the UPDATE if
/// the user has no `overslash_idp_provider`.
pub async fn set_instance_admin(
    pool: &PgPool,
    user_id: Uuid,
    flag: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE users SET is_instance_admin = $2, updated_at = now() WHERE id = $1",
        user_id,
        flag,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Primary auth-time lookup. Keyed on `(provider, subject)`, never on email —
/// email-based lookup would let an IdP vouch for a user it doesn't actually
/// control (see `DECISIONS.md` D12).
pub async fn find_by_overslash_idp(
    pool: &PgPool,
    provider: &str,
    subject: &str,
) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as!(
        UserRow,
        "SELECT id, email, display_name, overslash_idp_provider, overslash_idp_subject, personal_org_id, is_instance_admin, welcome_email_sent_at, welcome_emails_unsubscribed_at, webhook_digest_unsubscribed_at, created_at, updated_at
         FROM users
         WHERE overslash_idp_provider = $1 AND overslash_idp_subject = $2",
        provider,
        subject,
    )
    .fetch_optional(pool)
    .await
}

/// Create an Overslash-backed user row (has a root-level IdP binding and will
/// own a personal org once one is provisioned).
pub async fn create_overslash_backed(
    pool: &PgPool,
    email: Option<&str>,
    display_name: Option<&str>,
    provider: &str,
    subject: &str,
) -> Result<UserRow, sqlx::Error> {
    sqlx::query_as!(
        UserRow,
        "INSERT INTO users (email, display_name, overslash_idp_provider, overslash_idp_subject)
         VALUES ($1, $2, $3, $4)
         RETURNING id, email, display_name, overslash_idp_provider, overslash_idp_subject, personal_org_id, is_instance_admin, welcome_email_sent_at, welcome_emails_unsubscribed_at, webhook_digest_unsubscribed_at, created_at, updated_at",
        email,
        display_name,
        provider,
        subject,
    )
    .fetch_one(pool)
    .await
}

/// Create an org-only user row (only reachable through the identities of a
/// specific corp org; no root-level IdP binding, no personal org).
pub async fn create_org_only(
    pool: &PgPool,
    email: Option<&str>,
    display_name: Option<&str>,
) -> Result<UserRow, sqlx::Error> {
    sqlx::query_as!(
        UserRow,
        "INSERT INTO users (email, display_name)
         VALUES ($1, $2)
         RETURNING id, email, display_name, overslash_idp_provider, overslash_idp_subject, personal_org_id, is_instance_admin, welcome_email_sent_at, welcome_emails_unsubscribed_at, webhook_digest_unsubscribed_at, created_at, updated_at",
        email,
        display_name,
    )
    .fetch_one(pool)
    .await
}

/// Refresh the email/display_name the IdP returned on latest login. No-op if
/// the values are unchanged. Returns the updated row.
pub async fn refresh_profile(
    pool: &PgPool,
    id: Uuid,
    email: Option<&str>,
    display_name: Option<&str>,
) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as!(
        UserRow,
        "UPDATE users
         SET email = COALESCE($2, email),
             display_name = COALESCE($3, display_name),
             updated_at = now()
         WHERE id = $1
         RETURNING id, email, display_name, overslash_idp_provider, overslash_idp_subject, personal_org_id, is_instance_admin, welcome_email_sent_at, welcome_emails_unsubscribed_at, webhook_digest_unsubscribed_at, created_at, updated_at",
        id,
        email,
        display_name,
    )
    .fetch_optional(pool)
    .await
}

/// Set the personal org pointer. Used by the login-time provisioning path
/// immediately after creating the personal org for a new Overslash-backed user.
pub async fn set_personal_org(
    pool: &PgPool,
    id: Uuid,
    personal_org_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE users SET personal_org_id = $2, updated_at = now() WHERE id = $1",
        id,
        personal_org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Stamp `welcome_email_sent_at = now()` once after the welcome send
/// succeeds. The send service checks `IS NULL` before dispatching, so this
/// is the gate that makes welcome sends naturally idempotent.
pub async fn mark_welcome_sent(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
    let res = sqlx::query!(
        "UPDATE users
         SET welcome_email_sent_at = now(), updated_at = now()
         WHERE id = $1 AND welcome_email_sent_at IS NULL",
        id,
    )
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

/// Set or clear the per-user welcome / non-transactional unsubscribe state.
/// Pass `Some(now())` to unsubscribe, `None` to re-subscribe. Returns the
/// updated row (or `None` if `id` doesn't exist).
pub async fn set_welcome_unsubscribed(
    pool: &PgPool,
    id: Uuid,
    unsubscribed_at: Option<OffsetDateTime>,
) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as!(
        UserRow,
        "UPDATE users
         SET welcome_emails_unsubscribed_at = $2, updated_at = now()
         WHERE id = $1
         RETURNING id, email, display_name, overslash_idp_provider, overslash_idp_subject, personal_org_id, is_instance_admin, welcome_email_sent_at, welcome_emails_unsubscribed_at, webhook_digest_unsubscribed_at, created_at, updated_at",
        id,
        unsubscribed_at,
    )
    .fetch_optional(pool)
    .await
}

/// Per-category opt-out for the daily webhook DLQ digest. Pass `Some(now())`
/// to unsubscribe, `None` to re-subscribe. Independent of
/// `set_welcome_unsubscribed` — flipping one does not affect the other.
pub async fn set_webhook_digest_unsubscribed(
    pool: &PgPool,
    id: Uuid,
    unsubscribed_at: Option<OffsetDateTime>,
) -> Result<Option<UserRow>, sqlx::Error> {
    sqlx::query_as!(
        UserRow,
        "UPDATE users
         SET webhook_digest_unsubscribed_at = $2, updated_at = now()
         WHERE id = $1
         RETURNING id, email, display_name, overslash_idp_provider, overslash_idp_subject, personal_org_id, is_instance_admin, welcome_email_sent_at, welcome_emails_unsubscribed_at, webhook_digest_unsubscribed_at, created_at, updated_at",
        id,
        unsubscribed_at,
    )
    .fetch_optional(pool)
    .await
}
