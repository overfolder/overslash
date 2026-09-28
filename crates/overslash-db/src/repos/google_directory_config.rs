//! `org_google_directory_configs` — an org's Google Workspace Directory
//! credential, and the scheduling state of its group sync.
//!
//! Three things can start a sync: the periodic sweep (`next_sync_at`), an
//! admin's "Sync now" (`sync_requested_at`), and a sign-in (which runs a
//! per-user pull outside this table entirely). The first two go through
//! [`claim_due`], which leases a row to exactly one worker across replicas.
//! See migration 129 and `docs/design/directory-group-sync.md`.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug)]
pub struct GoogleDirectoryConfigRow {
    pub org_id: Uuid,
    pub encrypted_service_account_key: Vec<u8>,
    pub service_account_email: String,
    pub service_account_key_id: String,
    pub admin_subject: String,
    pub customer_id: String,
    pub domains: Vec<String>,
    pub enabled: bool,
    pub sync_interval_hours: i32,
    pub next_sync_at: OffsetDateTime,
    pub sync_requested_at: Option<OffsetDateTime>,
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<OffsetDateTime>,
    pub last_sync_started_at: Option<OffsetDateTime>,
    pub last_sync_finished_at: Option<OffsetDateTime>,
    pub last_sync_status: Option<String>,
    pub last_sync_error: Option<String>,
    pub last_sync_stats: Option<serde_json::Value>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl GoogleDirectoryConfigRow {
    /// A worker holds a live lease: a sync is running right now.
    pub fn is_running(&self, now: OffsetDateTime) -> bool {
        self.lease_owner.is_some() && self.lease_expires_at.is_some_and(|t| t > now)
    }
}

/// The credential-bearing half of a config, written together on create and on
/// a key replacement.
pub struct GoogleDirectoryCredential<'a> {
    pub encrypted_service_account_key: &'a [u8],
    pub service_account_email: &'a str,
    pub service_account_key_id: &'a str,
}

/// Everything an admin edits besides the key. `None` leaves a field as it is.
#[derive(Default)]
pub struct GoogleDirectorySettings<'a> {
    pub admin_subject: Option<&'a str>,
    pub customer_id: Option<&'a str>,
    pub domains: Option<&'a [String]>,
    pub enabled: Option<bool>,
    pub sync_interval_hours: Option<i32>,
}

pub(crate) async fn get_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Option<GoogleDirectoryConfigRow>, sqlx::Error> {
    sqlx::query_as!(
        GoogleDirectoryConfigRow,
        "SELECT org_id, encrypted_service_account_key, service_account_email,
                service_account_key_id, admin_subject, customer_id, domains, enabled,
                sync_interval_hours, next_sync_at, sync_requested_at, lease_owner,
                lease_expires_at, last_sync_started_at, last_sync_finished_at,
                last_sync_status, last_sync_error, last_sync_stats, created_at, updated_at
           FROM org_google_directory_configs WHERE org_id = $1",
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// Create the org's config. A fresh config is due immediately (`next_sync_at`
/// defaults to `now()`), so the first sweep follows the save within a tick.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create(
    pool: &PgPool,
    org_id: Uuid,
    credential: GoogleDirectoryCredential<'_>,
    admin_subject: &str,
    customer_id: &str,
    domains: &[String],
    enabled: bool,
    sync_interval_hours: i32,
) -> Result<GoogleDirectoryConfigRow, sqlx::Error> {
    sqlx::query_as!(
        GoogleDirectoryConfigRow,
        "INSERT INTO org_google_directory_configs
             (org_id, encrypted_service_account_key, service_account_email,
              service_account_key_id, admin_subject, customer_id, domains, enabled,
              sync_interval_hours)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING org_id, encrypted_service_account_key, service_account_email,
                   service_account_key_id, admin_subject, customer_id, domains, enabled,
                   sync_interval_hours, next_sync_at, sync_requested_at, lease_owner,
                   lease_expires_at, last_sync_started_at, last_sync_finished_at,
                   last_sync_status, last_sync_error, last_sync_stats, created_at, updated_at",
        org_id,
        credential.encrypted_service_account_key,
        credential.service_account_email,
        credential.service_account_key_id,
        admin_subject,
        customer_id,
        domains,
        enabled,
        sync_interval_hours,
    )
    .fetch_one(pool)
    .await
}

/// Update settings and, optionally, replace the key.
///
/// Changing the credential or the domains makes the row due at once: what the
/// last sweep established was computed under the old ones.
pub(crate) async fn update(
    pool: &PgPool,
    org_id: Uuid,
    credential: Option<GoogleDirectoryCredential<'_>>,
    settings: GoogleDirectorySettings<'_>,
) -> Result<Option<GoogleDirectoryConfigRow>, sqlx::Error> {
    let (key, email, key_id) = match &credential {
        Some(c) => (
            Some(c.encrypted_service_account_key),
            Some(c.service_account_email),
            Some(c.service_account_key_id),
        ),
        None => (None, None, None),
    };
    sqlx::query_as!(
        GoogleDirectoryConfigRow,
        "UPDATE org_google_directory_configs SET
             encrypted_service_account_key = COALESCE($2, encrypted_service_account_key),
             service_account_email = COALESCE($3, service_account_email),
             service_account_key_id = COALESCE($4, service_account_key_id),
             admin_subject = COALESCE($5, admin_subject),
             customer_id = COALESCE($6, customer_id),
             domains = COALESCE($7, domains),
             enabled = COALESCE($8, enabled),
             sync_interval_hours = COALESCE($9, sync_interval_hours),
             next_sync_at = CASE
                 WHEN $2::bytea IS NOT NULL OR $5::text IS NOT NULL
                      OR $6::text IS NOT NULL OR $7::text[] IS NOT NULL
                 THEN now()
                 ELSE next_sync_at
             END,
             updated_at = now()
         WHERE org_id = $1
         RETURNING org_id, encrypted_service_account_key, service_account_email,
                   service_account_key_id, admin_subject, customer_id, domains, enabled,
                   sync_interval_hours, next_sync_at, sync_requested_at, lease_owner,
                   lease_expires_at, last_sync_started_at, last_sync_finished_at,
                   last_sync_status, last_sync_error, last_sync_stats, created_at, updated_at",
        org_id,
        key,
        email,
        key_id,
        settings.admin_subject,
        settings.customer_id,
        settings.domains,
        settings.enabled,
        settings.sync_interval_hours,
    )
    .fetch_optional(pool)
    .await
}

/// Remove the config and everything it reported.
///
/// Deleting the `google_directory` directory groups cascades to their
/// memberships and to any mapping an admin drew, so the derived access is
/// revoked in the same transaction the credential disappears in. Leaving them
/// would freeze whatever the last sync said, with nothing left to update it.
pub(crate) async fn delete(pool: &PgPool, org_id: Uuid) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let deleted = sqlx::query!(
        "DELETE FROM org_google_directory_configs WHERE org_id = $1",
        org_id,
    )
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    sqlx::query!(
        "DELETE FROM directory_groups WHERE org_id = $1 AND source = 'google_directory'",
        org_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(deleted)
}

/// Queue a manual run. Returns `false` when one is already queued (or the
/// config is missing or disabled) — the column is either set or not, so no
/// number of clicks can queue a second run.
pub(crate) async fn request_sync(pool: &PgPool, org_id: Uuid) -> Result<bool, sqlx::Error> {
    let queued = sqlx::query_scalar!(
        "UPDATE org_google_directory_configs
            SET sync_requested_at = now()
          WHERE org_id = $1 AND enabled AND sync_requested_at IS NULL
          RETURNING org_id",
        org_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(queued.is_some())
}

/// Lease up to `limit` due configs to `worker_id`.
///
/// Due means enabled, not leased by a live worker, and either a manual run is
/// queued or the periodic interval has elapsed. `FOR UPDATE SKIP LOCKED` as in
/// `execution::claim_async_batch`: co-running replicas each take different
/// rows, never the same one.
///
/// The claim consumes the manual request and pushes `next_sync_at` a full
/// interval out, so an admin clicking "Sync now" *during* a run queues exactly
/// one follow-up rather than being swallowed by the run in progress.
pub(crate) async fn claim_due(
    pool: &PgPool,
    worker_id: &str,
    lease_ttl_secs: i64,
    limit: i64,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar!(
        "WITH due AS (
             SELECT org_id FROM org_google_directory_configs
              WHERE enabled
                AND (lease_expires_at IS NULL OR lease_expires_at <= now())
                AND (sync_requested_at IS NOT NULL OR next_sync_at <= now())
              ORDER BY sync_requested_at NULLS LAST, next_sync_at
              LIMIT $3
              FOR UPDATE SKIP LOCKED
         )
         UPDATE org_google_directory_configs c
            SET lease_owner = $1,
                lease_expires_at = now() + make_interval(secs => $2),
                sync_requested_at = NULL,
                next_sync_at = now() + make_interval(hours => c.sync_interval_hours),
                last_sync_started_at = now()
           FROM due
          WHERE c.org_id = due.org_id
         RETURNING c.org_id",
        worker_id,
        lease_ttl_secs as f64,
        limit,
    )
    .fetch_all(pool)
    .await
}

/// Record a run's outcome and release the lease — only if it is still ours.
/// A worker that overran its lease and lost the row to another replica must
/// not overwrite the newer run's state.
pub(crate) async fn finish(
    pool: &PgPool,
    org_id: Uuid,
    worker_id: &str,
    status: &str,
    error: Option<&str>,
    stats: Option<&serde_json::Value>,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE org_google_directory_configs
            SET lease_owner = NULL,
                lease_expires_at = NULL,
                last_sync_finished_at = now(),
                last_sync_status = $3,
                last_sync_error = $4,
                last_sync_stats = $5
          WHERE org_id = $1 AND lease_owner = $2",
        org_id,
        worker_id,
        status,
        error,
        stats,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// A human the directory may speak about: a live user identity in the org
/// whose email falls under one of the configured domains.
pub struct DirectoryCandidate {
    pub identity_id: Uuid,
    /// Lower-cased.
    pub email: String,
}

/// Every non-archived user identity in the org whose email domain is in
/// `domains` (which the caller has lower-cased). The domain match is on the
/// part after the *last* `@`, so `a@b@evil.com` is judged by `evil.com`.
pub(crate) async fn list_candidates(
    pool: &PgPool,
    org_id: Uuid,
    domains: &[String],
) -> Result<Vec<DirectoryCandidate>, sqlx::Error> {
    sqlx::query_as!(
        DirectoryCandidate,
        r#"SELECT id AS "identity_id!", lower(email) AS "email!"
             FROM identities
            WHERE org_id = $1
              AND kind = 'user'
              AND archived_at IS NULL
              AND email IS NOT NULL
              AND lower(substring(email from '@([^@]+)$')) = ANY($2)"#,
        org_id,
        domains,
    )
    .fetch_all(pool)
    .await
}
