//! `org_google_directory_configs` — which Google Workspace an org has
//! connected, and the scheduling state of its group sync.
//!
//! The credential is not here: every org uses the instance's one service
//! account (see `overslash_api::config::GoogleDirectoryInstance`). What an org
//! owns is the proof of which Workspace it is — `domain`, as Google's `hd`
//! claim reported it when an admin of that Workspace signed in — and that proof
//! is unique per instance.
//!
//! Three things can start a sync: the periodic sweep (`next_sync_at`), an
//! admin's "Sync now" (`sync_requested_at`), and a sign-in (which runs a
//! per-user pull outside this table entirely). The first two go through
//! [`claim_due`], which leases a row to exactly one worker across replicas.
//! See migrations 129 and 131 and `docs/design/directory-group-sync.md`.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug)]
pub struct GoogleDirectoryConfigRow {
    pub org_id: Uuid,
    /// The Workspace admin the instance service account impersonates. Always
    /// the account that signed in to connect — never typed.
    pub admin_subject: String,
    pub customer_id: String,
    /// The Workspace's primary domain, from Google's `hd` claim. Lower-cased.
    pub domain: String,
    pub connected_by_identity_id: Option<Uuid>,
    pub connected_at: OffsetDateTime,
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

/// What an admin may edit after connecting. `None` leaves a field as it is.
/// The Workspace itself is not editable: changing it means connecting again.
#[derive(Default)]
pub struct GoogleDirectorySettings {
    pub enabled: Option<bool>,
    pub sync_interval_hours: Option<i32>,
}

pub(crate) async fn get_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Option<GoogleDirectoryConfigRow>, sqlx::Error> {
    sqlx::query_as!(
        GoogleDirectoryConfigRow,
        "SELECT org_id, admin_subject, customer_id, domain, connected_by_identity_id,
                connected_at, enabled, sync_interval_hours, next_sync_at, sync_requested_at,
                lease_owner, lease_expires_at, last_sync_started_at, last_sync_finished_at,
                last_sync_status, last_sync_error, last_sync_stats, created_at, updated_at
           FROM org_google_directory_configs WHERE org_id = $1",
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// Record a proven Workspace connection for the org, creating the config or
/// re-pointing it at the admin who just signed in.
///
/// Due at once either way: the first sweep follows the connect within a tick.
/// Fails with a unique violation on `org_google_directory_configs_domain_key`
/// when another org already connected this Workspace; the caller turns that
/// into a refusal. A reconnect to a *different* Workspace must delete first —
/// the old Workspace's groups are not this one's.
pub(crate) async fn connect(
    pool: &PgPool,
    org_id: Uuid,
    admin_subject: &str,
    domain: &str,
    identity_id: Uuid,
) -> Result<GoogleDirectoryConfigRow, sqlx::Error> {
    sqlx::query_as!(
        GoogleDirectoryConfigRow,
        "INSERT INTO org_google_directory_configs
             (org_id, admin_subject, domain, connected_by_identity_id)
         VALUES ($1, $2, lower($3), $4)
         ON CONFLICT (org_id) DO UPDATE SET
             admin_subject = EXCLUDED.admin_subject,
             domain = EXCLUDED.domain,
             connected_by_identity_id = EXCLUDED.connected_by_identity_id,
             connected_at = now(),
             next_sync_at = now(),
             updated_at = now()
         RETURNING org_id, admin_subject, customer_id, domain, connected_by_identity_id,
                   connected_at, enabled, sync_interval_hours, next_sync_at, sync_requested_at,
                   lease_owner, lease_expires_at, last_sync_started_at, last_sync_finished_at,
                   last_sync_status, last_sync_error, last_sync_stats, created_at, updated_at",
        org_id,
        admin_subject,
        domain,
        identity_id,
    )
    .fetch_one(pool)
    .await
}

/// Update the admin-editable settings.
pub(crate) async fn update(
    pool: &PgPool,
    org_id: Uuid,
    settings: GoogleDirectorySettings,
) -> Result<Option<GoogleDirectoryConfigRow>, sqlx::Error> {
    sqlx::query_as!(
        GoogleDirectoryConfigRow,
        "UPDATE org_google_directory_configs SET
             enabled = COALESCE($2, enabled),
             sync_interval_hours = COALESCE($3, sync_interval_hours),
             updated_at = now()
         WHERE org_id = $1
         RETURNING org_id, admin_subject, customer_id, domain, connected_by_identity_id,
                   connected_at, enabled, sync_interval_hours, next_sync_at, sync_requested_at,
                   lease_owner, lease_expires_at, last_sync_started_at, last_sync_finished_at,
                   last_sync_status, last_sync_error, last_sync_stats, created_at, updated_at",
        org_id,
        settings.enabled,
        settings.sync_interval_hours,
    )
    .fetch_optional(pool)
    .await
}

// ── Connect flows ────────────────────────────────────────────────────

/// Start a "Sign in with Google" connect, bound to the admin who started it.
/// Returns the flow id, which rides the OAuth `state`.
pub(crate) async fn create_connect_flow(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    pkce_verifier: &str,
    ttl_secs: i64,
) -> Result<Uuid, sqlx::Error> {
    // Opportunistic cleanup: flows are short-lived and rarely created, so
    // sweeping expired ones here keeps the table bounded without a loop.
    sqlx::query!("DELETE FROM google_directory_connect_flows WHERE expires_at < now()")
        .execute(pool)
        .await?;
    sqlx::query_scalar!(
        "INSERT INTO google_directory_connect_flows
             (org_id, identity_id, pkce_verifier, expires_at)
         VALUES ($1, $2, $3, now() + make_interval(secs => $4))
         RETURNING id",
        org_id,
        identity_id,
        pkce_verifier,
        ttl_secs as f64,
    )
    .fetch_one(pool)
    .await
}

/// A consumed connect flow.
pub struct ConnectFlow {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub pkce_verifier: String,
    pub expires_at: OffsetDateTime,
}

/// Consume a connect flow. Single use: the row is deleted whether or not the
/// rest of the callback succeeds, so a replayed `state` finds nothing.
/// `None` for an unknown, used or expired flow.
pub async fn take_connect_flow(
    pool: &PgPool,
    id: Uuid,
) -> Result<Option<ConnectFlow>, sqlx::Error> {
    let flow = sqlx::query_as!(
        ConnectFlow,
        "DELETE FROM google_directory_connect_flows
          WHERE id = $1
          RETURNING org_id, identity_id, pkce_verifier, expires_at",
        id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(flow.filter(|f| f.expires_at > OffsetDateTime::now_utc()))
}

/// Remove the config and everything it reported.
///
/// The `google_directory` directory groups reference the config through
/// `google_directory_org_id ON DELETE CASCADE`, so this one statement also
/// removes them, their memberships and any mapping an admin drew: derived
/// access is revoked atomically with the credential. The same FK makes a
/// sweep that is mid-flight fail on its next upsert rather than resurrect them.
pub(crate) async fn delete(pool: &PgPool, org_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM org_google_directory_configs WHERE org_id = $1",
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
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
/// whose email is under the connected Workspace's domain.
pub struct DirectoryCandidate {
    pub identity_id: Uuid,
    /// Lower-cased.
    pub email: String,
}

/// Every non-archived user identity in the org whose email domain is
/// `domain`. The match is on the part after the *last* `@`, so `a@b@evil.com`
/// is judged by `evil.com`.
pub(crate) async fn list_candidates(
    pool: &PgPool,
    org_id: Uuid,
    domain: &str,
) -> Result<Vec<DirectoryCandidate>, sqlx::Error> {
    sqlx::query_as!(
        DirectoryCandidate,
        r#"SELECT id AS "identity_id!", lower(email) AS "email!"
             FROM identities
            WHERE org_id = $1
              AND kind = 'user'
              AND archived_at IS NULL
              AND email IS NOT NULL
              AND lower(substring(email from '@([^@]+)$')) = lower($2)"#,
        org_id,
        domain,
    )
    .fetch_all(pool)
    .await
}
