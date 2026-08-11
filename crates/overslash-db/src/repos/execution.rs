//! Execution lifecycle: once an approval is `allowed`, a pending `executions`
//! row is created. The row transitions through `pending → executing → executed`
//! (or `failed`, `cancelled`, `expired`) and is triggered by an explicit
//! `POST /v1/approvals/{id}/call`.
//!
//! The unique index on `approval_id` and the `status='pending' AND expires_at > now()`
//! guard on `claim_for_execution` together enforce at-most-one replay per approval,
//! even under user+agent races.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct ExecutionRow {
    pub id: Uuid,
    /// NULL for a direct async call, which has no approval behind it.
    pub approval_id: Option<Uuid>,
    pub org_id: Uuid,
    /// The identity whose call this is. Always set: for approval-backed rows
    /// it is copied from the approval, for async rows it is the caller.
    /// Having it on the row is what lets the execution endpoints authorize a
    /// read without joining `approvals`.
    pub identity_id: Uuid,
    pub status: String,
    pub remember: bool,
    pub remember_keys: Option<Vec<String>>,
    pub remember_rule_ttl: Option<OffsetDateTime>,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub triggered_by: Option<String>,
    pub started_at: Option<OffsetDateTime>,
    pub completed_at: Option<OffsetDateTime>,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
    /// Set the first time the requesting agent fetches the result. Drives the
    /// "called but output unread" surfaces on the dashboard's pending-calls
    /// list — NULL means the agent hasn't seen the upstream response yet.
    pub result_viewed_at: Option<OffsetDateTime>,
    /// Copied verbatim from the originating approval at insert time — see
    /// `create_pending`. An execution never re-derives its own tags.
    pub tags: Vec<String>,
    /// `request IS NOT NULL` — this row is worker-run rather than run on a
    /// request. Projected rather than carrying `request` itself, because the
    /// payload can be megabytes and `find_by_approval_ids` backs the
    /// dashboard's approvals list; only [`AsyncClaim`] reads the payload.
    pub has_request: bool,
    pub service_key: Option<String>,
    pub service_instance_id: Option<Uuid>,
    /// While `status='executing'`, the instant after which the claiming worker
    /// is presumed dead. Renewed by heartbeat.
    pub lease_expires_at: Option<OffsetDateTime>,
    pub worker_id: Option<String>,
    /// Attempts that ended by *losing* a lease — incremented by the reclaim
    /// sweep, never by the claim, so a clean hand-back at shutdown is free.
    pub attempts: i32,
    pub cancel_requested: bool,
}

/// Create the pending execution for an approved approval.
///
/// `INSERT … SELECT` rather than `VALUES` so `tags` are copied from the
/// approval in the same statement — the cascade call site
/// (`services::permission_chain`) holds only the approval id, and a copy that
/// cannot drift beats one threaded through two paths.
///
/// The `SELECT` matching no row (→ `RowNotFound`) means the approval does not
/// exist *in this org*. That is not a new failure mode: the
/// `executions.approval_id` FK raised a constraint violation for the same
/// condition before, so a nonexistent approval always errored here. The
/// `a.org_id = $2` half is in fact stricter than the old `VALUES` form, which
/// wrote the caller-supplied `org_id` without ever checking it against the
/// approval's. Both call sites hold the approval row when they call this, and
/// the cascade site already treats an error as non-fatal.
pub(crate) async fn create_pending(
    pool: &PgPool,
    org_id: Uuid,
    approval_id: Uuid,
    remember: bool,
    remember_keys: Option<&[String]>,
    remember_rule_ttl: Option<OffsetDateTime>,
    expires_at: OffsetDateTime,
) -> Result<ExecutionRow, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "INSERT INTO executions (approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, expires_at, tags, identity_id)
         SELECT $1, $2, 'pending', $3, $4, $5, $6, a.tags, a.identity_id
           FROM approvals a WHERE a.id = $1 AND a.org_id = $2
         RETURNING id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at, result_viewed_at, tags, identity_id, (request IS NOT NULL) AS \"has_request!\", service_key, service_instance_id, lease_expires_at, worker_id, attempts, cancel_requested",
        approval_id,
        org_id,
        remember,
        remember_keys as Option<&[String]>,
        remember_rule_ttl,
        expires_at,
    )
    .fetch_one(pool)
    .await
}

/// Atomically claim a pending execution for replay. Returns `Some(row)` on
/// win (status was 'pending' AND not yet expired), `None` on any other state.
/// The caller must inspect the current row via `find_by_approval` to produce
/// a specific error.
pub(crate) async fn claim_for_execution(
    pool: &PgPool,
    org_id: Uuid,
    approval_id: Uuid,
    triggered_by: &str,
) -> Result<Option<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "UPDATE executions
            SET status = 'executing',
                triggered_by = $3,
                started_at = now()
          WHERE approval_id = $1
            AND org_id = $2
            AND status = 'pending'
            AND expires_at > now()
          RETURNING id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at, result_viewed_at, tags, identity_id, (request IS NOT NULL) AS \"has_request!\", service_key, service_instance_id, lease_expires_at, worker_id, attempts, cancel_requested",
        approval_id,
        org_id,
        triggered_by,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn finalize_executed(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    result: &serde_json::Value,
) -> Result<Option<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "UPDATE executions
            SET status = 'executed',
                result = $3,
                completed_at = now()
          WHERE id = $1
            AND org_id = $2
            AND status = 'executing'
          RETURNING id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at, result_viewed_at, tags, identity_id, (request IS NOT NULL) AS \"has_request!\", service_key, service_instance_id, lease_expires_at, worker_id, attempts, cancel_requested",
        id,
        org_id,
        result,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn finalize_failed(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    error: &str,
) -> Result<Option<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "UPDATE executions
            SET status = 'failed',
                error = $3,
                completed_at = now()
          WHERE id = $1
            AND org_id = $2
            AND status = 'executing'
          RETURNING id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at, result_viewed_at, tags, identity_id, (request IS NOT NULL) AS \"has_request!\", service_key, service_instance_id, lease_expires_at, worker_id, attempts, cancel_requested",
        id,
        org_id,
        error,
    )
    .fetch_optional(pool)
    .await
}

/// Transition a pending execution to cancelled. Returns the updated row on
/// success, `None` if the row was not pending (already executing / terminal).
pub(crate) async fn cancel_if_pending(
    pool: &PgPool,
    org_id: Uuid,
    approval_id: Uuid,
) -> Result<Option<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "UPDATE executions
            SET status = 'cancelled',
                completed_at = now()
          WHERE approval_id = $1
            AND org_id = $2
            AND status = 'pending'
          RETURNING id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at, result_viewed_at, tags, identity_id, (request IS NOT NULL) AS \"has_request!\", service_key, service_instance_id, lease_expires_at, worker_id, attempts, cancel_requested",
        approval_id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn find_by_approval(
    pool: &PgPool,
    org_id: Uuid,
    approval_id: Uuid,
) -> Result<Option<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "SELECT id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at, result_viewed_at, tags, identity_id, (request IS NOT NULL) AS \"has_request!\", service_key, service_instance_id, lease_expires_at, worker_id, attempts, cancel_requested
         FROM executions
         WHERE approval_id = $1 AND org_id = $2",
        approval_id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn find_by_approval_ids(
    pool: &PgPool,
    org_id: Uuid,
    approval_ids: &[Uuid],
) -> Result<Vec<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "SELECT id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at, result_viewed_at, tags, identity_id, (request IS NOT NULL) AS \"has_request!\", service_key, service_instance_id, lease_expires_at, worker_id, attempts, cancel_requested
         FROM executions
         WHERE org_id = $1 AND approval_id = ANY($2)",
        org_id,
        approval_ids,
    )
    .fetch_all(pool)
    .await
}

/// First-read marker: mark this execution's result as viewed. Idempotent —
/// once stamped, subsequent reads do not move the timestamp. The CHECK on
/// `status` prevents accidentally marking a row that hasn't completed yet.
pub(crate) async fn mark_viewed(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let r = sqlx::query!(
        "UPDATE executions
            SET result_viewed_at = now()
          WHERE id = $1
            AND org_id = $2
            AND result_viewed_at IS NULL
            AND status IN ('executed', 'failed')",
        id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(r.rows_affected() > 0)
}

/// Cross-org maintenance: transition pending executions that have passed their
/// 15-minute deadline to `expired`. Exposed via `SystemScope`.
pub(crate) async fn expire_stale(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE executions
            SET status = 'expired',
                completed_at = now(),
                error = 'expired_before_execution'
          WHERE status = 'pending' AND expires_at < now()",
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Cross-org maintenance: reap `executing` rows that have been in flight far
/// longer than any legitimate replay — the API likely crashed mid-call.
/// Exposed via `SystemScope`.
pub(crate) async fn expire_orphaned_executing(
    pool: &PgPool,
    grace_secs: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE executions
            SET status = 'failed',
                error = 'orphaned',
                completed_at = now()
          WHERE status = 'executing'
            -- Async rows are governed by lease liveness, not by `started_at`:
            -- a worker-run job may legitimately run for many minutes while
            -- heartbeating. Excluding them here is what keeps this sweep's
            -- meaning unchanged -- an approval replay whose request died --
            -- rather than merely untouched.
            AND request IS NULL
            AND started_at IS NOT NULL
            AND started_at < now() - make_interval(secs => $1)",
        grace_secs as f64,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

// ── Async (worker-run) executions ────────────────────────────────────────────
//
// `request IS NOT NULL` marks a row as worker-run. Every query below carries
// that predicate, and `expire_orphaned_executing` carries its negation, so the
// two sweeps provably cannot reach each other's rows.
//
// Concurrency here is a claim-and-lease rather than the CAS-in-WHERE the rest
// of this module uses. CAS is sufficient for the synchronous path because the
// claimant *is* the HTTP request and dies with its connection. An async row is
// claimed by a process that outlives any request and that Cloud Run may recycle
// mid-call, so ownership has to be a renewable fact in the row.

/// What a worker needs to run one claimed row.
///
/// Deliberately narrower than [`ExecutionRow`]: this is the only place
/// `request` is read, and the payload can be megabytes.
#[derive(Debug)]
pub struct AsyncClaim {
    pub id: Uuid,
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub approval_id: Option<Uuid>,
    pub request: serde_json::Value,
    pub service_key: Option<String>,
    pub service_instance_id: Option<Uuid>,
    pub attempts: i32,
    pub tags: Vec<String>,
    pub render_verbose: Option<bool>,
    pub template_key: Option<String>,
    pub description: Option<String>,
    pub client_ip: Option<String>,
}

/// Terminal outcome of a worker-run call.
///
/// An enum rather than a `&str` so the status written can never drift from the
/// table's CHECK constraint.
pub enum AsyncOutcome<'a> {
    Executed(&'a serde_json::Value),
    Failed(&'a str),
    Cancelled,
}

impl AsyncOutcome<'_> {
    fn status(&self) -> &'static str {
        match self {
            Self::Executed(_) => "executed",
            Self::Failed(_) => "failed",
            Self::Cancelled => "cancelled",
        }
    }
    fn result(&self) -> Option<&serde_json::Value> {
        match self {
            Self::Executed(v) => Some(v),
            _ => None,
        }
    }
    fn error(&self) -> Option<&str> {
        match self {
            Self::Failed(m) => Some(m),
            Self::Cancelled => Some("cancelled_in_flight"),
            Self::Executed(_) => None,
        }
    }
}

/// Input for a direct async call — one with no approval behind it.
pub struct AsyncExecutionInput<'a> {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub request: &'a serde_json::Value,
    pub service_key: Option<&'a str>,
    pub service_instance_id: Option<Uuid>,
    pub tags: &'a [String],
    pub render_verbose: Option<bool>,
    pub template_key: Option<&'a str>,
    pub description: Option<&'a str>,
    pub client_ip: Option<&'a str>,
    pub expires_at: OffsetDateTime,
}

/// Create the queued row for a direct async call.
///
/// The one `VALUES` insert in this module: there is no approval to `SELECT`
/// from, and the caller has already minted the exact tag set via
/// `services::tags::call_tags` for its audit row.
pub(crate) async fn create_async_direct(
    pool: &PgPool,
    input: AsyncExecutionInput<'_>,
) -> Result<ExecutionRow, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "INSERT INTO executions
             (org_id, identity_id, status, request, service_key, service_instance_id,
              tags, render_verbose, template_key, description, client_ip, expires_at,
              triggered_by)
         VALUES ($1, $2, 'pending', $3, $4, $5, $6, $7, $8, $9, $10, $11, 'async')
         RETURNING id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at, result_viewed_at, tags, identity_id, (request IS NOT NULL) AS \"has_request!\", service_key, service_instance_id, lease_expires_at, worker_id, attempts, cancel_requested",
        input.org_id,
        input.identity_id,
        input.request,
        input.service_key,
        input.service_instance_id,
        input.tags,
        input.render_verbose,
        input.template_key,
        input.description,
        input.client_ip,
        input.expires_at,
    )
    .fetch_one(pool)
    .await
}

/// Create the queued row for a gated call that was approved and must run async.
///
/// Same `INSERT … SELECT` shape as [`create_pending`], but it also lifts the
/// approval's `replay_payload` into `request` so the worker has exactly one
/// payload source and never joins back to `approvals`.
///
/// `a.replay_payload IS NOT NULL` in the `WHERE` means a legacy approval with
/// no stored payload yields `RowNotFound`, and the caller falls back to
/// creating a synchronous pending row.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_pending_async_from_approval(
    pool: &PgPool,
    approval_id: Uuid,
    org_id: Uuid,
    remember: bool,
    remember_keys: Option<&[String]>,
    remember_rule_ttl: Option<OffsetDateTime>,
    expires_at: OffsetDateTime,
) -> Result<ExecutionRow, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "INSERT INTO executions
             (approval_id, org_id, status, remember, remember_keys, remember_rule_ttl,
              expires_at, tags, identity_id, request, service_key, service_instance_id,
              triggered_by)
         SELECT $1, $2, 'pending', $3, $4, $5, $6, a.tags, a.identity_id,
                a.replay_payload,
                a.replay_payload->>'service_key',
                (a.replay_payload->>'instance_id')::uuid,
                'async'
           FROM approvals a
          WHERE a.id = $1 AND a.org_id = $2 AND a.replay_payload IS NOT NULL
         RETURNING id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at, result_viewed_at, tags, identity_id, (request IS NOT NULL) AS \"has_request!\", service_key, service_instance_id, lease_expires_at, worker_id, attempts, cancel_requested",
        approval_id,
        org_id,
        remember,
        remember_keys as Option<&[String]>,
        remember_rule_ttl,
        expires_at,
    )
    .fetch_one(pool)
    .await
}

/// Take up to `limit` queued async rows and lease them to `worker_id`.
///
/// `FOR UPDATE SKIP LOCKED` is new to this codebase. The only prior
/// cross-replica claim is `webhook_digest_run::try_claim`'s
/// `INSERT … ON CONFLICT`, which works because its key is `(org, date)` and so
/// is known before the query; here the key is "whatever is next", which that
/// idiom cannot express. Note `webhook_dispatcher`'s retry loop has *no* claim
/// at all and has every replica retrying the same rows — the wrong precedent.
///
/// Neither this nor any sweep below opens an explicit transaction: the implicit
/// single-statement transaction holds the row locks for exactly the duration of
/// the `UPDATE`, which is what keeps this compatible with the module's
/// no-transactions rule.
///
/// Does not touch `attempts` (only a *lost* lease costs an attempt) and does
/// not clear `cancel_requested` — a `pending` row can never carry a live cancel
/// flag, because [`request_cancel`] terminates such a row outright.
pub(crate) async fn claim_async_batch(
    pool: &PgPool,
    worker_id: &str,
    lease_ttl_secs: i64,
    limit: i64,
) -> Result<Vec<AsyncClaim>, sqlx::Error> {
    sqlx::query_as!(
        AsyncClaim,
        "WITH claimed AS (
             SELECT id FROM executions
              WHERE status = 'pending'
                AND request IS NOT NULL
                AND expires_at > now()
              ORDER BY created_at
              LIMIT $3
              FOR UPDATE SKIP LOCKED
         )
         UPDATE executions e
            SET status = 'executing',
                worker_id = $1,
                started_at = now(),
                lease_expires_at = now() + make_interval(secs => $2)
           FROM claimed c
          WHERE e.id = c.id
         RETURNING e.id, e.org_id, e.identity_id, e.approval_id,
                   e.request AS \"request!\", e.service_key, e.service_instance_id,
                   e.attempts, e.tags, e.render_verbose, e.template_key,
                   e.description, e.client_ip",
        worker_id,
        lease_ttl_secs as f64,
        limit,
    )
    .fetch_all(pool)
    .await
}

/// Renew a lease, and learn whether a cancel was requested, in one statement.
///
/// `None` means the lease was lost — the row was reclaimed, failed, or
/// cancelled out from under this worker — and the caller must abandon its
/// result rather than finalize, because someone else may already own the row.
/// `Some(true)` means stop.
///
/// The two facts are returned together on purpose: "I still own this row" and
/// "I should stop" have to be a single atomic observation, or a worker can act
/// on a cancel it no longer has the right to act on.
pub(crate) async fn heartbeat_async(
    pool: &PgPool,
    id: Uuid,
    worker_id: &str,
    lease_ttl_secs: i64,
) -> Result<Option<bool>, sqlx::Error> {
    let row = sqlx::query!(
        "UPDATE executions
            SET lease_expires_at = now() + make_interval(secs => $3)
          WHERE id = $1 AND worker_id = $2 AND status = 'executing'
         RETURNING cancel_requested",
        id,
        worker_id,
        lease_ttl_secs as f64,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.cancel_requested))
}

/// Hand a claimed row back to the queue without charging an attempt.
///
/// Called on SIGTERM. `expires_at` is pushed out so a row released near its
/// queue deadline is not swept to `expired` by [`expire_stale`] before another
/// worker can take it.
pub(crate) async fn release_async(
    pool: &PgPool,
    id: Uuid,
    worker_id: &str,
    queue_ttl_secs: i64,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE executions
            SET status = 'pending',
                worker_id = NULL,
                started_at = NULL,
                lease_expires_at = NULL,
                expires_at = GREATEST(expires_at, now() + make_interval(secs => $3))
          WHERE id = $1 AND worker_id = $2 AND status = 'executing'",
        id,
        worker_id,
        queue_ttl_secs as f64,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Terminal transition for a worker-run row, guarded on lease ownership.
///
/// `None` means the lease was lost before the result landed; the caller
/// discards its result. Same CAS-in-WHERE discipline as the synchronous
/// finalizers, with `worker_id` added as the ownership half.
pub(crate) async fn finalize_async(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
    worker_id: &str,
    outcome: AsyncOutcome<'_>,
) -> Result<Option<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "UPDATE executions
            SET status = $4,
                result = $5,
                error = $6,
                completed_at = now(),
                lease_expires_at = NULL,
                worker_id = NULL
          WHERE id = $1 AND org_id = $2 AND worker_id = $3 AND status = 'executing'
         RETURNING id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at, result_viewed_at, tags, identity_id, (request IS NOT NULL) AS \"has_request!\", service_key, service_instance_id, lease_expires_at, worker_id, attempts, cancel_requested",
        id,
        org_id,
        worker_id,
        outcome.status(),
        outcome.result(),
        outcome.error(),
    )
    .fetch_optional(pool)
    .await
}

/// Reclaim async rows whose lease expired, charging one attempt.
///
/// The `CASE` folds in "the worker died while a cancel was pending", so a
/// cancel can never be lost to a crash. `expires_at` is extended for the same
/// reason as in [`release_async`]: without it, a row claimed late in its queue
/// TTL would be requeued already-expired and silently killed, losing the retry.
///
/// Disjoint from [`fail_exhausted_async`] by construction (`<` vs `>=`), so the
/// order the two run in within a tick does not matter.
pub(crate) async fn requeue_expired_leases(
    pool: &PgPool,
    max_attempts: i32,
    queue_ttl_secs: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE executions
            SET status = CASE WHEN cancel_requested THEN 'cancelled' ELSE 'pending' END,
                attempts = attempts + 1,
                worker_id = NULL,
                started_at = NULL,
                lease_expires_at = NULL,
                completed_at = CASE WHEN cancel_requested THEN now() ELSE NULL END,
                error = CASE WHEN cancel_requested THEN 'cancelled' ELSE NULL END,
                expires_at = GREATEST(expires_at, now() + make_interval(secs => $2))
          WHERE status = 'executing'
            AND request IS NOT NULL
            AND lease_expires_at < now()
            AND attempts + 1 < $1",
        max_attempts,
        queue_ttl_secs as f64,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Fail async rows that have exhausted their attempts.
pub(crate) async fn fail_exhausted_async(
    pool: &PgPool,
    max_attempts: i32,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE executions
            SET status = 'failed',
                attempts = attempts + 1,
                error = 'lease_lost',
                worker_id = NULL,
                lease_expires_at = NULL,
                completed_at = now()
          WHERE status = 'executing'
            AND request IS NOT NULL
            AND lease_expires_at < now()
            AND attempts + 1 >= $1",
        max_attempts,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Backstop for a worker that is alive enough to heartbeat but wedged on an
/// upstream that never answers. Without this, the heartbeat would hold the
/// lease forever and neither sweep above would ever see the row.
pub(crate) async fn fail_async_over_wall(
    pool: &PgPool,
    wall_secs: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE executions
            SET status = 'failed',
                error = 'async_wall_clock',
                worker_id = NULL,
                lease_expires_at = NULL,
                completed_at = now()
          WHERE status = 'executing'
            AND request IS NOT NULL
            AND started_at IS NOT NULL
            AND started_at < now() - make_interval(secs => $1)",
        wall_secs as f64,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Request cancellation of an async row.
///
/// From `pending` this is immediate and worker-free — no one owns the row.
/// From `executing` it only records the intent; the worker observes it on its
/// next heartbeat and finalizes. Returns `None` when the row is already
/// terminal or is not an async row.
///
/// Terminating a `pending` row here is what guarantees no `pending` row ever
/// carries a live cancel flag into [`claim_async_batch`].
pub(crate) async fn request_cancel(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<Option<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "UPDATE executions
            SET cancel_requested = true,
                status = CASE WHEN status = 'pending' THEN 'cancelled' ELSE status END,
                completed_at = CASE WHEN status = 'pending' THEN now() ELSE completed_at END,
                error = CASE WHEN status = 'pending' THEN 'cancelled_before_start' ELSE error END
          WHERE id = $1 AND org_id = $2 AND request IS NOT NULL
            AND status IN ('pending', 'executing')
         RETURNING id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at, result_viewed_at, tags, identity_id, (request IS NOT NULL) AS \"has_request!\", service_key, service_instance_id, lease_expires_at, worker_id, attempts, cancel_requested",
        id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// Point read by execution id, org-scoped.
pub(crate) async fn find_by_id(
    pool: &PgPool,
    org_id: Uuid,
    id: Uuid,
) -> Result<Option<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "SELECT id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at, result_viewed_at, tags, identity_id, (request IS NOT NULL) AS \"has_request!\", service_key, service_instance_id, lease_expires_at, worker_id, attempts, cancel_requested
           FROM executions WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// List executions for one identity, or for that identity's whole subtree.
///
/// Ordered newest-first and capped by `limit`. The subtree variant leans on the
/// same recursive descendant walk the approvals list uses, so "what did my
/// agents do" means the same thing on both surfaces.
pub(crate) async fn list_for_identity(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    subtree: bool,
    status: Option<&str>,
    limit: i64,
) -> Result<Vec<ExecutionRow>, sqlx::Error> {
    sqlx::query_as!(
        ExecutionRow,
        "WITH RECURSIVE subtree AS (
             SELECT id FROM identities WHERE id = $2 AND org_id = $1
             UNION
             SELECT i.id FROM identities i JOIN subtree s ON i.parent_id = s.id
         )
         SELECT id, approval_id, org_id, status, remember, remember_keys, remember_rule_ttl, result, error, triggered_by, started_at, completed_at, expires_at, created_at, result_viewed_at, tags, identity_id, (request IS NOT NULL) AS \"has_request!\", service_key, service_instance_id, lease_expires_at, worker_id, attempts, cancel_requested
           FROM executions
          WHERE org_id = $1
            AND ($3 OR identity_id = $2)
            AND (NOT $3 OR identity_id IN (SELECT id FROM subtree))
            AND ($4::text IS NULL OR status = $4)
          ORDER BY created_at DESC
          LIMIT $5",
        org_id,
        identity_id,
        subtree,
        status,
        limit,
    )
    .fetch_all(pool)
    .await
}
