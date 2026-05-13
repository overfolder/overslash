//! `webhook_digest_runs` — atomic per-org-per-day claim row that gates the
//! daily webhook DLQ digest send. Every API replica races the same
//! `INSERT ... ON CONFLICT DO NOTHING RETURNING`; the PK on `(org_id,
//! run_date)` guarantees exactly one winner per UTC day. The winner is
//! responsible for the org's digest that day. See migration 069.

use sqlx::PgPool;
use time::Date;
use uuid::Uuid;

/// Attempt to claim the send slot for `(org_id, run_date)`. Returns `true`
/// when this caller won the race and must send the digest, `false` when
/// another replica already claimed it. `run_date` should be the UTC calendar
/// date — pass `OffsetDateTime::now_utc().date()` from the caller so the
/// session's `TimeZone` GUC can't sneak in.
pub async fn try_claim(pool: &PgPool, org_id: Uuid, run_date: Date) -> Result<bool, sqlx::Error> {
    let claimed = sqlx::query_scalar!(
        "INSERT INTO webhook_digest_runs (org_id, run_date)
         VALUES ($1, $2)
         ON CONFLICT (org_id, run_date) DO NOTHING
         RETURNING org_id",
        org_id,
        run_date,
    )
    .fetch_optional(pool)
    .await?;
    Ok(claimed.is_some())
}

/// Release a claim that was taken but couldn't be acted on (e.g. the
/// candidate org turned out to have no admins to email). Lets the next
/// tick retry. Best-effort: callers should log any error and continue.
pub async fn release(pool: &PgPool, org_id: Uuid, run_date: Date) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "DELETE FROM webhook_digest_runs WHERE org_id = $1 AND run_date = $2",
        org_id,
        run_date,
    )
    .execute(pool)
    .await?;
    Ok(())
}
