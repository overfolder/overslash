//! The durable event log behind `GET /v1/events/stream`.
//!
//! Two readers with different needs share this table. The *replay* path serves
//! one subscriber resuming from a cursor and must apply that subscriber's
//! visibility rules, so it filters by org, audience and topic in SQL. The
//! *listener* path serves the process-wide fan-out task, which forwards rows to
//! every locally-connected subscriber and therefore reads them unfiltered —
//! visibility is applied per-connection in memory instead. Keep that split:
//! the listener must never grow an identity filter, and the replay query must
//! never lose one.

use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EventRow {
    /// Resume cursor — the SSE `id:` field, echoed back as `Last-Event-ID`.
    pub id: i64,
    /// Stable uuid for the wire envelope (mirrors the webhook envelope `id`).
    pub event_id: Uuid,
    pub org_id: Uuid,
    pub r#type: String,
    pub topic: String,
    pub payload: serde_json::Value,
    /// Identity ids allowed to receive this event, frozen at emit time.
    pub audience: Vec<Uuid>,
    pub created_at: OffsetDateTime,
}

super::impl_org_owned!(EventRow);

/// Append an event. The `events_notify_trigger` fires `pg_notify` on commit,
/// so callers never notify by hand.
pub(crate) async fn insert(
    pool: &PgPool,
    org_id: Uuid,
    event_type: &str,
    topic: &str,
    payload: serde_json::Value,
    audience: &[Uuid],
) -> Result<EventRow, sqlx::Error> {
    sqlx::query_as!(
        EventRow,
        r#"INSERT INTO events (org_id, type, topic, payload, audience)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, event_id, org_id, type, topic, payload, audience, created_at"#,
        org_id,
        event_type,
        topic,
        payload,
        audience,
    )
    .fetch_one(pool)
    .await
}

/// Fetch one row by cursor for the fan-out listener. Deliberately unscoped:
/// the listener forwards to every subscriber on this replica and each
/// connection re-applies its own org/audience filter before emitting.
pub(crate) async fn get_by_cursor(
    pool: &PgPool,
    cursor: i64,
) -> Result<Option<EventRow>, sqlx::Error> {
    sqlx::query_as!(
        EventRow,
        r#"SELECT id, event_id, org_id, type, topic, payload, audience, created_at
           FROM events WHERE id = $1"#,
        cursor,
    )
    .fetch_optional(pool)
    .await
}

/// Rows after `cursor`, for the listener's catch-up sweep when the LISTEN
/// connection drops and reconnects. Same unscoped rationale as
/// [`get_by_cursor`].
pub(crate) async fn get_after(
    pool: &PgPool,
    cursor: i64,
    limit: i64,
) -> Result<Vec<EventRow>, sqlx::Error> {
    sqlx::query_as!(
        EventRow,
        r#"SELECT id, event_id, org_id, type, topic, payload, audience, created_at
           FROM events WHERE id > $1 ORDER BY id LIMIT $2"#,
        cursor,
        limit,
    )
    .fetch_all(pool)
    .await
}

/// Replay for one resuming subscriber. This is the access-control boundary for
/// the whole replay path: rows the caller may not see are never fetched, so a
/// bug downstream cannot leak them.
pub(crate) async fn replay_for_identity(
    pool: &PgPool,
    org_id: Uuid,
    cursor: i64,
    identity_id: Uuid,
    is_org_admin: bool,
    topics: &[String],
    limit: i64,
) -> Result<Vec<EventRow>, sqlx::Error> {
    sqlx::query_as!(
        EventRow,
        r#"SELECT id, event_id, org_id, type, topic, payload, audience, created_at
           FROM events
           WHERE org_id = $1
             AND id > $2
             AND ($3 OR audience && ARRAY[$4::uuid])
             AND topic = ANY($5)
           ORDER BY id
           LIMIT $6"#,
        org_id,
        cursor,
        is_org_admin,
        identity_id,
        topics,
        limit,
    )
    .fetch_all(pool)
    .await
}

/// Highest cursor in this org, so a fresh subscriber can be handed a resume
/// point without replaying history. Org-scoped rather than `MAX(id)` overall:
/// a global maximum would leak platform-wide event volume to any caller.
pub(crate) async fn latest_cursor_for_org(pool: &PgPool, org_id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar!(
        r#"SELECT COALESCE(MAX(id), 0) AS "cursor!" FROM events WHERE org_id = $1"#,
        org_id,
    )
    .fetch_one(pool)
    .await
}

/// Retention sweep. The log only has to outlive a reconnect window, so
/// anything older than the cutoff is dead weight.
pub(crate) async fn prune_older_than(
    pool: &PgPool,
    cutoff: OffsetDateTime,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query!("DELETE FROM events WHERE created_at < $1", cutoff)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
