use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct WebhookSubscriptionRow {
    pub id: Uuid,
    pub org_id: Uuid,
    pub url: String,
    pub events: Vec<String>,
    pub secret: String,
    pub active: bool,
    /// Why the platform switched this subscription off, when it did —
    /// `needs_https` for a plaintext URL registered before 7.1.1 enforcement.
    pub disabled_reason: Option<String>,
    /// `pending_verification` until the endpoint echoes the ownership
    /// challenge (CASA 7.1.2), then `verified`. Only verified subscriptions
    /// are dialed; events for a pending one are recorded as held deliveries.
    pub verification_status: String,
    pub verified_at: Option<OffsetDateTime>,
    /// Marked verified by migration 125 without a handshake, because it
    /// predates one. Cleared by the next successful verification.
    pub grandfathered: bool,
    pub verification_attempted_at: Option<OffsetDateTime>,
    /// Why the last handshake failed; `None` after a success.
    pub verification_error: Option<String>,
    pub created_at: OffsetDateTime,
}

/// `webhook_subscriptions.verification_status` for a subscription whose
/// endpoint has proven ownership.
pub const VERIFIED: &str = "verified";
/// `webhook_deliveries.held_reason` for an event raised while its
/// subscription was still pending verification.
pub const HELD_PENDING_VERIFICATION: &str = "pending_verification";

#[derive(Debug, sqlx::FromRow)]
pub struct WebhookDeliveryRow {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub event: String,
    pub payload: serde_json::Value,
    pub status_code: Option<i32>,
    pub response_body: Option<String>,
    pub attempts: i32,
    pub next_retry_at: Option<OffsetDateTime>,
    pub delivered_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    /// Set while the delivery is held back undialed — `pending_verification`
    /// for an event raised before the subscription verified.
    pub held_reason: Option<String>,
}

pub(crate) async fn create_subscription(
    pool: &PgPool,
    org_id: Uuid,
    url: &str,
    events: &[String],
    secret: &str,
) -> Result<WebhookSubscriptionRow, sqlx::Error> {
    sqlx::query_as!(
        WebhookSubscriptionRow,
        "INSERT INTO webhook_subscriptions (org_id, url, events, secret)
         VALUES ($1, $2, $3, $4)
         RETURNING id, org_id, url, events, secret, active, disabled_reason,
                   verification_status, verified_at, grandfathered,
                   verification_attempted_at, verification_error, created_at",
        org_id,
        url,
        events,
        secret,
    )
    .fetch_one(pool)
    .await
}

pub(crate) async fn list_by_org(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Vec<WebhookSubscriptionRow>, sqlx::Error> {
    sqlx::query_as!(
        WebhookSubscriptionRow,
        "SELECT id, org_id, url, events, secret, active, disabled_reason,
                   verification_status, verified_at, grandfathered,
                   verification_attempted_at, verification_error, created_at
         FROM webhook_subscriptions WHERE org_id = $1 ORDER BY created_at",
        org_id,
    )
    .fetch_all(pool)
    .await
}

pub(crate) async fn delete_subscription(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "DELETE FROM webhook_subscriptions WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub(crate) async fn find_matching_subscriptions(
    pool: &PgPool,
    org_id: Uuid,
    event: &str,
) -> Result<Vec<WebhookSubscriptionRow>, sqlx::Error> {
    sqlx::query_as!(
        WebhookSubscriptionRow,
        "SELECT id, org_id, url, events, secret, active, disabled_reason,
                   verification_status, verified_at, grandfathered,
                   verification_attempted_at, verification_error, created_at
         FROM webhook_subscriptions WHERE org_id = $1 AND active = true AND $2 = ANY(events)",
        org_id,
        event,
    )
    .fetch_all(pool)
    .await
}

pub(crate) async fn get_subscription(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
) -> Result<Option<WebhookSubscriptionRow>, sqlx::Error> {
    sqlx::query_as!(
        WebhookSubscriptionRow,
        "SELECT id, org_id, url, events, secret, active, disabled_reason,
                verification_status, verified_at, grandfathered,
                verification_attempted_at, verification_error, created_at
         FROM webhook_subscriptions WHERE id = $1 AND org_id = $2",
        id,
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// Record a successful ownership handshake: the subscription is `verified`
/// (no longer grandfathered — it has now proven ownership itself), and every
/// delivery held while it was pending is released to the retry sweep.
///
/// Only rows still carrying `url` are touched, so a handshake that raced a
/// URL change cannot verify the new URL on the old endpoint's say-so.
pub(crate) async fn mark_verified(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
    url: &str,
) -> Result<Option<WebhookSubscriptionRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query_as!(
        WebhookSubscriptionRow,
        "UPDATE webhook_subscriptions
            SET verification_status = 'verified', verified_at = now(), grandfathered = false,
                verification_attempted_at = now(), verification_error = NULL
          WHERE id = $1 AND org_id = $2 AND url = $3
          RETURNING id, org_id, url, events, secret, active, disabled_reason,
                    verification_status, verified_at, grandfathered,
                    verification_attempted_at, verification_error, created_at",
        id,
        org_id,
        url,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if row.is_some() {
        sqlx::query!(
            "UPDATE webhook_deliveries SET held_reason = NULL, next_retry_at = now()
              WHERE subscription_id = $1 AND held_reason IS NOT NULL AND delivered_at IS NULL",
            id,
        )
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(row)
}

/// Record a failed ownership handshake. The status is left alone: a pending
/// subscription stays pending, and a verified one stays verified — a blip on
/// a re-check must not cut a working consumer off.
pub(crate) async fn record_verification_failure(
    pool: &PgPool,
    id: Uuid,
    org_id: Uuid,
    error: &str,
) -> Result<Option<WebhookSubscriptionRow>, sqlx::Error> {
    sqlx::query_as!(
        WebhookSubscriptionRow,
        "UPDATE webhook_subscriptions
            SET verification_attempted_at = now(), verification_error = $3
          WHERE id = $1 AND org_id = $2
          RETURNING id, org_id, url, events, secret, active, disabled_reason,
                    verification_status, verified_at, grandfathered,
                    verification_attempted_at, verification_error, created_at",
        id,
        org_id,
        error,
    )
    .fetch_optional(pool)
    .await
}

pub(crate) async fn list_deliveries_for_subscription(
    pool: &PgPool,
    subscription_id: Uuid,
    org_id: Uuid,
    limit: i64,
) -> Result<Option<Vec<WebhookDeliveryRow>>, sqlx::Error> {
    // Run ownership check and the delivery fetch in a single transaction so a
    // concurrent delete cannot turn a 404 into an empty 200.
    let mut tx = pool.begin().await?;
    let owner = sqlx::query_scalar!(
        "SELECT org_id FROM webhook_subscriptions WHERE id = $1 FOR SHARE",
        subscription_id,
    )
    .fetch_optional(&mut *tx)
    .await?;
    if owner != Some(org_id) {
        return Ok(None);
    }
    let rows = sqlx::query_as!(
        WebhookDeliveryRow,
        "SELECT id, subscription_id, event, payload, status_code, response_body, attempts,
                next_retry_at, delivered_at, created_at, held_reason
         FROM webhook_deliveries WHERE subscription_id = $1
         ORDER BY created_at DESC LIMIT $2",
        subscription_id,
        limit,
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Some(rows))
}

pub(crate) async fn create_delivery(
    pool: &PgPool,
    subscription_id: Uuid,
    event: &str,
    payload: serde_json::Value,
    held_reason: Option<&str>,
) -> Result<WebhookDeliveryRow, sqlx::Error> {
    // A held row still gets `next_retry_at = now()`: the retry sweep only
    // picks rows whose subscription is verified, so it stays put until then —
    // and a row created in the instant a verification lands is picked up by
    // the next sweep instead of being stranded.
    sqlx::query_as!(
        WebhookDeliveryRow,
        "INSERT INTO webhook_deliveries (subscription_id, event, payload, next_retry_at, held_reason)
         VALUES ($1, $2, $3, now(), $4)
         RETURNING id, subscription_id, event, payload, status_code, response_body, attempts,
                   next_retry_at, delivered_at, created_at, held_reason",
        subscription_id,
        event,
        payload,
        held_reason,
    )
    .fetch_one(pool)
    .await
}

pub(crate) async fn mark_delivered(
    pool: &PgPool,
    id: Uuid,
    status_code: i32,
    body: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "UPDATE webhook_deliveries SET delivered_at = now(), status_code = $2, response_body = $3,
         attempts = attempts + 1, held_reason = NULL WHERE id = $1",
        id,
        status_code,
        body,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub(crate) async fn mark_failed(
    pool: &PgPool,
    id: Uuid,
    status_code: Option<i32>,
    error: &str,
) -> Result<(), sqlx::Error> {
    // Exponential backoff: 1m, 5m, 15m, 1h, 4h
    sqlx::query!(
        "UPDATE webhook_deliveries SET
           attempts = attempts + 1,
           status_code = $2,
           response_body = $3,
           held_reason = NULL,
           next_retry_at = now() + (INTERVAL '1 minute' * POWER(3, LEAST(attempts, 4)))
         WHERE id = $1",
        id,
        status_code,
        error,
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
pub struct PendingDeliveryRow {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub event: String,
    pub payload: serde_json::Value,
    pub attempts: i32,
    pub created_at: OffsetDateTime,
    pub org_id: Uuid,
    pub url: String,
    pub secret: String,
}

pub(crate) async fn get_pending_deliveries(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<PendingDeliveryRow>, sqlx::Error> {
    sqlx::query_as!(
        PendingDeliveryRow,
        "SELECT d.id, d.subscription_id, d.event, d.payload, d.attempts, d.created_at,
                s.org_id, s.url, s.secret
         FROM webhook_deliveries d
         JOIN webhook_subscriptions s ON d.subscription_id = s.id
         WHERE d.delivered_at IS NULL AND d.attempts < 5 AND d.next_retry_at <= now()
           AND s.active = true AND s.verification_status = 'verified'
         ORDER BY d.next_retry_at
         LIMIT $1",
        limit,
    )
    .fetch_all(pool)
    .await
}

/// One summarized failing endpoint inside an org's daily DLQ digest. Aggregates
/// every terminal-failure delivery row for a single subscription within the
/// caller's window. `last_error_excerpt` is pre-truncated at the SQL layer so
/// the email template can drop it in without re-clamping.
#[derive(Debug, sqlx::FromRow)]
pub struct DigestEndpointSummary {
    pub subscription_id: Uuid,
    pub url: String,
    pub attempt_count: i64,
    pub first_failure_at: OffsetDateTime,
    pub last_status_code: Option<i32>,
    pub last_error_excerpt: Option<String>,
}

/// Distinct org ids that have at least one *terminal* webhook delivery
/// (`delivered_at IS NULL AND attempts >= 5`) created since `since`, joined
/// against still-active subscriptions only. The digest loop uses this as the
/// candidate list before racing for the per-org claim row.
pub(crate) async fn list_org_ids_with_terminal_failures(
    pool: &PgPool,
    since: OffsetDateTime,
) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar!(
        "SELECT DISTINCT s.org_id
         FROM webhook_deliveries d
         JOIN webhook_subscriptions s ON d.subscription_id = s.id
         WHERE d.delivered_at IS NULL
           AND d.attempts >= 5
           AND s.active = true
           AND d.created_at > $1",
        since,
    )
    .fetch_all(pool)
    .await
}

/// Per-subscription summary of terminal failures for `org_id` since `since`.
/// One row per subscription. `last_error_excerpt` is the `response_body` of
/// the most recent failure, truncated to 200 chars. Inactive subscriptions
/// are excluded — a disabled endpoint shouldn't generate digest noise.
pub(crate) async fn summarize_terminal_failures_for_org(
    pool: &PgPool,
    org_id: Uuid,
    since: OffsetDateTime,
) -> Result<Vec<DigestEndpointSummary>, sqlx::Error> {
    sqlx::query_as!(
        DigestEndpointSummary,
        // Status code and error excerpt come from a single LATERAL join
        // so they're structurally guaranteed to be from the same row. The
        // previous shape used two independent correlated subqueries each
        // doing `ORDER BY created_at DESC LIMIT 1`, which could pick
        // different rows when two deliveries share the same `created_at`
        // (batch insert / high-load tie) and produce a mismatched pair.
        // `id DESC` is the additional tie-breaker inside the LATERAL so
        // the row picked is deterministic.
        r#"SELECT
             s.id AS "subscription_id!",
             s.url AS "url!",
             COUNT(*) AS "attempt_count!",
             MIN(d.created_at) AS "first_failure_at!",
             latest.status_code AS "last_status_code?",
             latest.last_error_excerpt AS "last_error_excerpt?"
           FROM webhook_deliveries d
           JOIN webhook_subscriptions s ON d.subscription_id = s.id
           LEFT JOIN LATERAL (
               SELECT d2.status_code, LEFT(d2.response_body, 200) AS last_error_excerpt
               FROM webhook_deliveries d2
               WHERE d2.subscription_id = s.id
                 AND d2.delivered_at IS NULL
                 AND d2.attempts >= 5
                 AND d2.created_at > $2
               ORDER BY d2.created_at DESC, d2.id DESC
               LIMIT 1
           ) latest ON true
           WHERE s.org_id = $1
             AND s.active = true
             AND d.delivered_at IS NULL
             AND d.attempts >= 5
             AND d.created_at > $2
           GROUP BY s.id, s.url, latest.status_code, latest.last_error_excerpt
           ORDER BY MIN(d.created_at)"#,
        org_id,
        since,
    )
    .fetch_all(pool)
    .await
}
