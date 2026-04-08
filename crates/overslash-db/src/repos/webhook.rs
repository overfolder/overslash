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
    pub created_at: OffsetDateTime,
}

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
         RETURNING id, org_id, url, events, secret, active, created_at",
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
        "SELECT id, org_id, url, events, secret, active, created_at
         FROM webhook_subscriptions WHERE org_id = $1 AND active = true ORDER BY created_at",
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
        "SELECT id, org_id, url, events, secret, active, created_at
         FROM webhook_subscriptions WHERE org_id = $1 AND active = true AND $2 = ANY(events)",
        org_id,
        event,
    )
    .fetch_all(pool)
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
                next_retry_at, delivered_at, created_at
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
) -> Result<WebhookDeliveryRow, sqlx::Error> {
    sqlx::query_as!(
        WebhookDeliveryRow,
        "INSERT INTO webhook_deliveries (subscription_id, event, payload, next_retry_at)
         VALUES ($1, $2, $3, now())
         RETURNING id, subscription_id, event, payload, status_code, response_body, attempts, next_retry_at, delivered_at, created_at",
        subscription_id,
        event,
        payload,
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
         attempts = attempts + 1 WHERE id = $1",
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
    pub url: String,
    pub secret: String,
}

pub(crate) async fn get_pending_deliveries(
    pool: &PgPool,
    limit: i64,
) -> Result<Vec<PendingDeliveryRow>, sqlx::Error> {
    sqlx::query_as!(
        PendingDeliveryRow,
        "SELECT d.id, d.subscription_id, d.event, d.payload, d.attempts, s.url, s.secret
         FROM webhook_deliveries d
         JOIN webhook_subscriptions s ON d.subscription_id = s.id
         WHERE d.delivered_at IS NULL AND d.attempts < 5 AND d.next_retry_at <= now()
         ORDER BY d.next_retry_at
         LIMIT $1",
        limit,
    )
    .fetch_all(pool)
    .await
}
