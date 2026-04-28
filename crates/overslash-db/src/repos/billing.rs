use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct PendingCheckout {
    pub id: String,
    pub user_id: Uuid,
    pub org_name: String,
    pub org_slug: String,
    pub seats: i32,
    pub currency: String,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub fulfilled_org_id: Option<Uuid>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct OrgSubscription {
    pub org_id: Uuid,
    pub stripe_subscription_id: String,
    pub stripe_customer_id: String,
    pub plan: String,
    pub seats: i32,
    pub status: String,
    pub currency: String,
    pub current_period_start: Option<OffsetDateTime>,
    pub current_period_end: Option<OffsetDateTime>,
    pub cancel_at_period_end: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

pub async fn get_stripe_customer(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query!(
        "SELECT stripe_customer_id FROM users WHERE id = $1",
        user_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|r| r.stripe_customer_id))
}

pub async fn set_stripe_customer(
    pool: &PgPool,
    user_id: Uuid,
    customer_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE users SET stripe_customer_id = $2, updated_at = now() WHERE id = $1",
        user_id,
        customer_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn insert_pending_checkout(
    pool: &PgPool,
    session_id: &str,
    user_id: Uuid,
    org_name: &str,
    org_slug: &str,
    seats: i32,
    currency: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO pending_checkouts (id, user_id, org_name, org_slug, seats, currency)
         VALUES ($1, $2, $3, $4, $5, $6)",
        session_id,
        user_id,
        org_name,
        org_slug,
        seats,
        currency,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_pending_checkout(
    pool: &PgPool,
    session_id: &str,
) -> Result<Option<PendingCheckout>, sqlx::Error> {
    sqlx::query_as!(
        PendingCheckout,
        "SELECT id, user_id, org_name, org_slug, seats, currency, created_at, expires_at, fulfilled_org_id
         FROM pending_checkouts
         WHERE id = $1 AND expires_at > now()",
        session_id,
    )
    .fetch_optional(pool)
    .await
}

/// Get a pending checkout regardless of expiry (used by status polling to show
/// fulfilled state even if the row has technically expired).
pub async fn get_pending_checkout_any(
    pool: &PgPool,
    session_id: &str,
) -> Result<Option<PendingCheckout>, sqlx::Error> {
    sqlx::query_as!(
        PendingCheckout,
        "SELECT id, user_id, org_name, org_slug, seats, currency, created_at, expires_at, fulfilled_org_id
         FROM pending_checkouts
         WHERE id = $1",
        session_id,
    )
    .fetch_optional(pool)
    .await
}

pub async fn fulfill_pending_checkout(
    pool: &PgPool,
    session_id: &str,
    org_id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE pending_checkouts SET fulfilled_org_id = $2 WHERE id = $1",
        session_id,
        org_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

pub struct UpsertSubscription<'a> {
    pub stripe_subscription_id: &'a str,
    pub stripe_customer_id: &'a str,
    pub seats: i32,
    pub status: &'a str,
    pub currency: &'a str,
    pub current_period_start: Option<OffsetDateTime>,
    pub current_period_end: Option<OffsetDateTime>,
    pub cancel_at_period_end: bool,
}

pub async fn upsert_org_subscription(
    pool: &PgPool,
    org_id: Uuid,
    sub: UpsertSubscription<'_>,
) -> Result<(), sqlx::Error> {
    let UpsertSubscription {
        stripe_subscription_id,
        stripe_customer_id,
        seats,
        status,
        currency,
        current_period_start,
        current_period_end,
        cancel_at_period_end,
    } = sub;
    sqlx::query!(
        "INSERT INTO org_subscriptions (
            org_id, stripe_subscription_id, stripe_customer_id, seats, status,
            currency, current_period_start, current_period_end, cancel_at_period_end
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (org_id) DO UPDATE SET
            stripe_subscription_id = EXCLUDED.stripe_subscription_id,
            stripe_customer_id = EXCLUDED.stripe_customer_id,
            seats = EXCLUDED.seats,
            status = EXCLUDED.status,
            currency = EXCLUDED.currency,
            current_period_start = EXCLUDED.current_period_start,
            current_period_end = EXCLUDED.current_period_end,
            cancel_at_period_end = EXCLUDED.cancel_at_period_end,
            updated_at = now()",
        org_id,
        stripe_subscription_id,
        stripe_customer_id,
        seats,
        status,
        currency,
        current_period_start,
        current_period_end,
        cancel_at_period_end,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_org_subscription(
    pool: &PgPool,
    org_id: Uuid,
) -> Result<Option<OrgSubscription>, sqlx::Error> {
    sqlx::query_as!(
        OrgSubscription,
        "SELECT org_id, stripe_subscription_id, stripe_customer_id, plan, seats, status,
                currency, current_period_start, current_period_end, cancel_at_period_end,
                created_at, updated_at
         FROM org_subscriptions WHERE org_id = $1",
        org_id,
    )
    .fetch_optional(pool)
    .await
}

/// Update subscription from a Stripe subscription object (lifecycle events).
pub async fn update_subscription_status(
    pool: &PgPool,
    stripe_subscription_id: &str,
    status: &str,
    seats: i32,
    current_period_start: Option<OffsetDateTime>,
    current_period_end: Option<OffsetDateTime>,
    cancel_at_period_end: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE org_subscriptions SET
            status = $2,
            seats = $3,
            current_period_start = $4,
            current_period_end = $5,
            cancel_at_period_end = $6,
            updated_at = now()
         WHERE stripe_subscription_id = $1",
        stripe_subscription_id,
        status,
        seats,
        current_period_start,
        current_period_end,
        cancel_at_period_end,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Cancel a subscription by Stripe subscription ID.
pub async fn cancel_subscription(
    pool: &PgPool,
    stripe_subscription_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query!(
        "UPDATE org_subscriptions SET status = 'canceled', updated_at = now()
         WHERE stripe_subscription_id = $1",
        stripe_subscription_id,
    )
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
