//! Integration coverage for `services::webhook_digest::run_once`.
//!
//! Drives the digest pass against the migrated test pool with a capturing
//! mailer. Asserts the six scenarios in the approved plan:
//!
//! 1. one terminal failure → digest reaches the admin only, not members;
//! 2. unsubscribed admin → skipped;
//! 3. two concurrent passes → exactly one digest claimed per (org, day);
//! 4. no failures in window → no digest, no claim row;
//! 5. inactive subscription → excluded even with recent failures;
//! 6. one-click unsubscribe with `purpose='webhook_digest'` → only the
//!    digest column flips; welcome opt-out is untouched.

// Tests rely on runtime `sqlx::query()` for setup so they can drop the
// compile-time DATABASE_URL dependency — matches `tests/common/mod.rs`.
#![allow(clippy::disallowed_methods)]

use crate::common;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use overslash_api::services::webhook_digest;
use overslash_core::email::mailer::EmailMessage;
use overslash_core::email::{Mailer, MailerError};
use overslash_db::repos::{user as user_repo, webhook_digest_run};
use sqlx::PgPool;
use time::{Date, OffsetDateTime};
use uuid::Uuid;

use crate::common::test_pool;

#[derive(Clone, Default)]
struct Capturing {
    sent: Arc<Mutex<Vec<EmailMessage>>>,
}

impl Capturing {
    fn new() -> Self {
        Self::default()
    }
    fn drain(&self) -> Vec<EmailMessage> {
        std::mem::take(&mut *self.sent.lock().unwrap())
    }
}

#[async_trait]
impl Mailer for Capturing {
    async fn send(&self, msg: EmailMessage) -> Result<(), MailerError> {
        self.sent.lock().unwrap().push(msg);
        Ok(())
    }
}

/// Insert an org. Returns the new id.
async fn make_org(pool: &PgPool, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug, is_personal) VALUES ($1, $2, $3, false)")
        .bind(id)
        .bind(name)
        .bind(format!("digest-test-{}", Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap();
    id
}

/// Insert a `users` row + `user_org_memberships` row with the given role.
async fn make_member(pool: &PgPool, org_id: Uuid, email: &str, role: &str) -> Uuid {
    let user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, display_name) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(email)
        .bind(email.split('@').next().unwrap())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO user_org_memberships (user_id, org_id, role) VALUES ($1, $2, $3)")
        .bind(user_id)
        .bind(org_id)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
    user_id
}

/// Insert a webhook subscription. Returns the subscription id.
async fn make_subscription(pool: &PgPool, org_id: Uuid, url: &str, active: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO webhook_subscriptions (id, org_id, url, events, secret, active)
         VALUES ($1, $2, $3, ARRAY['action.completed']::text[], 'whsec_test', $4)",
    )
    .bind(id)
    .bind(org_id)
    .bind(url)
    .bind(active)
    .execute(pool)
    .await
    .unwrap();
    id
}

/// Insert a terminal-failure delivery row (`attempts >= 5`, no `delivered_at`).
async fn make_terminal_delivery(
    pool: &PgPool,
    subscription_id: Uuid,
    status_code: i32,
    body: &str,
) {
    sqlx::query(
        "INSERT INTO webhook_deliveries
           (subscription_id, event, payload, status_code, response_body, attempts, delivered_at, next_retry_at)
         VALUES ($1, 'action.completed', '{}'::jsonb, $2, $3, 5, NULL, now() + interval '4 hours')",
    )
    .bind(subscription_id)
    .bind(status_code)
    .bind(body)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn sends_digest_to_admins_only_not_members() {
    let pool = test_pool().await;
    let org = make_org(&pool, "Acme").await;
    let admin = make_member(&pool, org, "admin@example.com", "admin").await;
    let _member = make_member(&pool, org, "member@example.com", "member").await;
    let sub = make_subscription(&pool, org, "https://hook.example.com/a", true).await;
    make_terminal_delivery(&pool, sub, 502, "bad gateway").await;

    let mailer = Capturing::new();
    let today = OffsetDateTime::now_utc().date();
    let sent_orgs = webhook_digest::run_once(&pool, &mailer, "http://api.test", today)
        .await
        .unwrap();
    assert_eq!(sent_orgs, 1);

    let sent = mailer.drain();
    assert_eq!(sent.len(), 1, "exactly one email per admin");
    assert_eq!(sent[0].to, "admin@example.com");
    assert!(sent[0].html.contains("hook.example.com/a"));
    assert!(sent[0].html.contains("502"));
    // RFC 8058 one-click unsubscribe headers must flow through the digest too.
    assert!(sent[0].headers.contains_key("List-Unsubscribe"));
    assert!(sent[0].headers.contains_key("List-Unsubscribe-Post"));

    // Claim row was written for today.
    let claim_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_digest_runs WHERE org_id = $1 AND run_date = $2",
    )
    .bind(org)
    .bind(today)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(claim_count, 1);
    let _ = admin; // silence unused
}

#[tokio::test]
async fn skips_unsubscribed_admin() {
    let pool = test_pool().await;
    let org = make_org(&pool, "Beta").await;
    let admin1 = make_member(&pool, org, "a1@example.com", "admin").await;
    let admin2 = make_member(&pool, org, "a2@example.com", "admin").await;
    // a2 has opted out of the digest specifically.
    user_repo::set_webhook_digest_unsubscribed(&pool, admin2, Some(OffsetDateTime::now_utc()))
        .await
        .unwrap();
    let sub = make_subscription(&pool, org, "https://hook.example.com/b", true).await;
    make_terminal_delivery(&pool, sub, 503, "service unavailable").await;

    let mailer = Capturing::new();
    let today = OffsetDateTime::now_utc().date();
    webhook_digest::run_once(&pool, &mailer, "http://api.test", today)
        .await
        .unwrap();

    let sent = mailer.drain();
    assert_eq!(sent.len(), 1, "only the subscribed admin gets email");
    assert_eq!(sent[0].to, "a1@example.com");
    let _ = admin1;
}

#[tokio::test]
async fn concurrent_passes_send_exactly_once() {
    let pool = test_pool().await;
    let org = make_org(&pool, "Gamma").await;
    let _admin = make_member(&pool, org, "ops@example.com", "admin").await;
    let sub = make_subscription(&pool, org, "https://hook.example.com/c", true).await;
    make_terminal_delivery(&pool, sub, 500, "boom").await;

    let mailer = Capturing::new();
    let today = OffsetDateTime::now_utc().date();
    let (a, b) = tokio::join!(
        webhook_digest::run_once(&pool, &mailer, "http://api.test", today),
        webhook_digest::run_once(&pool, &mailer, "http://api.test", today),
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a + b, 1, "exactly one pass won the claim");
    assert_eq!(mailer.drain().len(), 1);
}

#[tokio::test]
async fn no_failures_in_window_means_no_digest_no_claim() {
    let pool = test_pool().await;
    let org = make_org(&pool, "Delta").await;
    let _admin = make_member(&pool, org, "quiet@example.com", "admin").await;
    let _sub = make_subscription(&pool, org, "https://hook.example.com/d", true).await;
    // No deliveries → org isn't a candidate.

    let mailer = Capturing::new();
    let today = OffsetDateTime::now_utc().date();
    let sent_orgs = webhook_digest::run_once(&pool, &mailer, "http://api.test", today)
        .await
        .unwrap();
    assert_eq!(sent_orgs, 0);
    assert!(mailer.drain().is_empty());

    let claim_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM webhook_digest_runs WHERE org_id = $1 AND run_date = $2",
    )
    .bind(org)
    .bind(today)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(claim_count, 0, "no claim row written for quiet orgs");
}

#[tokio::test]
async fn inactive_subscription_is_excluded() {
    let pool = test_pool().await;
    let org = make_org(&pool, "Epsilon").await;
    let _admin = make_member(&pool, org, "boss@example.com", "admin").await;
    let sub = make_subscription(&pool, org, "https://hook.example.com/e", false).await;
    make_terminal_delivery(&pool, sub, 500, "should not surface").await;

    let mailer = Capturing::new();
    let today = OffsetDateTime::now_utc().date();
    let sent_orgs = webhook_digest::run_once(&pool, &mailer, "http://api.test", today)
        .await
        .unwrap();
    assert_eq!(sent_orgs, 0);
    assert!(mailer.drain().is_empty());
}

#[tokio::test]
async fn unsubscribe_redemption_flips_only_digest_column() {
    // End-to-end check: send the digest (which mints a `webhook_digest`
    // unsubscribe token), redeem the token through the *real* route, and
    // assert exactly the digest column flips — welcome opt-out must remain
    // NULL. Routing through `/v1/unsubscribe?token=...` exercises the
    // `match row.purpose` branch in `routes::unsubscribe::apply_unsubscribe`;
    // a swapped arm would mis-route the digest token to the welcome setter
    // and the welcome-column assertion below would catch it.
    let pool = test_pool().await;
    let (base, client, _guard) = common::start_api_shared(pool.clone()).await;
    let org = make_org(&pool, "Zeta").await;
    let admin = make_member(&pool, org, "redeemer@example.com", "admin").await;
    let sub = make_subscription(&pool, org, "https://hook.example.com/z", true).await;
    make_terminal_delivery(&pool, sub, 500, "expected").await;

    let mailer = Capturing::new();
    let today = OffsetDateTime::now_utc().date();
    webhook_digest::run_once(&pool, &mailer, &format!("http://{base}"), today)
        .await
        .unwrap();

    let token: Uuid = sqlx::query_scalar(
        "SELECT token FROM email_unsubscribe_tokens
         WHERE user_id = $1 AND purpose = 'webhook_digest'",
    )
    .bind(admin)
    .fetch_one(&pool)
    .await
    .unwrap();

    let resp = client
        .post(format!("http://{base}/v1/unsubscribe?token={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    let row = user_repo::get_by_id(&pool, admin).await.unwrap().unwrap();
    assert!(
        row.webhook_digest_unsubscribed_at.is_some(),
        "digest column must flip for a webhook_digest-purpose token"
    );
    assert!(
        row.welcome_emails_unsubscribed_at.is_none(),
        "welcome column must not be touched by digest unsubscribe"
    );
}

#[tokio::test]
async fn same_timestamp_failures_produce_matched_status_and_body() {
    // Two terminal-failure rows sharing the exact same `created_at` on a
    // single subscription. The summary picks "the most recent failure" for
    // `last_status_code` + `last_error_excerpt`, so without a deterministic
    // tie-breaker the two values could come from different rows. Assert
    // they came from the *same* row (the summary's reported status+body
    // pair matches one of the two inserted rows verbatim).
    let pool = test_pool().await;
    let org = make_org(&pool, "TimestampTie").await;
    let _admin = make_member(&pool, org, "tie@example.com", "admin").await;
    let sub = make_subscription(&pool, org, "https://hook.example.com/tie", true).await;

    let same_ts = OffsetDateTime::now_utc() - time::Duration::hours(1);
    sqlx::query(
        "INSERT INTO webhook_deliveries
           (subscription_id, event, payload, status_code, response_body, attempts, delivered_at, next_retry_at, created_at)
         VALUES ($1, 'action.completed', '{}'::jsonb, 502, 'bad gateway A', 5, NULL, $2 + interval '4 hours', $2),
                ($1, 'action.completed', '{}'::jsonb, 503, 'unavailable B',  5, NULL, $2 + interval '4 hours', $2)",
    )
    .bind(sub)
    .bind(same_ts)
    .execute(&pool)
    .await
    .unwrap();

    let mailer = Capturing::new();
    let today = OffsetDateTime::now_utc().date();
    webhook_digest::run_once(&pool, &mailer, "http://api.test", today)
        .await
        .unwrap();

    let sent = mailer.drain();
    assert_eq!(sent.len(), 1);
    let html = &sent[0].html;
    let has_a = html.contains("502") && html.contains("bad gateway A");
    let has_b = html.contains("503") && html.contains("unavailable B");
    assert!(
        has_a ^ has_b,
        "summary must pick one row's status+body pair (xor) \u{2014} html was:\n{html}"
    );
}

/// Sanity guard: `try_claim` is exposed for the test to verify race semantics
/// directly, independent of the run_once orchestration.
#[tokio::test]
async fn try_claim_is_atomic() {
    let pool = test_pool().await;
    let org = make_org(&pool, "Race").await;
    let today: Date = OffsetDateTime::now_utc().date();

    let a = webhook_digest_run::try_claim(&pool, org, today)
        .await
        .unwrap();
    let b = webhook_digest_run::try_claim(&pool, org, today)
        .await
        .unwrap();
    assert!(a, "first caller wins");
    assert!(!b, "second caller loses");

    // Tomorrow is a separate slot.
    let tomorrow = today + time::Duration::days(1);
    let c = webhook_digest_run::try_claim(&pool, org, tomorrow)
        .await
        .unwrap();
    assert!(c);
}
