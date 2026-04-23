use hmac::{Hmac, Mac, digest::KeyInit};
use sha2::Sha256;
use sqlx::PgPool;
use uuid::Uuid;

use overslash_db::{OrgScope, SystemScope};

type HmacSha256 = Hmac<Sha256>;

/// Dispatch a webhook event to all matching subscriptions for the org.
///
/// Resolving subscriptions is bounded to the caller's org and therefore
/// lives on `OrgScope`. Creating the per-delivery rows and updating their
/// status runs on the system dispatcher, so it uses `SystemScope`.
pub async fn dispatch(
    pool: &PgPool,
    http_client: &reqwest::Client,
    org_id: Uuid,
    event: &str,
    payload: serde_json::Value,
) {
    let org = OrgScope::new(org_id, pool.clone());
    let system = SystemScope::new_internal(pool.clone());
    let subs = match org.find_matching_webhook_subscriptions(event).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to find webhook subscriptions: {e}");
            return;
        }
    };

    for sub in subs {
        let delivery = match system
            .create_webhook_delivery(sub.id, event, payload.clone())
            .await
        {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("Failed to create webhook delivery: {e}");
                continue;
            }
        };

        deliver(
            pool,
            http_client,
            delivery.id,
            &sub.url,
            &sub.secret,
            &payload,
        )
        .await;
    }
}

/// Attempt to deliver a single webhook.
async fn deliver(
    pool: &PgPool,
    http_client: &reqwest::Client,
    delivery_id: Uuid,
    url: &str,
    secret: &str,
    payload: &serde_json::Value,
) {
    let body = serde_json::to_string(payload).unwrap_or_default();

    // HMAC-SHA256 signature
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(body.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let result = http_client
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Overslash-Signature", format!("sha256={signature}"))
        .body(body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    let system = SystemScope::new_internal(pool.clone());
    match result {
        Ok(resp) => {
            let status = resp.status().as_u16() as i32;
            let body = resp.text().await.unwrap_or_default();
            if (200..300).contains(&(status as u16).into()) {
                let _ = system
                    .mark_webhook_delivered(delivery_id, status, &body)
                    .await;
            } else {
                let _ = system
                    .mark_webhook_failed(delivery_id, Some(status), &body)
                    .await;
            }
        }
        Err(e) => {
            let _ = system
                .mark_webhook_failed(delivery_id, None, &e.to_string())
                .await;
        }
    }
}

/// Background task: retry failed webhook deliveries.
pub async fn spawn_retry_loop(pool: PgPool, http_client: reqwest::Client) {
    let system = SystemScope::new_internal(pool.clone());
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        let pending = match system.get_pending_webhook_deliveries(20).await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Webhook retry query failed: {e}");
                continue;
            }
        };

        for row in pending {
            deliver(
                &pool,
                &http_client,
                row.id,
                &row.url,
                &row.secret,
                &row.payload,
            )
            .await;
        }
    }
}
