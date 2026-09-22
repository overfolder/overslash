use hmac::{Hmac, Mac, digest::KeyInit};
use serde_json::json;
use sha2::Sha256;
use sqlx::PgPool;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use overslash_db::{OrgScope, SystemScope};

type HmacSha256 = Hmac<Sha256>;

/// Dispatch a webhook event to all matching subscriptions for the org.
///
/// Resolving subscriptions is bounded to the caller's org and therefore
/// lives on `OrgScope`. Creating the per-delivery rows and updating their
/// status runs on the system dispatcher, so it uses `SystemScope`.
pub async fn dispatch(pool: &PgPool, org_id: Uuid, event: &str, payload: serde_json::Value) {
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

        // Use the JSONB-roundtripped payload from the row (not the original
        // in-memory `payload`) so the first attempt and any retries serialize
        // — and therefore sign — identically. Postgres JSONB does not
        // preserve insertion order; both code paths must read through it.
        let envelope = build_envelope(delivery.id, event, delivery.created_at, &delivery.payload);

        deliver(
            pool,
            delivery.id,
            &sub.url,
            &sub.secret,
            &envelope,
            event,
            1,
        )
        .await;
    }
}

/// Build the stable webhook envelope: `{id, type, created_at, data}`.
///
/// Used by both first-attempt and retry paths so replays are byte-identical
/// (same id, same created_at, same signature).
fn build_envelope(
    delivery_id: Uuid,
    event: &str,
    created_at: OffsetDateTime,
    payload: &serde_json::Value,
) -> serde_json::Value {
    let created_at = created_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::new());
    json!({
        "id": delivery_id,
        "type": event,
        "created_at": created_at,
        "data": payload,
    })
}

/// Attempt to deliver a single webhook.
///
/// The URL is registrant-supplied, so it goes through the SSRF guard on every
/// attempt: resolve, refuse private / loopback / link-local answers, pin the
/// validated IP, and no redirects. Without that this function is an SSRF
/// oracle — it records the response status *and* body on the delivery row,
/// which the dashboard then shows back to whoever registered the endpoint.
/// A refusal is a terminal-shaped failure recorded like any other: it will be
/// retried, and it will be refused again, because the address is the problem.
///
/// Connection-hold invariant: this takes the `pool` (an `Arc`-cheap handle),
/// **not** a checked-out `PoolConnection`, and never acquires a DB connection
/// before the outbound HTTP `send()` below. The only DB work — marking the
/// delivery delivered/failed via `SystemScope` — happens *after* the network
/// round-trip completes and each query acquires+releases its own connection.
/// So a slow/hung webhook endpoint can never pin a pool connection across the
/// (up to 10s) HTTP call. Keep it that way: do not thread a `PoolConnection`
/// or open a transaction that spans the `send()`.
#[allow(clippy::too_many_arguments)]
async fn deliver(
    pool: &PgPool,
    delivery_id: Uuid,
    url: &str,
    secret: &str,
    envelope: &serde_json::Value,
    event_type: &str,
    attempt: u32,
) {
    let body = serde_json::to_string(envelope).unwrap_or_default();

    // HMAC-SHA256 signature over the raw body bytes (the envelope JSON).
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(body.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    let system = SystemScope::new_internal(pool.clone());

    let http_client = match crate::services::ssrf_guard::outbound_client(url).await {
        Ok((client, _)) => client,
        Err(e) => {
            let _ = system
                .mark_webhook_failed(delivery_id, None, &e.to_string())
                .await;
            record_failed_attempt(event_type, attempt);
            return;
        }
    };

    let result = http_client
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Overslash-Event", event_type)
        .header("X-Overslash-Delivery", delivery_id.to_string())
        .header("X-Overslash-Signature", format!("sha256={signature}"))
        .body(body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status = resp.status().as_u16() as i32;
            let body = resp.text().await.unwrap_or_default();
            if (200..300).contains(&(status as u16).into()) {
                let _ = system
                    .mark_webhook_delivered(delivery_id, status, &body)
                    .await;
                overslash_metrics::webhooks::record_delivery(event_type, "success", true);
                overslash_metrics::webhooks::record_attempts(event_type, "success", attempt);
            } else {
                let _ = system
                    .mark_webhook_failed(delivery_id, Some(status), &body)
                    .await;
                record_failed_attempt(event_type, attempt);
            }
        }
        Err(e) => {
            let _ = system
                .mark_webhook_failed(delivery_id, None, &e.to_string())
                .await;
            record_failed_attempt(event_type, attempt);
        }
    }
}

/// Metrics for one delivery attempt that did not succeed — refused by the
/// guard, refused by the network, or answered with a non-2xx. One place, so
/// the three failure shapes can't drift into labelling themselves differently.
fn record_failed_attempt(event_type: &str, attempt: u32) {
    let exhausted = attempt >= MAX_DELIVERY_ATTEMPTS;
    let status_label = if exhausted { "failed" } else { "retry" };
    overslash_metrics::webhooks::record_delivery(event_type, status_label, exhausted);
    if exhausted {
        overslash_metrics::webhooks::record_attempts(event_type, "exhausted", attempt);
    }
}

/// Mirrors the `attempts < 5` filter in `get_pending_deliveries`. Once the
/// stored attempt counter reaches this number, the retry loop will stop
/// picking the row up; further delivery attempts are also terminal.
const MAX_DELIVERY_ATTEMPTS: u32 = 5;

/// Background task: retry failed webhook deliveries.
pub async fn spawn_retry_loop(pool: PgPool) {
    let system = SystemScope::new_internal(pool.clone());
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        let start = std::time::Instant::now();
        let pending = match system.get_pending_webhook_deliveries(20).await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Webhook retry query failed: {e}");
                overslash_metrics::background::record_tick("webhook_retry", "err", start.elapsed());
                continue;
            }
        };

        let status = if pending.is_empty() { "noop" } else { "ok" };
        for row in pending {
            let envelope = build_envelope(row.id, &row.event, row.created_at, &row.payload);
            deliver(
                &pool,
                row.id,
                &row.url,
                &row.secret,
                &envelope,
                &row.event,
                (row.attempts as u32).saturating_add(1),
            )
            .await;
        }
        overslash_metrics::background::record_tick("webhook_retry", status, start.elapsed());
        overslash_metrics::background::set_last_success("webhook_retry");
    }
}
