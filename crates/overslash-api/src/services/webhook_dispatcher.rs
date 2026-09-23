use hmac::{Hmac, Mac, digest::KeyInit};
use serde_json::json;
use sha2::Sha256;
use sqlx::PgPool;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use overslash_db::repos::webhook::{HELD_PENDING_VERIFICATION, VERIFIED};
use overslash_db::{OrgScope, SystemScope};

use crate::error::AppError;
use crate::services::https_policy::{self, HttpsUrl};

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
        // CASA 7.1.2: nothing is sent to an endpoint that has not proven
        // ownership. The event is not dropped either — it is recorded as a
        // held delivery (visible in the delivery history) and released to the
        // retry sweep when the subscription verifies.
        let held = (sub.verification_status != VERIFIED).then_some(HELD_PENDING_VERIFICATION);
        let delivery = match system
            .create_webhook_delivery(sub.id, event, payload.clone(), held)
            .await
        {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("Failed to create webhook delivery: {e}");
                continue;
            }
        };
        if held.is_some() {
            overslash_metrics::webhooks::record_delivery(event, "held", false);
            continue;
        }

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
/// The same goes for a plain `http://` URL anywhere but loopback (CASA 7.1.1):
/// the attempt is recorded as failed with the reason, and nothing is sent.
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
    let system = SystemScope::new_internal(pool.clone());
    let result = send_signed(url, secret, event_type, delivery_id, body).await;

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
        Err(reason) => {
            let _ = system.mark_webhook_failed(delivery_id, None, &reason).await;
            record_failed_attempt(event_type, attempt);
        }
    }
}

/// How long one outbound webhook request — delivery or verification — may
/// take, host resolution included.
const ATTEMPT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// Sign `body` with the subscription secret and POST it to `url`: HTTPS-only
/// (CASA 7.1.1), through the SSRF guard (7.3.1), one deadline over resolution
/// and request. Shared by event delivery and the ownership handshake, so the
/// handshake can never reach an address a delivery could not.
///
/// `Err` carries the reason as text — a guard refusal, a transport failure or
/// the deadline — ready to be recorded where the registrant can read it.
async fn send_signed(
    url: &str,
    secret: &str,
    event_type: &str,
    delivery_id: Uuid,
    body: String,
) -> Result<reqwest::Response, String> {
    // HMAC-SHA256 signature over the raw body bytes (the envelope JSON).
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(body.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    // One deadline over resolution *and* the request. The guard looks the host
    // up before a client with a timeout exists, so a `RequestBuilder::timeout`
    // alone would leave the lookup outside the deadline this promises.
    let sent = tokio::time::timeout(ATTEMPT_DEADLINE, async {
        // CASA 7.1.1: never sign a payload onto the wire in the clear.
        // Registration already refuses `http://`, so this only fires for a
        // row that predates that check or was written around it — checked
        // twice: from the string before any lookup, then against the address
        // the guard actually pinned, so `localhost` resolving elsewhere
        // cannot slip through either.
        HttpsUrl::parse(url)
            .map_err(|e| AppError::BadRequest(format!("webhook delivery refused: {e}")))?;
        let (http_client, parsed, ip) =
            crate::services::ssrf_guard::outbound_client_validated(url).await?;
        if !https_policy::scheme_allowed(parsed.scheme(), &ip) {
            return Err(AppError::BadRequest(format!(
                "webhook delivery refused: plain http is only accepted to loopback (resolved {ip})"
            )));
        }
        http_client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-Overslash-Event", event_type)
            .header("X-Overslash-Delivery", delivery_id.to_string())
            .header("X-Overslash-Signature", format!("sha256={signature}"))
            .body(body)
            .send()
            .await
            .map_err(|e| AppError::BadGateway(e.to_string()))
    })
    .await;

    match sent {
        Ok(Ok(resp)) => Ok(resp),
        // A refusal by the guard and a transport failure land the same way:
        // no status, the reason as text. The distinction that matters to a
        // registrant — "we would not dial this" versus "it did not answer" —
        // is in the text.
        Ok(Err(e)) => Err(e.to_string()),
        Err(_elapsed) => Err(format!(
            "webhook request did not complete within {}s",
            ATTEMPT_DEADLINE.as_secs()
        )),
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

/// Background task: retry failed webhook deliveries, and send the ones held
/// while their subscription awaited verification once it has verified.
pub async fn spawn_retry_loop(pool: PgPool) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;

        let start = std::time::Instant::now();
        match retry_pending_once(&pool).await {
            Ok(attempted) => {
                let status = if attempted == 0 { "noop" } else { "ok" };
                overslash_metrics::background::record_tick(
                    "webhook_retry",
                    status,
                    start.elapsed(),
                );
                overslash_metrics::background::set_last_success("webhook_retry");
            }
            Err(e) => {
                tracing::error!("Webhook retry query failed: {e}");
                overslash_metrics::background::record_tick("webhook_retry", "err", start.elapsed());
            }
        }
    }
}

/// One sweep of the retry loop: attempt up to 20 due deliveries on verified
/// subscriptions. Returns how many were attempted. Public so tests can drive
/// a sweep without waiting on the loop's timer.
pub async fn retry_pending_once(pool: &PgPool) -> Result<usize, sqlx::Error> {
    let system = SystemScope::new_internal(pool.clone());
    let pending = system.get_pending_webhook_deliveries(20).await?;
    let attempted = pending.len();
    for row in pending {
        let envelope = build_envelope(row.id, &row.event, row.created_at, &row.payload);
        deliver(
            pool,
            row.id,
            &row.url,
            &row.secret,
            &envelope,
            &row.event,
            (row.attempts as u32).saturating_add(1),
        )
        .await;
    }
    Ok(attempted)
}

// ── Endpoint-ownership handshake (CASA 7.1.2) ───────────────────────

/// Event type of the ownership challenge. Never a subscribable event: it is
/// sent once per handshake, to one endpoint, outside the delivery tables.
pub const VERIFICATION_EVENT: &str = "webhook.verification";

/// The most of a verification response we read. A correct echo is a
/// 64-character challenge, bare or in a small JSON object.
const VERIFICATION_BODY_CAP: usize = 4096;

/// Prove the registrant controls `url` before anything is delivered to it.
///
/// POSTs a signed `webhook.verification` envelope — the same shape, headers
/// and signature as every event — whose `data.challenge` is 32 fresh random
/// bytes, hex. The endpoint passes by answering 2xx with the challenge echoed
/// back, either as the whole body (`text/plain`, surrounding whitespace
/// ignored) or as `{"challenge": "<value>"}`. Anything else fails.
///
/// The request goes through [`send_signed`] — HTTPS-only, SSRF-guarded, one
/// 10s deadline — so a handshake reaches nothing a delivery could not. The
/// `Err` text is shown to the registrant and never includes the response
/// body, so a failed handshake cannot be used to read what an address says.
///
/// Like [`deliver`], this takes no DB connection: the caller records the
/// outcome after the round trip.
pub async fn verify_endpoint(url: &str, secret: &str) -> Result<(), String> {
    use rand::RngExt;
    let mut challenge = [0u8; 32];
    rand::rng().fill(&mut challenge);
    let challenge = hex::encode(challenge);

    let id = Uuid::new_v4();
    let envelope = build_envelope(
        id,
        VERIFICATION_EVENT,
        OffsetDateTime::now_utc(),
        &json!({ "challenge": challenge }),
    );
    let body = serde_json::to_string(&envelope).unwrap_or_default();

    let mut resp = send_signed(url, secret, VERIFICATION_EVENT, id, body).await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!(
            "endpoint answered HTTP {} — expected a 2xx echoing the challenge",
            status.as_u16()
        ));
    }

    let mut received = Vec::new();
    let read = tokio::time::timeout(ATTEMPT_DEADLINE, async {
        while let Some(chunk) = resp.chunk().await? {
            received.extend_from_slice(&chunk);
            if received.len() > VERIFICATION_BODY_CAP {
                break;
            }
        }
        Ok::<_, reqwest::Error>(())
    })
    .await;
    match read {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("reading the endpoint's answer failed: {e}")),
        Err(_) => {
            return Err(format!(
                "the endpoint's answer did not complete within {}s",
                ATTEMPT_DEADLINE.as_secs()
            ));
        }
    }
    if received.len() > VERIFICATION_BODY_CAP {
        return Err(format!(
            "endpoint answered with more than {VERIFICATION_BODY_CAP} bytes — expected only the challenge"
        ));
    }

    if echoed_challenge(&received).is_some_and(|echo| echo == challenge) {
        Ok(())
    } else {
        Err("endpoint answered 2xx but did not echo the challenge".to_string())
    }
}

/// The challenge a verification response carries: `{"challenge": "..."}`, or
/// else the whole body as text with surrounding whitespace trimmed.
fn echoed_challenge(body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?.trim();
    if let Ok(serde_json::Value::Object(obj)) = serde_json::from_str::<serde_json::Value>(text) {
        return obj
            .get("challenge")
            .and_then(|c| c.as_str())
            .map(str::to_string);
    }
    Some(text.to_string())
}

#[cfg(test)]
mod tests {
    use super::echoed_challenge;

    #[test]
    fn echo_is_read_from_json_or_plain_text() {
        assert_eq!(
            echoed_challenge(br#"{"challenge":"abc"}"#).as_deref(),
            Some("abc")
        );
        assert_eq!(echoed_challenge(b"  abc\n").as_deref(), Some("abc"));
        // A JSON object without the key is not a plain-text echo of itself.
        assert_eq!(echoed_challenge(br#"{"ok":true}"#), None);
        assert_eq!(echoed_challenge(br#"{"challenge":42}"#), None);
        assert_eq!(echoed_challenge(&[0xff, 0xfe]), None);
    }
}
