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
            org_id,
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
/// Used by both first-attempt and retry paths so every attempt's body is
/// byte-identical (same id, same created_at, same legacy signature). The
/// `v1` signature still differs per attempt: it covers the attempt's own
/// timestamp.
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
    org_id: Uuid,
    delivery_id: Uuid,
    url: &str,
    secret: &str,
    envelope: &serde_json::Value,
    event_type: &str,
    attempt: u32,
) {
    let body = serde_json::to_string(envelope).unwrap_or_default();
    let system = SystemScope::new_internal(pool.clone());
    // One deadline over the request *and* the response body: the pinned
    // client has no total timeout, so an endpoint that sent its headers and
    // then stalled would otherwise hold this attempt — and the sequential
    // retry sweep behind it — forever.
    let result = tokio::time::timeout(ATTEMPT_DEADLINE, async {
        let mut resp = send_signed(url, secret, org_id, event_type, delivery_id, body).await?;
        let status = resp.status().as_u16() as i32;
        let mut kept = Vec::new();
        // Keep what fits in the cap and stop reading; the rest is the
        // receiver's business, not ours to store.
        while kept.len() < DELIVERY_BODY_CAP {
            match resp.chunk().await {
                Ok(Some(chunk)) => kept.extend_from_slice(&chunk),
                Ok(None) | Err(_) => break,
            }
        }
        kept.truncate(DELIVERY_BODY_CAP);
        Ok::<_, String>((status, String::from_utf8_lossy(&kept).into_owned()))
    })
    .await
    .unwrap_or_else(|_elapsed| {
        Err(format!(
            "webhook delivery did not complete within {}s",
            ATTEMPT_DEADLINE.as_secs()
        ))
    });

    match result {
        Ok((status, body)) => {
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

/// How long one outbound webhook exchange — delivery or verification — may
/// take, host resolution and the response body included.
const ATTEMPT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// The most of a delivery's response body we keep on the delivery row.
const DELIVERY_BODY_CAP: usize = 16 * 1024;

/// Sign `body` with the subscription secret — see [`sign`] — and POST it to `url`: HTTPS-only
/// (CASA 7.1.1), through the SSRF guard (7.3.1), one deadline over resolution
/// and request. Shared by event delivery and the ownership handshake, so the
/// handshake can never reach an address a delivery could not.
///
/// `Err` carries the reason as text — a guard refusal, a transport failure or
/// the deadline — ready to be recorded where the registrant can read it.
async fn send_signed(
    url: &str,
    secret: &str,
    org_id: Uuid,
    event_type: &str,
    delivery_id: Uuid,
    body: String,
) -> Result<reqwest::Response, String> {
    // Signed per attempt, not per delivery: a retry carries the same body but
    // a fresh timestamp, so it lands inside the receiver's tolerance window
    // while a captured earlier attempt does not (CASA 7.2.3).
    let signature = sign(secret, OffsetDateTime::now_utc().unix_timestamp(), &body);

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
            // The org that registered the subscription, so a receiver serving
            // several orgs can pick the secret to check before verifying, and
            // one serving only its own can refuse a stranger's challenge.
            .header("X-Overslash-Org", org_id.to_string())
            .header("X-Overslash-Event", event_type)
            .header("X-Overslash-Delivery", delivery_id.to_string())
            .header(TIMESTAMP_HEADER, signature.timestamp.to_string())
            .header(SIGNATURE_V1_HEADER, signature.v1)
            .header(LEGACY_SIGNATURE_HEADER, signature.legacy)
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

/// Unix seconds at which the attempt was signed — the `<timestamp>` inside
/// the `v1` signature.
pub const TIMESTAMP_HEADER: &str = "X-Overslash-Timestamp";

/// `v1=<hex>`: HMAC-SHA256 over `"<timestamp>.<raw body>"`. The scheme prefix
/// lets a later scheme, or a second `v1` during secret rotation, share the
/// header as a comma-separated list; a verifier accepts if any `v1` matches.
pub const SIGNATURE_V1_HEADER: &str = "X-Overslash-Signature-V1";

/// `sha256=<hex>`: HMAC-SHA256 over the raw body alone. No time component, so
/// it replays forever — kept, byte-for-byte as before, only so verifiers
/// written against it keep working. Deprecated; see TECH_DEBT.md.
pub const LEGACY_SIGNATURE_HEADER: &str = "X-Overslash-Signature";

/// The signature headers of one attempt.
#[derive(Debug, PartialEq, Eq)]
pub struct Signature {
    pub timestamp: i64,
    /// Value of [`SIGNATURE_V1_HEADER`].
    pub v1: String,
    /// Value of [`LEGACY_SIGNATURE_HEADER`].
    pub legacy: String,
}

/// Sign `body` as sent at `timestamp`. Pure, so the wire format is pinned by
/// unit tests without a receiver.
pub fn sign(secret: &str, timestamp: i64, body: &str) -> Signature {
    let hmac = |parts: &[&[u8]]| {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
        for p in parts {
            mac.update(p);
        }
        hex::encode(mac.finalize().into_bytes())
    };
    let ts = timestamp.to_string();
    Signature {
        timestamp,
        v1: format!("v1={}", hmac(&[ts.as_bytes(), b".", body.as_bytes()])),
        legacy: format!("sha256={}", hmac(&[body.as_bytes()])),
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
            row.org_id,
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
/// bytes, hex, next to the `org_id` and `subscription_id` that registered the
/// URL. The endpoint passes by answering 2xx with the challenge echoed back,
/// either as the whole body (`text/plain`, surrounding whitespace ignored) or
/// as `{"challenge": "<value>"}`. Anything else fails. A receiver that serves
/// only known orgs should echo only challenges carrying one of them — that is
/// what stops a stranger's org from verifying a subscription to it.
///
/// The request goes through [`send_signed`] — HTTPS-only, SSRF-guarded — so a
/// handshake reaches nothing a delivery could not, and one 10s deadline covers
/// the whole exchange, body included. The `Err` text is shown to the
/// registrant and never includes the response body, so a failed handshake
/// cannot be used to read what an address says.
///
/// Like [`deliver`], this takes no DB connection: the caller records the
/// outcome after the round trip.
pub async fn verify_endpoint(
    url: &str,
    secret: &str,
    org_id: Uuid,
    subscription_id: Uuid,
) -> Result<(), String> {
    // One deadline over the whole handshake — send, headers *and* body — so a
    // slow endpoint cannot stretch it past 10s by trickling its answer in
    // after `send_signed`'s own deadline has been met.
    tokio::time::timeout(
        ATTEMPT_DEADLINE,
        challenge_endpoint(url, secret, org_id, subscription_id),
    )
    .await
    .unwrap_or_else(|_elapsed| {
        Err(format!(
            "the endpoint did not answer the challenge within {}s",
            ATTEMPT_DEADLINE.as_secs()
        ))
    })
}

async fn challenge_endpoint(
    url: &str,
    secret: &str,
    org_id: Uuid,
    subscription_id: Uuid,
) -> Result<(), String> {
    use rand::RngExt;
    let mut challenge = [0u8; 32];
    rand::rng().fill(&mut challenge);
    let challenge = hex::encode(challenge);

    let id = Uuid::new_v4();
    let envelope = build_envelope(
        id,
        VERIFICATION_EVENT,
        OffsetDateTime::now_utc(),
        // Who is asking: set from the subscription row, never from anything
        // the registrant sent, so a receiver can refuse to echo a challenge
        // for an org it does not belong to.
        &json!({
            "challenge": challenge,
            "org_id": org_id,
            "subscription_id": subscription_id,
        }),
    );
    let body = serde_json::to_string(&envelope).unwrap_or_default();

    let mut resp = send_signed(url, secret, org_id, VERIFICATION_EVENT, id, body).await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!(
            "endpoint answered HTTP {} — expected a 2xx echoing the challenge",
            status.as_u16()
        ));
    }

    let mut received = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("reading the endpoint's answer failed: {e}"))?
    {
        received.extend_from_slice(&chunk);
        if received.len() > VERIFICATION_BODY_CAP {
            return Err(format!(
                "endpoint answered with more than {VERIFICATION_BODY_CAP} bytes — expected only the challenge"
            ));
        }
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
    use super::{Signature, echoed_challenge, sign};

    #[test]
    fn v1_covers_timestamp_and_body_and_legacy_covers_the_body() {
        // Fixed vector, so a change to the wire format fails loudly here
        // before it fails silently in every receiver.
        let got = sign("whsec_test", 1_790_000_000, r#"{"id":"x"}"#);
        assert_eq!(
            got,
            Signature {
                timestamp: 1_790_000_000,
                v1: "v1=67533a13d71e2eb77b03c01b4fe125052bbf1417cff15203550ad39a75c4995b".into(),
                legacy: "sha256=efe09dee2f0a8b843785c534ae775acaa4e4143f8a95eb2446f509c062af9055"
                    .into(),
            }
        );
    }

    #[test]
    fn only_v1_changes_with_the_timestamp() {
        let a = sign("s", 100, "body");
        let b = sign("s", 101, "body");
        assert_ne!(a.v1, b.v1);
        assert_eq!(a.legacy, b.legacy);
        assert_ne!(sign("s", 100, "body!").v1, a.v1);
    }

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
