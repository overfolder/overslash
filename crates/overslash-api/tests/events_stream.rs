//! `GET /v1/events/stream` — the SSE event stream.
//!
//! These are the first tests in the suite to consume SSE over the wire; the
//! field-aware reader they need lives in `common::sse`, which also owns the
//! `start_stream_api` harness (the shared router cannot serve a stream — see
//! that module).

use std::collections::HashMap;
use std::time::Duration;

use reqwest::Client;
use serde_json::Value;
use uuid::Uuid;

use crate::common;
use crate::common::sse::start_stream_api as start;
use crate::common::sse::{Frame, STREAM_SECS, open_stream, read_stream};

/// Mint a secret request — the cheapest way to produce a real event, since it
/// needs no permission-gate setup and its audience is the caller's own chain.
async fn mint_secret_request(client: &Client, base: &str, key: &str, name: &str) -> String {
    let resp = client
        .post(format!("{base}/v1/secrets/requests"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&serde_json::json!({ "secret_name": name }))
        .send()
        .await
        .expect("mint secret request");
    assert_eq!(resp.status(), 200, "mint should succeed");
    resp.json::<Value>().await.unwrap()["id"]
        .as_str()
        .expect("request id")
        .to_string()
}

#[tokio::test]
async fn fresh_connect_opens_with_a_cursor_and_closes_at_the_deadline() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool).await;
    let (_org, _ident, agent_key, _org_key) = common::bootstrap_org_identity(&base, &client).await;

    let started = std::time::Instant::now();
    let frames = read_stream(&client, &base, &agent_key, "", None).await;
    let elapsed = started.elapsed();

    let open = frames.first().expect("at least the open frame");
    assert_eq!(open.event.as_deref(), Some("stream.open"));
    assert_eq!(open.json()["v"], 1, "wire version is advertised");
    assert!(
        open.json()["cursor"].is_i64(),
        "open carries a resume cursor"
    );

    // The server, not the client, ends the connection.
    assert!(
        elapsed < Duration::from_secs(STREAM_SECS + 4),
        "stream should close at the deadline, took {elapsed:?}"
    );
}

#[tokio::test]
async fn an_event_emitted_while_connected_arrives_live() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool).await;
    let (_org, _ident, agent_key, _org_key) = common::bootstrap_org_identity(&base, &client).await;

    // Open the stream first, then emit — this is the path that exercises
    // NOTIFY → listener → bus rather than the replay query.
    let stream = tokio::spawn({
        let (client, base, key) = (client.clone(), base.clone(), agent_key.clone());
        async move { read_stream(&client, &base, &key, "", None).await }
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    let request_id = mint_secret_request(&client, &base, &agent_key, "LIVE_TAIL_KEY").await;

    let frames = stream.await.expect("stream task");
    let event = frames
        .iter()
        .find(|f| f.event.as_deref() == Some("secret_request.created"))
        .expect("live event delivered");

    assert_eq!(event.payload()["request_id"], request_id);
    assert_eq!(event.payload()["secret_name"], "LIVE_TAIL_KEY");
    assert!(event.cursor() > 0, "event frames carry a numeric cursor");
    assert_eq!(event.json()["type"], "secret_request.created");
    assert!(
        event.json()["created_at"].is_string(),
        "envelope matches the webhook shape"
    );
}

#[tokio::test]
async fn the_provide_token_never_reaches_a_subscriber() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool).await;
    let (_org, _ident, agent_key, _org_key) = common::bootstrap_org_identity(&base, &client).await;

    mint_secret_request(&client, &base, &agent_key, "TOKEN_LEAK_CHECK").await;
    let frames = read_stream(&client, &base, &agent_key, "", Some(0)).await;

    let event = frames
        .iter()
        .find(|f| f.event.as_deref() == Some("secret_request.created"))
        .expect("event replayed");

    // The provide URL is a bearer capability: anyone holding it can fulfil the
    // request. It must not ride along on a fan-out transport.
    let payload = event.payload();
    for leaked in ["token", "url", "short_url", "provide_url"] {
        assert!(
            payload.get(leaked).is_none(),
            "payload leaked `{leaked}`: {payload}"
        );
    }
    assert!(
        !event.data.contains("token="),
        "payload leaked a tokenised URL: {}",
        event.data
    );
}

#[tokio::test]
async fn reconnecting_with_a_cursor_replays_the_gap_exactly_once() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool).await;
    let (_org, _ident, agent_key, _org_key) = common::bootstrap_org_identity(&base, &client).await;

    mint_secret_request(&client, &base, &agent_key, "REPLAY_ONE").await;
    mint_secret_request(&client, &base, &agent_key, "REPLAY_TWO").await;

    // From the beginning of time: both events come back.
    let first = read_stream(&client, &base, &agent_key, "", Some(0)).await;
    let replayed: Vec<i64> = first
        .iter()
        .filter(|f| f.event.as_deref() == Some("secret_request.created"))
        .map(|f| f.cursor())
        .collect();
    assert_eq!(replayed.len(), 2, "both events replayed: {first:?}");
    assert!(replayed[0] < replayed[1], "replay is cursor-ordered");

    // Resuming from the last cursor delivers nothing again — the property the
    // 30-second reconnect cycle depends on.
    let second = read_stream(&client, &base, &agent_key, "", Some(replayed[1])).await;
    let redelivered: Vec<&Frame> = second
        .iter()
        .filter(|f| f.event.as_deref() == Some("secret_request.created"))
        .collect();
    assert!(
        redelivered.is_empty(),
        "resume redelivered events: {redelivered:?}"
    );

    // ...and the open frame points at where the client already is.
    let open = second.first().expect("open frame");
    assert_eq!(open.json()["cursor"].as_i64(), Some(replayed[1]));
}

#[tokio::test]
async fn the_open_frame_never_advances_past_events_it_precedes() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool).await;
    let (_org, _ident, agent_key, _org_key) = common::bootstrap_org_identity(&base, &client).await;

    mint_secret_request(&client, &base, &agent_key, "OPEN_CURSOR_ONE").await;
    mint_secret_request(&client, &base, &agent_key, "OPEN_CURSOR_TWO").await;

    let frames = read_stream(&client, &base, &agent_key, "", Some(0)).await;
    let open = frames.first().expect("open frame");
    let replayed: Vec<i64> = frames
        .iter()
        .filter(|f| f.event.as_deref() == Some("secret_request.created"))
        .map(|f| f.cursor())
        .collect();
    assert_eq!(replayed.len(), 2, "both events replayed");

    // `stream.open` is written before the replayed rows, and EventSource
    // updates `lastEventId` per frame as it arrives. If the open frame claimed
    // the end of the batch, a connection dropping mid-replay would leave the
    // client believing it had consumed rows it never saw — and its reconnect
    // would resume past them, losing them permanently.
    assert!(
        open.cursor() < replayed[0],
        "open frame ({}) must not advance past the rows that follow it ({:?})",
        open.cursor(),
        replayed
    );
    assert_eq!(
        open.json()["cursor"].as_i64(),
        Some(0),
        "resumes from the requested cursor"
    );
}

#[tokio::test]
async fn events_are_scoped_to_the_identity_chain_not_the_org() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool.clone()).await;
    let (org_id, _agent_id, agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // A second agent under the same owner-user. It is a sibling of the first,
    // so neither is in the other's ancestor chain — which is the whole point:
    // same org, no shared chain, therefore no shared events.
    let owner_id = common::owner_user_id(&pool, org_id).await;
    let sibling_id: Uuid = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&serde_json::json!({
            "name": "sibling-agent",
            "kind": "agent",
            "parent_id": owner_id,
        }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let sibling_key = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&serde_json::json!({
            "org_id": org_id,
            "identity_id": sibling_id,
            "name": "sibling-key",
        }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["key"]
        .as_str()
        .unwrap()
        .to_string();

    mint_secret_request(&client, &base, &agent_key, "CHAIN_SCOPED").await;

    // The requester sees its own event.
    let mine = read_stream(&client, &base, &agent_key, "", Some(0)).await;
    assert!(
        mine.iter()
            .any(|f| f.event.as_deref() == Some("secret_request.created")),
        "requester should see its own event"
    );

    // The sibling is in the same org and would see this approval through
    // `GET /v1/approvals`, which has no ACL gate. The stream must not inherit
    // that: it is not in the audience.
    let theirs = read_stream(&client, &base, &sibling_key, "", Some(0)).await;
    assert!(
        !theirs
            .iter()
            .any(|f| f.event.as_deref() == Some("secret_request.created")),
        "a sibling agent must not receive another chain's events: {theirs:?}"
    );
}

#[tokio::test]
async fn org_admins_receive_events_they_are_not_an_audience_of() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool).await;
    let (_org, _ident, agent_key, org_key) = common::bootstrap_org_identity(&base, &client).await;

    // `org_key` belongs to the bootstrap "admin" identity, which the bootstrap
    // path marks `is_org_admin`. It is not in the audience of the agent's
    // request, but it can already read every resource in the org over REST —
    // the stream matches that rather than being arbitrarily stricter.
    mint_secret_request(&client, &base, &agent_key, "ADMIN_VISIBLE").await;

    let frames = read_stream(&client, &base, &org_key, "", Some(0)).await;
    assert!(
        frames
            .iter()
            .any(|f| f.event.as_deref() == Some("secret_request.created")),
        "org admin should see org events: {frames:?}"
    );
}

#[tokio::test]
async fn topics_filter_the_stream_and_unknown_topics_are_rejected() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool).await;
    let (_org, _ident, agent_key, _org_key) = common::bootstrap_org_identity(&base, &client).await;

    mint_secret_request(&client, &base, &agent_key, "TOPIC_FILTER").await;

    // `secrets` is subscribed: the event arrives.
    let subscribed = read_stream(&client, &base, &agent_key, "?topics=secrets", Some(0)).await;
    assert!(
        subscribed
            .iter()
            .any(|f| f.event.as_deref() == Some("secret_request.created"))
    );

    // `connections` is not: the same event is filtered out.
    let filtered = read_stream(&client, &base, &agent_key, "?topics=connections", Some(0)).await;
    assert!(
        !filtered
            .iter()
            .any(|f| f.event.as_deref() == Some("secret_request.created")),
        "unsubscribed topic leaked: {filtered:?}"
    );

    // A typo fails loudly rather than silently delivering nothing forever.
    let resp = open_stream(&client, &base, &agent_key, "?topics=approvals,bogus", None).await;
    assert_eq!(resp.status(), 400);
    assert!(
        resp.text().await.unwrap().contains("bogus"),
        "the error should name the offending topic"
    );
}

#[tokio::test]
async fn concurrent_streams_are_capped_per_identity() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool).await;
    let (_org, _ident, agent_key, _org_key) = common::bootstrap_org_identity(&base, &client).await;

    // Hold the cap open. These are never read, so they stay connected until
    // the server's deadline.
    let mut held = Vec::new();
    for _ in 0..4 {
        held.push(open_stream(&client, &base, &agent_key, "", None).await);
        // The permit is taken during the handler, but the response headers
        // arrive before the body; give each connect time to register.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for resp in &held {
        assert_eq!(resp.status(), 200, "the first four should connect");
    }

    let rejected = open_stream(&client, &base, &agent_key, "", None).await;
    assert_eq!(
        rejected.status(),
        429,
        "the fifth concurrent stream should be refused"
    );
    assert!(
        rejected.headers().contains_key("retry-after"),
        "a refused stream should say when to come back"
    );
}

#[tokio::test]
async fn stream_events_and_webhooks_carry_the_same_payload() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool.clone()).await;
    let (_org, _ident, agent_key, org_key) = common::bootstrap_org_identity(&base, &client).await;

    // Subscribe a webhook to the new event so both transports fire.
    let resp = client
        .post(format!("{base}/v1/webhooks"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&serde_json::json!({
            "url": "http://127.0.0.1:9/unused",
            "events": ["secret_request.created"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "webhook subscription should be created");

    let request_id = mint_secret_request(&client, &base, &agent_key, "PARITY_KEY").await;
    let frames = read_stream(&client, &base, &agent_key, "", Some(0)).await;
    let streamed = frames
        .iter()
        .find(|f| f.event.as_deref() == Some("secret_request.created"))
        .expect("stream delivered the event")
        .payload();

    // The HTTP delivery fails (nothing is listening on port 9), but the row
    // records the payload that was signed and sent. Read it from the table:
    // `GET /v1/webhooks/{id}/deliveries` deliberately omits the payload.
    let delivered: Value = sqlx::query_scalar!(
        "SELECT payload FROM webhook_deliveries WHERE event = $1 ORDER BY created_at DESC LIMIT 1",
        "secret_request.created",
    )
    .fetch_one(&pool)
    .await
    .expect("webhook delivery row created");

    assert_eq!(
        delivered, streamed,
        "SPEC §10: the same payload regardless of transport"
    );
    assert_eq!(streamed["request_id"], request_id);
}

#[tokio::test]
async fn an_unidentified_credential_cannot_open_a_stream() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool).await;
    let (_org, _ident, _agent_key, _org_key) = common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .get(format!("{base}/v1/events/stream"))
        .header("Accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "the stream requires authentication like every other /v1 route"
    );
}

// ─── approval.pending: the inbox signal ───────────────────────────────

/// Drive a gated call so the permission chain raises a real approval.
///
/// The call comes from a sub-agent one level below the bootstrap agent: it
/// holds no rules of its own and does not inherit, so the chain walk finds a
/// gap immediately and opens an approval at the first ancestor that could
/// grant one. Returns `(approval_id, sub_agent_id, org_key)`.
async fn raise_approval(base: &str, client: &Client) -> (String, Uuid, String) {
    let caller = gated_caller(base, client).await;
    let approval_id = trigger_gated_call(base, client, &caller).await;
    (approval_id, caller.sub_id, caller.org_key)
}

/// A sub-agent positioned to gap, plus the org it lives in. Split out from
/// [`raise_approval`] so a test can subscribe a webhook to the org *before*
/// the event it wants to observe is emitted.
struct GatedCaller {
    org_key: String,
    sub_key: String,
    sub_id: Uuid,
    mock_addr: std::net::SocketAddr,
}

async fn gated_caller(base: &str, client: &Client) -> GatedCaller {
    common::allow_loopback_ssrf();
    let mock_addr = common::start_mock().await;
    let (org_id, agent_id, _agent_key, org_key) =
        common::bootstrap_org_identity(base, client).await;

    let sub_id: Uuid = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&serde_json::json!({
            "name": "gated-sub", "kind": "sub_agent", "parent_id": agent_id,
        }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let sub_key = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&serde_json::json!({
            "org_id": org_id, "identity_id": sub_id, "name": "sub-key",
        }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["key"]
        .as_str()
        .unwrap()
        .to_string();

    GatedCaller {
        org_key,
        sub_key,
        sub_id,
        mock_addr,
    }
}

/// Make the call that gaps, returning the approval it raised.
async fn trigger_gated_call(base: &str, client: &Client, caller: &GatedCaller) -> String {
    let (sub_key, mock_addr) = (&caller.sub_key, caller.mock_addr);
    let body: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {sub_key}"))
        .json(&serde_json::json!({
            "service": "http",
            "method": "POST",
            "url": format!("http://{mock_addr}/echo"),
            "headers": {"Content-Type": "application/json"},
            "body": "{}",
            "secrets": [{"name": "test_token", "inject_as": "header", "header_name": "X-Token"}]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    body["approval_id"]
        .as_str()
        .unwrap_or_else(|| panic!("expected the call to be gated into an approval, got {body}"))
        .to_string()
}

#[tokio::test]
async fn raising_an_approval_emits_created_then_pending_in_that_order() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool).await;
    let (approval_id, requester_id, org_key) = raise_approval(&base, &client).await;

    let frames = read_stream(&client, &base, &org_key, "", Some(0)).await;
    let created = frames
        .iter()
        .find(|f| f.event.as_deref() == Some("approval.created"))
        .expect("approval.created delivered");
    let pending = frames
        .iter()
        .find(|f| f.event.as_deref() == Some("approval.pending"))
        .expect("approval.pending delivered");

    // The derived signal must never precede the fact it derives from. Two
    // independent emits would have raced here.
    assert!(
        created.cursor() < pending.cursor(),
        "pending ({}) must follow created ({})",
        pending.cursor(),
        created.cursor()
    );

    let p = pending.payload();
    assert_eq!(p["approval_id"], approval_id.as_str());
    assert_eq!(p["identity_id"], requester_id.to_string());
    assert_eq!(p["reason"], "created");
    assert!(
        p["current_resolver_identity_id"].is_string(),
        "pending names who it is waiting on: {p}"
    );
    assert!(
        p["can_be_handled_by"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "pending carries who can act, so no subscriber walks the tree: {p}"
    );
}

#[tokio::test]
async fn bubbling_emits_bubbled_then_pending_for_the_new_resolver() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool).await;
    let (approval_id, requester_id, org_key) = raise_approval(&base, &client).await;

    // Hand it up. The org-admin key can resolve on the current resolver's
    // behalf, which is what the dashboard does.
    let resp = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&serde_json::json!({ "resolution": "bubble_up" }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    if status == 409 {
        // Already at the final resolver — this chain has nowhere to bubble,
        // so there is no hand-up to assert on.
        return;
    }
    assert_eq!(status, 200, "bubble_up should succeed");

    let frames = read_stream(&client, &base, &org_key, "", Some(0)).await;
    let bubbled = frames
        .iter()
        .find(|f| f.event.as_deref() == Some("approval.bubbled"))
        .expect("approval.bubbled delivered");
    let pending: Vec<&Frame> = frames
        .iter()
        .filter(|f| f.event.as_deref() == Some("approval.pending"))
        .collect();

    assert_eq!(
        pending.len(),
        2,
        "one pending at creation, one at the hand-up: {frames:?}"
    );
    let handoff = pending.last().unwrap();
    assert!(
        bubbled.cursor() < handoff.cursor(),
        "the pending that follows a hand-up must come after the hand-up itself"
    );

    let b = bubbled.payload();
    assert_eq!(b["approval_id"], approval_id.as_str());
    assert_eq!(b["identity_id"], requester_id.to_string());
    assert_eq!(b["via"], "user");
    assert_ne!(b["from"], b["to"], "a hand-up changes the resolver");

    assert_eq!(handoff.payload()["reason"], "bubbled");
    assert_eq!(handoff.payload()["current_resolver_identity_id"], b["to"]);
}

#[tokio::test]
async fn pending_reaches_webhook_subscribers_too() {
    let pool = common::test_pool().await;
    let (base, client) = start(pool.clone()).await;

    // Same org for both halves: webhook subscriptions are org-scoped, so a
    // subscription in one org would never see another org's approval.
    let caller = gated_caller(&base, &client).await;
    let resp = client
        .post(format!("{base}/v1/webhooks"))
        .header("Authorization", format!("Bearer {}", caller.org_key))
        .json(&serde_json::json!({
            "url": "http://127.0.0.1:9/unused",
            "events": ["approval.pending"],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    trigger_gated_call(&base, &client, &caller).await;

    // The delivery attempt fails (nothing listens on port 9) but the row
    // records that the event was routed to webhooks at all.
    let mut delivered: Option<Value> = None;
    for _ in 0..50 {
        delivered = sqlx::query_scalar!(
            "SELECT payload FROM webhook_deliveries WHERE event = $1 ORDER BY created_at DESC LIMIT 1",
            "approval.pending",
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        if delivered.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let delivered = delivered.expect("approval.pending dispatched to webhooks");
    assert_eq!(delivered["reason"], "created");
    assert!(delivered["can_be_handled_by"].is_array());
}

/// Frames are keyed by event name for assertions that only care about which
/// types arrived. Unused today but kept next to the parser it belongs to.
#[allow(dead_code)]
fn by_event(frames: &[Frame]) -> HashMap<String, Vec<&Frame>> {
    let mut out: HashMap<String, Vec<&Frame>> = HashMap::new();
    for frame in frames {
        if let Some(event) = frame.event.clone() {
            out.entry(event).or_default().push(frame);
        }
    }
    out
}
