//! `GET /v1/events/stream` — the SSE event stream.
//!
//! These are the first tests in the suite to consume SSE over the wire. The
//! existing client-side parser (`overslash-mcp-puppet/src/sse.rs`) deliberately
//! ignores `id:` and `event:` because the MCP transport never emits them; this
//! stream's whole resume contract is built on `id:`, so the tests carry their
//! own field-aware parser below.
//!
//! They use `start_api_with_event_stream` rather than the shared router: a
//! stream outlives the shared harness's per-test `ResourceGuard`, and live
//! fan-out needs the Postgres `LISTEN` task that only this harness spawns.

use std::collections::HashMap;
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::Client;
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::common;

/// Connection ceiling used by these tests. Long enough to observe a live event,
/// short enough that a test asserting "the server hangs up" finishes fast.
const STREAM_SECS: u64 = 3;

/// One parsed SSE frame. Keep-alive comments are dropped by the parser.
#[derive(Debug, Clone)]
struct Frame {
    id: Option<String>,
    event: Option<String>,
    data: String,
}

impl Frame {
    fn json(&self) -> Value {
        serde_json::from_str(&self.data).expect("frame data is json")
    }

    /// The `data` of the wire envelope — what a webhook subscriber would get.
    fn payload(&self) -> Value {
        self.json()
            .get("data")
            .cloned()
            .expect("envelope carries data")
    }

    fn cursor(&self) -> i64 {
        self.id
            .as_ref()
            .expect("event frames carry an id")
            .parse()
            .expect("id is the numeric cursor")
    }
}

/// Read an SSE response to completion, returning every frame. Bounded by
/// `timeout` so a stream the server forgot to close fails the test instead of
/// hanging it.
async fn collect_frames(resp: reqwest::Response, timeout: Duration) -> Vec<Frame> {
    assert!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .starts_with("text/event-stream"),
        "expected an SSE content-type, got {:?}",
        resp.headers().get("content-type")
    );

    let mut frames = Vec::new();
    let mut buf = String::new();
    let mut body = resp.bytes_stream();

    let read = async {
        while let Some(chunk) = body.next().await {
            let chunk = chunk.expect("stream chunk");
            buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(split) = find_frame_boundary(&buf) {
                let (raw, rest) = buf.split_at(split.0);
                let remainder = rest[split.1..].to_string();
                if let Some(frame) = parse_frame(raw) {
                    frames.push(frame);
                }
                buf = remainder;
            }
        }
    };
    // A clean server-side close ends `read` on its own; the timeout is the
    // backstop for a stream that never closes.
    let _ = tokio::time::timeout(timeout, read).await;
    frames
}

/// Byte offset of the next frame terminator and its length, handling both
/// `\n\n` and `\r\n\r\n`.
fn find_frame_boundary(buf: &str) -> Option<(usize, usize)> {
    match (buf.find("\r\n\r\n"), buf.find("\n\n")) {
        (Some(crlf), Some(lf)) if crlf <= lf => Some((crlf, 4)),
        (_, Some(lf)) => Some((lf, 2)),
        (Some(crlf), None) => Some((crlf, 4)),
        (None, None) => None,
    }
}

/// Parse one frame. Returns `None` for keep-alive comments and any block with
/// no `data:` line.
fn parse_frame(raw: &str) -> Option<Frame> {
    let mut id = None;
    let mut event = None;
    let mut data: Vec<String> = Vec::new();

    for line in raw.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "id" => id = Some(value.to_string()),
            "event" => event = Some(value.to_string()),
            "data" => data.push(value.to_string()),
            _ => {}
        }
    }

    if data.is_empty() {
        return None;
    }
    Some(Frame {
        id,
        event,
        data: data.join("\n"),
    })
}

/// Open a stream and read it to completion.
async fn read_stream(
    client: &Client,
    base: &str,
    key: &str,
    query: &str,
    last_event_id: Option<i64>,
) -> Vec<Frame> {
    let resp = open_stream(client, base, key, query, last_event_id).await;
    assert_eq!(resp.status(), 200, "stream should open");
    collect_frames(resp, Duration::from_secs(STREAM_SECS + 5)).await
}

async fn open_stream(
    client: &Client,
    base: &str,
    key: &str,
    query: &str,
    last_event_id: Option<i64>,
) -> reqwest::Response {
    let mut req = client
        .get(format!("{base}/v1/events/stream{query}"))
        .header("Accept", "text/event-stream")
        .header("Authorization", format!("Bearer {key}"));
    if let Some(cursor) = last_event_id {
        req = req.header("Last-Event-ID", cursor.to_string());
    }
    req.send().await.expect("stream request")
}

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

async fn start(pool: PgPool) -> (String, Client) {
    let (addr, client) = common::start_api_with_event_stream(pool, |config| {
        config.events_stream_max_connection_secs = STREAM_SECS;
    })
    .await;
    (format!("http://{addr}"), client)
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
