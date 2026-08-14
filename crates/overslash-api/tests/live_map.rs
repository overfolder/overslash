//! `action.called` / `action.completed` — the per-call events the Live Map
//! animates.
//!
//! Three things need holding down. Emission is gated, because one durable
//! `events` row per action call is a cost no production deployment should pay
//! for a dev view. The pair is correlated, because the client has to match a
//! return leg to its outbound one and the two events are not ordered. And the
//! audience is the actor's chain, because an org-wide fan-out of every call
//! would be the widest disclosure surface in the system.
//!
//! Uses `start_api_with_event_stream`: live fan-out needs the Postgres
//! `LISTEN` task that only that harness spawns.

use std::time::Duration;

use axum::{Router, http::StatusCode, routing::any};
use futures_util::StreamExt;
use reqwest::Client;
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::net::TcpListener;
use uuid::Uuid;

use crate::common;

/// Long enough to observe a call's two events, short enough that a test does
/// not sit on the connection ceiling.
const STREAM_SECS: u64 = 3;

#[derive(Debug, Clone)]
struct Frame {
    event: Option<String>,
    data: String,
}

impl Frame {
    fn payload(&self) -> Value {
        serde_json::from_str::<Value>(&self.data)
            .expect("frame data is json")
            .get("data")
            .cloned()
            .expect("envelope carries data")
    }
}

/// An upstream that always answers, so a call has a real outcome rather than a
/// transport error.
async fn start_stub() -> std::net::SocketAddr {
    let app = Router::new()
        .route("/ok", any(|| async { (StatusCode::OK, "fine") }))
        .route(
            "/boom",
            any(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "upstream down") }),
        );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

async fn start(pool: PgPool, live_map: bool) -> (String, Client) {
    let (addr, client) = common::start_api_with_event_stream(pool, |config| {
        config.events_stream_max_connection_secs = STREAM_SECS;
        config.live_map_enabled = live_map;
    })
    .await;
    (format!("http://{addr}"), client)
}

/// Read an SSE response to completion. Bounded, so a stream the server forgot
/// to close fails the test instead of hanging it.
async fn collect(resp: reqwest::Response) -> Vec<Frame> {
    let mut frames = Vec::new();
    let mut buf = String::new();
    let mut body = resp.bytes_stream();
    let read = async {
        while let Some(chunk) = body.next().await {
            buf.push_str(&String::from_utf8_lossy(&chunk.expect("stream chunk")));
            while let Some(at) = buf.find("\n\n") {
                let raw = buf[..at].to_string();
                buf = buf[at + 2..].to_string();
                let mut event = None;
                let mut data: Vec<String> = Vec::new();
                for line in raw.lines() {
                    let line = line.trim_end_matches('\r');
                    let Some((field, value)) = line.split_once(':') else {
                        continue;
                    };
                    let value = value.strip_prefix(' ').unwrap_or(value);
                    match field {
                        "event" => event = Some(value.to_string()),
                        "data" => data.push(value.to_string()),
                        _ => {}
                    }
                }
                if !data.is_empty() {
                    frames.push(Frame {
                        event,
                        data: data.join("\n"),
                    });
                }
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(STREAM_SECS + 5), read).await;
    frames
}

/// Subscribe, then run `body`, then return everything the stream delivered.
///
/// The subscription opens first on purpose: that is the NOTIFY → listener →
/// bus path, which is what the map actually rides. Replaying from a cursor
/// would pass even if live fan-out were broken.
async fn watch<F, Fut>(base: &str, client: &Client, key: &str, body: F) -> Vec<Frame>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let stream = tokio::spawn({
        let (client, base, key) = (client.clone(), base.to_string(), key.to_string());
        async move {
            let resp = client
                .get(format!("{base}/v1/events/stream?topics=activity"))
                .header("Accept", "text/event-stream")
                .header("Authorization", format!("Bearer {key}"))
                .send()
                .await
                .expect("stream request");
            assert_eq!(resp.status(), 200, "stream should open");
            collect(resp).await
        }
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    body().await;
    stream.await.expect("stream task")
}

async fn raw_http_call(base: &str, client: &Client, key: &str, url: String) -> Value {
    client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({ "service": "http", "method": "GET", "url": url }))
        .send()
        .await
        .expect("action call")
        .json()
        .await
        .expect("json body")
}

fn of_type<'a>(frames: &'a [Frame], ty: &str) -> Vec<&'a Frame> {
    frames
        .iter()
        .filter(|f| f.event.as_deref() == Some(ty))
        .collect()
}

#[tokio::test]
async fn a_call_emits_a_correlated_pair_on_the_activity_topic() {
    let pool = common::test_pool().await;
    let stub = start_stub().await;
    let (base, client) = start(pool, true).await;
    let (_org, ident_id, agent_key, _admin) = common::bootstrap_org_identity(&base, &client).await;
    common::allow_loopback_ssrf();

    let frames = watch(&base, &client, &agent_key, || async {
        let body = raw_http_call(&base, &client, &agent_key, format!("http://{stub}/ok")).await;
        assert_eq!(body["status"], "called", "control: the call itself worked");
    })
    .await;

    let called = of_type(&frames, "action.called");
    let completed = of_type(&frames, "action.completed");
    assert_eq!(called.len(), 1, "exactly one outbound event per call");
    assert_eq!(completed.len(), 1, "exactly one terminal event per call");

    let a = called[0].payload();
    let b = completed[0].payload();
    assert_eq!(
        a["call_id"], b["call_id"],
        "the pair is correlated — this is the only thing tying a return leg \
         to its outbound one, since the two events are not ordered"
    );
    assert_eq!(a["actor_identity_id"], ident_id.to_string());
    assert_eq!(a["service"], "http");
    assert_eq!(b["outcome"], "called");
    assert!(
        b["duration_ms"].is_u64(),
        "completed carries how long it took, got {:?}",
        b["duration_ms"]
    );
}

/// The outcome is the metrics classification, not the HTTP status: a buffered
/// upstream 500 rides behind an outer 200 and must still read as a failure.
#[tokio::test]
async fn an_upstream_failure_is_reported_as_such_not_as_success() {
    let pool = common::test_pool().await;
    let stub = start_stub().await;
    let (base, client) = start(pool, true).await;
    let (_org, _ident, agent_key, _admin) = common::bootstrap_org_identity(&base, &client).await;
    common::allow_loopback_ssrf();

    let frames = watch(&base, &client, &agent_key, || async {
        let body = raw_http_call(&base, &client, &agent_key, format!("http://{stub}/boom")).await;
        assert_eq!(body["result"]["status_code"], 500, "control: in-band 5xx");
    })
    .await;

    let completed = of_type(&frames, "action.completed");
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].payload()["outcome"], "upstream_error");
}

#[tokio::test]
async fn nothing_is_emitted_when_the_flag_is_off() {
    let pool = common::test_pool().await;
    let stub = start_stub().await;
    let (base, client) = start(pool, false).await;
    let (_org, _ident, agent_key, _admin) = common::bootstrap_org_identity(&base, &client).await;
    common::allow_loopback_ssrf();

    let frames = watch(&base, &client, &agent_key, || async {
        let body = raw_http_call(&base, &client, &agent_key, format!("http://{stub}/ok")).await;
        assert_eq!(body["status"], "called", "control: the call still runs");
    })
    .await;

    assert!(
        of_type(&frames, "action.called").is_empty()
            && of_type(&frames, "action.completed").is_empty(),
        "the flag gates emission, not just the dashboard nav: {frames:?}"
    );
    // `activity` stays a valid topic either way — a client asking for it on a
    // deployment with the flag off gets silence, not a 400.
    assert!(
        frames
            .iter()
            .any(|f| f.event.as_deref() == Some("stream.open")),
        "the subscription itself is still accepted"
    );
}

#[tokio::test]
async fn a_sibling_chain_sees_nothing_but_an_org_admin_sees_everything() {
    let pool = common::test_pool().await;
    let stub = start_stub().await;
    let (base, client) = start(pool, true).await;
    let (org_id, _ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    common::allow_loopback_ssrf();

    // A second user with its own agent — same org, unrelated chain.
    let sibling_key = mint_sibling_agent(&base, &client, &admin_key, org_id).await;

    let sibling_frames = watch(&base, &client, &sibling_key, || async {
        raw_http_call(&base, &client, &agent_key, format!("http://{stub}/ok")).await;
    })
    .await;
    assert!(
        of_type(&sibling_frames, "action.called").is_empty(),
        "audience is the actor's chain: a sibling must not watch another \
         chain's traffic, {sibling_frames:?}"
    );

    let admin_frames = watch(&base, &client, &admin_key, || async {
        raw_http_call(&base, &client, &agent_key, format!("http://{stub}/ok")).await;
    })
    .await;
    assert_eq!(
        of_type(&admin_frames, "action.called").len(),
        1,
        "org admins bypass the audience array — that is what makes the map an \
         org-wide operator view, {admin_frames:?}"
    );
}

/// A user + agent + identity-bound key on a chain unrelated to `test-user`.
async fn mint_sibling_agent(base: &str, client: &Client, admin_key: &str, org_id: Uuid) -> String {
    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "other-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap().to_string();

    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "other-agent", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = agent["id"].as_str().unwrap().to_string();

    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"org_id": org_id, "identity_id": agent_id, "name": "other-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    key["key"].as_str().unwrap().to_string()
}
