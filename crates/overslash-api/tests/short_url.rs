//! Unit tests for the `oversla.sh` shortener helper. Integration-flavoured
//! since they spin up a tiny in-process axum server, but they don't need a
//! database — `mint_with_client` is `AppState`-free for exactly this reason.

use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use overslash_api::services::short_url;

#[derive(Clone, Default)]
struct MockState {
    calls: Arc<AtomicUsize>,
    last_auth: Arc<std::sync::Mutex<Option<String>>>,
    last_body: Arc<std::sync::Mutex<Option<Value>>>,
    response: Arc<std::sync::Mutex<MockResponse>>,
}

#[derive(Clone)]
enum MockResponse {
    OkJson(Value),
    OkText(String),
    Status(StatusCode),
}

impl Default for MockResponse {
    fn default() -> Self {
        MockResponse::OkJson(json!({"short_url": "https://oversla.sh/abc123"}))
    }
}

async fn handler(
    State(state): State<MockState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    state.calls.fetch_add(1, Ordering::SeqCst);
    *state.last_auth.lock().unwrap() = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    *state.last_body.lock().unwrap() = Some(body);
    let resp = state.response.lock().unwrap().clone();
    match resp {
        MockResponse::OkJson(v) => Json(v).into_response(),
        MockResponse::OkText(t) => (StatusCode::OK, t).into_response(),
        MockResponse::Status(s) => (s, "boom").into_response(),
    }
}

use axum::response::IntoResponse;

async fn start_mock() -> (SocketAddr, MockState) {
    let state = MockState::default();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/api/links", post(handler))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, state)
}

fn future_expiry(secs: i64) -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + time::Duration::seconds(secs)
}

#[tokio::test]
async fn returns_short_url_on_success_and_forwards_auth_and_payload() {
    let (addr, mock) = start_mock().await;
    let client = reqwest::Client::new();

    let result = short_url::mint_with_client(
        &client,
        &format!("http://{addr}"),
        "test_api_key",
        "https://dashboard.example.com/approvals/00000000-0000-0000-0000-000000000001",
        future_expiry(600),
    )
    .await;

    assert_eq!(result.as_deref(), Some("https://oversla.sh/abc123"));
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        mock.last_auth.lock().unwrap().as_deref(),
        Some("Bearer test_api_key")
    );
    let body = mock.last_body.lock().unwrap().clone().unwrap();
    assert_eq!(
        body["url"],
        "https://dashboard.example.com/approvals/00000000-0000-0000-0000-000000000001"
    );
    let ttl = body["ttl_seconds"].as_u64().unwrap();
    assert!((300..=600).contains(&ttl), "ttl_seconds was {ttl}");
}

#[tokio::test]
async fn trailing_slash_in_base_url_is_normalized() {
    let (addr, _mock) = start_mock().await;
    let client = reqwest::Client::new();

    let result = short_url::mint_with_client(
        &client,
        &format!("http://{addr}/"),
        "k",
        "https://dashboard.example.com/approvals/x",
        future_expiry(600),
    )
    .await;
    assert_eq!(result.as_deref(), Some("https://oversla.sh/abc123"));
}

#[tokio::test]
async fn ttl_floor_is_60_seconds_for_already_expired_links() {
    let (addr, mock) = start_mock().await;
    let client = reqwest::Client::new();

    let _ = short_url::mint_with_client(
        &client,
        &format!("http://{addr}"),
        "k",
        "https://dashboard.example.com/approvals/x",
        time::OffsetDateTime::now_utc() - time::Duration::seconds(120),
    )
    .await;
    let body = mock.last_body.lock().unwrap().clone().unwrap();
    assert_eq!(body["ttl_seconds"].as_u64().unwrap(), 60);
}

#[tokio::test]
async fn returns_none_on_non_2xx_response() {
    let (addr, mock) = start_mock().await;
    *mock.response.lock().unwrap() = MockResponse::Status(StatusCode::INTERNAL_SERVER_ERROR);
    let client = reqwest::Client::new();

    let result = short_url::mint_with_client(
        &client,
        &format!("http://{addr}"),
        "k",
        "https://dashboard.example.com/approvals/x",
        future_expiry(600),
    )
    .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn returns_none_when_response_is_not_json() {
    let (addr, mock) = start_mock().await;
    *mock.response.lock().unwrap() = MockResponse::OkText("not-json".into());
    let client = reqwest::Client::new();

    let result = short_url::mint_with_client(
        &client,
        &format!("http://{addr}"),
        "k",
        "https://dashboard.example.com/approvals/x",
        future_expiry(600),
    )
    .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn returns_none_when_short_url_field_is_missing() {
    let (addr, mock) = start_mock().await;
    *mock.response.lock().unwrap() = MockResponse::OkJson(json!({"id": "abc123"}));
    let client = reqwest::Client::new();

    let result = short_url::mint_with_client(
        &client,
        &format!("http://{addr}"),
        "k",
        "https://dashboard.example.com/approvals/x",
        future_expiry(600),
    )
    .await;
    assert!(result.is_none());
}

#[tokio::test]
async fn returns_none_on_transport_error() {
    // Bind a listener and immediately drop it so the address refuses
    // connections — exercises the `Err(err)` arm of the `send()` match.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let client = reqwest::Client::new();
    let result = short_url::mint_with_client(
        &client,
        &format!("http://{addr}"),
        "k",
        "https://dashboard.example.com/approvals/x",
        future_expiry(600),
    )
    .await;
    assert!(result.is_none());
}
