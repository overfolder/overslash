//! Integration tests: full API flows against a real Valkey.
//!
//! Tests require a running Valkey reachable via `VALKEY_URL` (default:
//! `redis://localhost:6380` — what `make shortener-dev` exposes). If Valkey
//! is not reachable, tests **panic** so broken CI surfaces loudly rather
//! than passing green on an empty run. Match the `overslash-api` pattern of
//! failing hard when a required test dependency is missing.

use std::net::SocketAddr;
use std::time::Duration;

use oversla_sh::{AppState, Config, Storage, create_app};
use reqwest::{Client, StatusCode, redirect::Policy};
use serde_json::json;
use tokio::net::TcpListener;

const TEST_API_KEY: &str = "test-api-key-abcdef";
const TEST_BASE_URL: &str = "http://localhost:9999";

fn valkey_url() -> String {
    std::env::var("VALKEY_URL").unwrap_or_else(|_| "redis://localhost:6380".into())
}

async fn start() -> (SocketAddr, Client) {
    let url = valkey_url();
    let storage = Storage::connect(&url).await.unwrap_or_else(|e| {
        panic!(
            "cannot connect to Valkey at {url}: {e}\n\
             hint: run `make shortener-dev` or set VALKEY_URL to a reachable instance"
        )
    });
    storage
        .ping()
        .await
        .unwrap_or_else(|e| panic!("Valkey PING failed at {url}: {e}"));

    let config = Config {
        host: "127.0.0.1".into(),
        port: 0,
        valkey_url: url,
        api_key: TEST_API_KEY.into(),
        base_url: TEST_BASE_URL.into(),
        min_ttl_secs: 1, // relaxed for tests (production default: 60)
        max_ttl_secs: 3600,
    };
    let state = AppState::from_config(&config, storage);
    let app = create_app(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Client must NOT follow redirects — we assert on the 302 itself.
    let client = Client::builder()
        .redirect(Policy::none())
        .build()
        .expect("client");

    (addr, client)
}

fn auth_header() -> (&'static str, String) {
    ("Authorization", format!("Bearer {TEST_API_KEY}"))
}

#[tokio::test]
async fn health_returns_ok() {
    let (addr, client) = start().await;
    let resp = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn ready_returns_ready_when_valkey_up() {
    let (addr, client) = start().await;
    let resp = client
        .get(format!("http://{addr}/ready"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn create_and_redirect_roundtrip() {
    let (addr, client) = start().await;
    let (hdr_name, hdr_val) = auth_header();

    let resp = client
        .post(format!("http://{addr}/api/links"))
        .header(hdr_name, hdr_val)
        .json(&json!({ "url": "https://example.com/roundtrip", "ttl_seconds": 60 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body: serde_json::Value = resp.json().await.unwrap();
    let slug = body["slug"].as_str().unwrap().to_string();
    let short = body["short_url"].as_str().unwrap();
    assert_eq!(short, format!("{TEST_BASE_URL}/{slug}"));
    assert!(body["expires_at"].as_str().unwrap().len() > 10);

    let resp = client
        .get(format!("http://{addr}/{slug}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "https://example.com/roundtrip"
    );
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "no-store, max-age=0"
    );
}

#[tokio::test]
async fn redirect_returns_404_after_ttl_expiry() {
    let (addr, client) = start().await;
    let (hdr_name, hdr_val) = auth_header();

    let resp = client
        .post(format!("http://{addr}/api/links"))
        .header(hdr_name, hdr_val)
        .json(&json!({ "url": "https://example.com/ephemeral", "ttl_seconds": 1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let slug = resp.json::<serde_json::Value>().await.unwrap()["slug"]
        .as_str()
        .unwrap()
        .to_string();

    // Valkey rounds TTLs at the second boundary — wait 2s to be safe.
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let resp = client
        .get(format!("http://{addr}/{slug}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn missing_auth_is_401() {
    let (addr, client) = start().await;
    let resp = client
        .post(format!("http://{addr}/api/links"))
        .json(&json!({ "url": "https://example.com", "ttl_seconds": 60 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bad_api_key_is_401() {
    let (addr, client) = start().await;
    let resp = client
        .post(format!("http://{addr}/api/links"))
        .header("Authorization", "Bearer wrong-key")
        .json(&json!({ "url": "https://example.com", "ttl_seconds": 60 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ttl_below_min_is_422() {
    let (addr, client) = start().await;
    let (hdr_name, hdr_val) = auth_header();
    let resp = client
        .post(format!("http://{addr}/api/links"))
        .header(hdr_name, hdr_val)
        .json(&json!({ "url": "https://example.com", "ttl_seconds": 0 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn ttl_above_max_is_422() {
    let (addr, client) = start().await;
    let (hdr_name, hdr_val) = auth_header();
    let resp = client
        .post(format!("http://{addr}/api/links"))
        .header(hdr_name, hdr_val)
        .json(&json!({ "url": "https://example.com", "ttl_seconds": 1_000_000 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn invalid_url_is_400() {
    let (addr, client) = start().await;
    let (hdr_name, hdr_val) = auth_header();
    let resp = client
        .post(format!("http://{addr}/api/links"))
        .header(hdr_name, hdr_val)
        .json(&json!({ "url": "not-a-url", "ttl_seconds": 60 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unsupported_scheme_is_400() {
    let (addr, client) = start().await;
    let (hdr_name, hdr_val) = auth_header();
    let resp = client
        .post(format!("http://{addr}/api/links"))
        .header(hdr_name, hdr_val)
        .json(&json!({ "url": "ftp://example.com/file", "ttl_seconds": 60 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_slug_is_404() {
    let (addr, client) = start().await;
    let resp = client
        .get(format!("http://{addr}/doesnotexist12"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn slug_with_invalid_chars_is_404() {
    let (addr, client) = start().await;
    let resp = client
        .get(format!("http://{addr}/has-dashes"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
