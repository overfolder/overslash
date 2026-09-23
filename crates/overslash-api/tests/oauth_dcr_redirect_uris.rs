//! `POST /oauth/register` redirect_uri grammar (CASA 3.2.2): only https,
//! loopback http and private-use app schemes register, capped in count and
//! length. The grammar's edge cases are unit-tested next to the parser in
//! `services/oauth_redirect_uri.rs`; these pin the HTTP contract.

use crate::common;

use overslash_db::repos::oauth_mcp_client;
use serde_json::{Value, json};

async fn register(client: &reqwest::Client, base: &str, uris: Value) -> (u16, Value) {
    let resp = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "client_name": "dcr-redirect-test",
            "redirect_uris": uris,
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap())
}

#[tokio::test]
async fn dcr_accepts_https_loopback_and_app_schemes() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    for uri in [
        "https://claude.ai/api/mcp/auth_callback",
        "http://127.0.0.1:1234/callback",
        "http://[::1]:9/cb",
        "http://localhost:6274/oauth/callback",
        "cursor://anysphere.cursor-mcp/oauth/callback",
        "com.example.app:/oauth",
    ] {
        let (status, body) = register(&client, &base, json!([uri])).await;
        assert_eq!(status, 201, "{uri} should register: {body}");
        // Stored and echoed byte-for-byte — authorize matches with `==`.
        assert_eq!(body["redirect_uris"], json!([uri]));
    }
}

#[tokio::test]
async fn dcr_rejects_dangerous_and_non_loopback_uris() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    for uri in [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "vbscript:msgbox(1)",
        "http://evil.example/cb",
        "http://127.0.0.1.evil.com/cb",
        "https://ok.example/cb#frag",
        "https://user@ok.example/cb",
    ] {
        let (status, body) = register(&client, &base, json!([uri])).await;
        assert_eq!(status, 400, "{uri} must be rejected: {body}");
        assert_eq!(body["error"], "invalid_redirect_uri", "{uri}");
        assert!(
            !body["error_description"].as_str().unwrap().contains(uri),
            "the description must not echo the URI back"
        );
    }

    let too_long = format!("https://ok.example/{}", "a".repeat(2048));
    let (status, body) = register(&client, &base, json!([too_long])).await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_redirect_uri");

    let eleven: Vec<String> = (0..11)
        .map(|i| format!("http://127.0.0.1:{}/cb", 2000 + i))
        .collect();
    let (status, body) = register(&client, &base, json!(eleven)).await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_redirect_uri");

    // One bad entry fails the whole registration.
    let (status, body) = register(
        &client,
        &base,
        json!(["https://ok.example/cb", "javascript:alert(1)"]),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_redirect_uri");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .starts_with("redirect_uris[1]"),
        "{body}"
    );

    assert!(
        oauth_mcp_client::list_all(&pool).await.unwrap().is_empty(),
        "no rejected registration may leave a client behind"
    );
}

#[tokio::test]
async fn authorize_still_requires_an_exact_redirect_match() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let (status, body) = register(&client, &base, json!(["http://127.0.0.1:1234/callback"])).await;
    assert_eq!(status, 201);
    let client_id = body["client_id"].as_str().unwrap();

    let resp = client
        .get(format!(
            "{base}/oauth/authorize?response_type=code&client_id={client_id}\
             &redirect_uri=http%3A%2F%2F127.0.0.1%3A1234%2Fcallback%2F\
             &code_challenge=x&code_challenge_method=S256&scope=mcp"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_redirect_uri");
}
