//! Integration tests for the MCP OAuth transport
//! (`docs/design/mcp-oauth-transport.md`). Covers AS metadata, DCR,
//! authorize + PKCE, token exchange, refresh rotation and replay
//! detection, revoke, `/mcp` acceptance of `aud=mcp` JWTs and agent keys,
//! and the 401 + WWW-Authenticate challenge shape.

mod common;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn pkce() -> (String, String) {
    let verifier = URL_SAFE_NO_PAD.encode(b"pkce-verifier-0123456789abcdefghij");
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

async fn register_client(client: &reqwest::Client, base: &str, redirect_uri: &str) -> String {
    let resp = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "client_name": "test-client",
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::CREATED,
        "DCR must return 201"
    );
    let body: Value = resp.json().await.unwrap();
    body["client_id"].as_str().unwrap().to_string()
}

// ---------------------------------------------------------------------------
// AS metadata
// ---------------------------------------------------------------------------

#[tokio::test]
async fn as_metadata_advertises_mcp_endpoints() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .get(format!("{base}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // Endpoints should point at the same origin as `public_url`.
    assert!(
        body["authorization_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth/authorize")
    );
    assert!(
        body["token_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth/token")
    );
    assert!(
        body["registration_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth/register")
    );
    assert!(
        body["revocation_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth/revoke")
    );
    assert_eq!(body["scopes_supported"], json!(["mcp"]));
    assert_eq!(body["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        body["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );
}

#[tokio::test]
async fn protected_resource_metadata_points_at_as() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .get(format!("{base}/.well-known/oauth-protected-resource"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["resource"].as_str().unwrap().ends_with("/mcp"));
    assert!(body["authorization_servers"].is_array());
    assert_eq!(body["scopes_supported"], json!(["mcp"]));
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dcr_happy_path_returns_public_client() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "client_name": "my-editor",
            "redirect_uris": ["http://127.0.0.1:1234/callback"],
            "token_endpoint_auth_method": "none",
            "software_id": "my-editor",
            "software_version": "1.0.0",
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);
    let body: Value = resp.json().await.unwrap();
    assert!(body["client_id"].as_str().unwrap().starts_with("osc_"));
    assert!(
        body.get("client_secret").is_none(),
        "public clients must not get a client_secret"
    );
    assert_eq!(body["token_endpoint_auth_method"], "none");
}

#[tokio::test]
async fn dcr_rejects_non_public_auth_method() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "redirect_uris": ["http://127.0.0.1/x"],
            "token_endpoint_auth_method": "client_secret_basic",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn dcr_requires_redirect_uris() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({ "redirect_uris": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_redirect_uri");
}

// ---------------------------------------------------------------------------
// Authorize
// ---------------------------------------------------------------------------

#[tokio::test]
async fn authorize_without_session_redirects_to_login() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let redirect = "http://127.0.0.1:9/callback";
    let client_id = register_client(&client, &base, redirect).await;
    let (_, challenge) = pkce();

    // Use a no-redirect client so we can inspect the 302.
    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let url = format!(
        "{base}/oauth/authorize?response_type=code&client_id={}\
         &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp&state=s1",
        urlencoding::encode(&client_id),
        urlencoding::encode(redirect),
        urlencoding::encode(&challenge),
    );
    let resp = no_redirect.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        loc.starts_with("/auth/login/"),
        "redirect to login, got: {loc}"
    );
    assert!(loc.contains("next="), "next= query param present");
}

#[tokio::test]
async fn authorize_rejects_mismatched_redirect_uri() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let client_id = register_client(&client, &base, "http://127.0.0.1:9/callback").await;
    let (_, challenge) = pkce();

    // Get a session cookie first via dev login so we bypass the IdP bounce.
    let login = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap();
    let cookie = login
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|v| v.to_str().ok().filter(|s| s.starts_with("oss_session=")))
        .unwrap()
        .to_string();
    let session_cookie = cookie.split(';').next().unwrap().to_string();

    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let url = format!(
        "{base}/oauth/authorize?response_type=code&client_id={}\
         &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp",
        urlencoding::encode(&client_id),
        urlencoding::encode("http://evil.example.com/pwn"),
        urlencoding::encode(&challenge),
    );
    let resp = no_redirect
        .get(&url)
        .header("cookie", session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_redirect_uri");
}

#[tokio::test]
async fn authorize_full_flow_issues_code_and_token() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let redirect = "http://127.0.0.1:9999/callback";
    let client_id = register_client(&client, &base, redirect).await;
    let (verifier, challenge) = pkce();

    // dev login → session cookie
    let login = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap();
    let session_cookie = login
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|v| v.to_str().ok().filter(|s| s.starts_with("oss_session=")))
        .and_then(|c| c.split(';').next())
        .unwrap()
        .to_string();

    // /oauth/authorize → 303 to redirect_uri?code=…
    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let authorize_url = format!(
        "{base}/oauth/authorize?response_type=code&client_id={}\
         &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp&state=abc",
        urlencoding::encode(&client_id),
        urlencoding::encode(redirect),
        urlencoding::encode(&challenge),
    );
    let resp = no_redirect
        .get(&authorize_url)
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    let loc = resp.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert!(loc.starts_with(redirect));
    let code: String = loc
        .split(&['?', '&'][..])
        .find_map(|p: &str| p.strip_prefix("code=").map(|s| s.to_string()))
        .unwrap();
    let code = urlencoding::decode(&code).unwrap().into_owned();

    // /oauth/token authorization_code
    let token_resp = client
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect),
            ("client_id", client_id.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(token_resp.status(), 200);
    let tok: Value = token_resp.json().await.unwrap();
    assert_eq!(tok["token_type"], "Bearer");
    assert_eq!(tok["scope"], "mcp");
    assert!(tok["access_token"].as_str().unwrap().len() > 20);
    let refresh = tok["refresh_token"].as_str().unwrap().to_string();
    let access = tok["access_token"].as_str().unwrap().to_string();

    // /mcp with the access token accepts the frame (we just hit tools/list).
    let mcp_resp = client
        .post(format!("{base}/mcp"))
        .bearer_auth(&access)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(mcp_resp.status(), 200);
    let frame: Value = mcp_resp.json().await.unwrap();
    assert_eq!(frame["jsonrpc"], "2.0");
    assert_eq!(frame["id"], 1);
    let tools = frame["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 4);

    // Refresh rotates the refresh token.
    let refresh_resp = client
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(refresh_resp.status(), 200);
    let rotated: Value = refresh_resp.json().await.unwrap();
    let new_refresh = rotated["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(new_refresh, refresh, "refresh token must rotate");

    // Reuse of the *old* refresh is a replay → rejected + chain revoked.
    let replay = client
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 400);

    // The new refresh is now also revoked (chain invariant).
    let after_chain_revoke = client
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", new_refresh.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(after_chain_revoke.status(), 400);
}

// ---------------------------------------------------------------------------
// Token endpoint — negative cases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_rejects_wrong_pkce_verifier() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let redirect = "http://127.0.0.1:9998/callback";
    let client_id = register_client(&client, &base, redirect).await;
    let (_verifier, challenge) = pkce();

    let login = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap();
    let session_cookie = login
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|v| v.to_str().ok().filter(|s| s.starts_with("oss_session=")))
        .and_then(|c| c.split(';').next())
        .unwrap()
        .to_string();

    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let url = format!(
        "{base}/oauth/authorize?response_type=code&client_id={}\
         &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp",
        urlencoding::encode(&client_id),
        urlencoding::encode(redirect),
        urlencoding::encode(&challenge),
    );
    let resp = no_redirect
        .get(&url)
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let loc = resp.headers()[reqwest::header::LOCATION].to_str().unwrap();
    let code: String = loc
        .split(&['?', '&'][..])
        .find_map(|p: &str| p.strip_prefix("code=").map(|s| s.to_string()))
        .unwrap();
    let code = urlencoding::decode(&code).unwrap().into_owned();

    let token_resp = client
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect),
            ("client_id", client_id.as_str()),
            ("code_verifier", "the-wrong-verifier-123456789abcdef-xxxxxx"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(token_resp.status(), 400);
    let body: Value = token_resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}

// ---------------------------------------------------------------------------
// /mcp Bearer acceptance + 401 challenge
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mcp_without_bearer_returns_401_with_challenge() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .post(format!("{base}/mcp"))
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let www = resp
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(www.contains("Bearer"));
    assert!(www.contains("resource_metadata"));
}

#[tokio::test]
async fn mcp_rejects_bogus_bearer() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .post(format!("{base}/mcp"))
        .bearer_auth("not_a_real_token")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mcp_tools_call_forwards_to_rest_with_bearer() {
    // End-to-end: mint an MCP access token via the full OAuth dance, then
    // hit `/mcp` with `tools/call` for `overslash_auth.whoami`. The tools
    // dispatcher must forward the Bearer to the loopback REST endpoint
    // (`/v1/whoami`) and return the user's identity. This exercises the
    // critical dispatch path (tools_call → forward) that static
    // `tools/list` does not touch.
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let redirect = "http://127.0.0.1:9997/callback";
    let client_id = register_client(&client, &base, redirect).await;
    let (verifier, challenge) = pkce();

    // dev login → session cookie
    let login = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap();
    let session_cookie = login
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|v| v.to_str().ok().filter(|s| s.starts_with("oss_session=")))
        .and_then(|c| c.split(';').next())
        .unwrap()
        .to_string();

    // /oauth/authorize → redirect with code
    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let authorize_url = format!(
        "{base}/oauth/authorize?response_type=code&client_id={}\
         &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp",
        urlencoding::encode(&client_id),
        urlencoding::encode(redirect),
        urlencoding::encode(&challenge),
    );
    let resp = no_redirect
        .get(&authorize_url)
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let loc = resp.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let code: String = loc
        .split(&['?', '&'][..])
        .find_map(|p: &str| p.strip_prefix("code=").map(|s| s.to_string()))
        .unwrap();
    let code = urlencoding::decode(&code).unwrap().into_owned();

    // /oauth/token → access_token
    let token_resp = client
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect),
            ("client_id", client_id.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .unwrap();
    let tok: Value = token_resp.json().await.unwrap();
    let access = tok["access_token"].as_str().unwrap().to_string();

    // tools/call overslash_auth.whoami → forwards to /v1/whoami
    let frame = client
        .post(format!("{base}/mcp"))
        .bearer_auth(&access)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "overslash_auth",
                "arguments": {
                    "action": "whoami",
                    "params": {}
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(frame.status(), 200);
    let body: Value = frame.json().await.unwrap();
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 42);
    let text = body["result"]["content"][0]["text"].as_str().unwrap();
    let payload: Value = serde_json::from_str(text).unwrap();
    // /v1/whoami returns identity_id / org_id — just confirm forwarding
    // worked by checking at least one of the expected keys is present.
    assert!(
        payload.get("identity_id").is_some() || payload.get("org_id").is_some(),
        "expected whoami payload, got: {payload}"
    );
}

#[tokio::test]
async fn revoke_returns_200_for_unknown_token() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .post(format!("{base}/oauth/revoke"))
        .form(&[("token", "does-not-exist")])
        .send()
        .await
        .unwrap();
    // RFC 7009: always 200 on success, including for unknown tokens.
    assert_eq!(resp.status(), 200);
}
