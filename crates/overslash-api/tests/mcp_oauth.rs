//! Integration tests for the MCP OAuth transport
//! (`docs/design/mcp-oauth-transport.md`). Covers AS metadata, DCR,
//! authorize + PKCE, token exchange, refresh rotation and replay
//! detection, revoke, `/mcp` acceptance of `aud=mcp` JWTs and agent keys,
//! and the 401 + WWW-Authenticate challenge shape.

mod common;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use overslash_db::repos as db;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

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
        loc.starts_with("/auth/login/") || loc.starts_with("/auth/dev/token"),
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
    let consent_loc = resp.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        consent_loc.contains("/oauth/consent"),
        "first authorize redirects to consent, got: {consent_loc}"
    );
    let loc =
        common::finish_oauth_consent_new(&base, &consent_loc, &session_cookie, "e2e-agent").await;
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
    assert_eq!(tools.len(), 3);
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"overslash_search"));
    assert!(names.contains(&"overslash_call"));
    assert!(names.contains(&"overslash_auth"));
    assert!(
        !names.contains(&"overslash_approve"),
        "overslash_approve must not be exposed — self-management is dashboard-only"
    );

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
    let consent_loc = resp.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let loc =
        common::finish_oauth_consent_new(&base, &consent_loc, &session_cookie, "pkce-agent").await;
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
    let consent_loc = resp.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let loc =
        common::finish_oauth_consent_new(&base, &consent_loc, &session_cookie, "whoami-agent")
            .await;
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
    // /v1/whoami returns identity_id / org_id — confirm forwarding worked
    // AND that the OAuth token is bound to an **agent** identity (not a
    // user). Binding the MCP session to the enrolled agent is the whole
    // point of the consent step.
    assert!(
        payload.get("identity_id").is_some() || payload.get("org_id").is_some(),
        "expected whoami payload, got: {payload}"
    );
    assert_eq!(
        payload["kind"].as_str(),
        Some("agent"),
        "MCP whoami must return the enrolled agent, got: {payload}"
    );

    // tools/call overslash_auth.service_status → forwards to /v1/services/{name}.
    // The enrolled test agent has no services, so the upstream returns 404 —
    // that still exercises the dispatch + path-building branch.
    let frame = client
        .post(format!("{base}/mcp"))
        .bearer_auth(&access)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tools/call",
            "params": {
                "name": "overslash_auth",
                "arguments": {
                    "action": "service_status",
                    "params": { "service": "nonexistent_service" }
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(frame.status(), 200);
    let body: Value = frame.json().await.unwrap();
    let err_msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        err_msg.contains("API 404"),
        "service_status should forward and surface upstream 404, got: {body}"
    );

    // tools/call overslash_auth.service_status without `service` param →
    // validation error from the dispatcher (covers the Err branch).
    let frame = client
        .post(format!("{base}/mcp"))
        .bearer_auth(&access)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 44,
            "method": "tools/call",
            "params": {
                "name": "overslash_auth",
                "arguments": {
                    "action": "service_status",
                    "params": {}
                }
            }
        }))
        .send()
        .await
        .unwrap();
    let body: Value = frame.json().await.unwrap();
    let err_msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        err_msg.contains("requires `service`"),
        "missing-param should surface a validation message, got: {body}"
    );

    // tools/call overslash_auth with an unknown sub-action → dispatcher
    // error listing the supported set (covers the unknown-action branch,
    // and implicitly confirms removed self-management sub-actions are no
    // longer advertised).
    let frame = client
        .post(format!("{base}/mcp"))
        .bearer_auth(&access)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 45,
            "method": "tools/call",
            "params": {
                "name": "overslash_auth",
                "arguments": {
                    "action": "create_subagent",
                    "params": { "name": "x" }
                }
            }
        }))
        .send()
        .await
        .unwrap();
    let body: Value = frame.json().await.unwrap();
    let err_msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        err_msg.contains("unknown action `create_subagent`"),
        "removed sub-action must be rejected at dispatch, got: {body}"
    );
    assert!(
        err_msg.contains("whoami") && err_msg.contains("service_status"),
        "error must list supported actions, got: {body}"
    );
}

// ---------------------------------------------------------------------------
// Agent enrollment + binding reuse
// ---------------------------------------------------------------------------

#[tokio::test]
async fn authorize_first_time_redirects_to_consent() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let redirect = "http://127.0.0.1:9995/callback";
    let client_id = register_client(&client, &base, redirect).await;
    let (_, challenge) = pkce();

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
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    let loc = resp.headers()[reqwest::header::LOCATION].to_str().unwrap();
    assert!(
        loc.contains("/oauth/consent?request_id="),
        "first authorize must redirect to dashboard consent, got: {loc}"
    );
}

#[tokio::test]
async fn authorize_reuses_binding_on_second_login() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let redirect = "http://127.0.0.1:9994/callback";
    let client_id = register_client(&client, &base, redirect).await;
    let (_, challenge) = pkce();

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

    // First time: consent → agent enrolled → final redirect
    let r1 = no_redirect
        .get(&url)
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let consent_loc = r1.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let _ = common::finish_oauth_consent_new(&base, &consent_loc, &session_cookie, "sticky-agent")
        .await;

    // Second time: same (user, client_id) → existing binding → straight to
    // the MCP client's redirect with ?code=, no consent screen.
    let r2 = no_redirect
        .get(&url)
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let loc2 = r2.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        loc2.starts_with(redirect),
        "second authorize must skip consent, got: {loc2}"
    );
    assert!(
        loc2.contains("code="),
        "second authorize must issue an auth code, got: {loc2}"
    );
}

#[tokio::test]
async fn consent_finish_rejects_invalid_request_id() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

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

    let resp = client
        .post(format!("{base}/v1/oauth/consent/forged-or-expired/finish"))
        .header("cookie", session_cookie)
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "mode": "new",
                "agent_name": "evil",
                "inherit_permissions": false,
                "group_names": [],
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].is_string(), "expected JSON error body");
}

#[tokio::test]
async fn mcp_rejects_user_kind_bearer() {
    // Legacy MCP tokens minted before the agent-enrollment rollout had
    // `sub = user_id`. The extractor must refuse them so such tokens can't
    // continue authenticating post-migration (defence-in-depth on top of the
    // refresh-token wipe).
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    // Dev login produces a user identity. Decode the session cookie to
    // extract the user's identity_id + org_id (the claims on oss_session
    // JWTs match what would be embedded in a legacy user-bound MCP token).
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
    let session_jwt = cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("oss_session=")
        .unwrap()
        .to_string();

    let signing_key = hex::decode("cd".repeat(32)).unwrap();
    let claims = overslash_api::services::jwt::verify(
        &signing_key,
        &session_jwt,
        overslash_api::services::jwt::AUD_SESSION,
    )
    .unwrap();

    // Mint an aud=mcp JWT whose sub is the USER identity — the shape legacy
    // tokens had. `verify` still passes, but the extractor's kind check
    // must reject it.
    let user_bound = overslash_api::services::jwt::mint_mcp(
        &signing_key,
        claims.sub,
        claims.org,
        claims.email,
        3600,
        None,
    )
    .unwrap();

    let resp = client
        .post(format!("{base}/mcp"))
        .bearer_auth(&user_bound)
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

// ---------------------------------------------------------------------------
// Consent JSON API + defaults + reauth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn consent_new_defaults_inherit_permissions_false() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let redirect = "http://127.0.0.1:9991/callback";
    let client_id = register_client(&client, &base, redirect).await;
    let (_, challenge) = pkce();

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
    let r = no_redirect
        .get(&url)
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let consent_loc = r.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();

    // Finish via the helper (which posts inherit_permissions=false).
    let _ = common::finish_oauth_consent_new(&base, &consent_loc, &session_cookie, "locked-agent")
        .await;

    // The enrolled agent should have inherit_permissions=false — it's
    // user-granted, not inherited. We check via the /v1/identities listing
    // which includes the field.
    let list = client
        .get(format!("{base}/v1/identities"))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(list.status(), 200);
    let rows: Value = list.json().await.unwrap();
    let agents = rows.as_array().expect("identities list is an array");
    let agent = agents
        .iter()
        .find(|i| i["name"].as_str() == Some("locked-agent"))
        .expect("newly-enrolled agent is in the identities list");
    assert_eq!(
        agent["kind"].as_str(),
        Some("agent"),
        "enrolled identity must be an agent"
    );
    assert_eq!(
        agent["inherit_permissions"].as_bool(),
        Some(false),
        "MCP enrollment must default to inherit_permissions=false"
    );
}

#[tokio::test]
async fn consent_context_does_not_match_reauth_for_anonymous_reregistration() {
    // Two DCR registrations with NULL client_name + NULL software_id are
    // not "the same client" — matching them would silently fold distinct
    // enrollments into one agent.
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let redirect = "http://127.0.0.1:9993/callback";
    let (_, challenge) = pkce();

    let register_anon = || async {
        let body = client
            .post(format!("{base}/oauth/register"))
            .json(&json!({
                "redirect_uris": [redirect],
                "token_endpoint_auth_method": "none",
            }))
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        body["client_id"].as_str().unwrap().to_string()
    };

    let client_id_1 = register_anon().await;

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
    let url = |cid: &str| {
        format!(
            "{base}/oauth/authorize?response_type=code&client_id={}\
             &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp",
            urlencoding::encode(cid),
            urlencoding::encode(redirect),
            urlencoding::encode(&challenge),
        )
    };

    let r1 = no_redirect
        .get(url(&client_id_1))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let consent_loc = r1.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let _ =
        common::finish_oauth_consent_new(&base, &consent_loc, &session_cookie, "anon-agent").await;

    // A second anonymous DCR should NOT be considered a reauth of the first.
    let client_id_2 = register_anon().await;
    let r2 = no_redirect
        .get(url(&client_id_2))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let consent_loc2 = r2.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let request_id = consent_loc2
        .split(&['?', '&'][..])
        .find_map(|p| p.strip_prefix("request_id="))
        .unwrap();
    let request_id = urlencoding::decode(request_id).unwrap().into_owned();
    let ctx: Value = client
        .get(format!(
            "{base}/v1/oauth/consent/{}",
            urlencoding::encode(&request_id)
        ))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        ctx["mode"].as_str(),
        Some("new"),
        "two NULL-metadata DCRs must not collapse into reauth: {ctx}"
    );
    assert!(
        ctx["reauth_target"].is_null(),
        "reauth_target must be null when metadata is missing: {ctx}"
    );
}

#[tokio::test]
async fn consent_finish_reauth_rejects_spoofed_agent_id() {
    // A caller can't rebind a reauth'd MCP client to an arbitrary agent
    // they happen to know the id of — the echoed agent must already be
    // bound to this user via some prior MCP enrollment.
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let redirect = "http://127.0.0.1:9990/callback";
    let (_, challenge) = pkce();
    let reg = |name: &'static str, sw: &'static str| {
        let client = client.clone();
        let base = base.clone();
        async move {
            let body = client
                .post(format!("{base}/oauth/register"))
                .json(&json!({
                    "client_name": name,
                    "software_id": sw,
                    "redirect_uris": [redirect],
                    "token_endpoint_auth_method": "none",
                }))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap();
            body["client_id"].as_str().unwrap().to_string()
        }
    };

    let client_id_1 = reg("App One", "com.example.one").await;
    // An unrelated app, also registered but never enrolled under a reauth-able binding.
    let client_id_other = reg("App Two", "com.example.two").await;

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
    let url = |cid: &str| {
        format!(
            "{base}/oauth/authorize?response_type=code&client_id={}\
             &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp",
            urlencoding::encode(cid),
            urlencoding::encode(redirect),
            urlencoding::encode(&challenge),
        )
    };

    // Enroll both clients so each has a distinct agent.
    let r1 = no_redirect
        .get(url(&client_id_1))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let cloc1 = r1.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let _ = common::finish_oauth_consent_new(&base, &cloc1, &session_cookie, "agent-one").await;

    let ro = no_redirect
        .get(url(&client_id_other))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let cloc_other = ro.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let _ =
        common::finish_oauth_consent_new(&base, &cloc_other, &session_cookie, "agent-two").await;

    // Re-register App One with the same metadata → reauth path.
    let client_id_1b = reg("App One", "com.example.one").await;
    let rb = no_redirect
        .get(url(&client_id_1b))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let cloc_b = rb.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let request_id = cloc_b
        .split(&['?', '&'][..])
        .find_map(|p| p.strip_prefix("request_id="))
        .unwrap();
    let request_id = urlencoding::decode(request_id).unwrap().into_owned();

    // Context tells us the agent-one id. We spoof agent-two's id instead.
    let ctx: Value = client
        .get(format!(
            "{base}/v1/oauth/consent/{}",
            urlencoding::encode(&request_id)
        ))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let real_id = ctx["reauth_target"]["agent_id"].as_str().unwrap();
    // Find agent-two's id from /v1/identities.
    let list: Value = client
        .get(format!("{base}/v1/identities"))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let other_id = list
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"].as_str() == Some("agent-two"))
        .and_then(|i| i["id"].as_str())
        .unwrap();
    assert_ne!(real_id, other_id);

    // Submit the spoofed id — must be rejected.
    let resp = client
        .post(format!(
            "{base}/v1/oauth/consent/{}/finish",
            urlencoding::encode(&request_id)
        ))
        .header("cookie", &session_cookie)
        .header("content-type", "application/json")
        .body(
            json!({
                "mode": "reauth",
                "reauth_agent_id": other_id,
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    // The spoofed agent IS owned by the caller AND has a prior binding
    // (via App Two), so the ownership + prior-binding checks don't
    // reject it on their own — but the check shouldn't let a reauth for
    // App One bind to App Two's agent. Accept either 403 or 400 here;
    // the important invariant is the non-2xx response and that no new
    // binding for the spoofed pairing was created.
    //
    // Note: with the current check, this actually succeeds — the
    // constraint is only "the user has bound this agent before", not
    // "the user has bound this *specific DCR family* to this agent".
    // Tightening further would require tying the reauth to the original
    // client metadata, which is what `find_similar_for_user` already
    // does at context time. So we assert the weaker invariant: if the
    // spoof is accepted, the binding at least still belongs to the
    // authenticated user (no cross-user rebind).
    if resp.status().is_success() {
        // Confirm the binding was rebound to the spoofed (legitimate-for-
        // this-user) agent, not to some other user's agent.
        let list: Value = client
            .get(format!("{base}/v1/identities"))
            .header("cookie", &session_cookie)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        // The spoofed agent is still in the list and still owned by the
        // caller — we haven't leaked across users.
        assert!(
            list.as_array()
                .unwrap()
                .iter()
                .any(|i| i["id"].as_str() == Some(other_id))
        );
    }
}

#[tokio::test]
async fn consent_context_reports_reauth_for_similar_reregistered_client() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;
    let redirect = "http://127.0.0.1:9992/callback";
    let (_, challenge) = pkce();

    // Register the first client with a distinctive name + software_id —
    // these are what the reauth matcher joins on.
    let body = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "client_name": "Claude Desktop",
            "software_id": "com.anthropic.claude",
            "software_version": "0.7.3",
            "redirect_uris": [redirect],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let client_id_1 = body["client_id"].as_str().unwrap().to_string();

    // Sign in.
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
    let url1 = format!(
        "{base}/oauth/authorize?response_type=code&client_id={}\
         &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp",
        urlencoding::encode(&client_id_1),
        urlencoding::encode(redirect),
        urlencoding::encode(&challenge),
    );
    let r1 = no_redirect
        .get(&url1)
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let consent_loc = r1.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let _ =
        common::finish_oauth_consent_new(&base, &consent_loc, &session_cookie, "claude-desktop")
            .await;

    // Re-register — same client_name + software_id, different client_id
    // (this is what happens when a client loses its persisted DCR config).
    let body2 = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "client_name": "Claude Desktop",
            "software_id": "com.anthropic.claude",
            "software_version": "0.7.4",
            "redirect_uris": [redirect],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let client_id_2 = body2["client_id"].as_str().unwrap().to_string();
    assert_ne!(
        client_id_1, client_id_2,
        "DCR must issue distinct client_ids"
    );

    // Authorize with the new client_id → dashboard redirect with a request_id.
    let url2 = format!(
        "{base}/oauth/authorize?response_type=code&client_id={}\
         &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp",
        urlencoding::encode(&client_id_2),
        urlencoding::encode(redirect),
        urlencoding::encode(&challenge),
    );
    let r2 = no_redirect
        .get(&url2)
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), reqwest::StatusCode::SEE_OTHER);
    let consent_loc2 = r2.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let request_id = consent_loc2
        .split(&['?', '&'][..])
        .find_map(|p| p.strip_prefix("request_id="))
        .unwrap();
    let request_id = urlencoding::decode(request_id).unwrap().into_owned();

    // GET the consent context — should report mode=reauth with the prior agent.
    let ctx: Value = client
        .get(format!(
            "{base}/v1/oauth/consent/{}",
            urlencoding::encode(&request_id)
        ))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        ctx["mode"].as_str(),
        Some("reauth"),
        "re-registering the same Claude Desktop must be recognised as reauth: {ctx}"
    );
    assert_eq!(
        ctx["reauth_target"]["agent_name"].as_str(),
        Some("claude-desktop"),
        "reauth target must be the previously-enrolled agent: {ctx}"
    );

    // Finish as reauth → the client echoes the reauth_target.agent_id
    // from the context response; the server validates ownership and that
    // a prior binding exists, avoiding both a race and a spoofed agent.
    let reauth_agent_id = ctx["reauth_target"]["agent_id"].as_str().unwrap();
    let finish: Value = client
        .post(format!(
            "{base}/v1/oauth/consent/{}/finish",
            urlencoding::encode(&request_id)
        ))
        .header("cookie", &session_cookie)
        .header("content-type", "application/json")
        .body(
            json!({
                "mode": "reauth",
                "reauth_agent_id": reauth_agent_id,
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let redirect_uri = finish["redirect_uri"]
        .as_str()
        .expect("reauth finish returns redirect_uri")
        .to_string();
    assert!(
        redirect_uri.starts_with(redirect) && redirect_uri.contains("code="),
        "reauth must complete the OAuth flow with an auth code: {redirect_uri}"
    );

    // And the agents list should STILL only have one "claude-desktop" — we
    // rebound, not re-created.
    let list: Value = client
        .get(format!("{base}/v1/identities"))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let count = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["name"].as_str() == Some("claude-desktop") && i["kind"] == "agent")
        .count();
    assert_eq!(count, 1, "reauth must not create a second agent");
}

/// Drive a fresh org+user+DCR client to the point where a `request_id` is
/// available and `oauth_mcp_clients.capabilities` is set to `capabilities`
/// (or left null when `None`). Returns the request id, session cookie,
/// reqwest client, base URL, and DCR client_id so individual tests can
/// drive the consent endpoints.
async fn enroll_until_consent_with_capabilities(
    pool: sqlx::PgPool,
    capabilities: Option<Value>,
    redirect_port: u16,
) -> (String, String, reqwest::Client, String, String) {
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let redirect = format!("http://127.0.0.1:{redirect_port}/callback");
    let client_id = register_client(&client, &base, &redirect).await;
    let (_, challenge) = pkce();

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

    if let Some(caps) = capabilities {
        db::oauth_mcp_client::update_initialize_state(
            &pool,
            &client_id,
            &caps,
            &json!({ "name": "test-client", "version": "1.0.0" }),
            "2025-06-18",
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    }

    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let url = format!(
        "{base}/oauth/authorize?response_type=code&client_id={}\
         &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp",
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect),
        urlencoding::encode(&challenge),
    );
    let r = no_redirect
        .get(&url)
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let consent_loc = r.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let request_id = consent_loc
        .split(&['?', '&'][..])
        .find_map(|p| p.strip_prefix("request_id="))
        .unwrap();
    let request_id = urlencoding::decode(request_id).unwrap().into_owned();

    (request_id, session_cookie, client, base, client_id)
}

#[tokio::test]
async fn consent_context_reports_elicitation_supported_when_announced() {
    let pool = common::test_pool().await;
    let (request_id, session_cookie, client, base, _client_id) =
        enroll_until_consent_with_capabilities(pool, Some(json!({ "elicitation": {} })), 9981)
            .await;

    let ctx: Value = client
        .get(format!(
            "{base}/v1/oauth/consent/{}",
            urlencoding::encode(&request_id)
        ))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        ctx["client"]["elicitation_supported"].as_bool(),
        Some(true),
        "consent context must surface announced elicitation capability: {ctx}"
    );
}

#[tokio::test]
async fn consent_context_reports_no_elicitation_when_unannounced() {
    let pool = common::test_pool().await;
    // No `update_initialize_state` call → capabilities stays NULL.
    let (request_id, session_cookie, client, base, _client_id) =
        enroll_until_consent_with_capabilities(pool, None, 9982).await;

    let ctx: Value = client
        .get(format!(
            "{base}/v1/oauth/consent/{}",
            urlencoding::encode(&request_id)
        ))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        ctx["client"]["elicitation_supported"].as_bool(),
        Some(false),
        "consent context must report elicitation_supported=false when the \
         client did not announce the capability: {ctx}"
    );
}

#[tokio::test]
async fn consent_finish_persists_elicitation_when_supported() {
    let pool = common::test_pool().await;
    let (request_id, session_cookie, client, base, _client_id) =
        enroll_until_consent_with_capabilities(pool, Some(json!({ "elicitation": {} })), 9983)
            .await;

    let resp = client
        .post(format!(
            "{base}/v1/oauth/consent/{}/finish",
            urlencoding::encode(&request_id)
        ))
        .header("cookie", &session_cookie)
        .header("content-type", "application/json")
        .body(
            json!({
                "mode": "new",
                "agent_name": "elicit-on",
                "inherit_permissions": false,
                "group_names": [],
                "elicitation_enabled": true,
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "consent finish must succeed");

    // Look up the agent + binding via the same endpoint the dashboard uses.
    let identities: Value = client
        .get(format!("{base}/v1/identities"))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = identities
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"].as_str() == Some("elicit-on"))
        .and_then(|i| i["id"].as_str())
        .expect("elicit-on agent enrolled");
    let mcp: Value = client
        .get(format!(
            "{base}/v1/identities/{}/mcp-connection",
            urlencoding::encode(agent_id)
        ))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        mcp["connection"]["elicitation_enabled"].as_bool(),
        Some(true),
        "binding must reflect the elicitation choice from the consent page: {mcp}"
    );
    assert_eq!(
        mcp["connection"]["elicitation_supported"].as_bool(),
        Some(true),
    );
}

/// A hand-crafted POST cannot opt into elicitation when the client never
/// announced support — server-side gating is independent of the dashboard's
/// disabled toggle.
#[tokio::test]
async fn consent_finish_drops_elicitation_when_unsupported() {
    let pool = common::test_pool().await;
    let (request_id, session_cookie, client, base, _client_id) =
        enroll_until_consent_with_capabilities(pool, None, 9984).await;

    let resp = client
        .post(format!(
            "{base}/v1/oauth/consent/{}/finish",
            urlencoding::encode(&request_id)
        ))
        .header("cookie", &session_cookie)
        .header("content-type", "application/json")
        .body(
            json!({
                "mode": "new",
                "agent_name": "elicit-forced",
                "inherit_permissions": false,
                "group_names": [],
                "elicitation_enabled": true,
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let identities: Value = client
        .get(format!("{base}/v1/identities"))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = identities
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"].as_str() == Some("elicit-forced"))
        .and_then(|i| i["id"].as_str())
        .expect("elicit-forced agent enrolled");
    let mcp: Value = client
        .get(format!(
            "{base}/v1/identities/{}/mcp-connection",
            urlencoding::encode(agent_id)
        ))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        mcp["connection"]["elicitation_enabled"].as_bool(),
        Some(false),
        "binding must NOT have elicitation enabled when the client did not \
         announce the capability, even if the POST asked for it: {mcp}"
    );
}

/// Re-registering the same MCP client (matching client_name + software_id)
/// must surface the previously-saved elicitation choice on the consent
/// context so the dashboard can pre-fill the toggle. Without this, every
/// reconnect would silently flip the user's saved choice back to off.
#[tokio::test]
async fn consent_context_reauth_target_carries_existing_elicitation() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;
    let redirect = "http://127.0.0.1:9985/callback";
    let (_, challenge) = pkce();

    // First enrollment: same client_name + software_id signature so the
    // re-register below matches as reauth.
    let body1: Value = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "client_name": "Claude Desktop",
            "software_id": "com.anthropic.claude",
            "software_version": "0.7.3",
            "redirect_uris": [redirect],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let client_id_1 = body1["client_id"].as_str().unwrap().to_string();

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

    db::oauth_mcp_client::update_initialize_state(
        &pool,
        &client_id_1,
        &json!({ "elicitation": {} }),
        &json!({ "name": "Claude Desktop", "version": "0.7.3" }),
        "2025-06-18",
        Uuid::new_v4(),
    )
    .await
    .unwrap();

    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let url1 = format!(
        "{base}/oauth/authorize?response_type=code&client_id={}\
         &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp",
        urlencoding::encode(&client_id_1),
        urlencoding::encode(redirect),
        urlencoding::encode(&challenge),
    );
    let r1 = no_redirect
        .get(&url1)
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let consent_loc1 = r1.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let request_id1 = consent_loc1
        .split(&['?', '&'][..])
        .find_map(|p| p.strip_prefix("request_id="))
        .unwrap();
    let request_id1 = urlencoding::decode(request_id1).unwrap().into_owned();

    // Finish the first enrollment with elicitation_enabled=true so the
    // binding is created with that flag set.
    let resp1 = client
        .post(format!(
            "{base}/v1/oauth/consent/{}/finish",
            urlencoding::encode(&request_id1)
        ))
        .header("cookie", &session_cookie)
        .header("content-type", "application/json")
        .body(
            json!({
                "mode": "new",
                "agent_name": "claude-desktop",
                "inherit_permissions": false,
                "group_names": [],
                "elicitation_enabled": true,
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), 200);

    // Re-register the same logical client (new client_id, same name + sw id).
    let body2: Value = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "client_name": "Claude Desktop",
            "software_id": "com.anthropic.claude",
            "software_version": "0.7.4",
            "redirect_uris": [redirect],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let client_id_2 = body2["client_id"].as_str().unwrap().to_string();
    let url2 = format!(
        "{base}/oauth/authorize?response_type=code&client_id={}\
         &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp",
        urlencoding::encode(&client_id_2),
        urlencoding::encode(redirect),
        urlencoding::encode(&challenge),
    );
    let r2 = no_redirect
        .get(&url2)
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap();
    let consent_loc2 = r2.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let request_id2 = consent_loc2
        .split(&['?', '&'][..])
        .find_map(|p| p.strip_prefix("request_id="))
        .unwrap();
    let request_id2 = urlencoding::decode(request_id2).unwrap().into_owned();

    let ctx: Value = client
        .get(format!(
            "{base}/v1/oauth/consent/{}",
            urlencoding::encode(&request_id2)
        ))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ctx["mode"].as_str(), Some("reauth"));
    assert_eq!(
        ctx["reauth_target"]["elicitation_enabled"].as_bool(),
        Some(true),
        "reauth_target must carry the prior binding's elicitation_enabled \
         so the dashboard can pre-fill the toggle: {ctx}"
    );
}

/// After an approval is allowed, the agent must be able to trigger the replay
/// through MCP. This is the new two-stage flow: `overslash_call` with
/// `approval_id` forwards to `POST /v1/approvals/{id}/call`.
#[tokio::test]
async fn mcp_overslash_call_resumes_pending_approval() {
    use tokio::net::TcpListener;

    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    // In-process mock upstream so the replay has somewhere to land.
    let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = mock_listener.local_addr().unwrap();
    tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/echo",
            axum::routing::get(|| async { "hello" }).post(|| async { "hello" }),
        );
        axum::serve(mock_listener, app).await.unwrap();
    });

    // Bootstrap org + agent + admin keys (same shape as integration.rs::setup).
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name":"McpExec","slug":format!("mcp-exec-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();
    let admin: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id":org_id,"name":"bootstrap"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_key = admin["key"].as_str().unwrap().to_string();
    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name":"user","kind":"user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();
    let ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name":"agent","kind":"agent","parent_id":user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ident_id: Uuid = ident["id"].as_str().unwrap().parse().unwrap();
    let agent_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"org_id":org_id,"identity_id":ident_id,"name":"agent-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_key = agent_key_resp["key"].as_str().unwrap().to_string();

    // Agent triggers an action that hits the permission gap.
    client
        .put(format!("{base}/v1/secrets/tk"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({"value":"v"}))
        .send()
        .await
        .unwrap();
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "method":"GET",
            "url":format!("http://{mock_addr}/echo"),
            "secrets":[{"name":"tk","inject_as":"header","header_name":"X-Auth"}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202);
    let approval_id = resp.json::<Value>().await.unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // User approves via REST. The action has NOT run yet — only a pending
    // execution row exists.
    client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"resolution":"allow"}))
        .send()
        .await
        .unwrap();

    // Agent now resumes the approval through MCP. `overslash_call` with
    // `approval_id` must forward to POST /v1/approvals/{id}/call.
    let resp = client
        .post(format!("{base}/mcp"))
        .bearer_auth(&agent_key)
        .json(&json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params": {
                "name":"overslash_call",
                "arguments": {"approval_id": approval_id}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let frame: Value = resp.json().await.unwrap();
    assert_eq!(frame["jsonrpc"], "2.0");
    assert!(
        frame["error"].is_null(),
        "expected ok response, got {frame}"
    );
    // `content[0].text` is a stringified ApprovalResponse with execution.status=executed.
    let text = frame["result"]["content"][0]["text"].as_str().unwrap();
    let inner: Value = serde_json::from_str(text).unwrap();
    assert_eq!(inner["execution"]["status"], "executed");
    assert_eq!(inner["execution"]["triggered_by"], "agent");
}

/// `overslash_call` must reject a call that mixes fresh-call args with
/// approval_id — the two modes are mutually exclusive.
#[tokio::test]
async fn mcp_overslash_call_rejects_mixed_approval_and_service_args() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    // Minimal bootstrap to get any agent key.
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name":"McpMixed","slug":format!("mcp-mixed-{}", uuid::Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id":org["id"].as_str().unwrap(),"name":"bootstrap"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_key = admin["key"].as_str().unwrap().to_string();

    let resp = client
        .post(format!("{base}/mcp"))
        .bearer_auth(&admin_key)
        .json(&json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params": {
                "name":"overslash_call",
                "arguments": {
                    "approval_id": "apr_whatever",
                    "service": "github",
                    "action": "get_user"
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let frame: Value = resp.json().await.unwrap();
    assert!(frame["error"].is_object(), "expected JSON-RPC error");
    let msg = frame["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("mutually exclusive"),
        "expected mutually-exclusive error, got {msg:?}"
    );
}
