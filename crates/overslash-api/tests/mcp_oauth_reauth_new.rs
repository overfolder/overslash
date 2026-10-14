//! The consent page's reauth match is a heuristic (same `client_name` +
//! `software_id` as a prior binding), so a genuinely separate instance of
//! the same MCP client lands on it. The dashboard lets the user opt out and
//! connect as a new agent; that relies on `finish` honouring the *posted*
//! mode rather than the one `consent_context` suggested. This pins that
//! contract.

use crate::common;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use overslash_db::repos as db;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const REDIRECT: &str = "http://127.0.0.1:9993/callback";

fn pkce_challenge() -> String {
    let verifier = URL_SAFE_NO_PAD.encode(b"pkce-verifier-0123456789abcdefghij");
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

async fn register(client: &reqwest::Client, base: &str) -> String {
    let body: Value = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "client_name": "Claude Desktop",
            "software_id": "com.anthropic.claude",
            "redirect_uris": [REDIRECT],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["client_id"].as_str().unwrap().to_string()
}

/// Run `/oauth/authorize` for `client_id` and return the consent redirect
/// location (which carries the `request_id`).
async fn authorize(base: &str, client_id: &str, session_cookie: &str) -> String {
    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let url = format!(
        "{base}/oauth/authorize?response_type=code&client_id={}\
         &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp",
        urlencoding::encode(client_id),
        urlencoding::encode(REDIRECT),
        urlencoding::encode(&pkce_challenge()),
    );
    let resp = no_redirect
        .get(&url)
        .header("cookie", session_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    resp.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_string()
}

fn agent_id_named(list: &Value, name: &str) -> Uuid {
    let matches: Vec<&Value> = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["name"].as_str() == Some(name) && i["kind"] == "agent")
        .collect();
    assert_eq!(matches.len(), 1, "expected one agent named {name}: {list}");
    matches[0]["id"].as_str().unwrap().parse().unwrap()
}

#[tokio::test]
async fn consent_finish_new_mode_on_reauth_detected_request_creates_fresh_agent() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;

    let login = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap();
    let session_cookie = login
        .headers()
        .get_all("set-cookie")
        .iter()
        .find_map(|v| {
            v.to_str()
                .ok()
                .filter(|s| s.starts_with("__Host-oss_session="))
        })
        .and_then(|c| c.split(';').next())
        .unwrap()
        .to_string();

    // First instance enrolls normally.
    let client_id_1 = register(&client, &base).await;
    let loc1 = authorize(&base, &client_id_1, &session_cookie).await;
    let _ = common::finish_oauth_consent_new(&base, &loc1, &session_cookie, "claude-desktop").await;

    // A second instance with identical metadata is detected as reauth…
    let client_id_2 = register(&client, &base).await;
    let loc2 = authorize(&base, &client_id_2, &session_cookie).await;
    let request_id = loc2
        .split(&['?', '&'][..])
        .find_map(|p| p.strip_prefix("request_id="))
        .unwrap();
    let ctx: Value = client
        .get(format!("{base}/v1/oauth/consent/{request_id}"))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ctx["mode"].as_str(), Some("reauth"), "{ctx}");
    assert_eq!(
        ctx["reauth_target"]["agent_name"].as_str(),
        Some("claude-desktop"),
        "{ctx}"
    );

    // …but the user opts out and connects it as a new, renamed agent.
    let _ =
        common::finish_oauth_consent_new(&base, &loc2, &session_cookie, "claude-desktop-2").await;

    let list: Value = client
        .get(format!("{base}/v1/identities"))
        .header("cookie", &session_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let original = agent_id_named(&list, "claude-desktop");
    let fresh = agent_id_named(&list, "claude-desktop-2");
    assert_ne!(original, fresh);

    // Each client is bound to its own agent; the original keeps its binding.
    let b_original = db::mcp_client_agent_binding::get_by_agent_identity(&pool, original)
        .await
        .unwrap()
        .expect("original agent keeps its binding");
    assert_eq!(b_original.client_id, client_id_1);
    let b_fresh = db::mcp_client_agent_binding::get_by_agent_identity(&pool, fresh)
        .await
        .unwrap()
        .expect("new agent is bound");
    assert_eq!(b_fresh.client_id, client_id_2);
}
