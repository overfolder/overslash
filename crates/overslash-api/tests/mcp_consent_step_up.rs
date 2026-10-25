//! Enrolling an MCP client as an org admin needs the admin step-up.
//!
//! An MCP token is bound to an agent, and an agent resolves its `AdminAcl`
//! level through its owner — so an org admin's MCP token passes `AdminAcl`
//! on admin mutations, which skip the step-up for bearer credentials. The
//! gate therefore sits where the token is minted: `consent_finish` refuses a
//! session that would fail the step-up whenever the enrolling human is an
//! admin of the (shared) org. Otherwise a magic-link session re-scoped into
//! a shared org could mint a long-lived bearer that does admin work no
//! dashboard session of its own could.

use crate::admin_step_up::{
    cookie, create_group, session, set_session, shared_org, start_with_google, step_up_reason,
};
use crate::common;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const REDIRECT: &str = "http://127.0.0.1:9999/callback";

fn pkce() -> (String, String) {
    let verifier = URL_SAFE_NO_PAD.encode(b"pkce-verifier-0123456789abcdefghij");
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

/// Register a client and park an authorize request for `cookie`'s session;
/// returns the client id and the consent `request_id`.
async fn start_enrollment(base: &str, client: &Client, cookie: &str) -> (String, String) {
    let reg: Value = client
        .post(format!("{base}/oauth/register"))
        .json(&json!({
            "client_name": "step-up-client",
            "redirect_uris": [REDIRECT],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let client_id = reg["client_id"].as_str().unwrap().to_string();
    let (_, challenge) = pkce();
    let resp = client
        .get(format!(
            "{base}/oauth/authorize?response_type=code&client_id={}\
             &redirect_uri={}&code_challenge={}&code_challenge_method=S256&scope=mcp",
            urlencoding::encode(&client_id),
            urlencoding::encode(REDIRECT),
            urlencoding::encode(&challenge),
        ))
        .header("cookie", cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp.headers()[reqwest::header::LOCATION].to_str().unwrap();
    let request_id = loc
        .split(&['?', '&'][..])
        .find_map(|p| p.strip_prefix("request_id="))
        .unwrap_or_else(|| panic!("authorize must park a consent request, got {loc}"));
    (
        client_id,
        urlencoding::decode(request_id).unwrap().into_owned(),
    )
}

async fn finish(base: &str, client: &Client, cookie: &str, request_id: &str) -> reqwest::Response {
    client
        .post(format!(
            "{base}/v1/oauth/consent/{}/finish",
            urlencoding::encode(request_id)
        ))
        .header("cookie", cookie)
        .json(&json!({
            "mode": "new",
            "agent_name": "admin-agent",
            "inherit_permissions": false,
            "group_names": [],
        }))
        .send()
        .await
        .unwrap()
}

/// Exchange a successful finish's code for the MCP access token.
async fn access_token(
    base: &str,
    client: &Client,
    client_id: &str,
    finished: reqwest::Response,
) -> String {
    assert_eq!(finished.status(), StatusCode::OK);
    let body: Value = finished.json().await.unwrap();
    let redirect = body["redirect_uri"].as_str().unwrap();
    let code = redirect
        .split(&['?', '&'][..])
        .find_map(|p| p.strip_prefix("code="))
        .unwrap();
    let code = urlencoding::decode(code).unwrap().into_owned();
    let (verifier, _) = pkce();
    let tok: Value = client
        .post(format!("{base}/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT),
            ("client_id", client_id),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    tok["access_token"].as_str().unwrap().to_string()
}

/// `(org_id, identity_id)` the session acts as.
async fn whoami(base: &str, client: &Client, cookie: &str) -> (Uuid, Uuid) {
    let me: Value = client
        .get(format!("{base}/v1/whoami"))
        .header("cookie", cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = |k: &str| me[k].as_str().unwrap().parse().unwrap();
    (id("org_id"), id("identity_id"))
}

/// A magic-link sign-in, landed in its personal org.
async fn magic_link(base: &str, client: &Client) -> String {
    let email = format!("mcp-stepup-{}@example.com", Uuid::new_v4());
    let body: Value = client
        .post(format!("{base}/auth/magic-link/request"))
        .json(&json!({ "email": email }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let link = body["dev_verify_url"].as_str().unwrap();
    let path = &link[link.find("/auth/").unwrap()..];
    let resp = client.get(format!("{base}{path}")).send().await.unwrap();
    cookie(&set_session(&resp).expect("verify sets a session"))
}

/// The reported hole: a magic link, re-scoped into a shared org its human
/// administers, enrolls an MCP client — and the token then performs admin
/// mutations the session itself is refused.
#[tokio::test]
async fn a_magic_link_session_cannot_mint_an_admin_mcp_token() {
    let pool = common::test_pool().await;
    let (base, client) = start_with_google(pool.clone(), true).await;
    let personal = magic_link(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/orgs"))
        .header("cookie", &personal)
        .json(&json!({"name": "Corp", "slug": format!("corp-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let corp = cookie(&set_session(&resp).expect("create re-scopes the session"));
    let (reason, _) = step_up_reason(create_group(&base, &client, ("cookie", &corp)).await).await;
    assert_eq!(reason.as_deref(), Some("idp_required"));

    let (client_id, request_id) = start_enrollment(&base, &client, &corp).await;
    let (reason, body) = step_up_reason(finish(&base, &client, &corp, &request_id).await).await;
    assert_eq!(reason.as_deref(), Some("idp_required"));
    assert_eq!(body["providers"][0]["key"], "google", "{body}");

    // The refusal leaves the request parked, so the human can step up and
    // come back to the same consent page.
    let (org_id, admin) = whoami(&base, &client, &corp).await;
    let fresh = session(&pool, org_id, admin, Some("idp"), Some("google"), 60).await;
    let token = access_token(
        &base,
        &client,
        &client_id,
        finish(&base, &client, &fresh, &request_id).await,
    )
    .await;
    let bearer = format!("Bearer {token}");
    let resp = create_group(&base, &client, ("authorization", &bearer)).await;
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
}

#[tokio::test]
async fn a_stale_admin_session_must_step_up_to_enroll() {
    let pool = common::test_pool().await;
    let (base, client) = start_with_google(pool.clone(), true).await;
    let (org_id, admin, _) = shared_org(&base, &client).await;

    let stale = session(&pool, org_id, admin, Some("idp"), Some("google"), 7200).await;
    let (_, request_id) = start_enrollment(&base, &client, &stale).await;
    let (reason, _) = step_up_reason(finish(&base, &client, &stale, &request_id).await).await;
    assert_eq!(reason.as_deref(), Some("stale"));
}

/// The gate is about admin power: a member's agent cannot pass `AdminAcl`,
/// and a personal org has no one else to reach.
#[tokio::test]
async fn members_and_personal_orgs_enroll_without_a_step_up() {
    let pool = common::test_pool().await;
    let (base, client) = start_with_google(pool.clone(), true).await;
    let (org_id, _, admin_key) = shared_org(&base, &client).await;

    let member: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "member", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let member_id: Uuid = member["id"].as_str().unwrap().parse().unwrap();
    let member_link = session(&pool, org_id, member_id, Some("magic_link"), None, 7200).await;
    let (client_id, request_id) = start_enrollment(&base, &client, &member_link).await;
    let token = access_token(
        &base,
        &client,
        &client_id,
        finish(&base, &client, &member_link, &request_id).await,
    )
    .await;
    let bearer = format!("Bearer {token}");
    let resp = create_group(&base, &client, ("authorization", &bearer)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let personal = magic_link(&base, &client).await;
    let (_, request_id) = start_enrollment(&base, &client, &personal).await;
    let resp = finish(&base, &client, &personal, &request_id).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "{}",
        resp.text().await.unwrap()
    );
}
