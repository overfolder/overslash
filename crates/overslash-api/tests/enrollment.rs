//! Integration tests for agent enrollment (both token-based and agent-initiated flows).

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

// ─── Helpers ───────────────────────────────────────────────────────────

/// Bootstrap org + agent identity + org-level API key.
/// Returns (org_id, agent_identity_id, org_admin_api_key).
async fn setup_org_with_agent(base: &str, client: &reqwest::Client) -> (Uuid, Uuid, String) {
    let (org_id, _agent_id, _agent_key, api_key) =
        common::bootstrap_org_identity(base, client).await;

    // bootstrap_org_identity already creates an agent identity and an identity-bound key.
    // But for enrollment tokens we need the org-level key (to create tokens) and the agent identity.
    // Let's create a fresh agent identity that has NO key yet (to test enrollment properly).

    // Find the user identity to use as parent (agents require a parent_id)
    let identities: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = identities.iter().find(|i| i["kind"] == "user").unwrap()["id"]
        .as_str()
        .unwrap();

    let ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({"name": "enrollment-target", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = ident["id"].as_str().unwrap().parse().unwrap();

    (org_id, agent_id, api_key)
}

/// Extract the approval token from an approval URL (which points to the dashboard
/// consent page) and rebuild as the backend POST endpoint at the test base.
fn rebase_approval_url(approval_url: &str, base: &str) -> String {
    // approval_url looks like ".../enroll/consent/{token}"
    // We need ".../enroll/approve/{token}" against the test API base.
    let token = approval_url
        .rsplit_once('/')
        .map(|(_, t)| t)
        .unwrap_or(approval_url);
    format!("{base}/enroll/approve/{token}")
}

/// Get dev session JWT token string.
async fn dev_session_token(base: &str, client: &reqwest::Client) -> String {
    let resp: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["token"].as_str().unwrap().to_string()
}

/// Create an enrollment token via API key auth.
async fn create_token(
    base: &str,
    client: &reqwest::Client,
    api_key: &str,
    identity_id: Uuid,
) -> Value {
    client
        .post(format!("{base}/v1/enrollment-tokens"))
        .header(common::auth(api_key).0, common::auth(api_key).1)
        .json(&json!({ "identity_id": identity_id }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

// ─── Flow 1: Enrollment Token Tests ────────────────────────────────────

#[tokio::test]
async fn test_create_enrollment_token() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, agent_id, api_key) = setup_org_with_agent(&base, &client).await;

    let body = create_token(&base, &client, &api_key, agent_id).await;

    assert!(body["token"].as_str().unwrap().starts_with("ose_"));
    assert!(body["token_prefix"].as_str().unwrap().starts_with("ose_"));
    assert_eq!(body["identity_id"].as_str().unwrap(), agent_id.to_string());
    assert!(body["expires_at"].is_string());
}

#[tokio::test]
async fn test_enroll_with_valid_token() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, agent_id, api_key) = setup_org_with_agent(&base, &client).await;

    let token_resp = create_token(&base, &client, &api_key, agent_id).await;
    let token = token_resp["token"].as_str().unwrap();

    // Agent enrolls
    let enroll_resp: Value = client
        .post(format!("{base}/v1/enroll"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(enroll_resp["api_key"].as_str().unwrap().starts_with("osk_"));
    assert_eq!(
        enroll_resp["identity_id"].as_str().unwrap(),
        agent_id.to_string()
    );
    assert_eq!(enroll_resp["org_id"].as_str().unwrap(), org_id.to_string());

    // Verify the returned key works
    let new_key = enroll_resp["api_key"].as_str().unwrap();
    let identities_resp = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {new_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(identities_resp.status(), 200);
}

#[tokio::test]
async fn test_enroll_token_single_use() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, agent_id, api_key) = setup_org_with_agent(&base, &client).await;

    let token_resp = create_token(&base, &client, &api_key, agent_id).await;
    let token = token_resp["token"].as_str().unwrap();

    // First use succeeds
    let resp1 = client
        .post(format!("{base}/v1/enroll"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp1.status(), 200);

    // Second use fails
    let resp2 = client
        .post(format!("{base}/v1/enroll"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert!(resp2.status() == 401 || resp2.status() == 409);
}

#[tokio::test]
async fn test_enroll_token_expired() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, agent_id, api_key) = setup_org_with_agent(&base, &client).await;

    // Create token with 1 second expiry
    let token_resp: Value = client
        .post(format!("{base}/v1/enrollment-tokens"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({ "identity_id": agent_id, "expires_in_secs": 1 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = token_resp["token"].as_str().unwrap();

    // Wait for it to expire
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let resp = client
        .post(format!("{base}/v1/enroll"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_enroll_token_invalid() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .post(format!("{base}/v1/enroll"))
        .json(&json!({ "token": "ose_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef00" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_list_and_revoke_enrollment_tokens() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, agent_id, api_key) = setup_org_with_agent(&base, &client).await;

    // Create 2 tokens
    let t1 = create_token(&base, &client, &api_key, agent_id).await;
    let _t2 = create_token(&base, &client, &api_key, agent_id).await;

    // List — should have 2
    let list: Vec<Value> = client
        .get(format!("{base}/v1/enrollment-tokens"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.len(), 2);

    // Revoke one
    let t1_id = t1["id"].as_str().unwrap();
    let del_resp = client
        .delete(format!("{base}/v1/enrollment-tokens/{t1_id}"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(del_resp.status(), 204);

    // List — should have 1
    let list: Vec<Value> = client
        .get(format!("{base}/v1/enrollment-tokens"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.len(), 1);
}

#[tokio::test]
async fn test_enrollment_token_requires_auth() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .post(format!("{base}/v1/enrollment-tokens"))
        .json(&json!({ "identity_id": Uuid::new_v4() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_enrollment_token_rejects_user_identity() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _agent_id, api_key) = setup_org_with_agent(&base, &client).await;

    // Create a user identity
    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({"name": "human", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = user["id"].as_str().unwrap().parse().unwrap();

    // Should reject — tokens only for agents
    let resp = client
        .post(format!("{base}/v1/enrollment-tokens"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({ "identity_id": user_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

// ─── Flow 2: Agent-Initiated Enrollment Tests ──────────────────────────

#[tokio::test]
async fn test_initiate_enrollment() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let resp: Value = client
        .post(format!("{base}/v1/enroll/initiate"))
        .json(&json!({ "name": "my-claw", "platform": "openclaw" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(resp["enrollment_id"].is_string());
    assert!(
        resp["approval_url"]
            .as_str()
            .unwrap()
            .contains("/enroll/consent/")
    );
    assert!(resp["poll_token"].as_str().unwrap().starts_with("osp_"));
    assert!(resp["expires_at"].is_string());
}

#[tokio::test]
async fn test_poll_pending() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let init: Value = client
        .post(format!("{base}/v1/enroll/initiate"))
        .json(&json!({ "name": "my-claw" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let poll_token = init["poll_token"].as_str().unwrap();

    let status: Value = client
        .get(format!("{base}/v1/enroll/status?poll_token={poll_token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(status["status"], "pending");
}

#[tokio::test]
async fn test_approve_enrollment() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    // Agent initiates
    let init: Value = client
        .post(format!("{base}/v1/enroll/initiate"))
        .json(&json!({ "name": "my-claw", "platform": "openclaw" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let poll_token = init["poll_token"].as_str().unwrap();
    let approval_url = rebase_approval_url(init["approval_url"].as_str().unwrap(), &base);

    // User gets session
    let session = dev_session_token(&base, &client).await;

    // User approves
    let approve_resp: Value = client
        .post(approval_url)
        .header("cookie", format!("oss_session={session}"))
        .json(&json!({ "decision": "approve" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(approve_resp["status"], "approved");
    assert!(approve_resp["identity_id"].is_string());

    // Agent polls and gets its key
    let status: Value = client
        .get(format!("{base}/v1/enroll/status?poll_token={poll_token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(status["status"], "approved");
    let api_key = status["api_key"].as_str().unwrap();
    assert!(api_key.starts_with("osk_"));

    // Verify the key works
    let identities_resp = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(identities_resp.status(), 200);
}

#[tokio::test]
async fn test_approve_with_name_override() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let init: Value = client
        .post(format!("{base}/v1/enroll/initiate"))
        .json(&json!({ "name": "my-claw" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let approval_url = rebase_approval_url(init["approval_url"].as_str().unwrap(), &base);
    let poll_token = init["poll_token"].as_str().unwrap();
    let session = dev_session_token(&base, &client).await;

    // Approve with a different name
    client
        .post(approval_url)
        .header("cookie", format!("oss_session={session}"))
        .json(&json!({ "decision": "approve", "agent_name": "renamed-claw" }))
        .send()
        .await
        .unwrap();

    // Poll to get identity
    let status: Value = client
        .get(format!("{base}/v1/enroll/status?poll_token={poll_token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Use the key to check identity name
    let api_key = status["api_key"].as_str().unwrap();
    let identity_id = status["identity_id"].as_str().unwrap();
    let identities: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let agent = identities
        .iter()
        .find(|i| i["id"].as_str().unwrap() == identity_id)
        .expect("agent identity should exist");
    assert_eq!(agent["name"], "renamed-claw");
}

#[tokio::test]
async fn test_approve_keeps_suggested_name() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let init: Value = client
        .post(format!("{base}/v1/enroll/initiate"))
        .json(&json!({ "name": "keep-this-name" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let approval_url = rebase_approval_url(init["approval_url"].as_str().unwrap(), &base);
    let poll_token = init["poll_token"].as_str().unwrap();
    let session = dev_session_token(&base, &client).await;

    // Approve without overriding name
    client
        .post(approval_url)
        .header("cookie", format!("oss_session={session}"))
        .json(&json!({ "decision": "approve" }))
        .send()
        .await
        .unwrap();

    let status: Value = client
        .get(format!("{base}/v1/enroll/status?poll_token={poll_token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let api_key = status["api_key"].as_str().unwrap();
    let identity_id = status["identity_id"].as_str().unwrap();
    let identities: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let agent = identities
        .iter()
        .find(|i| i["id"].as_str().unwrap() == identity_id)
        .unwrap();
    assert_eq!(agent["name"], "keep-this-name");
}

#[tokio::test]
async fn test_deny_enrollment() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let init: Value = client
        .post(format!("{base}/v1/enroll/initiate"))
        .json(&json!({ "name": "my-claw" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let approval_url = rebase_approval_url(init["approval_url"].as_str().unwrap(), &base);
    let poll_token = init["poll_token"].as_str().unwrap();
    let session = dev_session_token(&base, &client).await;

    // Deny
    let resp: Value = client
        .post(approval_url)
        .header("cookie", format!("oss_session={session}"))
        .json(&json!({ "decision": "deny" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"], "denied");

    // Poll shows denied
    let status: Value = client
        .get(format!("{base}/v1/enroll/status?poll_token={poll_token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["status"], "denied");
    assert!(status.get("api_key").is_none() || status["api_key"].is_null());
}

#[tokio::test]
async fn test_poll_invalid_token() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let resp = client
        .get(format!(
            "{base}/v1/enroll/status?poll_token=osp_deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef00"
        ))
        .send()
        .await
        .unwrap();

    assert!(resp.status() == 404 || resp.status() == 401);
}

#[tokio::test]
async fn test_approve_requires_session() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let init: Value = client
        .post(format!("{base}/v1/enroll/initiate"))
        .json(&json!({ "name": "my-claw" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let approval_url = rebase_approval_url(init["approval_url"].as_str().unwrap(), &base);

    // Try to approve without session
    let resp = client
        .post(approval_url)
        .json(&json!({ "decision": "approve" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_approve_sets_org_from_session() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    // Dev token creates user in "Dev Org"
    let session_resp: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session = session_resp["token"].as_str().unwrap();
    let user_org_id = session_resp["org_id"].as_str().unwrap();

    let init: Value = client
        .post(format!("{base}/v1/enroll/initiate"))
        .json(&json!({ "name": "my-claw" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let approval_url = rebase_approval_url(init["approval_url"].as_str().unwrap(), &base);
    let poll_token = init["poll_token"].as_str().unwrap();

    client
        .post(approval_url)
        .header("cookie", format!("oss_session={session}"))
        .json(&json!({ "decision": "approve" }))
        .send()
        .await
        .unwrap();

    let status: Value = client
        .get(format!("{base}/v1/enroll/status?poll_token={poll_token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Agent should be in the same org as the approving user
    assert_eq!(status["org_id"].as_str().unwrap(), user_org_id);
}

// ─── Dual Auth Tests ───────────────────────────────────────────────────

#[tokio::test]
async fn test_token_crud_with_api_key() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, agent_id, api_key) = setup_org_with_agent(&base, &client).await;

    // Create with API key
    let resp = client
        .post(format!("{base}/v1/enrollment-tokens"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .json(&json!({ "identity_id": agent_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // List with API key
    let list: Vec<Value> = client
        .get(format!("{base}/v1/enrollment-tokens"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.len(), 1);
}

#[tokio::test]
async fn test_token_crud_with_session() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let session = dev_session_token(&base, &client).await;

    // We need an agent identity in the dev org. Create one via dev token's org.
    let session_resp: Value = client
        .get(format!("{base}/auth/dev/token"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = session_resp["org_id"].as_str().unwrap();

    // Need an API key to create the agent identity first (session auth doesn't work on /v1/identities yet)
    // Create an org-level key
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("cookie", format!("oss_session={session}"))
        .json(&json!({ "org_id": org_id, "name": "admin" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_key = key_resp["key"].as_str().unwrap();

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "session-test-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap();

    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "session-test-agent", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id = agent["id"].as_str().unwrap();

    // Create enrollment token with session cookie
    let resp = client
        .post(format!("{base}/v1/enrollment-tokens"))
        .header("cookie", format!("oss_session={session}"))
        .json(&json!({ "identity_id": agent_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // List with session cookie
    let list: Vec<Value> = client
        .get(format!("{base}/v1/enrollment-tokens"))
        .header("cookie", format!("oss_session={session}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.len(), 1);
}

// ─── Audit Trail Tests ─────────────────────────────────────────────────

#[tokio::test]
async fn test_enrollment_token_audit() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, agent_id, api_key) = setup_org_with_agent(&base, &client).await;

    let token_resp = create_token(&base, &client, &api_key, agent_id).await;
    let token = token_resp["token"].as_str().unwrap();

    // Enroll
    client
        .post(format!("{base}/v1/enroll"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();

    // Check audit log
    let audit: Vec<Value> = client
        .get(format!("{base}/v1/audit"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let events: Vec<&str> = audit.iter().filter_map(|e| e["action"].as_str()).collect();
    assert!(events.contains(&"enrollment_token.created"));
    assert!(events.contains(&"enrollment.completed"));
}

#[tokio::test]
async fn test_agent_initiated_audit() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let init: Value = client
        .post(format!("{base}/v1/enroll/initiate"))
        .json(&json!({ "name": "audit-agent" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let approval_url = rebase_approval_url(init["approval_url"].as_str().unwrap(), &base);
    let poll_token = init["poll_token"].as_str().unwrap();
    let session = dev_session_token(&base, &client).await;

    client
        .post(approval_url)
        .header("cookie", format!("oss_session={session}"))
        .json(&json!({ "decision": "approve" }))
        .send()
        .await
        .unwrap();

    // Get API key to check audit
    let status: Value = client
        .get(format!("{base}/v1/enroll/status?poll_token={poll_token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let api_key = status["api_key"].as_str().unwrap();
    let audit: Vec<Value> = client
        .get(format!("{base}/v1/audit"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let events: Vec<&str> = audit.iter().filter_map(|e| e["action"].as_str()).collect();
    // enrollment.initiated is logged with nil org_id (floating enrollment),
    // so it won't appear in the agent's org-scoped audit view.
    // But enrollment.approved is logged under the approving user's org.
    assert!(events.contains(&"enrollment.approved"));
}

#[tokio::test]
async fn test_get_approval_returns_requester_ip_and_created_at() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let init: Value = client
        .post(format!("{base}/v1/enroll/initiate"))
        .json(&json!({ "name": "ip-bot" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let approval_url = rebase_approval_url(init["approval_url"].as_str().unwrap(), &base);
    let session = dev_session_token(&base, &client).await;

    let resp: Value = client
        .get(approval_url)
        .header("cookie", format!("oss_session={session}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp["status"], "pending");
    assert!(resp["created_at"].is_string());
    assert!(resp.get("requester_ip").is_some());
}

#[tokio::test]
async fn test_approve_with_parent_id_places_under_parent() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let session = dev_session_token(&base, &client).await;

    // First, create an intermediate agent by approving a prior enrollment under the dev user.
    let init_parent: Value = client
        .post(format!("{base}/v1/enroll/initiate"))
        .json(&json!({ "name": "intermediate-agent" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let parent_approval_url =
        rebase_approval_url(init_parent["approval_url"].as_str().unwrap(), &base);
    let parent_approve: Value = client
        .post(parent_approval_url)
        .header("cookie", format!("oss_session={session}"))
        .json(&json!({ "decision": "approve" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let parent_id = parent_approve["identity_id"].as_str().unwrap().to_string();

    // Initiate enrollment
    let init: Value = client
        .post(format!("{base}/v1/enroll/initiate"))
        .json(&json!({ "name": "child-bot" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let approval_url = rebase_approval_url(init["approval_url"].as_str().unwrap(), &base);
    let poll_token = init["poll_token"].as_str().unwrap();

    // Approve under the chosen parent
    let approve_resp = client
        .post(approval_url)
        .header("cookie", format!("oss_session={session}"))
        .json(&json!({ "decision": "approve", "parent_id": &parent_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(approve_resp.status(), 200);

    let status: Value = client
        .get(format!("{base}/v1/enroll/status?poll_token={poll_token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = status["api_key"].as_str().unwrap();
    let new_id = status["identity_id"].as_str().unwrap();

    let identities: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent = identities
        .iter()
        .find(|i| i["id"].as_str().unwrap() == new_id)
        .unwrap();
    assert_eq!(agent["parent_id"].as_str().unwrap(), parent_id.as_str());
    let parent_agent = identities
        .iter()
        .find(|i| i["id"].as_str().unwrap() == parent_id.as_str())
        .unwrap();
    assert_eq!(
        agent["owner_id"].as_str().unwrap(),
        parent_agent["owner_id"].as_str().unwrap(),
        "new agent should inherit owner_id from its parent agent"
    );
}

#[tokio::test]
async fn test_approve_rejects_parent_from_other_org() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let init: Value = client
        .post(format!("{base}/v1/enroll/initiate"))
        .json(&json!({ "name": "stray-bot" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let approval_url = rebase_approval_url(init["approval_url"].as_str().unwrap(), &base);
    let session = dev_session_token(&base, &client).await;

    let bogus = Uuid::new_v4();
    let resp = client
        .post(approval_url)
        .header("cookie", format!("oss_session={session}"))
        .json(&json!({ "decision": "approve", "parent_id": bogus }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
