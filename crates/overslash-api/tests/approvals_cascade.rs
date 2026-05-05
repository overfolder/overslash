//! Cascading approval resolution after a remembered rule is committed
//! (`crates/overslash-api/src/services/permission_chain.rs::cascade_resolve`).
//!
//! When `/v1/approvals/{id}/call` succeeds with `remember=true`, the new rule
//! lands on the requester's `rule_placement_id`. The cascade then re-walks
//! every other pending approval whose requester is `placement_id` itself or
//! a descendant, and auto-resolves those whose chain now passes — saving the
//! reviewer from re-approving structurally identical follow-ups.

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

// ── helpers (mirrored from permission_chain_walk.rs) ────────────────

async fn call_echo(
    base: &str,
    api_key: &str,
    mock_addr: std::net::SocketAddr,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "method": "POST",
            "url": format!("http://{mock_addr}/echo"),
            "headers": {"Content-Type": "application/json"},
            "body": "{}",
            "secrets": [{"name": "test_token", "inject_as": "header", "header_name": "X-Token"}]
        }))
        .send()
        .await
        .unwrap()
}

/// Variant used to make a deliberately-unrelated request — different host on
/// the same mock so its permission key won't be covered by an `/echo` rule.
async fn call_other(
    base: &str,
    api_key: &str,
    mock_addr: std::net::SocketAddr,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=8"),
            "secrets": [{"name": "test_token", "inject_as": "header", "header_name": "X-Token"}]
        }))
        .send()
        .await
        .unwrap()
}

async fn create_identity(
    base: &str,
    org_key: &str,
    name: &str,
    kind: &str,
    parent_id: Option<Uuid>,
) -> Uuid {
    let mut body = json!({"name": name, "kind": kind});
    if let Some(pid) = parent_id {
        body["parent_id"] = json!(pid);
    }
    let resp: Value = reqwest::Client::new()
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["id"].as_str().unwrap().parse().unwrap()
}

async fn create_api_key(
    base: &str,
    org_key: &str,
    org_id: Uuid,
    identity_id: Uuid,
    name: &str,
) -> String {
    let resp: Value = reqwest::Client::new()
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"org_id": org_id, "identity_id": identity_id, "name": name}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["key"].as_str().unwrap().to_string()
}

async fn bootstrap(pool: sqlx::PgPool) -> (String, String, Uuid, std::net::SocketAddr) {
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let mock_addr = common::start_mock().await;

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "CascadeOrg", "slug": format!("cascade-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    let org_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "org-admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_key = org_key_resp["key"].as_str().unwrap().to_string();

    // Cascade tests assert on `triggered_by="agent"` semantics from the
    // manual `/call` flow; flip the org default so every agent we
    // create below is seeded with auto_call_on_approve=false and the
    // manual call wins the execution claim deterministically.
    client
        .patch(format!("{base}/v1/orgs/{org_id}/execution-settings"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"default_deferred_execution": true}))
        .send()
        .await
        .unwrap();

    client
        .put(format!("{base}/v1/secrets/test_token"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"value": "secret123"}))
        .send()
        .await
        .unwrap();

    (base, org_key, org_id, mock_addr)
}

async fn approval_id_from_call(resp: reqwest::Response) -> String {
    assert_eq!(resp.status(), 202, "expected 202 from /v1/actions/call");
    let body: Value = resp.json().await.unwrap();
    body["approval_id"].as_str().unwrap().to_string()
}

// ── happy path: cascade auto-resolves a peer pending approval ───────

#[tokio::test]
async fn cascade_resolves_peer_under_placement_after_remember() {
    let pool = common::test_pool().await;
    let (base, org_key, org_id, mock_addr) = bootstrap(pool.clone()).await;

    // User → AgentA, with SubAgentS inheriting from AgentA.
    let user_id = create_identity(&base, &org_key, "alice", "user", None).await;
    let agent_a_id = create_identity(&base, &org_key, "agent-a", "agent", Some(user_id)).await;
    let sub_s_id = create_identity(&base, &org_key, "sub-s", "sub_agent", Some(agent_a_id)).await;
    overslash_db::repos::identity::set_inherit_permissions(&pool, org_id, sub_s_id, true)
        .await
        .unwrap();

    let agent_a_key = create_api_key(&base, &org_key, org_id, agent_a_id, "agent-a-key").await;
    let sub_s_key = create_api_key(&base, &org_key, org_id, sub_s_id, "sub-s-key").await;

    // Both make the same /echo request — neither has any rules, so each
    // produces a pending approval at AgentA's level (gap), resolver = User.
    let agent_appr_id =
        approval_id_from_call(call_echo(&base, &agent_a_key, mock_addr).await).await;
    let sub_appr_id = approval_id_from_call(call_echo(&base, &sub_s_key, mock_addr).await).await;
    assert_ne!(agent_appr_id, sub_appr_id);

    // Approve AgentA's request and remember.
    let resolve_resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{agent_appr_id}/resolve"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"resolution": "allow_remember"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resolve_resp.status(), 200);

    // Replay AgentA's request — this is what creates the rule and triggers
    // the cascade.
    let call_resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{agent_appr_id}/call"))
        .header("Authorization", format!("Bearer {agent_a_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(call_resp.status(), 200);
    let call_body: Value = call_resp.json().await.unwrap();
    let cascaded: Vec<String> = call_body["cascaded_approval_ids"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        cascaded.contains(&sub_appr_id),
        "expected sub_appr_id={sub_appr_id} in cascaded_approval_ids={cascaded:?}"
    );

    // The peer approval is now allowed with resolved_by='cascade' and has a
    // pending execution sitting ready for /call.
    let scope = overslash_db::OrgScope::new(org_id, pool.clone());
    let sub_row = scope
        .get_approval(sub_appr_id.parse().unwrap())
        .await
        .unwrap()
        .expect("peer approval row");
    assert_eq!(sub_row.status, "allowed");
    assert_eq!(sub_row.resolved_by.as_deref(), Some("cascade"));
    assert!(!sub_row.remember, "cascade must not flip remember=true");

    let exec = scope
        .get_execution_by_approval(sub_appr_id.parse().unwrap())
        .await
        .unwrap()
        .expect("cascade should have created a pending execution");
    assert_eq!(exec.status, "pending");
    assert!(!exec.remember);

    // Sub-agent can now /call its own approval and the replay should succeed.
    let sub_call = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{sub_appr_id}/call"))
        .header("Authorization", format!("Bearer {sub_s_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        sub_call.status(),
        200,
        "cascaded approval should be callable"
    );
}

// ── unrelated key under the same subtree is left pending ────────────

#[tokio::test]
async fn cascade_skips_pending_approvals_with_unrelated_keys() {
    let pool = common::test_pool().await;
    let (base, org_key, org_id, mock_addr) = bootstrap(pool.clone()).await;

    let user_id = create_identity(&base, &org_key, "alice", "user", None).await;
    let agent_a_id = create_identity(&base, &org_key, "agent-a", "agent", Some(user_id)).await;
    let sub_s_id = create_identity(&base, &org_key, "sub-s", "sub_agent", Some(agent_a_id)).await;
    overslash_db::repos::identity::set_inherit_permissions(&pool, org_id, sub_s_id, true)
        .await
        .unwrap();

    let agent_a_key = create_api_key(&base, &org_key, org_id, agent_a_id, "agent-a-key").await;
    let sub_s_key = create_api_key(&base, &org_key, org_id, sub_s_id, "sub-s-key").await;

    // AgentA's request: POST /echo. Sub's request: GET /large-file (different
    // method+path → different permission key → not covered by the /echo rule).
    let agent_appr_id =
        approval_id_from_call(call_echo(&base, &agent_a_key, mock_addr).await).await;
    let sub_appr_id = approval_id_from_call(call_other(&base, &sub_s_key, mock_addr).await).await;

    // Pin remember to a tight pattern so only /echo gets covered. The
    // suggested-tier validator only accepts keys that derive from the
    // request, so we use the default (tier 0) which is exactly the request's
    // permission key.
    let resolve_resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{agent_appr_id}/resolve"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"resolution": "allow_remember"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resolve_resp.status(), 200);
    let call_resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{agent_appr_id}/call"))
        .header("Authorization", format!("Bearer {agent_a_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(call_resp.status(), 200);
    let call_body: Value = call_resp.json().await.unwrap();
    let cascaded: Vec<String> = call_body["cascaded_approval_ids"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !cascaded.contains(&sub_appr_id),
        "unrelated approval must NOT be in cascaded_approval_ids: {cascaded:?}"
    );

    let scope = overslash_db::OrgScope::new(org_id, pool.clone());
    let sub_row = scope
        .get_approval(sub_appr_id.parse().unwrap())
        .await
        .unwrap()
        .expect("peer approval row");
    assert_eq!(
        sub_row.status, "pending",
        "unrelated approval must remain pending"
    );
}

// ── approvals outside the placement subtree are left untouched ──────

#[tokio::test]
async fn cascade_ignores_approvals_outside_placement_subtree() {
    let pool = common::test_pool().await;
    let (base, org_key, org_id, mock_addr) = bootstrap(pool.clone()).await;

    // Two sibling subtrees under the same user: AgentA / AgentB.
    // The new rule lands on AgentA — AgentB's pending approval must be
    // untouched even though it asks for the same key.
    let user_id = create_identity(&base, &org_key, "alice", "user", None).await;
    let agent_a_id = create_identity(&base, &org_key, "agent-a", "agent", Some(user_id)).await;
    let agent_b_id = create_identity(&base, &org_key, "agent-b", "agent", Some(user_id)).await;

    let agent_a_key = create_api_key(&base, &org_key, org_id, agent_a_id, "agent-a-key").await;
    let agent_b_key = create_api_key(&base, &org_key, org_id, agent_b_id, "agent-b-key").await;

    let agent_a_appr = approval_id_from_call(call_echo(&base, &agent_a_key, mock_addr).await).await;
    let agent_b_appr = approval_id_from_call(call_echo(&base, &agent_b_key, mock_addr).await).await;

    let resolve_resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{agent_a_appr}/resolve"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"resolution": "allow_remember"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resolve_resp.status(), 200);
    let call_resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{agent_a_appr}/call"))
        .header("Authorization", format!("Bearer {agent_a_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(call_resp.status(), 200);
    let call_body: Value = call_resp.json().await.unwrap();
    let cascaded: Vec<String> = call_body["cascaded_approval_ids"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !cascaded.contains(&agent_b_appr),
        "sibling-subtree approval must not cascade-resolve: {cascaded:?}"
    );

    let scope = overslash_db::OrgScope::new(org_id, pool.clone());
    let row_b = scope
        .get_approval(agent_b_appr.parse().unwrap())
        .await
        .unwrap()
        .expect("AgentB approval row");
    assert_eq!(row_b.status, "pending");
}
