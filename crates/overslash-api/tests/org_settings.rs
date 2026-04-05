mod common;

use serde_json::{Value, json};
use uuid::Uuid;

/// Bootstrap org + org-level key + user identity + user-bound key.
/// Returns (org_id, user_id, org_key, user_key, agent_key).
async fn setup(base: &str, client: &reqwest::Client) -> (Uuid, Uuid, String, String, String) {
    // Create org
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "TestOrg", "slug": format!("test-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    // Org-level key
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

    // User identity
    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "test-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = user["id"].as_str().unwrap().parse().unwrap();

    // User-bound key
    let user_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "identity_id": user_id, "name": "user-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_key = user_key_resp["key"].as_str().unwrap().to_string();

    // Agent identity + key
    let agent: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "test-agent", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();

    let agent_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "identity_id": agent_id, "name": "agent-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_key = agent_key_resp["key"].as_str().unwrap().to_string();

    (org_id, user_id, org_key, user_key, agent_key)
}

#[tokio::test]
async fn org_get_me() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_, _, org_key, _, _) = setup(&base, &client).await;

    let org: Value = client
        .get(format!("{base}/v1/orgs/me"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(org["name"], "TestOrg");
    assert!(org["slug"].as_str().unwrap().starts_with("test-"));
    assert_eq!(org["allow_user_templates"], true);
    assert!(org["id"].as_str().is_some());
    assert!(org["created_at"].as_str().is_some());
}

#[tokio::test]
async fn org_update_me_with_org_key() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_, _, org_key, _, _) = setup(&base, &client).await;

    // Org-level key can update
    let resp = client
        .put(format!("{base}/v1/orgs/me"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "Updated Corp", "allow_user_templates": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let updated: Value = resp.json().await.unwrap();
    assert_eq!(updated["name"], "Updated Corp");
    assert_eq!(updated["allow_user_templates"], false);
}

#[tokio::test]
async fn org_update_me_with_user_key() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_, _, _, user_key, _) = setup(&base, &client).await;

    // User-bound key can update
    let resp = client
        .put(format!("{base}/v1/orgs/me"))
        .header("Authorization", format!("Bearer {user_key}"))
        .json(&json!({"name": "User Updated", "allow_user_templates": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn org_update_me_agent_key_forbidden() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_, _, _, _, agent_key) = setup(&base, &client).await;

    // Agent-bound key is rejected
    let resp = client
        .put(format!("{base}/v1/orgs/me"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({"name": "Agent Attempt", "allow_user_templates": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn org_update_me_audit() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_, _, org_key, _, _) = setup(&base, &client).await;

    client
        .put(format!("{base}/v1/orgs/me"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "Audited Corp", "allow_user_templates": true}))
        .send()
        .await
        .unwrap();

    let audit: Vec<Value> = client
        .get(format!("{base}/v1/audit?action=org.updated"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(!audit.is_empty());
    assert_eq!(audit[0]["action"], "org.updated");
    assert_eq!(audit[0]["resource_type"], "org");
}
