//! `GET /v1/whoami` — the human-readable half of the response: the user the
//! caller acts for (name + email) and, for a non-user caller, its agent name.

use crate::common;

use serde_json::{Value, json};

async fn whoami(base: &str, client: &reqwest::Client, key: &str) -> Value {
    let resp = client
        .get(format!("{base}/v1/whoami"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "whoami: {}", resp.status());
    resp.json().await.unwrap()
}

#[tokio::test]
async fn whoami_names_the_agent_and_its_owner() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, agent_id, agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let user_id = common::owner_user_id(&pool, org_id).await;

    let patched = client
        .patch(format!("{base}/v1/identities/{user_id}"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "Alice Example", "email": "alice@example.com"}))
        .send()
        .await
        .unwrap();
    assert!(patched.status().is_success(), "patch: {}", patched.status());

    // Agent caller: `agent` is itself, `user` is the owner it acts for.
    let body = whoami(&base, &client, &agent_key).await;
    assert_eq!(body["kind"], "agent");
    assert_eq!(body["email"], Value::Null);
    assert_eq!(body["agent"]["id"], agent_id.to_string());
    assert_eq!(body["agent"]["name"], "test-agent");
    assert_eq!(body["user"]["id"], user_id.to_string());
    assert_eq!(body["user"]["name"], "Alice Example");
    assert_eq!(body["user"]["email"], "alice@example.com");

    // User caller: `user` is itself, no `agent`.
    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"org_id": org_id, "identity_id": user_id, "name": "user-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_key = key["key"].as_str().unwrap();
    let body = whoami(&base, &client, user_key).await;
    assert_eq!(body["kind"], "user");
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["agent"], Value::Null);
    assert_eq!(body["user"]["id"], user_id.to_string());
    assert_eq!(body["user"]["name"], "Alice Example");
    assert_eq!(body["user"]["email"], "alice@example.com");
}
