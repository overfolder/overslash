//! Self-service BYOC + oauth-providers catalog tests.
//!
//! The `POST /v1/byoc-credentials` endpoint is gated self-or-admin:
//! Write-level callers can manage BYOC only for their own identity;
//! cross-identity management requires admin. `GET /v1/oauth-providers`
//! is a read-only catalog consumed by the Create Service and Template
//! Editor UIs to decide whether BYOC is optional or required.

#![allow(clippy::disallowed_methods)]

mod common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

async fn create_second_user_with_key(
    base: &str,
    client: &Client,
    admin_key: &str,
    org_id: Uuid,
) -> (Uuid, String) {
    // New user identity + key, NOT flagged as org admin.
    let ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": format!("bystander-{}", Uuid::new_v4()), "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ident_id: Uuid = ident["id"].as_str().unwrap().parse().unwrap();

    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": ident_id,
            "name": "bystander-key",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let key = key_resp["key"].as_str().unwrap().to_string();
    (ident_id, key)
}

#[tokio::test]
async fn agent_can_create_and_delete_own_byoc() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, agent_ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Non-admin agent creates BYOC for itself → 200.
    let resp = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "provider": "github",
            "client_id": "agent_own_gh_id",
            "client_secret": "agent_own_gh_secret",
            "identity_id": agent_ident,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let byoc_id = body["id"].as_str().unwrap();
    assert_eq!(body["identity_id"], agent_ident.to_string());

    // Same agent deletes it → 200.
    let del = client
        .delete(format!("{base}/v1/byoc-credentials/{byoc_id}"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 200);
    assert_eq!(del.json::<Value>().await.unwrap()["deleted"], true);
}

#[tokio::test]
async fn agent_cannot_create_byoc_for_another_identity() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, _agent_ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let (other_ident, _other_key) =
        create_second_user_with_key(&base, &client, &admin_key, org_id).await;

    let resp = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "provider": "github",
            "client_id": "x",
            "client_secret": "x",
            "identity_id": other_ident,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn agent_cannot_delete_another_identitys_byoc() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, _agent_ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let (bystander_ident, _bystander_key) =
        create_second_user_with_key(&base, &client, &admin_key, org_id).await;

    // Admin provisions a BYOC for the bystander.
    let created: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "provider": "slack",
            "client_id": "by_slack_id",
            "client_secret": "by_slack_secret",
            "identity_id": bystander_ident,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap();

    // Agent (non-admin) attempts to delete bystander's BYOC → 403.
    let resp = client
        .delete(format!("{base}/v1/byoc-credentials/{id}"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn list_byoc_filters_to_own_identity_for_non_admin() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, agent_ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let (bystander_ident, _bystander_key) =
        create_second_user_with_key(&base, &client, &admin_key, org_id).await;

    // Two BYOCs: one for agent, one for bystander.
    client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "provider": "github",
            "client_id": "a", "client_secret": "b",
            "identity_id": agent_ident,
        }))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "provider": "slack",
            "client_id": "c", "client_secret": "d",
            "identity_id": bystander_ident,
        }))
        .send()
        .await
        .unwrap();

    // Agent sees only its own row.
    let agent_list: Vec<Value> = client
        .get(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(agent_list.len(), 1);
    assert_eq!(agent_list[0]["identity_id"], agent_ident.to_string());

    // Admin sees both.
    let admin_list: Vec<Value> = client
        .get(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(admin_list.len(), 2);
}

#[tokio::test]
async fn oauth_providers_lists_known_providers() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .get(format!("{base}/v1/oauth-providers"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let list: Vec<Value> = resp.json().await.unwrap();

    // The seed migrations ship built-in providers (google, github, slack, ...).
    let keys: Vec<&str> = list.iter().map(|r| r["key"].as_str().unwrap()).collect();
    assert!(keys.contains(&"google"), "missing google: {keys:?}");
    assert!(keys.contains(&"github"), "missing github: {keys:?}");
    assert!(keys.contains(&"slack"), "missing slack: {keys:?}");

    // Fresh org, no org creds, no env fallback, no user BYOC: all flags false.
    for row in &list {
        assert_eq!(
            row["has_org_credential"], false,
            "row {row}: expected has_org_credential=false on fresh org"
        );
        assert_eq!(
            row["has_system_credential"], false,
            "row {row}: expected has_system_credential=false without env opt-in"
        );
        assert_eq!(
            row["has_user_byoc_credential"], false,
            "row {row}: expected has_user_byoc_credential=false on fresh user"
        );
        assert!(row["supports_pkce"].is_boolean());
    }
}

#[tokio::test]
async fn oauth_providers_has_user_byoc_reflects_own_credential() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, agent_ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Agent stores their own google BYOC (e.g. from a google_calendar setup).
    let resp = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "provider": "google",
            "client_id": "my.apps.googleusercontent.com",
            "client_secret": "GOCSPX-my_secret",
            "identity_id": agent_ident,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Provider catalog should now mark google as having a user BYOC, but
    // other providers (e.g. github) must stay false.
    let list: Vec<Value> = client
        .get(format!("{base}/v1/oauth-providers"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let google = list
        .iter()
        .find(|r| r["key"] == "google")
        .expect("google row");
    let github = list
        .iter()
        .find(|r| r["key"] == "github")
        .expect("github row");
    assert_eq!(google["has_user_byoc_credential"], true);
    assert_eq!(github["has_user_byoc_credential"], false);
    // Org/system flags unchanged.
    assert_eq!(google["has_org_credential"], false);
    assert_eq!(google["has_system_credential"], false);
}

#[tokio::test]
async fn oauth_providers_has_org_credential_reflects_org_secrets() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Configure org-level google creds.
    let put = client
        .put(format!("{base}/v1/org-oauth-credentials/google"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "client_id": "org_google_id.apps.googleusercontent.com",
            "client_secret": "GOCSPX-org_secret",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200);

    // Provider catalog from a regular user — flag should flip for google only.
    let list: Vec<Value> = client
        .get(format!("{base}/v1/oauth-providers"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let google = list
        .iter()
        .find(|r| r["key"] == "google")
        .expect("google row");
    let github = list
        .iter()
        .find(|r| r["key"] == "github")
        .expect("github row");
    assert_eq!(google["has_org_credential"], true);
    assert_eq!(github["has_org_credential"], false);
}
