//! `GET /v1/services/{uuid}` reaches what the by-name resolver and the admin
//! listing reach.
//!
//! The dashboard's detail page always addresses an instance by id. The by-id
//! branch once reused the owner-or-admin *write* gate, so every org-level
//! instance (no owner, matches nobody's ceiling) and every group-shared one
//! 404'd as "Service not found" — while the same rows resolved fine by name.
//! The refusal for a stranger's user-level instance stays; that half lives in
//! `agent_self_setup_defaults::seeded_agent_cannot_touch_another_users_instance`.
use crate::common;

use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

/// A plain (non-admin) user in the org plus an identity-bound key for them.
async fn create_user_with_key(
    client: &Client,
    base: &str,
    admin_key: &str,
    org_id: Uuid,
    name: &str,
) -> (Uuid, String) {
    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": name, "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = user["id"].as_str().unwrap().parse().unwrap();
    let key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"org_id": org_id, "identity_id": user_id, "name": format!("{name}-key")}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (user_id, key["key"].as_str().unwrap().to_string())
}

async fn create_metabase(client: &Client, base: &str, key: &str, body: Value) -> String {
    let created: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    created["id"]
        .as_str()
        .unwrap_or_else(|| panic!("create service failed: {created}"))
        .to_string()
}

/// The exact request the dashboard detail page makes.
async fn get_by_id(client: &Client, base: &str, key: &str, id: &str) -> StatusCode {
    client
        .get(format!("{base}/v1/services/{id}?include_inactive=true"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn member_reads_an_org_level_instance_by_id() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (org_id, _agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let (_member_id, member_key) =
        create_user_with_key(&client, &base, &admin_key, org_id, "member").await;

    // Shared with Everyone, the way an admin publishes an org-wide service.
    let groups = common::everyone_grant(&base, &client, &admin_key).await;
    let org_instance = create_metabase(
        &client,
        &base,
        &admin_key,
        json!({"template_key": "metabase", "name": "org-metabase", "user_level": false,
               "groups": groups,
               "url": "https://org.example.com", "secret_name": "ORG_KEY"}),
    )
    .await;

    assert_eq!(
        get_by_id(&client, &base, &member_key, &org_instance).await,
        StatusCode::OK,
        "a non-admin member must open an org-level instance by id"
    );
    assert_eq!(
        get_by_id(&client, &base, &agent_key, &org_instance).await,
        StatusCode::OK,
        "an agent must open an org-level instance by id, as it can by name"
    );
}

#[tokio::test]
async fn org_admin_reads_another_users_instance_by_id() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (org_id, _agent_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let (_member_id, member_key) =
        create_user_with_key(&client, &base, &admin_key, org_id, "member").await;

    let members_instance = create_metabase(
        &client,
        &base,
        &member_key,
        json!({"template_key": "metabase", "name": "members-metabase",
               "url": "https://member.example.com", "secret_name": "MEMBER_KEY"}),
    )
    .await;

    // The admin "show all" listing surfaces this row; its detail link must open.
    assert_eq!(
        get_by_id(&client, &base, &admin_key, &members_instance).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn group_grantee_reads_a_shared_instance_by_id() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (org_id, _agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let (owner_id, owner_key) =
        create_user_with_key(&client, &base, &admin_key, org_id, "owner").await;

    let shared = create_metabase(
        &client,
        &base,
        &owner_key,
        json!({"template_key": "metabase", "name": "shared-metabase",
               "url": "https://owner.example.com", "secret_name": "OWNER_KEY"}),
    )
    .await;

    // Before any grant: someone else's user-level instance stays invisible.
    assert_eq!(
        get_by_id(&client, &base, &agent_key, &shared).await,
        StatusCode::NOT_FOUND
    );

    // Share it with a group holding the agent's owner-user ("test-user").
    let identities: Value = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let test_user_id = identities
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"].as_str() == Some("test-user"))
        .and_then(|r| r["id"].as_str())
        .unwrap()
        .to_string();
    let group: Value = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"name": "Shared"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let group_id = group["id"].as_str().unwrap();
    for member in [test_user_id, owner_id.to_string()] {
        let r = client
            .post(format!("{base}/v1/groups/{group_id}/members"))
            .header("Authorization", format!("Bearer {admin_key}"))
            .json(&json!({"identity_id": member}))
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success(), "add member: {}", r.status());
    }
    let r = client
        .post(format!("{base}/v1/groups/{group_id}/grants"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"service_instance_id": shared, "access_level": "read"}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "grant: {}", r.status());

    assert_eq!(
        get_by_id(&client, &base, &agent_key, &shared).await,
        StatusCode::OK,
        "a group grant makes the instance readable by id, as it is by name"
    );
}
