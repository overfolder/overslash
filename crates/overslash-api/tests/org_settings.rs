mod common;

use serde_json::{Value, json};

#[tokio::test]
async fn org_get_me() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_, _, key) = common::bootstrap_org_identity(&base, &client).await;

    let org: Value = client
        .get(format!("{base}/v1/orgs/me"))
        .header("Authorization", format!("Bearer {key}"))
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
async fn org_update_me() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_, _, key) = common::bootstrap_org_identity(&base, &client).await;

    // Update org
    let updated: Value = client
        .put(format!("{base}/v1/orgs/me"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "name": "Updated Corp",
            "allow_user_templates": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(updated["name"], "Updated Corp");
    assert_eq!(updated["allow_user_templates"], false);

    // Verify persistence
    let org: Value = client
        .get(format!("{base}/v1/orgs/me"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(org["name"], "Updated Corp");
    assert_eq!(org["allow_user_templates"], false);
}

#[tokio::test]
async fn org_update_me_audit() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_, _, key) = common::bootstrap_org_identity(&base, &client).await;

    // Update org to trigger audit
    client
        .put(format!("{base}/v1/orgs/me"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "name": "Audited Corp",
            "allow_user_templates": true
        }))
        .send()
        .await
        .unwrap();

    // Check audit log
    let audit: Vec<Value> = client
        .get(format!("{base}/v1/audit?action=org.updated"))
        .header("Authorization", format!("Bearer {key}"))
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
