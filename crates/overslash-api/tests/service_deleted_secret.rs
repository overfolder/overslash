//! A service bound to a secret that is later deleted reverts to needing setup.
//!
//! The binding is just a name, so it outlives the secret it names. Reading it
//! as bound left the badge on "ok" while every call failed with `secret not
//! found`; the badge has to follow the vault, on every surface that reports it.
#![allow(clippy::disallowed_methods)]

use crate::common;

use serde_json::{Value, json};

async fn seed_dual_mode_template(base: &str, client: &reqwest::Client, admin_key: &str, key: &str) {
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "openapi": common::render_openapi(
                include_str!("fixtures/openapi/dual_mode.yaml.tmpl"),
                &[("key", key), ("display_name", "Dual Mode")],
            ),
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "template seed failed: {} {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
}

async fn get_json(client: &reqwest::Client, url: String, key: &str) -> Value {
    let resp = client
        .get(url)
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "GET failed: {}", resp.status());
    resp.json().await.unwrap()
}

async fn put_secret(client: &reqwest::Client, base: &str, key: &str, name: &str) {
    let resp = client
        .put(format!("{base}/v1/secrets/{name}"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({"value": "tok"}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "secret put: {}", resp.status());
}

/// `(detail, list)` credential status for the service named `name`.
async fn statuses(client: &reqwest::Client, base: &str, key: &str, name: &str) -> (Value, Value) {
    let detail = get_json(client, format!("{base}/v1/services/{name}"), key).await;
    let list = get_json(client, format!("{base}/v1/services"), key).await;
    let row = list
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("{name} not listed: {list}"))
        .clone();
    (
        detail["credentials_status"].clone(),
        row["credentials_status"].clone(),
    )
}

#[tokio::test]
async fn deleting_the_bound_secret_reverts_the_service_to_needing_setup() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org, _ident, api_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    seed_dual_mode_template(&base, &client, &admin_key, "dm-del").await;

    put_secret(&client, &base, &api_key, "del_token").await;
    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "dm-del",
            "name": "svc-del",
            "auth_mode": "token",
            "credentials": { "token": "del_token" },
        }))
        .send()
        .await
        .unwrap();
    let created: Value = resp.json().await.unwrap();
    assert_eq!(created["credentials_status"], "ok", "{created}");
    let (detail, listed) = statuses(&client, &base, &api_key, "svc-del").await;
    assert_eq!((detail.as_str(), listed.as_str()), (Some("ok"), Some("ok")));

    // Deleting is admin-only; the secret lives in the service owner's vault.
    let owner = created["owner_identity_id"].as_str().unwrap();
    let resp = client
        .delete(format!("{base}/v1/secrets/del_token?owner={owner}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "delete: {}", resp.status());
    let (detail, listed) = statuses(&client, &base, &api_key, "svc-del").await;
    assert_eq!(
        (detail.as_str(), listed.as_str()),
        (Some("needs_authentication"), Some("needs_authentication")),
        "a binding to a deleted secret is not a credential"
    );

    // Storing it again under the same name heals the binding.
    put_secret(&client, &base, &api_key, "del_token").await;
    let (detail, listed) = statuses(&client, &base, &api_key, "svc-del").await;
    assert_eq!((detail.as_str(), listed.as_str()), (Some("ok"), Some("ok")));
}

/// Binding a name nobody has stored yet is not a credential either.
#[tokio::test]
async fn binding_a_secret_that_was_never_stored_needs_setup() {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org, _ident, api_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    seed_dual_mode_template(&base, &client, &admin_key, "dm-ghost").await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "template_key": "dm-ghost",
            "name": "svc-ghost",
            "auth_mode": "token",
            "credentials": { "token": "never_stored" },
        }))
        .send()
        .await
        .unwrap();
    let created: Value = resp.json().await.unwrap();
    assert_eq!(
        created["credentials_status"], "needs_authentication",
        "{created}"
    );
    let (detail, listed) = statuses(&client, &base, &api_key, "svc-ghost").await;
    assert_eq!(
        (detail.as_str(), listed.as_str()),
        (Some("needs_authentication"), Some("needs_authentication"))
    );
}
