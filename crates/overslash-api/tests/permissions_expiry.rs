//! Integration tests for `PATCH /v1/permissions/{id}` — the editable rule
//! expiry surface. Covers the owns-it-or-admin auth gate, ttl parsing
//! (set / clear via null / clear via "forever" / invalid / 365-day cap),
//! the not-found path, and the `permission_rule.updated` audit event.
#![allow(clippy::disallowed_methods)]

use crate::common;
use crate::common::{auth, bootstrap_agent_on_fixtures, start_api};

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

/// Create a rule on `ident_id` via the admin key and return its id. The REST
/// create path always mints a non-expiring rule (`expires_at` null).
async fn create_rule(base: &str, client: &Client, admin_key: &str, ident_id: Uuid) -> String {
    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let perm: Value = resp.json().await.unwrap();
    assert!(
        perm["expires_at"].is_null(),
        "fresh rule should never expire"
    );
    perm["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn test_owner_sets_then_clears_expiry() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    let perm_id = create_rule(&base, &client, &admin_key, ident_id).await;

    // Owner resets expiry to now + 7d.
    let resp = client
        .patch(format!("{base}/v1/permissions/{perm_id}"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"ttl": "7d"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["expires_at"].is_string(),
        "expiry should be set: {body:?}"
    );

    // Owner clears it with an explicit null → permanent again.
    let resp = client
        .patch(format!("{base}/v1/permissions/{perm_id}"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"ttl": null}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["expires_at"].is_null(), "expiry should be cleared");

    // "forever" is the sentinel the dashboard sends for the "Never" option and
    // must also clear the expiry.
    let _ = client
        .patch(format!("{base}/v1/permissions/{perm_id}"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"ttl": "24h"}))
        .send()
        .await
        .unwrap();
    let resp = client
        .patch(format!("{base}/v1/permissions/{perm_id}"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"ttl": "forever"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["expires_at"].is_null(),
        "\"forever\" should clear expiry"
    );
}

#[tokio::test]
async fn test_non_owner_non_admin_forbidden() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    // Agent A owns the rule; agent B is an unrelated, non-admin identity.
    let (_ua, ident_a, _key_a) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let (_ub, _ident_b, key_b) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    let perm_id = create_rule(&base, &client, &admin_key, ident_a).await;

    let resp = client
        .patch(format!("{base}/v1/permissions/{perm_id}"))
        .header(auth(&key_b).0, auth(&key_b).1)
        .json(&json!({"ttl": "7d"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "a non-owner non-admin cannot edit the rule"
    );
}

#[tokio::test]
async fn test_admin_can_edit_any_rule() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, ident_id, _key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    let perm_id = create_rule(&base, &client, &admin_key, ident_id).await;

    let resp = client
        .patch(format!("{base}/v1/permissions/{perm_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"ttl": "1h"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert!(body["expires_at"].is_string());
}

#[tokio::test]
async fn test_invalid_and_capped_ttl_rejected() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    let perm_id = create_rule(&base, &client, &admin_key, ident_id).await;

    for bad in ["nonsense", "400d"] {
        let resp = client
            .patch(format!("{base}/v1/permissions/{perm_id}"))
            .header(auth(&key).0, auth(&key).1)
            .json(&json!({"ttl": bad}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "ttl {bad:?} must be rejected");
    }
}

#[tokio::test]
async fn test_unknown_rule_id_404() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let admin_key = fx.org_key.clone();
    let fake = Uuid::new_v4();

    let resp = client
        .patch(format!("{base}/v1/permissions/{fake}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"ttl": "7d"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_audit_permission_rule_updated() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, ident_id, _key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    let perm_id = create_rule(&base, &client, &admin_key, ident_id).await;

    client
        .patch(format!("{base}/v1/permissions/{perm_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"ttl": "7d"}))
        .send()
        .await
        .unwrap();

    let entries: Vec<Value> = client
        .get(format!("{base}/v1/audit?action=permission_rule.updated"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_type"], "permission_rule");
    assert_eq!(entries[0]["resource_id"].as_str().unwrap(), perm_id);
}
