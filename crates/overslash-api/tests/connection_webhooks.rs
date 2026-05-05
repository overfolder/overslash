//! Webhook events emitted by connection lifecycle changes:
//! `connection.created`, `connection.scopes_upgraded`, `connection.deleted`.
//!
//! The dispatcher itself is exercised by the `approval.resolved` test in
//! `integration.rs`; here we just verify that the connection routes call into
//! the dispatcher at the expected lifecycle points.
#![allow(clippy::disallowed_methods)]

mod common;

use serde_json::{Value, json};

#[tokio::test]
async fn test_connection_created_webhook_fires_on_oauth_callback() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;

    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client_id");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_client_secret");
    }

    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'x'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Subscribe to all three connection events.
    client
        .post(format!("{base}/v1/webhooks"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "url": format!("http://{mock_addr}/webhooks/receive"),
            "events": ["connection.created", "connection.scopes_upgraded", "connection.deleted"],
        }))
        .send()
        .await
        .unwrap();

    // Drive an OAuth callback — this stores a connection AND should fire
    // `connection.created` to the subscribed mock.
    let state_param = format!("{org_id}:{ident_id}:x:_:_");
    let callback_resp: Value = client
        .get(format!(
            "{base}/v1/oauth/callback?code=x_auth_code_42&state={state_param}"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(callback_resp["status"], "connected");
    let connection_id = callback_resp["connection_id"].as_str().unwrap().to_string();

    // Webhook dispatch is fire-and-forget via tokio::spawn — give it a beat.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let received: Value = client
        .get(format!("http://{mock_addr}/webhooks/received"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let webhooks = received["webhooks"].as_array().unwrap();
    let headers = received["headers"].as_array().unwrap();

    let created = webhooks
        .iter()
        .zip(headers.iter())
        .find(|(w, _)| w["connection_id"] == connection_id.as_str())
        .expect("expected a connection.created webhook for the new connection");
    let (created_payload, created_headers) = created;
    assert_eq!(created_payload["provider"], "x");
    assert!(created_payload["scopes"].is_array());
    let sig = created_headers["x-overslash-signature"].as_str().unwrap();
    assert!(
        sig.starts_with("sha256="),
        "signature should start with sha256="
    );

    // Delete the connection — should fire `connection.deleted`.
    let resp = client
        .delete(format!("{base}/v1/connections/{connection_id}"))
        .header(common::auth(&api_key).0, common::auth(&api_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let received: Value = client
        .get(format!("http://{mock_addr}/webhooks/received"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let webhooks = received["webhooks"].as_array().unwrap();
    let deleted_count = webhooks
        .iter()
        .filter(|w| {
            w["connection_id"] == connection_id.as_str()
                && w["org_id"].as_str() == Some(&org_id.to_string())
        })
        .count();
    // Two payloads now reference this connection_id — created and deleted.
    // The created payload has no `org_id` field, so the filter above only
    // matches the deleted one.
    assert_eq!(
        deleted_count, 1,
        "expected exactly one connection.deleted webhook"
    );
}
