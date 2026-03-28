//! Eventbrite E2E tests — list orders, get event details, ticket classes, attendees.
//! Requires real Eventbrite credentials. Run with: cargo test --test eventbrite -- --ignored
//!
//! Env vars (Eventbrite calls the OAuth client_id "API Key" in their dashboard):
//!   OAUTH_EVENTBRITE_CLIENT_ID      — API Key from Eventbrite app settings
//!   OAUTH_EVENTBRITE_CLIENT_SECRET   — Client Secret
//!   OAUTH_EVENTBRITE_PRIVATE_TOKEN   — Private Token (used as bearer for E2E)

mod common;

use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

#[ignore] // E2E test: hits real Eventbrite API. Run with --ignored.
#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_eventbrite_e2e(pool: PgPool) {
    // --- Guard: skip if credentials not set ---
    let access_token = match std::env::var("OAUTH_EVENTBRITE_PRIVATE_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("SKIP: OAUTH_EVENTBRITE_PRIVATE_TOKEN not set");
            return;
        }
    };
    let client_id = std::env::var("OAUTH_EVENTBRITE_CLIENT_ID")
        .expect("OAUTH_EVENTBRITE_CLIENT_ID required for real test");
    let client_secret = std::env::var("OAUTH_EVENTBRITE_CLIENT_SECRET")
        .expect("OAUTH_EVENTBRITE_CLIENT_SECRET required for real test");

    // Enable reading OAuth secrets from env vars
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_EVENTBRITE_CLIENT_ID", &client_id);
        std::env::set_var("OAUTH_EVENTBRITE_CLIENT_SECRET", &client_secret);
    }

    // Start API with real service registry (no host override — hits real Eventbrite)
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;

    // Bootstrap org + identity + API key
    let (org_id, ident_id, key) = common::bootstrap_org_identity(&base, &client).await;

    // Store BYOC credential via API
    let byoc_resp: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "provider": "eventbrite",
            "client_id": client_id,
            "client_secret": client_secret
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let byoc_id: Uuid = byoc_resp["id"].as_str().unwrap().parse().unwrap();

    // Encrypt access token and insert connection directly into DB
    // (Eventbrite private tokens don't expire and don't have refresh tokens)
    let enc_key = overslash_core::crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let encrypted_access =
        overslash_core::crypto::encrypt(&enc_key, access_token.as_bytes()).unwrap();

    let _conn = overslash_db::repos::connection::create(
        &pool,
        &overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ident_id,
            provider_key: "eventbrite",
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: None,
            token_expires_at: None,
            scopes: &[],
            account_email: None,
            byoc_credential_id: Some(byoc_id),
        },
    )
    .await
    .unwrap();

    // Create broad permission rule
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();

    // ===== TEST 1: get_me (Mode C) =====
    eprintln!("  [1/5] get_me ...");
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "eventbrite",
            "action": "get_me",
            "params": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let me: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        me["id"].is_string(),
        "get_me should return user id, got: {me}"
    );
    let user_name = me["name"].as_str().unwrap_or("unknown");
    eprintln!("  get_me: {user_name} (id={})", me["id"]);

    // ===== TEST 2: list_my_orders (Mode C) =====
    eprintln!("  [2/5] list_my_orders ...");
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "eventbrite",
            "action": "list_my_orders",
            "params": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let orders_resp: Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let orders = orders_resp["orders"]
        .as_array()
        .expect("list_my_orders should return orders array");
    eprintln!("  list_my_orders: {} orders", orders.len());

    // Pick an event_id from existing orders for remaining tests
    let event_id = std::env::var("EVENTBRITE_TEST_EVENT_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            orders
                .first()
                .and_then(|o| o["event_id"].as_str().map(String::from))
        })
        .expect("need at least one order in account or EVENTBRITE_TEST_EVENT_ID set");
    eprintln!("  using event_id={event_id} for remaining tests");

    // ===== TEST 3: get_event (Mode C) =====
    eprintln!("  [3/5] get_event ...");
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "eventbrite",
            "action": "get_event",
            "params": {
                "event_id": event_id
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let event: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let event_name = event["name"]["text"].as_str().unwrap_or("unnamed");
    eprintln!("  get_event: '{event_name}' (id={event_id})");

    // ===== TEST 4: list_ticket_classes (Mode C) =====
    eprintln!("  [4/5] list_ticket_classes ...");
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "eventbrite",
            "action": "list_ticket_classes",
            "params": {
                "event_id": event_id
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let tickets: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let ticket_classes = tickets["ticket_classes"]
        .as_array()
        .expect("should return ticket_classes array");
    eprintln!(
        "  list_ticket_classes: {} ticket types",
        ticket_classes.len()
    );

    // ===== TEST 5: list_event_attendees (Mode C) =====
    // This only works if the user is the organizer of the event.
    eprintln!("  [5/5] list_event_attendees ...");
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "eventbrite",
            "action": "list_event_attendees",
            "params": {
                "event_id": event_id
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let upstream_status = body["result"]["status_code"].as_u64().unwrap();
    if upstream_status == 200 {
        let attendees: Value =
            serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
        let attendee_list = attendees["attendees"]
            .as_array()
            .expect("should return attendees array");
        eprintln!("  list_event_attendees: {} attendees", attendee_list.len());
    } else {
        // 403 is expected if user is not the organizer
        eprintln!(
            "  list_event_attendees: upstream returned {upstream_status} (expected if not organizer)"
        );
    }

    eprintln!("  All Eventbrite E2E tests completed!");
}
