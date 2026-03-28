//! Eventbrite E2E tests — search events, register, cancel registration.
//! Requires real Eventbrite credentials. Run with: cargo test --test eventbrite -- --ignored

mod common;

use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

#[ignore] // E2E test: hits real Eventbrite API. Run with --ignored.
#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_eventbrite_e2e(pool: PgPool) {
    // --- Guard: skip if credentials not set ---
    let access_token = match std::env::var("EVENTBRITE_TEST_ACCESS_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("SKIP: EVENTBRITE_TEST_ACCESS_TOKEN not set");
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
    // (Eventbrite personal tokens don't expire and don't have refresh tokens)
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
    eprintln!("  [1/7] get_me ...");
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

    // ===== TEST 2: search_events (Mode C) =====
    eprintln!("  [2/7] search_events ...");
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "eventbrite",
            "action": "search_events",
            "params": {
                "q": "tech"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let search_result: Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let events = search_result["events"]
        .as_array()
        .expect("search_events should return events array");
    eprintln!("  search_events: found {} events for 'tech'", events.len());

    // Pick an event ID for subsequent tests — prefer EVENTBRITE_TEST_EVENT_ID env var
    let event_id = std::env::var("EVENTBRITE_TEST_EVENT_ID")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            events
                .first()
                .and_then(|e| e["id"].as_str().map(String::from))
        })
        .expect("need at least one event from search or EVENTBRITE_TEST_EVENT_ID");
    eprintln!("  using event_id={event_id} for remaining tests");

    // ===== TEST 3: get_event (Mode C) =====
    eprintln!("  [3/7] get_event ...");
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
    eprintln!("  [4/7] list_ticket_classes ...");
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

    // ===== TEST 5: create_order — register for the event (Mode C) =====
    eprintln!("  [5/7] create_order ...");
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "eventbrite",
            "action": "create_order",
            "params": {
                "event_id": event_id
            }
        }))
        .send()
        .await
        .unwrap();
    let order_status = resp.status();
    let body: Value = resp.json().await.unwrap();
    // Order creation may fail if event doesn't allow API orders — log either way
    if order_status == 200 && body["status"] == "executed" {
        let order: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
        let order_id = order["id"].as_str().unwrap_or("unknown");
        eprintln!("  create_order: created order {order_id}");

        // ===== TEST 6: list_my_orders — verify order appears (Mode C) =====
        eprintln!("  [6/7] list_my_orders ...");
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
        let orders: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
        let order_list = orders["orders"]
            .as_array()
            .expect("should return orders array");
        eprintln!("  list_my_orders: {} orders", order_list.len());

        // ===== TEST 7: cancel_order (Mode C) =====
        eprintln!("  [7/7] cancel_order ...");
        let resp = client
            .post(format!("{base}/v1/actions/execute"))
            .header(common::auth(&key).0, common::auth(&key).1)
            .json(&json!({
                "service": "eventbrite",
                "action": "cancel_order",
                "params": {
                    "order_id": order_id
                }
            }))
            .send()
            .await
            .unwrap();
        let cancel_status = resp.status();
        let body: Value = resp.json().await.unwrap();
        if cancel_status == 200 && body["status"] == "executed" {
            eprintln!("  cancel_order: cancelled order {order_id}");
        } else {
            eprintln!(
                "  cancel_order: could not cancel (status={cancel_status}): {}",
                serde_json::to_string_pretty(&body).unwrap()
            );
        }
    } else {
        eprintln!(
            "  create_order: API returned {order_status} — event may not allow API orders. \
             Skipping order/cancel tests. Response: {}",
            serde_json::to_string_pretty(&body).unwrap()
        );
        eprintln!("  [6/7] list_my_orders (skipped — no order created)");
        eprintln!("  [7/7] cancel_order (skipped — no order created)");
    }

    eprintln!("  All Eventbrite E2E tests completed!");
}
