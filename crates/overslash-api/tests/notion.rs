//! Notion E2E tests — search / query_database (read) and create_page /
//! append_block_children (write) via connection-based execution (Mode C).
//!
//! The mock test runs by default and asserts the outgoing request the gateway
//! builds: resolved path, JSON body split, the auto-resolved OAuth header, and
//! the constant `Notion-Version` header the template pins on every call.
//!
//! The real test is `#[ignore]`'d — run with:
//!   cargo test --test notion -- --ignored
//!
//! Env vars for the real test:
//!   NOTION_TEST_TOKEN     — an integration token (secret_...) or OAuth access
//!                           token for a workspace the integration is added to.
//!   NOTION_TEST_PAGE_ID   — id of a page the integration can read/append to
//!                           (used by append_block_children + create subpage).
//!   NOTION_TEST_DATABASE_ID (optional) — a database the integration can query.

// Test setup requires dynamic SQL for provider endpoint overrides and DB seeding.
#![allow(clippy::disallowed_methods)]

use crate::common;

use serde_json::{Value, json};

// ============================================================================
// Mock-based test — Mode C read + write against a local mock server
// ============================================================================

#[tokio::test]
async fn test_notion_mode_c() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    // Start API with the real services/ registry, overriding notion's host to
    // the mock so every action call lands on the echo fake.
    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("notion", mock_host.clone()))).await;

    // Bootstrap org + identity + API key. Connections resolve at the owner
    // identity (D22), so the OAuth connection is seeded on the agent's owner.
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;

    // Mode C permission: allow every notion action for the agent.
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "notion:*:*"}))
        .send()
        .await
        .unwrap();

    // Layer-1: org-level notion instance + Everyone admin access so the ceiling
    // clears for the agent's owner-user.
    common::grant_service_to_everyone(&base, &client, &admin_key, "notion").await;

    // Seed the OAuth connection on the owner. Notion tokens don't expire and
    // have no refresh token, so `resolve_access_token` returns the stored token
    // verbatim without ever exchanging at the token endpoint. The instance-based
    // auth path still resolves OAuth *client* credentials up front, so a BYOC
    // credential must exist even though its secret is never used here.
    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_token =
        overslash_core::crypto::encrypt(&enc_key, b"notion-oauth-token-123").unwrap();
    let encrypted_cid = overslash_core::crypto::encrypt(&enc_key, b"notion_client_id").unwrap();
    let encrypted_csec =
        overslash_core::crypto::encrypt(&enc_key, b"notion_client_secret").unwrap();
    let byoc = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(
            ident_id,
            "notion",
            &encrypted_cid,
            &encrypted_csec,
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    let _conn = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "notion",
            encrypted_access_token: &encrypted_token,
            encrypted_refresh_token: None,
            token_expires_at: None,
            scopes: Some(&[]),
            account_email: None,
            account_picture: None,
            byoc_credential_id: Some(byoc.id),
        })
        .await
        .unwrap();

    // Small helper: run a Mode C call and return the echoed upstream request.
    async fn call_echo(client: &reqwest::Client, base: &str, key: &str, payload: Value) -> Value {
        let resp = client
            .post(format!("{base}/v1/actions/call"))
            .header(common::auth(key).0, common::auth(key).1)
            .json(&payload)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let body: Value = resp.json().await.unwrap();
        assert_eq!(status, 200, "call should succeed, got: {body}");
        assert_eq!(body["status"], "called");
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap()
    }

    // ===== READ: search (POST /v1/search) =====
    let echo = call_echo(
        &client,
        &base,
        &key,
        json!({
            "service": "notion",
            "action": "search",
            "params": {
                "query": "roadmap",
                "filter": {"value": "page", "property": "object"},
                "page_size": 10
            }
        }),
    )
    .await;
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.ends_with("/v1/search"),
        "search should POST to /v1/search, got: {uri}"
    );
    // The template pins Notion-Version on every request (header echoed lowercased).
    assert_eq!(
        echo["headers"]["notion-version"], "2022-06-28",
        "Notion-Version header must be stamped from the template default"
    );
    assert_eq!(
        echo["headers"]["authorization"], "Bearer notion-oauth-token-123",
        "OAuth token should be auto-resolved from the connection"
    );
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["query"], "roadmap");
    assert_eq!(req_body["filter"]["value"], "page");
    assert_eq!(req_body["page_size"], 10);
    assert!(
        req_body.get("Notion-Version").is_none(),
        "header param must NOT leak into the JSON body"
    );

    // ===== READ: query_database (POST /v1/databases/{id}/query) =====
    let echo = call_echo(
        &client,
        &base,
        &key,
        json!({
            "service": "notion",
            "action": "query_database",
            "params": {
                "database_id": "db_abc123",
                "filter": {"property": "Status", "select": {"equals": "Done"}},
                "sorts": [{"property": "Name", "direction": "ascending"}],
                "page_size": 25
            }
        }),
    )
    .await;
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.ends_with("/v1/databases/db_abc123/query"),
        "query_database should resolve the database_id path param, got: {uri}"
    );
    assert_eq!(echo["headers"]["notion-version"], "2022-06-28");
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["filter"]["property"], "Status");
    assert_eq!(req_body["sorts"][0]["direction"], "ascending");
    assert!(
        req_body.get("database_id").is_none(),
        "path param must NOT leak into the JSON body"
    );

    // ===== WRITE: create_page (POST /v1/pages) =====
    let echo = call_echo(
        &client,
        &base,
        &key,
        json!({
            "service": "notion",
            "action": "create_page",
            "params": {
                "parent": {"page_id": "page_parent_1"},
                "properties": {"title": {"title": [{"text": {"content": "New page"}}]}},
                "children": [
                    {"object": "block", "type": "paragraph",
                     "paragraph": {"rich_text": [{"text": {"content": "Hello"}}]}}
                ]
            }
        }),
    )
    .await;
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.ends_with("/v1/pages"),
        "create_page should POST to /v1/pages, got: {uri}"
    );
    assert_eq!(echo["headers"]["notion-version"], "2022-06-28");
    assert_eq!(
        echo["headers"]["authorization"],
        "Bearer notion-oauth-token-123"
    );
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["parent"]["page_id"], "page_parent_1");
    assert_eq!(
        req_body["properties"]["title"]["title"][0]["text"]["content"],
        "New page"
    );
    assert_eq!(req_body["children"][0]["type"], "paragraph");

    // ===== WRITE: append_block_children (PATCH /v1/blocks/{id}/children) =====
    let echo = call_echo(
        &client,
        &base,
        &key,
        json!({
            "service": "notion",
            "action": "append_block_children",
            "params": {
                "block_id": "block_xyz",
                "children": [
                    {"object": "block", "type": "heading_2",
                     "heading_2": {"rich_text": [{"text": {"content": "Section"}}]}}
                ]
            }
        }),
    )
    .await;
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.ends_with("/v1/blocks/block_xyz/children"),
        "append_block_children should resolve the block_id path param, got: {uri}"
    );
    assert_eq!(echo["headers"]["notion-version"], "2022-06-28");
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["children"][0]["type"], "heading_2");
    assert!(
        req_body.get("block_id").is_none(),
        "path param must NOT leak into the JSON body"
    );
}

// ============================================================================
// Real Notion API test (requires NOTION_TEST_TOKEN)
// ============================================================================

#[ignore] // E2E test: hits the real Notion API (creates a subpage). Run with --ignored.
#[tokio::test]
async fn test_notion_real() {
    let pool = common::test_pool().await;

    // --- Guards: skip if credentials not set ---
    let access_token = match std::env::var("NOTION_TEST_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("SKIP: NOTION_TEST_TOKEN not set");
            return;
        }
    };
    let parent_page_id = match std::env::var("NOTION_TEST_PAGE_ID") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            eprintln!("SKIP: NOTION_TEST_PAGE_ID not set");
            return;
        }
    };

    // Start API with the real service registry (no host override — hits Notion).
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;

    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;

    // Notion tokens don't expire and have no refresh token, so the client
    // credentials below are never exchanged — but the OAuth auth path still
    // resolves them, so a BYOC credential must exist. The real Notion API only
    // checks the access token, so placeholder client creds are fine.
    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_access =
        overslash_core::crypto::encrypt(&enc_key, access_token.as_bytes()).unwrap();
    let encrypted_cid = overslash_core::crypto::encrypt(&enc_key, b"notion_client_id").unwrap();
    let encrypted_csec =
        overslash_core::crypto::encrypt(&enc_key, b"notion_client_secret").unwrap();
    let byoc = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(
            ident_id,
            "notion",
            &encrypted_cid,
            &encrypted_csec,
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    let _conn = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "notion",
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: None,
            token_expires_at: None,
            scopes: Some(&[]),
            account_email: None,
            account_picture: None,
            byoc_credential_id: Some(byoc.id),
        })
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "notion:*:*"}))
        .send()
        .await
        .unwrap();

    // ===== READ: search =====
    eprintln!("  [1/3] search ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"service": "notion", "action": "search", "params": {"page_size": 5}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let results: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        results["object"], "list",
        "search should return a list object, got: {results}"
    );
    eprintln!(
        "  search: {} results",
        results["results"].as_array().map(|a| a.len()).unwrap_or(0)
    );

    // ===== WRITE: create_page (a subpage under the test page) =====
    eprintln!("  [2/3] create_page ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "notion",
            "action": "create_page",
            "params": {
                "parent": {"page_id": parent_page_id},
                "properties": {"title": {"title": [{"text": {"content": "Overslash test page"}}]}}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let created: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let new_page_id = created["id"]
        .as_str()
        .expect("created page should have an id");
    eprintln!("  create_page: created {new_page_id}");

    // ===== WRITE: append_block_children to the new page =====
    eprintln!("  [3/3] append_block_children ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "notion",
            "action": "append_block_children",
            "params": {
                "block_id": new_page_id,
                "children": [
                    {"object": "block", "type": "paragraph",
                     "paragraph": {"rich_text": [{"text": {"content": "Added by Overslash integration test"}}]}}
                ]
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    eprintln!("  append_block_children: appended a paragraph block");
    eprintln!(
        "  All Notion real tests completed! (created page {new_page_id} — archive it manually)"
    );
}
