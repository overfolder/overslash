//! HubSpot CRM E2E tests — contacts, companies, deals, notes via the v3
//! objects API, exercised through connection-based (Mode C) execution.
//!
//! The mock test (`test_hubspot_crm_modes`) runs by default: it points the
//! `hubspot` provider + service host at a local echo fake and asserts that each
//! action resolves to the right method/URL/body and carries the auto-resolved
//! OAuth bearer token. The real test (`test_hubspot_real`) is `#[ignore]`'d —
//! run with: cargo test --test hubspot -- --ignored
//!
//! Env vars for the real test (all required):
//!   HUBSPOT_TEST_TOKEN         — a HubSpot access token or Private App token
//!                                with contacts read/write scopes.
//!   OAUTH_HUBSPOT_CLIENT_ID    — OAuth app client id (stored as a BYOC
//!                                credential so token refresh can resolve).
//!   OAUTH_HUBSPOT_CLIENT_SECRET — OAuth app client secret.
//!
//! The real test creates a contact and then reads it back — use a sandbox/test
//! HubSpot account, not a production portal.

// Test setup requires dynamic SQL for provider endpoint overrides and DB seeding.
#![allow(clippy::disallowed_methods)]

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

/// The CRM scopes seeded onto the test connection — a subset of the six the
/// `hubspot` template declares, covering the read/write actions these tests
/// exercise. Enough to satisfy any auto-resolve scope checks.
fn crm_scopes() -> Vec<String> {
    [
        "crm.objects.contacts.read",
        "crm.objects.contacts.write",
        "crm.objects.companies.read",
        "crm.objects.deals.read",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

// ============================================================================
// Mock-based test — verifies Mode C CRM reads + writes against a local fake.
// ============================================================================

#[tokio::test]
async fn test_hubspot_crm_modes() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    // Point the hubspot provider's token_endpoint at the mock (only exercised
    // on refresh; the seeded token below is future-dated so it stays unused,
    // but wiring it keeps the provider row self-consistent for the test).
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'hubspot'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    // Start API with the bundled registry, overriding hubspot's host to the fake.
    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("hubspot", mock_host.clone()))).await;

    // Bootstrap org + identity + API key.
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    // Connections resolve at the owner identity (D22): seed on the agent's
    // owner user so the agent's auto-resolved action calls find the connection.
    let owner_id = common::owner_user_id(&pool, org_id).await;

    // Grant Mode C permissions for hubspot actions.
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "hubspot:*:*"}))
        .send()
        .await
        .unwrap();

    // Mode C requires Layer-1 access to the `hubspot` service instance. Create
    // an org-level instance and grant Everyone admin so the ceiling clears for
    // the test agent's owner-user.
    common::grant_service_to_everyone(&base, &client, &admin_key, "hubspot").await;

    // Seed a BYOC credential + OAuth connection at the owner identity. The
    // token is future-dated so `resolve_access_token` returns it verbatim
    // without a refresh round-trip.
    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_token =
        overslash_core::crypto::encrypt(&enc_key, b"hubspot-oauth-token-abc").unwrap();
    let encrypted_cid = overslash_core::crypto::encrypt(&enc_key, b"mock_client_id").unwrap();
    let encrypted_csec = overslash_core::crypto::encrypt(&enc_key, b"mock_client_secret").unwrap();
    let future_time = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let byoc = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(ident_id, "hubspot", &encrypted_cid, &encrypted_csec)
        .await
        .unwrap();
    let scopes = crm_scopes();
    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "hubspot",
            encrypted_access_token: &encrypted_token,
            encrypted_refresh_token: None,
            token_expires_at: Some(future_time),
            scopes: Some(&scopes),
            account_email: None,
            byoc_credential_id: Some(byoc.id),
        })
        .await
        .unwrap();

    // Helper: call a Mode C action and return the echoed request the fake saw.
    async fn call(client: &reqwest::Client, base: &str, key: &str, body: Value) -> Value {
        let resp = client
            .post(format!("{base}/v1/actions/call"))
            .header(common::auth(key).0, common::auth(key).1)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "action call failed: {}", body["action"]);
        let envelope: Value = resp.json().await.unwrap();
        assert_eq!(envelope["status"], "called", "envelope: {envelope}");
        serde_json::from_str(envelope["result"]["body"].as_str().unwrap()).unwrap()
    }

    // ===== list_contacts (GET) — query params + auto-resolved bearer =====
    let echo = call(
        &client,
        &base,
        &key,
        json!({
            "service": "hubspot",
            "action": "list_contacts",
            "params": {"limit": 5, "properties": "email,firstname,lastname"}
        }),
    )
    .await;
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/crm/v3/objects/contacts"),
        "list_contacts path, got: {uri}"
    );
    assert!(uri.contains("limit=5"), "limit query param, got: {uri}");
    assert!(
        uri.contains("properties="),
        "properties query param, got: {uri}"
    );
    assert_eq!(
        echo["headers"]["authorization"], "Bearer hubspot-oauth-token-abc",
        "OAuth token should be auto-resolved from the connection"
    );

    // ===== get_contact (GET) — path param resolution =====
    let echo = call(
        &client,
        &base,
        &key,
        json!({
            "service": "hubspot",
            "action": "get_contact",
            "params": {"contactId": "12345", "properties": "email"}
        }),
    )
    .await;
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/crm/v3/objects/contacts/12345"),
        "get_contact path should embed the contact id, got: {uri}"
    );

    // ===== create_contact (POST) — JSON body =====
    let echo = call(
        &client,
        &base,
        &key,
        json!({
            "service": "hubspot",
            "action": "create_contact",
            "params": {
                "properties": {
                    "email": "ada@analytical.example",
                    "firstname": "Ada",
                    "lastname": "Lovelace"
                }
            }
        }),
    )
    .await;
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/crm/v3/objects/contacts"),
        "create_contact path, got: {uri}"
    );
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["properties"]["email"], "ada@analytical.example");
    assert_eq!(req_body["properties"]["firstname"], "Ada");
    assert_eq!(
        echo["headers"]["authorization"], "Bearer hubspot-oauth-token-abc",
        "create_contact should carry the auto-resolved bearer token"
    );

    // ===== update_contact (PATCH) — path param + JSON body =====
    let echo = call(
        &client,
        &base,
        &key,
        json!({
            "service": "hubspot",
            "action": "update_contact",
            "params": {
                "contactId": "12345",
                "properties": {"jobtitle": "CTO", "phone": "+1-555-0199"}
            }
        }),
    )
    .await;
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/crm/v3/objects/contacts/12345"),
        "update_contact path should embed the contact id, got: {uri}"
    );
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["properties"]["jobtitle"], "CTO");
    assert!(
        req_body.get("contactId").is_none(),
        "path param must not leak into the JSON body"
    );

    // ===== list_companies (GET) =====
    let echo = call(
        &client,
        &base,
        &key,
        json!({
            "service": "hubspot",
            "action": "list_companies",
            "params": {"limit": 3}
        }),
    )
    .await;
    assert!(
        echo["uri"]
            .as_str()
            .unwrap()
            .contains("/crm/v3/objects/companies"),
        "list_companies path, got: {}",
        echo["uri"]
    );

    // ===== get_company (GET) — path param =====
    let echo = call(
        &client,
        &base,
        &key,
        json!({
            "service": "hubspot",
            "action": "get_company",
            "params": {"companyId": "777"}
        }),
    )
    .await;
    assert!(
        echo["uri"]
            .as_str()
            .unwrap()
            .contains("/crm/v3/objects/companies/777"),
        "get_company path should embed the company id, got: {}",
        echo["uri"]
    );

    // ===== list_deals (GET) =====
    let echo = call(
        &client,
        &base,
        &key,
        json!({
            "service": "hubspot",
            "action": "list_deals",
            "params": {"properties": "dealname,amount,dealstage"}
        }),
    )
    .await;
    assert!(
        echo["uri"]
            .as_str()
            .unwrap()
            .contains("/crm/v3/objects/deals"),
        "list_deals path, got: {}",
        echo["uri"]
    );

    // ===== get_deal (GET) — path param =====
    let echo = call(
        &client,
        &base,
        &key,
        json!({
            "service": "hubspot",
            "action": "get_deal",
            "params": {"dealId": "999"}
        }),
    )
    .await;
    assert!(
        echo["uri"]
            .as_str()
            .unwrap()
            .contains("/crm/v3/objects/deals/999"),
        "get_deal path should embed the deal id, got: {}",
        echo["uri"]
    );

    // ===== create_note (POST) — engagement write =====
    let echo = call(
        &client,
        &base,
        &key,
        json!({
            "service": "hubspot",
            "action": "create_note",
            "params": {
                "properties": {
                    "hs_note_body": "Called re: renewal",
                    "hs_timestamp": "2026-07-02T12:00:00Z"
                }
            }
        }),
    )
    .await;
    assert!(
        echo["uri"]
            .as_str()
            .unwrap()
            .contains("/crm/v3/objects/notes"),
        "create_note path, got: {}",
        echo["uri"]
    );
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["properties"]["hs_note_body"], "Called re: renewal");
}

// ============================================================================
// Real HubSpot API test (requires HUBSPOT_TEST_TOKEN + OAUTH_HUBSPOT_*).
// ============================================================================

#[ignore] // Write test: creates a real contact. Run with --ignored.
#[tokio::test]
async fn test_hubspot_real() {
    let pool = common::test_pool().await;

    // --- Guard: skip if credentials not set ---
    let access_token = match std::env::var("HUBSPOT_TEST_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("SKIP: HUBSPOT_TEST_TOKEN not set");
            return;
        }
    };
    let client_id = std::env::var("OAUTH_HUBSPOT_CLIENT_ID")
        .expect("OAUTH_HUBSPOT_CLIENT_ID required for real test");
    let client_secret = std::env::var("OAUTH_HUBSPOT_CLIENT_SECRET")
        .expect("OAUTH_HUBSPOT_CLIENT_SECRET required for real test");

    // Start API with real service registry (no host override — hits real HubSpot).
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;

    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .get_identity(ident_id)
        .await
        .unwrap()
        .unwrap()
        .owner_id
        .unwrap();

    // Store BYOC credential via API (production path) so client-credential
    // resolution succeeds during auth resolve.
    let byoc_resp: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "provider": "hubspot",
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

    // Encrypt the access token and insert the connection directly. Future-dated
    // so no refresh is attempted (the token may be a Private App token that has
    // no refresh grant).
    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_access =
        overslash_core::crypto::encrypt(&enc_key, access_token.as_bytes()).unwrap();
    let future_time = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let scopes = crm_scopes();
    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "hubspot",
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: None,
            token_expires_at: Some(future_time),
            scopes: Some(&scopes),
            account_email: None,
            byoc_credential_id: Some(byoc_id),
        })
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "hubspot:*:*"}))
        .send()
        .await
        .unwrap();

    // ===== TEST 1: list_contacts (Mode C) =====
    eprintln!("  [1/3] list_contacts ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "hubspot",
            "action": "list_contacts",
            "params": {"limit": 5, "properties": "email,firstname,lastname"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let listing: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        listing["results"].is_array(),
        "list_contacts should return a results array, got: {listing}"
    );
    eprintln!(
        "  list_contacts: {} contacts",
        listing["results"].as_array().unwrap().len()
    );

    // ===== TEST 2: create_contact (Mode C, POST) =====
    eprintln!("  [2/3] create_contact ...");
    let unique = time::OffsetDateTime::now_utc().unix_timestamp();
    let email = format!("overslash-test-{unique}@example.com");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "hubspot",
            "action": "create_contact",
            "params": {
                "properties": {
                    "email": email,
                    "firstname": "Overslash",
                    "lastname": "Test"
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let created: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let contact_id = created["id"]
        .as_str()
        .expect("created contact should have an id");
    eprintln!("  create_contact: created {contact_id} ({email})");

    // ===== TEST 3: get_contact (Mode C) — read back what we created =====
    eprintln!("  [3/3] get_contact ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "hubspot",
            "action": "get_contact",
            "params": {"contactId": contact_id, "properties": "email,firstname"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let fetched: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(fetched["id"].as_str().unwrap(), contact_id);
    assert_eq!(
        fetched["properties"]["email"]
            .as_str()
            .unwrap()
            .to_lowercase(),
        email.to_lowercase()
    );
    eprintln!("  get_contact: verified {contact_id}");
    eprintln!("  All HubSpot real tests passed!");
}
