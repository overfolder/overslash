//! Google Calendar E2E tests — list/create/get/update/delete events, mock + real API.
//!
//! The mock test runs by default. The real test is `#[ignore]`'d — run with:
//!   cargo test --test google_calendar -- --ignored
//!
//! Env vars for the real test (all required):
//!   OAUTH_GOOGLE_CLIENT_ID     — OAuth 2.0 client ID from Google Cloud Console
//!   OAUTH_GOOGLE_CLIENT_SECRET — OAuth 2.0 client secret
//!   GOOGLE_TEST_REFRESH_TOKEN  — Long-lived refresh token for a test Google account
//!
//! How to get a refresh token:
//!   1. Create an OAuth 2.0 Client (Desktop or Web) in Google Cloud Console with
//!      scope https://www.googleapis.com/auth/calendar
//!   2. Use https://developers.google.com/oauthplayground/ (set your own client
//!      id/secret in the gear menu) or run the Overslash OAuth flow locally to
//!      obtain an offline refresh token.
//!   3. The test calls POST https://oauth2.googleapis.com/token with
//!      grant_type=refresh_token to mint fresh access tokens on each run.
//!
//! The test creates events on the account's `primary` calendar and deletes them
//! at the end — use a dedicated test account, not a personal calendar.

// Test setup requires dynamic SQL for provider endpoint overrides and DB seeding.
#![allow(clippy::disallowed_methods)]

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

// ============================================================================
// Mock-based test — verifies three execution modes against a local mock server
// ============================================================================

#[tokio::test]
async fn test_google_calendar_three_modes() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    // Point google provider's token_endpoint at mock
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'google'")
        .bind(format!("http://{mock_addr}/oauth/token"))
        .execute(&pool)
        .await
        .unwrap();

    // Start API with registry, override google_calendar host to mock
    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("google_calendar", mock_host.clone())))
            .await;

    // Bootstrap org + identity + API key
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // Create broad permission rules: http:** for Mode A/B, google_calendar:*:* for Mode C
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "google_calendar:*:*"}))
        .send()
        .await
        .unwrap();

    // ===== MODE A: Raw HTTP with secret injection =====
    client
        .put(format!("{base}/v1/secrets/gcal_token"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"value": "manual-token-xyz"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "secrets": [{
                "name": "gcal_token",
                "inject_as": "header",
                "header_name": "Authorization",
                "prefix": "Bearer "
            }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        echo["headers"]["authorization"], "Bearer manual-token-xyz",
        "Mode A: secret should be injected as Authorization header"
    );

    // ===== MODE B: Connection-based OAuth =====
    let enc_key = overslash_core::crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let encrypted_token =
        overslash_core::crypto::encrypt(&enc_key, b"google-oauth-token-123").unwrap();
    let future_time = time::OffsetDateTime::now_utc() + time::Duration::hours(1);

    // Create a BYOC credential so client_credentials::resolve succeeds
    let encrypted_cid = overslash_core::crypto::encrypt(&enc_key, b"mock_client_id").unwrap();
    let encrypted_csec = overslash_core::crypto::encrypt(&enc_key, b"mock_client_secret").unwrap();
    let byoc = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(ident_id, "google", &encrypted_cid, &encrypted_csec)
        .await
        .unwrap();

    let conn = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ident_id,
            provider_key: "google",
            encrypted_access_token: &encrypted_token,
            encrypted_refresh_token: None,
            token_expires_at: Some(future_time),
            scopes: &[],
            account_email: None,
            byoc_credential_id: Some(byoc.id),
        })
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "connection": conn.id.to_string(),
            "method": "GET",
            "url": format!("http://{mock_addr}/echo")
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        echo["headers"]["authorization"], "Bearer google-oauth-token-123",
        "Mode B: OAuth token should be injected from connection"
    );

    // ===== MODE C (POST): create_event — path template + JSON body + OAuth auto-resolve =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "create_event",
            "params": {
                "calendarId": "primary",
                "summary": "Team Meeting",
                "start": {"dateTime": "2026-03-27T10:00:00Z"},
                "end": {"dateTime": "2026-03-27T11:00:00Z"},
                "description": "Weekly sync"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");

    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/calendar/v3/calendars/primary/events"),
        "Mode C POST: URL should contain resolved path, got: {uri}"
    );

    // Verify body contains non-path params as JSON
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["summary"], "Team Meeting");
    assert_eq!(req_body["description"], "Weekly sync");

    // Verify auth was auto-resolved from the connection
    assert_eq!(
        echo["headers"]["authorization"], "Bearer google-oauth-token-123",
        "Mode C: OAuth token should be auto-resolved from connection"
    );

    // ===== MODE C (GET): list_events — query param construction =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "list_events",
            "params": {
                "calendarId": "primary",
                "timeMin": "2026-03-27T00:00:00Z",
                "maxResults": 10
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");

    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/calendar/v3/calendars/primary/events"),
        "Mode C GET: URL should contain resolved path, got: {uri}"
    );
    assert!(
        uri.contains("timeMin="),
        "Mode C GET: query params should be appended, got: {uri}"
    );
    assert!(
        uri.contains("maxResults="),
        "Mode C GET: query params should be appended, got: {uri}"
    );

    // ===== MODE C (GET): list_calendars — no path params =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "list_calendars",
            "params": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/calendar/v3/users/me/calendarList"),
        "Mode C GET: list_calendars path should be correct, got: {uri}"
    );
}

// ============================================================================
// Real Google Calendar API test (requires GOOGLE_TEST_REFRESH_TOKEN + OAUTH_GOOGLE_*)
// ============================================================================

#[ignore] // Write test: creates/updates/deletes real calendar events. Run with --ignored.
#[tokio::test]
async fn test_google_calendar_real_byoc() {
    let pool = common::test_pool().await;
    // Skip if required env vars are not set
    let refresh_token = match std::env::var("GOOGLE_TEST_REFRESH_TOKEN") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("SKIP: GOOGLE_TEST_REFRESH_TOKEN not set");
            return;
        }
    };
    let client_id = std::env::var("OAUTH_GOOGLE_CLIENT_ID")
        .expect("OAUTH_GOOGLE_CLIENT_ID required for real test");
    let client_secret = std::env::var("OAUTH_GOOGLE_CLIENT_SECRET")
        .expect("OAUTH_GOOGLE_CLIENT_SECRET required for real test");

    // Start API with real service registry (no host override — hits real Google)
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;

    // Bootstrap org + identity + API key
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // Store BYOC credential via API (production path)
    let byoc_resp: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "provider": "google",
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

    // Exchange refresh token for access token via real Google token endpoint
    let token_resp: Value = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh_token),
            ("client_id", &client_id),
            ("client_secret", &client_secret),
        ])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let access_token = token_resp["access_token"]
        .as_str()
        .expect("failed to get access_token from Google token endpoint");
    let expires_in = token_resp["expires_in"].as_i64().unwrap_or(3600);

    // Encrypt tokens and insert connection in DB
    let enc_key = overslash_core::crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let encrypted_access =
        overslash_core::crypto::encrypt(&enc_key, access_token.as_bytes()).unwrap();
    let encrypted_refresh =
        overslash_core::crypto::encrypt(&enc_key, refresh_token.as_bytes()).unwrap();
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::seconds(expires_in);

    let conn = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ident_id,
            provider_key: "google",
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: Some(&encrypted_refresh),
            token_expires_at: Some(expires_at),
            scopes: &["https://www.googleapis.com/auth/calendar".to_string()],
            account_email: Some("angel.overspiral@gmail.com"),
            byoc_credential_id: Some(byoc_id),
        })
        .await
        .unwrap();

    // Create broad permission rules: http:** for raw HTTP, google_calendar:*:* for Mode C
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "google_calendar:*:*"}))
        .send()
        .await
        .unwrap();

    // ===== TEST 1: list_calendars (Mode C) =====
    eprintln!("  [1/8] list_calendars ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "list_calendars",
            "params": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let gcal_body: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        gcal_body["items"].is_array(),
        "list_calendars should return items array, got: {gcal_body}"
    );
    eprintln!(
        "  list_calendars: found {} calendars",
        gcal_body["items"].as_array().unwrap().len()
    );

    // ===== TEST 2: create_event (Mode C) =====
    eprintln!("  [2/8] create_event ...");
    let now = time::OffsetDateTime::now_utc();
    let start = now + time::Duration::hours(1);
    let end = now + time::Duration::hours(2);
    let event_summary = format!("Overslash Test - {}", now.unix_timestamp());

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "create_event",
            "params": {
                "calendarId": "primary",
                "summary": event_summary,
                "start": {"dateTime": start.format(&time::format_description::well_known::Rfc3339).unwrap()},
                "end": {"dateTime": end.format(&time::format_description::well_known::Rfc3339).unwrap()},
                "description": "Integration test event — will be deleted"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let created: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let event_id = created["id"]
        .as_str()
        .expect("created event should have an id");
    eprintln!("  create_event: created {event_id}");

    // ===== TEST 3: list_events with query params (Mode C, GET) =====
    eprintln!("  [3/8] list_events ...");
    let time_min = now
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "list_events",
            "params": {
                "calendarId": "primary",
                "timeMin": time_min,
                "maxResults": 10,
                "singleEvents": true,
                "orderBy": "startTime"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let events: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        events["items"].is_array(),
        "list_events should return items array"
    );
    let found = events["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["summary"].as_str() == Some(&event_summary));
    assert!(found, "created event should appear in list_events");
    eprintln!("  list_events: found test event in listing");

    // ===== TEST 4: get_event (Mode C) =====
    eprintln!("  [4/8] get_event ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "get_event",
            "params": {
                "calendarId": "primary",
                "eventId": event_id
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let fetched: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(fetched["id"].as_str().unwrap(), event_id);
    assert_eq!(fetched["summary"].as_str().unwrap(), event_summary);
    eprintln!("  get_event: verified event {event_id}");

    // ===== TEST 5: update_event (Mode C, PATCH) =====
    // This also verifies the template uses PATCH (partial update) — if it were
    // PUT, the summary field would be wiped because we don't resend it.
    eprintln!("  [5/8] update_event ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "update_event",
            "params": {
                "calendarId": "primary",
                "eventId": event_id,
                "description": "Updated \u{2014} will be deleted",
                "location": "Remote"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let updated: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        updated["description"].as_str().unwrap(),
        "Updated \u{2014} will be deleted",
        "update_event: description should be updated"
    );
    assert_eq!(
        updated["location"].as_str().unwrap(),
        "Remote",
        "update_event: location should be updated"
    );
    // PATCH preserves fields not sent — summary must still be the original value.
    // If the template mistakenly used PUT, this assertion would fail.
    assert_eq!(
        updated["summary"].as_str().unwrap(),
        event_summary,
        "update_event: summary must be preserved (PATCH semantics)"
    );
    eprintln!("  update_event: description/location updated, summary preserved");

    // ===== TEST 6: Mode A — raw HTTP with secret =====
    // Store the access token as a secret for raw HTTP mode
    eprintln!("  [6/8] Mode A raw HTTP ...");
    client
        .put(format!("{base}/v1/secrets/gcal_raw_token"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"value": access_token}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "method": "GET",
            "url": format!(
                "https://www.googleapis.com/calendar/v3/calendars/primary/events/{event_id}"
            ),
            "secrets": [{
                "name": "gcal_raw_token",
                "inject_as": "header",
                "header_name": "Authorization",
                "prefix": "Bearer "
            }]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let raw_fetched: Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(raw_fetched["id"].as_str().unwrap(), event_id);
    eprintln!("  Mode A raw HTTP: verified event via direct URL");

    // ===== TEST 7: Mode B — connection-based =====
    eprintln!("  [7/8] Mode B connection ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "connection": conn.id.to_string(),
            "method": "GET",
            "url": format!(
                "https://www.googleapis.com/calendar/v3/calendars/primary/events/{event_id}"
            )
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let conn_fetched: Value =
        serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(conn_fetched["id"].as_str().unwrap(), event_id);
    eprintln!("  Mode B connection: verified event via OAuth connection");

    // ===== CLEANUP: delete_event (Mode C) =====
    eprintln!("  [8/8] delete_event (cleanup) ...");
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "delete_event",
            "params": {
                "calendarId": "primary",
                "eventId": event_id
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    // Google returns 204 No Content for successful delete
    let status_code = body["result"]["status_code"].as_u64().unwrap();
    assert!(
        status_code == 204 || status_code == 200,
        "delete should return 204 or 200, got: {status_code}"
    );
    eprintln!("  delete_event: cleaned up test event");
    eprintln!("  All Google Calendar real tests passed!");
}
