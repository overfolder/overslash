//! Regression tests for the OAuth-token leak in pending approvals.
//!
//! Before the fix, OAuth access tokens were injected into
//! `ActionRequest.headers` at resolve time, and a template that declared
//! neither `x-overslash-disclose` nor `x-overslash-redact` fell back to
//! serializing the raw `ActionRequest` — token included — into
//! `approvals.action_detail`. That blob was returned to the *requesting
//! agent* in the inline `pending_approval` envelope (REST and MCP) and via
//! `GET /v1/approvals`, and the full request (with token) was persisted
//! plaintext in `approvals.replay_payload`.
//!
//! These tests pin the fixed behavior end-to-end:
//!   1. No surface of a pending approval — inline envelope, GET read path,
//!      list path, or either DB column — contains the token or any headers.
//!   2. Replay re-resolves a fresh token from the requester's connection
//!      (the stored payload carries none) and the upstream call succeeds.
//!   3. Replay of an OAuth-backed approval whose connection has since been
//!      deleted fails with a typed conflict instead of replaying tokenless.

// Test setup requires dynamic SQL for DB seeding/inspection.
#![allow(clippy::disallowed_methods)]

mod common;

use common::{auth, bootstrap_org_identity, start_api_with_registry, start_mock};
use serde_json::{Value, json};
use uuid::Uuid;

const OAUTH_TOKEN: &str = "gcal-secret-token-456";

struct PendingOauthApproval {
    base: String,
    client: reqwest::Client,
    pool: sqlx::PgPool,
    org_id: Uuid,
    approval_id: String,
    agent_key: String,
    admin_key: String,
    /// Raw JSON text of the inline `pending_approval` envelope, exactly as
    /// the requesting agent received it.
    envelope: String,
}

/// Shared setup: shipped `google_calendar` template (OAuth, no
/// disclose/redact declarations) pointed at the in-test mock, an agent with
/// Layer-1 access but no Layer-2 permission rule, and a seeded Google
/// connection carrying a valid (non-expired) access token.
async fn setup_pending_oauth_approval() -> PendingOauthApproval {
    let pool = common::test_pool().await;
    let mock_addr = start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    let (base, client) =
        start_api_with_registry(pool.clone(), Some(("google_calendar", mock_host))).await;
    let (org_id, ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    // Layer 1: org-level instance granted to Everyone. No Layer-2 permission
    // rule is created, so the agent's call gaps → pending approval.
    common::grant_service_to_everyone(&base, &client, &admin_key, "google_calendar").await;

    // Seed BYOC client credentials + a connection with a live, non-expired
    // access token so OAuth resolution succeeds without a refresh round-trip.
    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_token =
        overslash_core::crypto::encrypt(&enc_key, OAUTH_TOKEN.as_bytes()).unwrap();
    let encrypted_cid = overslash_core::crypto::encrypt(&enc_key, b"mock_client_id").unwrap();
    let encrypted_csec = overslash_core::crypto::encrypt(&enc_key, b"mock_client_secret").unwrap();
    let future_time = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let byoc = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(
            ident_id,
            "google",
            &encrypted_cid,
            &encrypted_csec,
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    // Connections resolve at the owner identity (D22): the agent shares its
    // owner user's connection, so create it on the owner ("test-user") that
    // `bootstrap_org_identity` puts the agent under.
    let owner_id = common::owner_user_id(&pool, org_id).await;
    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "google",
            encrypted_access_token: &encrypted_token,
            encrypted_refresh_token: None,
            token_expires_at: Some(future_time),
            scopes: Some(&["https://www.googleapis.com/auth/calendar".to_string()]),
            account_email: None,
            byoc_credential_id: Some(byoc.id),
        })
        .await
        .unwrap();

    // Mode C write action as the agent: OAuth resolves (token exists), the
    // permission chain gaps → 202 pending_approval.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "google_calendar",
            "action": "create_event",
            "params": {
                "calendarId": "primary",
                "summary": "Team Meeting",
                "start": {"dateTime": "2026-03-27T10:00:00Z"},
                "end": {"dateTime": "2026-03-27T11:00:00Z"}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202, "expected pending approval");
    let envelope = resp.text().await.unwrap();
    let body: Value = serde_json::from_str(&envelope).unwrap();
    assert_eq!(
        body["status"].as_str(),
        Some("pending_approval"),
        "expected pending_approval, got: {body:?}"
    );
    let approval_id = body["approval_id"].as_str().unwrap().to_string();

    PendingOauthApproval {
        base,
        client,
        pool,
        org_id,
        approval_id,
        agent_key,
        admin_key,
        envelope,
    }
}

#[tokio::test]
async fn pending_approval_never_exposes_oauth_token() {
    let t = setup_pending_oauth_approval().await;

    // 1. Inline pending_approval envelope returned to the *agent*: no token,
    //    no Authorization header anywhere in the payload.
    assert!(
        !t.envelope.contains(OAUTH_TOKEN),
        "OAuth token leaked into the pending_approval envelope:\n{}",
        t.envelope
    );
    assert!(
        !t.envelope.to_ascii_lowercase().contains("authorization"),
        "Authorization header leaked into the pending_approval envelope:\n{}",
        t.envelope
    );
    let body: Value = serde_json::from_str(&t.envelope).unwrap();
    let inline_detail = body["action_detail"]
        .as_str()
        .expect("inline action_detail present");
    assert!(
        !inline_detail.contains("headers"),
        "headers must not appear in action_detail:\n{inline_detail}"
    );
    // Sanity: the projection still tells the approver what the call does.
    assert!(
        inline_detail.contains("/calendar/v3/calendars/primary/events"),
        "action_detail should still carry the resolved url:\n{inline_detail}"
    );

    // 2. GET read path (what the dashboard and ancestor agents see).
    let detail_resp = t
        .client
        .get(format!("{}/v1/approvals/{}", t.base, t.approval_id))
        .header(auth(&t.admin_key).0, auth(&t.admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(detail_resp.status(), 200);
    let detail_raw = detail_resp.text().await.unwrap();
    assert!(
        !detail_raw.contains(OAUTH_TOKEN),
        "OAuth token leaked into GET /v1/approvals/{{id}}:\n{detail_raw}"
    );

    // 3. List path.
    let list_resp = t
        .client
        .get(format!("{}/v1/approvals", t.base))
        .header(auth(&t.admin_key).0, auth(&t.admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(list_resp.status(), 200);
    let list_raw = list_resp.text().await.unwrap();
    assert!(
        !list_raw.contains(OAUTH_TOKEN),
        "OAuth token leaked into GET /v1/approvals:\n{list_raw}"
    );

    // 4. At rest: neither stored column may contain the token. The replay
    //    payload records *where* to re-resolve auth (service_key) instead of
    //    the credential itself.
    let approval_uuid = Uuid::parse_str(&t.approval_id).unwrap();
    let row: (Option<Value>, Option<Value>) =
        sqlx::query_as("SELECT action_detail, replay_payload FROM approvals WHERE id = $1")
            .bind(approval_uuid)
            .fetch_one(&t.pool)
            .await
            .unwrap();
    let action_detail = row.0.expect("action_detail stored").to_string();
    let replay_payload = row.1.expect("replay_payload stored");
    let replay_raw = replay_payload.to_string();
    assert!(
        !action_detail.contains(OAUTH_TOKEN),
        "OAuth token persisted in approvals.action_detail:\n{action_detail}"
    );
    assert!(
        !replay_raw.contains(OAUTH_TOKEN),
        "OAuth token persisted in approvals.replay_payload:\n{replay_raw}"
    );
    assert!(
        replay_payload["action"]["headers"]
            .as_object()
            .is_none_or(|h| !h.keys().any(|k| k.eq_ignore_ascii_case("authorization"))),
        "Authorization header persisted in replay_payload:\n{replay_raw}"
    );
    assert_eq!(
        replay_payload["service_key"].as_str(),
        Some("google_calendar"),
        "replay_payload must record the service to re-resolve auth from:\n{replay_raw}"
    );
}

#[tokio::test]
async fn replay_re_resolves_fresh_oauth_token() {
    let t = setup_pending_oauth_approval().await;

    // Approve (admin), then trigger the replay from the agent side.
    let resp = t
        .client
        .post(format!("{}/v1/approvals/{}/resolve", t.base, t.approval_id))
        .header(auth(&t.admin_key).0, auth(&t.admin_key).1)
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = t
        .client
        .post(format!("{}/v1/approvals/{}/call", t.base, t.approval_id))
        .header(auth(&t.agent_key).0, auth(&t.agent_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let executed: Value = resp.json().await.unwrap();
    assert_eq!(
        executed["execution"]["status"], "executed",
        "replay should execute: {executed:?}"
    );

    // The stored payload carried no credential — the Authorization header
    // the mock saw must come from replay-time re-resolution.
    let echo: Value = serde_json::from_str(
        executed["execution"]["result"]["body"]
            .as_str()
            .expect("replay result body"),
    )
    .unwrap();
    assert_eq!(
        echo["headers"]["authorization"].as_str(),
        Some(&*format!("Bearer {OAUTH_TOKEN}")),
        "replay must re-resolve the OAuth token from the requester's connection: {echo:?}"
    );
}

#[tokio::test]
async fn replay_fails_typed_when_connection_is_gone() {
    let t = setup_pending_oauth_approval().await;

    // Approve, then delete the requester's connection out from under the
    // pending execution.
    let resp = t
        .client
        .post(format!("{}/v1/approvals/{}/resolve", t.base, t.approval_id))
        .header(auth(&t.admin_key).0, auth(&t.admin_key).1)
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    sqlx::query("DELETE FROM connections WHERE org_id = $1 AND provider_key = 'google'")
        .bind(t.org_id)
        .execute(&t.pool)
        .await
        .unwrap();

    // The original call carried OAuth; a tokenless replay must not happen.
    let resp = t
        .client
        .post(format!("{}/v1/approvals/{}/call", t.base, t.approval_id))
        .header(auth(&t.agent_key).0, auth(&t.agent_key).1)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert!(
        !status.is_success(),
        "replay without a resolvable credential must fail, got {status}: {body}"
    );
    assert!(
        !body.contains(OAUTH_TOKEN),
        "token leaked in replay failure body: {body}"
    );

    // The execution row records the failure rather than a tokenless call.
    let exec_resp = t
        .client
        .get(format!(
            "{}/v1/approvals/{}/execution",
            t.base, t.approval_id
        ))
        .header(auth(&t.admin_key).0, auth(&t.admin_key).1)
        .send()
        .await
        .unwrap();
    let exec_body: Value = exec_resp.json().await.unwrap();
    assert_eq!(
        exec_body["status"].as_str(),
        Some("failed"),
        "execution should be marked failed: {exec_body:?}"
    );
}
