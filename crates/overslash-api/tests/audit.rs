//! Audit log integration tests: covers the DB repo layer, the query API endpoint,
//! and every code path that emits an audit entry.

mod common;

use common::{auth, bootstrap_org_identity, start_api, start_mock};
use reqwest::Client;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Query audit log entries for the given org (via API key).
async fn fetch_audit(base: &str, client: &Client, key: &str) -> Vec<Value> {
    client
        .get(format!("{base}/v1/audit"))
        .header(auth(key).0, auth(key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Fetch audit entries with explicit limit/offset.
async fn fetch_audit_paged(
    base: &str,
    client: &Client,
    key: &str,
    limit: i64,
    offset: i64,
) -> Vec<Value> {
    client
        .get(format!("{base}/v1/audit?limit={limit}&offset={offset}"))
        .header(auth(key).0, auth(key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Full bootstrap: org + identity + identity-bound key + permissions + API base URL.
/// Returns (base_url, api_key, org_id, identity_id, client).
async fn setup_with_perm(pool: PgPool, pattern: &str) -> (String, String, Uuid, Uuid, Client) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, key) = bootstrap_org_identity(&base, &client).await;

    // Grant permission
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": pattern}))
        .send()
        .await
        .unwrap();

    (base, key, org_id, ident_id, client)
}

// ---------------------------------------------------------------------------
// DB repo layer
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_insert_and_query(pool: PgPool) {
    // Create a minimal org directly in the DB so we have a valid org_id
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("AuditTestOrg")
        .bind(format!("audit-test-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    // Insert an audit entry
    overslash_db::repos::audit::log(
        &pool,
        org_id,
        None,
        "test.action",
        Some("widget"),
        None,
        json!({"key": "value"}),
    )
    .await
    .unwrap();

    // Query back
    let rows = overslash_db::repos::audit::query_by_org(&pool, org_id, 10, 0)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.org_id, org_id);
    assert_eq!(row.action, "test.action");
    assert_eq!(row.resource_type.as_deref(), Some("widget"));
    assert!(row.resource_id.is_none());
    assert!(row.identity_id.is_none());
    assert_eq!(row.detail["key"], "value");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_with_identity_and_resource(pool: PgPool) {
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("AuditOrg2")
        .bind(format!("audit2-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    let identity_id = Uuid::new_v4();
    sqlx::query("INSERT INTO identities (id, org_id, name, kind) VALUES ($1, $2, $3, $4)")
        .bind(identity_id)
        .bind(org_id)
        .bind("agent-1")
        .bind("agent")
        .execute(&pool)
        .await
        .unwrap();

    let resource_id = Uuid::new_v4();

    overslash_db::repos::audit::log(
        &pool,
        org_id,
        Some(identity_id),
        "secret.created",
        Some("secret"),
        Some(resource_id),
        json!({"name": "my_token"}),
    )
    .await
    .unwrap();

    let rows = overslash_db::repos::audit::query_by_org(&pool, org_id, 10, 0)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].identity_id, Some(identity_id));
    assert_eq!(rows[0].resource_id, Some(resource_id));
    assert_eq!(rows[0].resource_type.as_deref(), Some("secret"));
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_ordering_desc(pool: PgPool) {
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("OrderOrg")
        .bind(format!("order-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    // Insert three entries sequentially
    for action in &["first", "second", "third"] {
        overslash_db::repos::audit::log(&pool, org_id, None, action, None, None, json!({}))
            .await
            .unwrap();
    }

    let rows = overslash_db::repos::audit::query_by_org(&pool, org_id, 10, 0)
        .await
        .unwrap();

    assert_eq!(rows.len(), 3);
    // Most recent first
    assert_eq!(rows[0].action, "third");
    assert_eq!(rows[1].action, "second");
    assert_eq!(rows[2].action, "first");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_pagination(pool: PgPool) {
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("PageOrg")
        .bind(format!("page-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    for i in 0..5 {
        overslash_db::repos::audit::log(
            &pool,
            org_id,
            None,
            &format!("action_{i}"),
            None,
            None,
            json!({}),
        )
        .await
        .unwrap();
    }

    // Limit 2
    let page1 = overslash_db::repos::audit::query_by_org(&pool, org_id, 2, 0)
        .await
        .unwrap();
    assert_eq!(page1.len(), 2);

    // Offset 2, limit 2
    let page2 = overslash_db::repos::audit::query_by_org(&pool, org_id, 2, 2)
        .await
        .unwrap();
    assert_eq!(page2.len(), 2);

    // No overlap
    assert_ne!(page1[0].id, page2[0].id);
    assert_ne!(page1[1].id, page2[1].id);

    // Offset past end
    let page_empty = overslash_db::repos::audit::query_by_org(&pool, org_id, 10, 100)
        .await
        .unwrap();
    assert!(page_empty.is_empty());
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_org_isolation(pool: PgPool) {
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    for (id, name, slug) in [
        (org_a, "OrgA", format!("a-{}", Uuid::new_v4())),
        (org_b, "OrgB", format!("b-{}", Uuid::new_v4())),
    ] {
        sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(name)
            .bind(slug)
            .execute(&pool)
            .await
            .unwrap();
    }

    overslash_db::repos::audit::log(&pool, org_a, None, "a.action", None, None, json!({}))
        .await
        .unwrap();
    overslash_db::repos::audit::log(&pool, org_b, None, "b.action", None, None, json!({}))
        .await
        .unwrap();

    let rows_a = overslash_db::repos::audit::query_by_org(&pool, org_a, 10, 0)
        .await
        .unwrap();
    let rows_b = overslash_db::repos::audit::query_by_org(&pool, org_b, 10, 0)
        .await
        .unwrap();

    assert_eq!(rows_a.len(), 1);
    assert_eq!(rows_a[0].action, "a.action");
    assert_eq!(rows_b.len(), 1);
    assert_eq!(rows_b[0].action, "b.action");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_empty_org(pool: PgPool) {
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("EmptyOrg")
        .bind(format!("empty-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    let rows = overslash_db::repos::audit::query_by_org(&pool, org_id, 10, 0)
        .await
        .unwrap();
    assert!(rows.is_empty());
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_identity_set_null_on_delete(pool: PgPool) {
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("NullOrg")
        .bind(format!("null-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    let identity_id = Uuid::new_v4();
    sqlx::query("INSERT INTO identities (id, org_id, name, kind) VALUES ($1, $2, $3, $4)")
        .bind(identity_id)
        .bind(org_id)
        .bind("temp-agent")
        .bind("agent")
        .execute(&pool)
        .await
        .unwrap();

    overslash_db::repos::audit::log(
        &pool,
        org_id,
        Some(identity_id),
        "test.action",
        None,
        None,
        json!({}),
    )
    .await
    .unwrap();

    // Delete the identity — FK should SET NULL
    sqlx::query("DELETE FROM identities WHERE id = $1")
        .bind(identity_id)
        .execute(&pool)
        .await
        .unwrap();

    let rows = overslash_db::repos::audit::query_by_org(&pool, org_id, 10, 0)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].identity_id.is_none(),
        "identity_id should be NULL after identity deletion"
    );
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_cascade_on_org_delete(pool: PgPool) {
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("CascadeOrg")
        .bind(format!("cascade-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    overslash_db::repos::audit::log(&pool, org_id, None, "before.delete", None, None, json!({}))
        .await
        .unwrap();

    // Delete the org — audit entries should cascade
    sqlx::query("DELETE FROM orgs WHERE id = $1")
        .bind(org_id)
        .execute(&pool)
        .await
        .unwrap();

    let rows = overslash_db::repos::audit::query_by_org(&pool, org_id, 10, 0)
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "audit rows should be deleted when org is deleted"
    );
}

// ---------------------------------------------------------------------------
// API endpoint: GET /v1/audit
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_api_empty(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;

    let entries = fetch_audit(&base, &client, &key).await;
    assert!(entries.is_empty());
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_api_requires_auth(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let resp = client
        .get(format!("http://{addr}/v1/audit"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_api_custom_limit(pool: PgPool) {
    let (base, key, _org_id, _ident_id, client) = setup_with_perm(pool, "http:**").await;
    let mock_addr = start_mock().await;

    // Execute 5 actions to generate entries
    for _ in 0..5 {
        client
            .post(format!("{base}/v1/actions/execute"))
            .header(auth(&key).0, auth(&key).1)
            .json(&json!({
                "method": "GET",
                "url": format!("http://{mock_addr}/echo")
            }))
            .send()
            .await
            .unwrap();
    }

    // With limit=3 we should get exactly 3
    let entries = fetch_audit_paged(&base, &client, &key, 3, 0).await;
    assert_eq!(entries.len(), 3);

    // With no limit (default 50), we should get all 5
    let all = fetch_audit(&base, &client, &key).await;
    assert_eq!(all.len(), 5);
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_api_pagination(pool: PgPool) {
    let (base, key, _org_id, _ident_id, client) = setup_with_perm(pool, "http:**").await;
    let mock_addr = start_mock().await;

    // Execute multiple actions to generate audit entries
    for _ in 0..3 {
        client
            .post(format!("{base}/v1/actions/execute"))
            .header(auth(&key).0, auth(&key).1)
            .json(&json!({
                "method": "GET",
                "url": format!("http://{mock_addr}/echo")
            }))
            .send()
            .await
            .unwrap();
    }

    let all = fetch_audit(&base, &client, &key).await;
    assert_eq!(all.len(), 3);

    // Page: limit=2, offset=0
    let page1 = fetch_audit_paged(&base, &client, &key, 2, 0).await;
    assert_eq!(page1.len(), 2);

    // Page: limit=2, offset=2
    let page2 = fetch_audit_paged(&base, &client, &key, 2, 2).await;
    assert_eq!(page2.len(), 1);

    // IDs should not overlap
    let p1_ids: Vec<&str> = page1.iter().map(|e| e["id"].as_str().unwrap()).collect();
    let p2_ids: Vec<&str> = page2.iter().map(|e| e["id"].as_str().unwrap()).collect();
    for id in &p2_ids {
        assert!(!p1_ids.contains(id));
    }
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_api_response_shape(pool: PgPool) {
    let (base, key, _org_id, _ident_id, client) = setup_with_perm(pool, "http:**").await;
    let mock_addr = start_mock().await;

    client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo")
        }))
        .send()
        .await
        .unwrap();

    let entries = fetch_audit(&base, &client, &key).await;
    assert_eq!(entries.len(), 1);

    let entry = &entries[0];
    // Every entry must have these fields
    assert!(entry["id"].is_string());
    assert!(entry["action"].is_string());
    assert!(entry["detail"].is_object());
    assert!(entry["created_at"].is_string());
    // identity_id is present (nullable)
    assert!(entry.get("identity_id").is_some());
    // resource_type and resource_id are present (nullable)
    assert!(entry.get("resource_type").is_some());
    assert!(entry.get("resource_id").is_some());
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_api_org_isolation(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");

    // Create two separate orgs
    let (_org_a, _ident_a, key_a) = bootstrap_org_identity(&base, &client).await;
    let (_org_b, _ident_b, key_b) = bootstrap_org_identity(&base, &client).await;

    let mock_addr = start_mock().await;

    // Grant permissions to both
    for (key, ident) in [(&key_a, _ident_a), (&key_b, _ident_b)] {
        client
            .post(format!("{base}/v1/permissions"))
            .header(auth(key).0, auth(key).1)
            .json(&json!({"identity_id": ident, "action_pattern": "http:**"}))
            .send()
            .await
            .unwrap();
    }

    // Execute action only with org A
    client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key_a).0, auth(&key_a).1)
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo")
        }))
        .send()
        .await
        .unwrap();

    let entries_a = fetch_audit(&base, &client, &key_a).await;
    let entries_b = fetch_audit(&base, &client, &key_b).await;

    assert!(!entries_a.is_empty(), "org A should have audit entries");
    assert!(entries_b.is_empty(), "org B should have no audit entries");
}

// ---------------------------------------------------------------------------
// Audit from action execution (action.executed)
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_action_executed(pool: PgPool) {
    let (base, key, _org_id, ident_id, client) = setup_with_perm(pool, "http:**").await;
    let mock_addr = start_mock().await;

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "POST",
            "url": format!("http://{mock_addr}/echo"),
            "body": "hello"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let entries = fetch_audit(&base, &client, &key).await;
    let executed: Vec<&Value> = entries
        .iter()
        .filter(|e| e["action"] == "action.executed")
        .collect();
    assert_eq!(executed.len(), 1);

    let detail = &executed[0]["detail"];
    assert_eq!(detail["method"], "POST");
    assert!(detail["url"].as_str().unwrap().contains("/echo"));
    assert!(detail["status_code"].is_number());
    assert!(detail["duration_ms"].is_number());

    // identity_id should match the agent
    assert_eq!(
        executed[0]["identity_id"].as_str().unwrap(),
        ident_id.to_string()
    );
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_action_executed_multiple(pool: PgPool) {
    let (base, key, _org_id, _ident_id, client) = setup_with_perm(pool, "http:**").await;
    let mock_addr = start_mock().await;

    // Execute 3 different actions
    for method in &["GET", "POST", "GET"] {
        client
            .post(format!("{base}/v1/actions/execute"))
            .header(auth(&key).0, auth(&key).1)
            .json(&json!({
                "method": method,
                "url": format!("http://{mock_addr}/echo")
            }))
            .send()
            .await
            .unwrap();
    }

    let entries = fetch_audit(&base, &client, &key).await;
    let executed: Vec<&Value> = entries
        .iter()
        .filter(|e| e["action"] == "action.executed")
        .collect();
    assert_eq!(executed.len(), 3);
}

// ---------------------------------------------------------------------------
// Audit from approval creation (approval.created)
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_approval_created(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, ident_id, key) = bootstrap_org_identity(&base, &client).await;
    let mock_addr = start_mock().await;

    // NO permission granted — action should require approval.
    // Store a secret so the request triggers gating
    client
        .put(format!("{base}/v1/secrets/my_token"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "secret123"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "secrets": [{"name": "my_token", "inject_as": "header", "header_name": "X-Token"}]
        }))
        .send()
        .await
        .unwrap();

    // Should get 202 Accepted (pending_approval)
    assert_eq!(resp.status(), 202);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "pending_approval");

    let entries = fetch_audit(&base, &client, &key).await;
    let approvals: Vec<&Value> = entries
        .iter()
        .filter(|e| e["action"] == "approval.created")
        .collect();
    assert_eq!(approvals.len(), 1);

    let a = approvals[0];
    assert_eq!(a["resource_type"], "approval");
    assert!(a["resource_id"].is_string()); // the approval UUID
    assert!(a["detail"]["summary"].is_string());
    assert_eq!(a["identity_id"].as_str().unwrap(), ident_id.to_string());
}

// ---------------------------------------------------------------------------
// Audit from BYOC credential operations
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_byoc_credential_created(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "provider": "google",
            "client_id": "test-client-id",
            "client_secret": "test-client-secret"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cred: Value = resp.json().await.unwrap();
    let cred_id = cred["id"].as_str().unwrap();

    let entries = fetch_audit(&base, &client, &key).await;
    let byoc: Vec<&Value> = entries
        .iter()
        .filter(|e| e["action"] == "byoc_credential.created")
        .collect();
    assert_eq!(byoc.len(), 1);
    assert_eq!(byoc[0]["resource_type"], "byoc_credential");
    assert_eq!(byoc[0]["resource_id"].as_str().unwrap(), cred_id);
    assert_eq!(byoc[0]["detail"]["provider"], "google");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_byoc_credential_deleted(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;

    // Create a BYOC credential first
    let resp = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "provider": "github",
            "client_id": "gh-client",
            "client_secret": "gh-secret"
        }))
        .send()
        .await
        .unwrap();
    let cred: Value = resp.json().await.unwrap();
    let cred_id = cred["id"].as_str().unwrap();

    // Delete it
    let del_resp = client
        .delete(format!("{base}/v1/byoc-credentials/{cred_id}"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(del_resp.status(), 200);

    let entries = fetch_audit(&base, &client, &key).await;
    let deleted: Vec<&Value> = entries
        .iter()
        .filter(|e| e["action"] == "byoc_credential.deleted")
        .collect();
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0]["resource_type"], "byoc_credential");
    assert_eq!(deleted[0]["resource_id"].as_str().unwrap(), cred_id);
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_byoc_delete_nonexistent_no_entry(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;

    // Delete a non-existent credential
    let fake_id = Uuid::new_v4();
    client
        .delete(format!("{base}/v1/byoc-credentials/{fake_id}"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();

    // No audit entry should be created (delete returned false)
    let entries = fetch_audit(&base, &client, &key).await;
    let deleted: Vec<&Value> = entries
        .iter()
        .filter(|e| e["action"] == "byoc_credential.deleted")
        .collect();
    assert!(deleted.is_empty(), "no audit entry for non-existent delete");
}

// ---------------------------------------------------------------------------
// Combined flow: multiple audit event types in one org
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_mixed_events(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, ident_id, key) = bootstrap_org_identity(&base, &client).await;
    let mock_addr = start_mock().await;

    // 1. Create BYOC credential → byoc_credential.created
    client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "provider": "spotify",
            "client_id": "sp-id",
            "client_secret": "sp-secret"
        }))
        .send()
        .await
        .unwrap();

    // 2. Grant permission + execute action → action.executed
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo")
        }))
        .send()
        .await
        .unwrap();

    let entries = fetch_audit(&base, &client, &key).await;
    let actions: Vec<String> = entries
        .iter()
        .map(|e| e["action"].as_str().unwrap().to_string())
        .collect();

    assert!(actions.contains(&"byoc_credential.created".to_string()));
    assert!(actions.contains(&"action.executed".to_string()));

    // Verify ordering: most recent first (action.executed after byoc_credential.created)
    let exec_pos = actions.iter().position(|a| a == "action.executed").unwrap();
    let byoc_pos = actions
        .iter()
        .position(|a| a == "byoc_credential.created")
        .unwrap();
    assert!(
        exec_pos < byoc_pos,
        "action.executed should appear before byoc_credential.created (DESC order)"
    );
}

// ---------------------------------------------------------------------------
// Detail field correctness
// ---------------------------------------------------------------------------

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_detail_json_structure(pool: PgPool) {
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("DetailOrg")
        .bind(format!("detail-{}", Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap();

    let complex_detail = json!({
        "nested": {"key": "value"},
        "array": [1, 2, 3],
        "number": 42,
        "boolean": true,
        "null_val": null
    });

    overslash_db::repos::audit::log(
        &pool,
        org_id,
        None,
        "complex.detail",
        None,
        None,
        complex_detail.clone(),
    )
    .await
    .unwrap();

    let rows = overslash_db::repos::audit::query_by_org(&pool, org_id, 10, 0)
        .await
        .unwrap();
    assert_eq!(rows[0].detail, complex_detail);
}
