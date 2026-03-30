//! Audit log integration tests: covers the DB repo layer, the query API endpoint,
//! filtering capabilities, and every code path that emits an audit entry.

mod common;

use common::{auth, bootstrap_org_identity, start_api, start_mock};
use overslash_db::repos::audit::{AuditEntry, AuditFilter};
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

/// Fetch audit entries with explicit query params.
async fn fetch_audit_with(base: &str, client: &Client, key: &str, qs: &str) -> Vec<Value> {
    client
        .get(format!("{base}/v1/audit?{qs}"))
        .header(auth(key).0, auth(key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Insert an org directly in the DB. Returns org_id.
async fn insert_org(pool: &PgPool) -> Uuid {
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind("TestOrg")
        .bind(format!("test-{}", Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap();
    org_id
}

/// Insert an identity directly in the DB. Returns identity_id.
async fn insert_identity(pool: &PgPool, org_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO identities (id, org_id, name, kind) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(org_id)
        .bind("agent")
        .bind("agent")
        .execute(pool)
        .await
        .unwrap();
    id
}

/// Helper to build an AuditEntry for insertion.
fn entry<'a>(
    org_id: Uuid,
    identity_id: Option<Uuid>,
    action: &'a str,
    resource_type: Option<&'a str>,
    resource_id: Option<Uuid>,
    detail: serde_json::Value,
) -> AuditEntry<'a> {
    AuditEntry {
        org_id,
        identity_id,
        action,
        resource_type,
        resource_id,
        detail,
        ip_address: None,
    }
}

/// Helper to build an AuditFilter with defaults.
fn filter(org_id: Uuid) -> AuditFilter {
    AuditFilter {
        org_id,
        action: None,
        resource_type: None,
        identity_id: None,
        since: None,
        until: None,
        limit: 100,
        offset: 0,
    }
}

/// Full bootstrap: org + identity + identity-bound key + permissions + API base URL.
async fn setup_with_perm(pool: PgPool, pattern: &str) -> (String, String, Uuid, Uuid, Client) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, key) = bootstrap_org_identity(&base, &client).await;

    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": pattern}))
        .send()
        .await
        .unwrap();

    (base, key, org_id, ident_id, client)
}

// ===========================================================================
// DB repo layer: audit::log + query_filtered
// ===========================================================================

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_insert_and_query(pool: PgPool) {
    let org_id = insert_org(&pool).await;

    overslash_db::repos::audit::log(
        &pool,
        &entry(
            org_id,
            None,
            "test.action",
            Some("widget"),
            None,
            json!({"key": "value"}),
        ),
    )
    .await
    .unwrap();

    let rows = overslash_db::repos::audit::query_filtered(&pool, &filter(org_id))
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
    let org_id = insert_org(&pool).await;
    let identity_id = insert_identity(&pool, org_id).await;
    let resource_id = Uuid::new_v4();

    overslash_db::repos::audit::log(
        &pool,
        &entry(
            org_id,
            Some(identity_id),
            "secret.created",
            Some("secret"),
            Some(resource_id),
            json!({"name": "my_token"}),
        ),
    )
    .await
    .unwrap();

    let rows = overslash_db::repos::audit::query_filtered(&pool, &filter(org_id))
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].identity_id, Some(identity_id));
    assert_eq!(rows[0].resource_id, Some(resource_id));
    assert_eq!(rows[0].resource_type.as_deref(), Some("secret"));
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_with_ip_address(pool: PgPool) {
    let org_id = insert_org(&pool).await;

    overslash_db::repos::audit::log(
        &pool,
        &AuditEntry {
            org_id,
            identity_id: None,
            action: "test.with_ip",
            resource_type: None,
            resource_id: None,
            detail: json!({}),
            ip_address: Some("192.168.1.42"),
        },
    )
    .await
    .unwrap();

    let rows = overslash_db::repos::audit::query_filtered(&pool, &filter(org_id))
        .await
        .unwrap();
    assert_eq!(rows[0].ip_address.as_deref(), Some("192.168.1.42"));
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_ordering_desc(pool: PgPool) {
    let org_id = insert_org(&pool).await;

    for action in &["first", "second", "third"] {
        overslash_db::repos::audit::log(&pool, &entry(org_id, None, action, None, None, json!({})))
            .await
            .unwrap();
    }

    let rows = overslash_db::repos::audit::query_filtered(&pool, &filter(org_id))
        .await
        .unwrap();

    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].action, "third");
    assert_eq!(rows[1].action, "second");
    assert_eq!(rows[2].action, "first");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_pagination(pool: PgPool) {
    let org_id = insert_org(&pool).await;

    for i in 0..5 {
        overslash_db::repos::audit::log(
            &pool,
            &entry(org_id, None, &format!("action_{i}"), None, None, json!({})),
        )
        .await
        .unwrap();
    }

    let mut f = filter(org_id);

    f.limit = 2;
    f.offset = 0;
    let page1 = overslash_db::repos::audit::query_filtered(&pool, &f)
        .await
        .unwrap();
    assert_eq!(page1.len(), 2);

    f.offset = 2;
    let page2 = overslash_db::repos::audit::query_filtered(&pool, &f)
        .await
        .unwrap();
    assert_eq!(page2.len(), 2);

    assert_ne!(page1[0].id, page2[0].id);
    assert_ne!(page1[1].id, page2[1].id);

    f.offset = 100;
    f.limit = 10;
    let empty = overslash_db::repos::audit::query_filtered(&pool, &f)
        .await
        .unwrap();
    assert!(empty.is_empty());
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_org_isolation(pool: PgPool) {
    let org_a = insert_org(&pool).await;
    let org_b = insert_org(&pool).await;

    overslash_db::repos::audit::log(
        &pool,
        &entry(org_a, None, "a.action", None, None, json!({})),
    )
    .await
    .unwrap();
    overslash_db::repos::audit::log(
        &pool,
        &entry(org_b, None, "b.action", None, None, json!({})),
    )
    .await
    .unwrap();

    let rows_a = overslash_db::repos::audit::query_filtered(&pool, &filter(org_a))
        .await
        .unwrap();
    let rows_b = overslash_db::repos::audit::query_filtered(&pool, &filter(org_b))
        .await
        .unwrap();

    assert_eq!(rows_a.len(), 1);
    assert_eq!(rows_a[0].action, "a.action");
    assert_eq!(rows_b.len(), 1);
    assert_eq!(rows_b[0].action, "b.action");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_empty_org(pool: PgPool) {
    let org_id = insert_org(&pool).await;
    let rows = overslash_db::repos::audit::query_filtered(&pool, &filter(org_id))
        .await
        .unwrap();
    assert!(rows.is_empty());
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_log_identity_set_null_on_delete(pool: PgPool) {
    let org_id = insert_org(&pool).await;
    let identity_id = insert_identity(&pool, org_id).await;

    overslash_db::repos::audit::log(
        &pool,
        &entry(
            org_id,
            Some(identity_id),
            "test.action",
            None,
            None,
            json!({}),
        ),
    )
    .await
    .unwrap();

    sqlx::query("DELETE FROM identities WHERE id = $1")
        .bind(identity_id)
        .execute(&pool)
        .await
        .unwrap();

    let rows = overslash_db::repos::audit::query_filtered(&pool, &filter(org_id))
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
    let org_id = insert_org(&pool).await;

    overslash_db::repos::audit::log(
        &pool,
        &entry(org_id, None, "before.delete", None, None, json!({})),
    )
    .await
    .unwrap();

    sqlx::query("DELETE FROM orgs WHERE id = $1")
        .bind(org_id)
        .execute(&pool)
        .await
        .unwrap();

    let rows = overslash_db::repos::audit::query_filtered(&pool, &filter(org_id))
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "audit rows should be deleted when org is deleted"
    );
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_detail_json_structure(pool: PgPool) {
    let org_id = insert_org(&pool).await;

    let complex_detail = json!({
        "nested": {"key": "value"},
        "array": [1, 2, 3],
        "number": 42,
        "boolean": true,
        "null_val": null
    });

    overslash_db::repos::audit::log(
        &pool,
        &entry(
            org_id,
            None,
            "complex.detail",
            None,
            None,
            complex_detail.clone(),
        ),
    )
    .await
    .unwrap();

    let rows = overslash_db::repos::audit::query_filtered(&pool, &filter(org_id))
        .await
        .unwrap();
    assert_eq!(rows[0].detail, complex_detail);
}

// ===========================================================================
// DB repo layer: query_filtered filters
// ===========================================================================

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_query_filtered_by_action(pool: PgPool) {
    let org_id = insert_org(&pool).await;

    overslash_db::repos::audit::log(
        &pool,
        &entry(org_id, None, "action.executed", None, None, json!({})),
    )
    .await
    .unwrap();
    overslash_db::repos::audit::log(
        &pool,
        &entry(org_id, None, "secret.put", None, None, json!({})),
    )
    .await
    .unwrap();

    let mut f = filter(org_id);
    f.action = Some("secret.put".to_string());
    let rows = overslash_db::repos::audit::query_filtered(&pool, &f)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "secret.put");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_query_filtered_by_resource_type(pool: PgPool) {
    let org_id = insert_org(&pool).await;

    overslash_db::repos::audit::log(
        &pool,
        &entry(org_id, None, "a.created", Some("secret"), None, json!({})),
    )
    .await
    .unwrap();
    overslash_db::repos::audit::log(
        &pool,
        &entry(org_id, None, "b.created", Some("webhook"), None, json!({})),
    )
    .await
    .unwrap();

    let mut f = filter(org_id);
    f.resource_type = Some("webhook".to_string());
    let rows = overslash_db::repos::audit::query_filtered(&pool, &f)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "b.created");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_query_filtered_by_identity_id(pool: PgPool) {
    let org_id = insert_org(&pool).await;
    let id_a = insert_identity(&pool, org_id).await;
    let id_b = insert_identity(&pool, org_id).await;

    overslash_db::repos::audit::log(
        &pool,
        &entry(org_id, Some(id_a), "from_a", None, None, json!({})),
    )
    .await
    .unwrap();
    overslash_db::repos::audit::log(
        &pool,
        &entry(org_id, Some(id_b), "from_b", None, None, json!({})),
    )
    .await
    .unwrap();

    let mut f = filter(org_id);
    f.identity_id = Some(id_a);
    let rows = overslash_db::repos::audit::query_filtered(&pool, &f)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "from_a");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_query_filtered_by_time_range(pool: PgPool) {
    let org_id = insert_org(&pool).await;

    // Insert with explicit timestamps via raw SQL to avoid timing issues
    let early_ts = time::OffsetDateTime::now_utc() - time::Duration::minutes(10);
    let late_ts = time::OffsetDateTime::now_utc();
    let boundary = early_ts + time::Duration::minutes(5);

    sqlx::query(
        "INSERT INTO audit_log (org_id, action, detail, created_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(org_id)
    .bind("early")
    .bind(json!({}))
    .bind(early_ts)
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO audit_log (org_id, action, detail, created_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(org_id)
    .bind("late")
    .bind(json!({}))
    .bind(late_ts)
    .execute(&pool)
    .await
    .unwrap();

    // since filter: only "late"
    let mut f = filter(org_id);
    f.since = Some(boundary);
    let rows = overslash_db::repos::audit::query_filtered(&pool, &f)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "late");

    // until filter: only "early"
    let mut f2 = filter(org_id);
    f2.until = Some(boundary);
    let rows2 = overslash_db::repos::audit::query_filtered(&pool, &f2)
        .await
        .unwrap();
    assert_eq!(rows2.len(), 1);
    assert_eq!(rows2[0].action, "early");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_query_filtered_combined_filters(pool: PgPool) {
    let org_id = insert_org(&pool).await;
    let id_a = insert_identity(&pool, org_id).await;

    overslash_db::repos::audit::log(
        &pool,
        &entry(
            org_id,
            Some(id_a),
            "secret.put",
            Some("secret"),
            None,
            json!({}),
        ),
    )
    .await
    .unwrap();
    overslash_db::repos::audit::log(
        &pool,
        &entry(
            org_id,
            Some(id_a),
            "webhook.created",
            Some("webhook"),
            None,
            json!({}),
        ),
    )
    .await
    .unwrap();
    overslash_db::repos::audit::log(
        &pool,
        &entry(org_id, None, "secret.put", Some("secret"), None, json!({})),
    )
    .await
    .unwrap();

    let mut f = filter(org_id);
    f.action = Some("secret.put".to_string());
    f.identity_id = Some(id_a);
    let rows = overslash_db::repos::audit::query_filtered(&pool, &f)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].identity_id, Some(id_a));
    assert_eq!(rows[0].action, "secret.put");
}

// ===========================================================================
// API endpoint: GET /v1/audit
// ===========================================================================

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
async fn test_audit_api_response_shape(pool: PgPool) {
    let (base, key, _org_id, _ident_id, client) = setup_with_perm(pool, "http:**").await;
    let mock_addr = start_mock().await;

    client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"method": "GET", "url": format!("http://{mock_addr}/echo")}))
        .send()
        .await
        .unwrap();

    let entries = fetch_audit(&base, &client, &key).await;
    let entry = entries
        .iter()
        .find(|e| e["action"] == "action.executed")
        .expect("should have action.executed entry");

    assert!(entry["id"].is_string());
    assert!(entry["action"].is_string());
    assert!(entry["detail"].is_object());
    assert!(entry["created_at"].is_string());
    assert!(entry.get("identity_id").is_some());
    assert!(entry.get("resource_type").is_some());
    assert!(entry.get("resource_id").is_some());
    assert!(entry.get("ip_address").is_some());
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_api_pagination(pool: PgPool) {
    let (base, key, _org_id, _ident_id, client) = setup_with_perm(pool, "http:**").await;
    let mock_addr = start_mock().await;

    for _ in 0..3 {
        client
            .post(format!("{base}/v1/actions/execute"))
            .header(auth(&key).0, auth(&key).1)
            .json(&json!({"method": "GET", "url": format!("http://{mock_addr}/echo")}))
            .send()
            .await
            .unwrap();
    }

    let all = fetch_audit_with(&base, &client, &key, "action=action.executed").await;
    assert_eq!(all.len(), 3);

    let page1 = fetch_audit_with(
        &base,
        &client,
        &key,
        "action=action.executed&limit=2&offset=0",
    )
    .await;
    assert_eq!(page1.len(), 2);

    let page2 = fetch_audit_with(
        &base,
        &client,
        &key,
        "action=action.executed&limit=2&offset=2",
    )
    .await;
    assert_eq!(page2.len(), 1);

    let p1_ids: Vec<&str> = page1.iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert!(!p1_ids.contains(&page2[0]["id"].as_str().unwrap()));
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_api_filter_by_action(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;

    // Store a secret → secret.put audit entry
    client
        .put(format!("{base}/v1/secrets/test_secret"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "val"}))
        .send()
        .await
        .unwrap();

    let all = fetch_audit(&base, &client, &key).await;
    assert!(all.len() > 1, "should have multiple types of audit entries");

    let filtered = fetch_audit_with(&base, &client, &key, "action=secret.put").await;
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["action"], "secret.put");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_api_filter_by_resource_type(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;

    // Store a secret → resource_type=secret
    client
        .put(format!("{base}/v1/secrets/filter_test"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "val"}))
        .send()
        .await
        .unwrap();

    let filtered = fetch_audit_with(&base, &client, &key, "resource_type=secret").await;
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["resource_type"], "secret");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_api_org_isolation(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");

    let (_org_a, ident_a, key_a) = bootstrap_org_identity(&base, &client).await;
    let (_org_b, _ident_b, key_b) = bootstrap_org_identity(&base, &client).await;

    let mock_addr = start_mock().await;

    // Grant permission + execute action only on org A
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key_a).0, auth(&key_a).1)
        .json(&json!({"identity_id": ident_a, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key_a).0, auth(&key_a).1)
        .json(&json!({"method": "GET", "url": format!("http://{mock_addr}/echo")}))
        .send()
        .await
        .unwrap();

    let entries_a = fetch_audit_with(&base, &client, &key_a, "action=action.executed").await;
    let entries_b = fetch_audit_with(&base, &client, &key_b, "action=action.executed").await;

    assert_eq!(entries_a.len(), 1);
    assert!(entries_b.is_empty());
}

// ===========================================================================
// Audit events: action.executed
// ===========================================================================

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

    let entries = fetch_audit_with(&base, &client, &key, "action=action.executed").await;
    assert_eq!(entries.len(), 1);

    let detail = &entries[0]["detail"];
    assert_eq!(detail["method"], "POST");
    assert!(detail["url"].as_str().unwrap().contains("/echo"));
    assert!(detail["status_code"].is_number());
    assert!(detail["duration_ms"].is_number());
    assert_eq!(
        entries[0]["identity_id"].as_str().unwrap(),
        ident_id.to_string()
    );
}

// ===========================================================================
// Audit events: approval.created
// ===========================================================================

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_approval_created(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, ident_id, key) = bootstrap_org_identity(&base, &client).await;
    let mock_addr = start_mock().await;

    // Store secret, no permission → triggers approval
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
    assert_eq!(resp.status(), 202);

    let entries = fetch_audit_with(&base, &client, &key, "action=approval.created").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_type"], "approval");
    assert!(entries[0]["resource_id"].is_string());
    assert!(entries[0]["detail"]["summary"].is_string());
    assert_eq!(
        entries[0]["identity_id"].as_str().unwrap(),
        ident_id.to_string()
    );
}

// ===========================================================================
// Audit events: approval.resolved
// ===========================================================================

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_approval_resolved(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;
    let mock_addr = start_mock().await;

    // Create an approval
    client
        .put(format!("{base}/v1/secrets/tok"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "s"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "secrets": [{"name": "tok", "inject_as": "header", "header_name": "X-T"}]
        }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let approval_id = body["approval_id"].as_str().unwrap();

    // Resolve the approval
    client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"decision": "allow"}))
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=approval.resolved").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_type"], "approval");
    assert_eq!(entries[0]["detail"]["decision"], "allow");
    assert!(entries[0]["detail"]["action_summary"].is_string());
}

// ===========================================================================
// Audit events: secret.put + secret.deleted
// ===========================================================================

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_secret_put(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;

    client
        .put(format!("{base}/v1/secrets/my_key"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "secret_value"}))
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=secret.put").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_type"], "secret");
    assert_eq!(entries[0]["detail"]["name"], "my_key");
    assert!(entries[0]["detail"]["version"].is_number());
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_secret_deleted(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;

    client
        .put(format!("{base}/v1/secrets/to_delete"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "val"}))
        .send()
        .await
        .unwrap();

    client
        .delete(format!("{base}/v1/secrets/to_delete"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=secret.deleted").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_type"], "secret");
    assert_eq!(entries[0]["detail"]["name"], "to_delete");
}

// ===========================================================================
// Audit events: permission_rule.created + permission_rule.deleted
// ===========================================================================

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_permission_rule_created(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, ident_id, key) = bootstrap_org_identity(&base, &client).await;

    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=permission_rule.created").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_type"], "permission_rule");
    assert_eq!(entries[0]["detail"]["action_pattern"], "http:**");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_permission_rule_deleted(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, ident_id, key) = bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();
    let perm: Value = resp.json().await.unwrap();
    let perm_id = perm["id"].as_str().unwrap();

    client
        .delete(format!("{base}/v1/permissions/{perm_id}"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=permission_rule.deleted").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_type"], "permission_rule");
    assert_eq!(entries[0]["resource_id"].as_str().unwrap(), perm_id);
}

// ===========================================================================
// Audit events: webhook.created + webhook.deleted
// ===========================================================================

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_webhook_created(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;

    client
        .post(format!("{base}/v1/webhooks"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"url": "https://example.com/hook", "events": ["approval.resolved"]}))
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=webhook.created").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_type"], "webhook");
    assert_eq!(entries[0]["detail"]["url"], "https://example.com/hook");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_webhook_deleted(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/webhooks"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"url": "https://example.com/hook", "events": ["approval.resolved"]}))
        .send()
        .await
        .unwrap();
    let wh: Value = resp.json().await.unwrap();
    let wh_id = wh["id"].as_str().unwrap();

    client
        .delete(format!("{base}/v1/webhooks/{wh_id}"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=webhook.deleted").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_type"], "webhook");
    assert_eq!(entries[0]["resource_id"].as_str().unwrap(), wh_id);
}

// ===========================================================================
// Audit events: byoc_credential.created + byoc_credential.deleted
// ===========================================================================

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_byoc_credential_created(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"provider": "google", "client_id": "cid", "client_secret": "cs"}))
        .send()
        .await
        .unwrap();
    let cred: Value = resp.json().await.unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=byoc_credential.created").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_type"], "byoc_credential");
    assert_eq!(
        entries[0]["resource_id"].as_str().unwrap(),
        cred["id"].as_str().unwrap()
    );
    assert_eq!(entries[0]["detail"]["provider"], "google");
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_byoc_credential_deleted(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"provider": "github", "client_id": "c", "client_secret": "s"}))
        .send()
        .await
        .unwrap();
    let cred: Value = resp.json().await.unwrap();
    let cred_id = cred["id"].as_str().unwrap();

    client
        .delete(format!("{base}/v1/byoc-credentials/{cred_id}"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=byoc_credential.deleted").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_id"].as_str().unwrap(), cred_id);
}

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_byoc_delete_nonexistent_no_entry(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;

    let fake_id = Uuid::new_v4();
    client
        .delete(format!("{base}/v1/byoc-credentials/{fake_id}"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=byoc_credential.deleted").await;
    assert!(entries.is_empty());
}

// ===========================================================================
// Audit events: no-op deletes should not produce entries
// ===========================================================================

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_noop_deletes_no_entries(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, key) = bootstrap_org_identity(&base, &client).await;

    // Delete non-existent webhook
    let fake = Uuid::new_v4();
    client
        .delete(format!("{base}/v1/webhooks/{fake}"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();

    // Delete non-existent permission
    client
        .delete(format!("{base}/v1/permissions/{fake}"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();

    // Delete non-existent secret
    client
        .delete(format!("{base}/v1/secrets/nope"))
        .header(auth(&key).0, auth(&key).1)
        .send()
        .await
        .unwrap();

    let all = fetch_audit(&base, &client, &key).await;
    let delete_entries: Vec<&Value> = all
        .iter()
        .filter(|e| {
            e["action"]
                .as_str()
                .map_or(false, |a| a.ends_with(".deleted"))
        })
        .collect();
    assert!(
        delete_entries.is_empty(),
        "no-op deletes should not create audit entries"
    );
}

// ===========================================================================
// Combined flow: mixed events + ordering
// ===========================================================================

#[sqlx::test(migrator = "overslash_db::MIGRATOR")]
async fn test_audit_mixed_events(pool: PgPool) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, ident_id, key) = bootstrap_org_identity(&base, &client).await;
    let mock_addr = start_mock().await;

    // BYOC credential
    client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"provider": "spotify", "client_id": "c", "client_secret": "s"}))
        .send()
        .await
        .unwrap();

    // Secret
    client
        .put(format!("{base}/v1/secrets/mix"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "v"}))
        .send()
        .await
        .unwrap();

    // Permission + execute
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
        .json(&json!({"method": "GET", "url": format!("http://{mock_addr}/echo")}))
        .send()
        .await
        .unwrap();

    let entries = fetch_audit(&base, &client, &key).await;
    let actions: Vec<String> = entries
        .iter()
        .map(|e| e["action"].as_str().unwrap().to_string())
        .collect();

    assert!(actions.contains(&"byoc_credential.created".to_string()));
    assert!(actions.contains(&"secret.put".to_string()));
    assert!(actions.contains(&"permission_rule.created".to_string()));
    assert!(actions.contains(&"action.executed".to_string()));

    // Most recent first
    let exec_pos = actions.iter().position(|a| a == "action.executed").unwrap();
    let byoc_pos = actions
        .iter()
        .position(|a| a == "byoc_credential.created")
        .unwrap();
    assert!(exec_pos < byoc_pos, "DESC ordering: newest first");
}
