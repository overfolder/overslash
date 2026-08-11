//! Audit log integration tests: covers the DB repo layer, the query API endpoint,
//! filtering capabilities, and every code path that emits an audit entry.
// Test setup requires dynamic SQL for provider endpoint overrides and DB seeding.
#![allow(clippy::disallowed_methods)]

use crate::common;

use crate::common::{
    auth, bootstrap_agent_on_fixtures, bootstrap_org_identity, start_api, start_mock,
};
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

/// Insert an identity with an explicit name/kind/owner. Returns identity_id.
async fn insert_named_identity(
    pool: &PgPool,
    org_id: Uuid,
    name: &str,
    kind: &str,
    owner_id: Option<Uuid>,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO identities (id, org_id, name, kind, owner_id) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(org_id)
    .bind(name)
    .bind(kind)
    .bind(owner_id)
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
        description: None,
        ip_address: None,
    }
}

/// Helper to build an AuditFilter with defaults.
fn filter(org_id: Uuid) -> AuditFilter {
    AuditFilter {
        org_id,
        limit: 100,
        ..Default::default()
    }
}

/// Full bootstrap: org + identity + identity-bound key + permissions + API base URL.
async fn setup_with_perm(
    pool: PgPool,
    fx: &common::BootstrapFixtures,
    pattern: &str,
) -> (String, String, Uuid, Uuid, Client) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, fx).await;
    let admin_key = fx.org_key.clone();
    let org_id = fx.org_id;

    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": pattern}))
        .send()
        .await
        .unwrap();

    (base, key, org_id, ident_id, client)
}

// ===========================================================================
// DB repo layer: audit::log + query_filtered
// ===========================================================================

#[tokio::test]
async fn test_audit_log_insert_and_query() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            None,
            "test.action",
            Some("widget"),
            None,
            json!({"key": "value"}),
        ))
        .await
        .unwrap();

    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(filter(org_id))
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

#[tokio::test]
async fn test_audit_log_with_identity_and_resource() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let identity_id = insert_identity(&pool, org_id).await;
    let resource_id = Uuid::new_v4();

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            Some(identity_id),
            "secret.created",
            Some("secret"),
            Some(resource_id),
            json!({"name": "my_token"}),
        ))
        .await
        .unwrap();

    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(filter(org_id))
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].identity_id, Some(identity_id));
    assert_eq!(rows[0].resource_id, Some(resource_id));
    assert_eq!(rows[0].resource_type.as_deref(), Some("secret"));
}

#[tokio::test]
async fn test_audit_log_with_ip_address() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(AuditEntry {
            org_id,
            identity_id: None,
            action: "test.with_ip",
            resource_type: None,
            resource_id: None,
            detail: json!({}),
            description: None,
            ip_address: Some("192.168.1.42"),
        })
        .await
        .unwrap();

    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(filter(org_id))
        .await
        .unwrap();
    assert_eq!(rows[0].ip_address.as_deref(), Some("192.168.1.42"));
}

#[tokio::test]
async fn test_audit_log_ordering_desc() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    for action in &["first", "second", "third"] {
        overslash_db::OrgScope::new(org_id, pool.clone())
            .log_audit(entry(org_id, None, action, None, None, json!({})))
            .await
            .unwrap();
    }

    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(filter(org_id))
        .await
        .unwrap();

    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].action, "third");
    assert_eq!(rows[1].action, "second");
    assert_eq!(rows[2].action, "first");
}

#[tokio::test]
async fn test_audit_log_pagination() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    for i in 0..5 {
        overslash_db::OrgScope::new(org_id, pool.clone())
            .log_audit(entry(
                org_id,
                None,
                &format!("action_{i}"),
                None,
                None,
                json!({}),
            ))
            .await
            .unwrap();
    }

    let mut f = filter(org_id);

    f.limit = 2;
    f.offset = 0;
    let page1 = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f.clone())
        .await
        .unwrap();
    assert_eq!(page1.len(), 2);

    f.offset = 2;
    let page2 = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f.clone())
        .await
        .unwrap();
    assert_eq!(page2.len(), 2);

    assert_ne!(page1[0].id, page2[0].id);
    assert_ne!(page1[1].id, page2[1].id);

    f.offset = 100;
    f.limit = 10;
    let empty = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f)
        .await
        .unwrap();
    assert!(empty.is_empty());
}

#[tokio::test]
async fn test_audit_log_org_isolation() {
    let pool = common::test_pool().await;
    let org_a = insert_org(&pool).await;
    let org_b = insert_org(&pool).await;

    overslash_db::OrgScope::new(org_a, pool.clone())
        .log_audit(entry(org_a, None, "a.action", None, None, json!({})))
        .await
        .unwrap();
    overslash_db::OrgScope::new(org_b, pool.clone())
        .log_audit(entry(org_b, None, "b.action", None, None, json!({})))
        .await
        .unwrap();

    let rows_a = overslash_db::OrgScope::new(org_a, pool.clone())
        .query_audit_log(filter(org_a))
        .await
        .unwrap();
    let rows_b = overslash_db::OrgScope::new(org_b, pool.clone())
        .query_audit_log(filter(org_b))
        .await
        .unwrap();

    assert_eq!(rows_a.len(), 1);
    assert_eq!(rows_a[0].action, "a.action");
    assert_eq!(rows_b.len(), 1);
    assert_eq!(rows_b[0].action, "b.action");
}

#[tokio::test]
async fn test_audit_log_empty_org() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(filter(org_id))
        .await
        .unwrap();
    assert!(rows.is_empty());
}

#[tokio::test]
async fn test_audit_log_identity_set_null_on_delete() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let identity_id = insert_identity(&pool, org_id).await;

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            Some(identity_id),
            "test.action",
            None,
            None,
            json!({}),
        ))
        .await
        .unwrap();

    sqlx::query("DELETE FROM identities WHERE id = $1")
        .bind(identity_id)
        .execute(&pool)
        .await
        .unwrap();

    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(filter(org_id))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].identity_id.is_none(),
        "identity_id should be NULL after identity deletion"
    );
    // The name is the whole reason it is on the row: a deleted identity used to
    // take its own audit trail's legibility with it.
    assert_eq!(rows[0].actor_name.as_deref(), Some("agent"));

    let mut f = filter(org_id);
    f.q_terms = Some(vec!["agent".to_string()]);
    let found = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f)
        .await
        .unwrap();
    assert_eq!(
        found.len(),
        1,
        "free-text search should still find rows whose actor has been deleted"
    );
}

#[tokio::test]
async fn test_audit_log_cascade_on_org_delete() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(org_id, None, "before.delete", None, None, json!({})))
        .await
        .unwrap();

    sqlx::query("DELETE FROM orgs WHERE id = $1")
        .bind(org_id)
        .execute(&pool)
        .await
        .unwrap();

    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(filter(org_id))
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "audit rows should be deleted when org is deleted"
    );
}

#[tokio::test]
async fn test_audit_detail_json_structure() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    let complex_detail = json!({
        "nested": {"key": "value"},
        "array": [1, 2, 3],
        "number": 42,
        "boolean": true,
        "null_val": null
    });

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            None,
            "complex.detail",
            None,
            None,
            complex_detail.clone(),
        ))
        .await
        .unwrap();

    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(filter(org_id))
        .await
        .unwrap();
    assert_eq!(rows[0].detail, complex_detail);
}

// ===========================================================================
// DB repo layer: query_filtered filters
// ===========================================================================

#[tokio::test]
async fn test_query_filtered_by_action() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            None,
            "action.executed",
            None,
            None,
            json!({}),
        ))
        .await
        .unwrap();
    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(org_id, None, "secret.put", None, None, json!({})))
        .await
        .unwrap();

    let mut f = filter(org_id);
    f.action = Some("secret.put".to_string());
    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "secret.put");
}

#[tokio::test]
async fn test_query_filtered_by_resource_type() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            None,
            "a.created",
            Some("secret"),
            None,
            json!({}),
        ))
        .await
        .unwrap();
    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            None,
            "b.created",
            Some("webhook"),
            None,
            json!({}),
        ))
        .await
        .unwrap();

    let mut f = filter(org_id);
    f.resource_type = Some("webhook".to_string());
    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "b.created");
}

#[tokio::test]
async fn test_query_filtered_by_identity_id() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let id_a = insert_identity(&pool, org_id).await;
    let id_b = insert_identity(&pool, org_id).await;

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(org_id, Some(id_a), "from_a", None, None, json!({})))
        .await
        .unwrap();
    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(org_id, Some(id_b), "from_b", None, None, json!({})))
        .await
        .unwrap();

    let mut f = filter(org_id);
    f.identity_id = Some(id_a);
    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "from_a");
}

#[tokio::test]
async fn test_query_filtered_by_time_range() {
    let pool = common::test_pool().await;
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
    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "late");

    // until filter: only "early"
    let mut f2 = filter(org_id);
    f2.until = Some(boundary);
    let rows2 = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f2)
        .await
        .unwrap();
    assert_eq!(rows2.len(), 1);
    assert_eq!(rows2[0].action, "early");
}

#[tokio::test]
async fn test_query_filtered_combined_filters() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let id_a = insert_identity(&pool, org_id).await;

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            Some(id_a),
            "secret.put",
            Some("secret"),
            None,
            json!({}),
        ))
        .await
        .unwrap();
    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            Some(id_a),
            "webhook.created",
            Some("webhook"),
            None,
            json!({}),
        ))
        .await
        .unwrap();
    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            None,
            "secret.put",
            Some("secret"),
            None,
            json!({}),
        ))
        .await
        .unwrap();

    let mut f = filter(org_id);
    f.action = Some("secret.put".to_string());
    f.identity_id = Some(id_a);
    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f)
        .await
        .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].identity_id, Some(id_a));
    assert_eq!(rows[0].action, "secret.put");
}

// ===========================================================================
// API endpoint: GET /v1/audit
// ===========================================================================

#[tokio::test]
async fn test_audit_api_requires_auth() {
    let pool = common::test_pool().await;
    let (addr, client) = start_api(pool).await;
    let resp = client
        .get(format!("http://{addr}/v1/audit"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn test_audit_api_response_shape() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org_id, _ident_id, client) = setup_with_perm(pool, &fx, "http:**").await;
    let mock_addr = start_mock().await;

    client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&key).0, auth(&key).1)
        .json(
            &json!({"service": "http", "method": "GET", "url": format!("http://{mock_addr}/echo")}),
        )
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
    assert!(entry.get("identity_name").is_some());
    assert!(entry.get("description").is_some());
    assert!(entry.get("resource_type").is_some());
    assert!(entry.get("resource_id").is_some());
    assert!(entry.get("ip_address").is_some());

    // Regression: `created_at` must be RFC 3339 so `new Date(...)` can parse
    // it in the dashboard. The `time` crate's Display impl is NOT RFC 3339.
    let created_at = entry["created_at"].as_str().expect("created_at is string");
    time::OffsetDateTime::parse(created_at, &time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|e| panic!("created_at {created_at:?} not RFC 3339: {e}"));
}

#[tokio::test]
async fn test_audit_api_pagination() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org_id, _ident_id, client) = setup_with_perm(pool, &fx, "http:**").await;
    let mock_addr = start_mock().await;

    for _ in 0..3 {
        client
            .post(format!("{base}/v1/actions/call"))
            .header(auth(&key).0, auth(&key).1)
            .json(&json!({"service": "http", "method": "GET", "url": format!("http://{mock_addr}/echo")}))
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

#[tokio::test]
async fn test_audit_api_filter_by_action() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, _ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;

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

#[tokio::test]
async fn test_audit_api_filter_by_resource_type() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, _ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;

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

#[tokio::test]
async fn test_audit_api_org_isolation() {
    let pool = common::test_pool().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");

    let (_org_a, ident_a, key_a, admin_key_a) = bootstrap_org_identity(&base, &client).await;
    let (_org_b, _ident_b, key_b, _) = bootstrap_org_identity(&base, &client).await;

    let mock_addr = start_mock().await;

    // Grant permission + call action only on org A
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&admin_key_a).0, auth(&admin_key_a).1)
        .json(&json!({"identity_id": ident_a, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&key_a).0, auth(&key_a).1)
        .json(
            &json!({"service": "http", "method": "GET", "url": format!("http://{mock_addr}/echo")}),
        )
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

#[tokio::test]
async fn test_audit_action_called() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org_id, ident_id, client) = setup_with_perm(pool, &fx, "http:**").await;
    let mock_addr = start_mock().await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "service": "http",
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

    // Human-readable description: Mode A generates "METHOD host/path"
    let desc = entries[0]["description"]
        .as_str()
        .expect("description should be present");
    assert!(
        desc.starts_with("POST "),
        "Mode A description should start with method: {desc}"
    );
    assert!(
        desc.contains("/echo"),
        "Mode A description should contain path: {desc}"
    );

    // Identity name should be resolved
    assert!(
        entries[0]["identity_name"].is_string(),
        "identity_name should be resolved"
    );
}

// ===========================================================================
// Audit events: approval.created
// ===========================================================================

#[tokio::test]
async fn test_audit_approval_created() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
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
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "service": "http",
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
    // approval.created should have a description matching the summary
    assert!(
        entries[0]["description"].is_string(),
        "approval.created should have a description"
    );
}

// ===========================================================================
// Audit events: approval.resolved
// ===========================================================================

#[tokio::test]
async fn test_audit_approval_resolved() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    // Resolve as the admin *user* (identity-bound key) so the event records a
    // distinct resolver. The org-level key is unbound and would carry no
    // identity. Admins can resolve any approval in their org.
    let admin_key = fx.admin_key.clone();
    let admin_identity = fx.user_ids[0];
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
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "secrets": [{"name": "tok", "inject_as": "header", "header_name": "X-T"}]
        }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let approval_id = body["approval_id"].as_str().unwrap();

    // Resolve the approval as the admin user.
    client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=approval.resolved").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_type"], "approval");
    assert_eq!(entries[0]["detail"]["resolution"], "allow");
    assert!(entries[0]["detail"]["action_summary"].is_string());
    // The event is attributed to the approval's *subject* (the agent), not the
    // resolver — so the agent shows even though the admin user resolved it.
    assert_eq!(entries[0]["identity_id"], json!(ident_id));
    // The resolver (approver) is recorded distinctly and enriched.
    assert_eq!(
        entries[0]["detail"]["resolved_by_identity_id"],
        json!(admin_identity)
    );
    assert!(entries[0]["detail"]["resolved_by_name"].is_string());
    assert_eq!(entries[0]["detail"]["resolved_by_kind"], "user");
    assert!(
        entries[0]["detail"]["resolved_by_path"]
            .as_str()
            .unwrap()
            .starts_with("spiffe://")
    );
}

/// Per-column `=`/`~` filters added for the audit search bar keys.
#[tokio::test]
async fn test_audit_column_filters() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    // An agent and a user, so we can exercise the kind-scoped name filter.
    async fn insert_named(pool: &PgPool, org_id: Uuid, name: &str, kind: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO identities (id, org_id, name, kind) VALUES ($1, $2, $3, $4)")
            .bind(id)
            .bind(org_id)
            .bind(name)
            .bind(kind)
            .execute(pool)
            .await
            .unwrap();
        id
    }
    let agent_id = insert_named(&pool, org_id, "henry", "agent").await;
    let user_id = insert_named(&pool, org_id, "alice", "user").await;

    let scope = overslash_db::OrgScope::new(org_id, pool.clone());
    // Row 1: agent actor, action.executed / secret, "fetched token", 10.0.0.1
    scope
        .log_audit(AuditEntry {
            org_id,
            identity_id: Some(agent_id),
            action: "action.executed",
            resource_type: Some("secret"),
            resource_id: None,
            detail: json!({}),
            description: Some("fetched token"),
            ip_address: Some("10.0.0.1"),
        })
        .await
        .unwrap();
    // Row 2: user actor, approval.resolved / approval, "approved call", 192.168.1.5
    scope
        .log_audit(AuditEntry {
            org_id,
            identity_id: Some(user_id),
            action: "approval.resolved",
            resource_type: Some("approval"),
            resource_id: None,
            detail: json!({}),
            description: Some("approved call"),
            ip_address: Some("192.168.1.5"),
        })
        .await
        .unwrap();

    let only = |mut f: overslash_db::repos::audit::AuditFilter| async {
        f.org_id = org_id;
        scope.query_audit_log(f).await.unwrap()
    };
    let base = || filter(org_id);

    // event ~ → action_contains
    let r = only(AuditFilter {
        action_contains: Some("exec".into()),
        ..base()
    })
    .await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].action, "action.executed");

    // resource ~ → resource_type_contains
    let r = only(AuditFilter {
        resource_type_contains: Some("appro".into()),
        ..base()
    })
    .await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].resource_type.as_deref(), Some("approval"));

    // description = (exact) and ~ (contains)
    let r = only(AuditFilter {
        description: Some("approved call".into()),
        ..base()
    })
    .await;
    assert_eq!(r.len(), 1);
    let r = only(AuditFilter {
        description_contains: Some("token".into()),
        ..base()
    })
    .await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].description.as_deref(), Some("fetched token"));

    // ip = (exact) and ~ (contains)
    let r = only(AuditFilter {
        ip_address: Some("10.0.0.1".into()),
        ..base()
    })
    .await;
    assert_eq!(r.len(), 1);
    let r = only(AuditFilter {
        ip_address_contains: Some("192.168".into()),
        ..base()
    })
    .await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].ip_address.as_deref(), Some("192.168.1.5"));

    // agent ~ : name substring scoped to agent kinds → only the agent row
    let r = only(AuditFilter {
        identity_name_contains: Some("en".into()),
        identity_kinds: Some(vec!["agent".into(), "sub_agent".into()]),
        ..base()
    })
    .await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].identity_id, Some(agent_id));

    // user ~ : same name fragment but user kind → only the user row
    let r = only(AuditFilter {
        identity_name_contains: Some("lic".into()),
        identity_kinds: Some(vec!["user".into()]),
        ..base()
    })
    .await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].identity_id, Some(user_id));
}

/// Free-text search bar bubbles. Each bubble is one `q` term, the terms are
/// comma-joined on the wire, and every one of them must match — so two bubbles
/// narrow the result set instead of asking for one literal phrase.
#[tokio::test]
async fn test_audit_free_text_terms_and() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    let agent_id = Uuid::new_v4();
    sqlx::query("INSERT INTO identities (id, org_id, name, kind) VALUES ($1, $2, $3, $4)")
        .bind(agent_id)
        .bind(org_id)
        .bind("henry")
        .bind("agent")
        .execute(&pool)
        .await
        .unwrap();

    let scope = overslash_db::OrgScope::new(org_id, pool.clone());
    scope
        .log_audit(AuditEntry {
            org_id,
            identity_id: Some(agent_id),
            action: "action.executed",
            resource_type: Some("secret"),
            resource_id: None,
            detail: json!({}),
            description: Some("fetched token"),
            ip_address: None,
        })
        .await
        .unwrap();
    scope
        .log_audit(AuditEntry {
            org_id,
            identity_id: None,
            action: "approval.resolved",
            resource_type: Some("approval"),
            resource_id: None,
            detail: json!({}),
            description: Some("approved call"),
            ip_address: None,
        })
        .await
        .unwrap();

    let only = |mut f: overslash_db::repos::audit::AuditFilter| async {
        f.org_id = org_id;
        scope.query_audit_log(f).await.unwrap()
    };
    let base = || filter(org_id);

    // One term behaves exactly as the old single-substring `q` did.
    let r = only(AuditFilter {
        q_terms: Some(vec!["approved".into()]),
        ..base()
    })
    .await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].description.as_deref(), Some("approved call"));

    // Two terms AND, and each may land in a *different* column — `henry` is the
    // identity name, `fetched` the description.
    let r = only(AuditFilter {
        q_terms: Some(vec!["henry".into(), "fetched".into()]),
        ..base()
    })
    .await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].identity_id, Some(agent_id));

    // Terms that match different *rows* match no row at all.
    let r = only(AuditFilter {
        q_terms: Some(vec!["henry".into(), "approved".into()]),
        ..base()
    })
    .await;
    assert!(r.is_empty());

    // No terms is not "match nothing".
    let r = only(AuditFilter {
        q_terms: Some(vec![]),
        ..base()
    })
    .await;
    assert_eq!(r.len(), 2);
}

/// A comma *inside* a search phrase is escaped as `\,`, so one bubble stays
/// one term instead of splitting into two on the way through the URL.
#[tokio::test]
async fn test_audit_q_term_escaped_comma() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_user, _ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    let scope = overslash_db::OrgScope::new(fx.org_id, pool.clone());
    for description in ["New York, NY", "New York and NY"] {
        scope
            .log_audit(AuditEntry {
                org_id: fx.org_id,
                identity_id: None,
                action: "action.executed",
                resource_type: Some("http"),
                resource_id: None,
                detail: json!({}),
                description: Some(description),
                ip_address: None,
            })
            .await
            .unwrap();
    }

    // Escaped: one term, so only the row carrying the literal phrase matches.
    let one = fetch_audit_with(&base, &client, &key, "q=New%20York%5C%2C%20NY").await;
    assert_eq!(one.len(), 1, "escaped comma must stay one term: {one:?}");
    assert_eq!(one[0]["description"], "New York, NY");

    // Unescaped: two terms (`New York` AND `NY`), which both rows satisfy.
    let two = fetch_audit_with(&base, &client, &key, "q=New%20York%2CNY").await;
    assert_eq!(two.len(), 2, "unescaped comma must separate terms: {two:?}");
}

/// The `q` query param carries the bubbles comma-separated, mirroring `tag`.
#[tokio::test]
async fn test_audit_api_q_param_splits_on_commas() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, _ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    client
        .put(format!("{base}/v1/secrets/comma_split"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "val"}))
        .send()
        .await
        .unwrap();

    // One term: the pre-existing single-substring behaviour.
    let one = fetch_audit_with(&base, &client, &key, "q=secret.put").await;
    assert!(!one.is_empty());
    assert!(one.iter().all(|e| e["action"] == "secret.put"));

    // Two terms AND — the second cannot match, so the whole set goes away.
    let two = fetch_audit_with(&base, &client, &key, "q=secret.put,zzzznotathing").await;
    assert!(
        two.is_empty(),
        "an unmatchable second term must narrow to nothing, got {two:?}"
    );

    // Empty terms between commas are dropped, not treated as "match nothing".
    let blank = fetch_audit_with(&base, &client, &key, "q=secret.put,,").await;
    assert_eq!(blank.len(), one.len());
}

/// `user =` (owner_user_id) / `user ~` (owner_user_contains) match the owning
/// user *subtree*: the user acting directly plus any agent they own — wider
/// than the exact-actor `identity_id` used by `agent`/`identity`.
#[tokio::test]
async fn test_audit_owner_user_filter() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    async fn insert_id(
        pool: &PgPool,
        org_id: Uuid,
        name: &str,
        kind: &str,
        owner_id: Option<Uuid>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO identities (id, org_id, name, kind, owner_id) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(org_id)
        .bind(name)
        .bind(kind)
        .bind(owner_id)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    // alice owns agent henry; bob is an unrelated user.
    let alice = insert_id(&pool, org_id, "alice", "user", None).await;
    let henry = insert_id(&pool, org_id, "henry", "agent", Some(alice)).await;
    let bob = insert_id(&pool, org_id, "bob", "user", None).await;

    let scope = overslash_db::OrgScope::new(org_id, pool.clone());
    for (actor, action) in [
        (alice, "alice.direct"),
        (henry, "henry.acted"),
        (bob, "bob.direct"),
    ] {
        scope
            .log_audit(AuditEntry {
                org_id,
                identity_id: Some(actor),
                action,
                resource_type: None,
                resource_id: None,
                detail: json!({}),
                description: None,
                ip_address: None,
            })
            .await
            .unwrap();
    }

    let only = |mut f: overslash_db::repos::audit::AuditFilter| async {
        f.org_id = org_id;
        scope.query_audit_log(f).await.unwrap()
    };
    let base = || filter(org_id);
    let actors = |rows: &[overslash_db::repos::audit::AuditRow]| {
        rows.iter()
            .filter_map(|r| r.identity_id)
            .collect::<std::collections::HashSet<_>>()
    };

    // user = alice → alice's own row + her agent henry's row (not bob's).
    let r = only(AuditFilter {
        owner_user_id: Some(alice),
        ..base()
    })
    .await;
    let a = actors(&r);
    assert_eq!(r.len(), 2);
    assert!(a.contains(&alice) && a.contains(&henry) && !a.contains(&bob));

    // Contrast: exact identity_id (the `agent`/`identity` path) → alice only.
    let r = only(AuditFilter {
        identity_id: Some(alice),
        ..base()
    })
    .await;
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].identity_id, Some(alice));

    // user ~ "lic" → owner_user_contains matches alice (own name) + henry
    // (owner's name), excludes bob.
    let r = only(AuditFilter {
        owner_user_contains: Some("lic".into()),
        ..base()
    })
    .await;
    let a = actors(&r);
    assert_eq!(r.len(), 2);
    assert!(a.contains(&alice) && a.contains(&henry) && !a.contains(&bob));
}

// ===========================================================================
// Audit events: secret.put + secret.deleted
// ===========================================================================

#[tokio::test]
async fn test_audit_secret_put() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, _ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;

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

#[tokio::test]
async fn test_audit_secret_deleted() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, _ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    client
        .put(format!("{base}/v1/secrets/to_delete"))
        .header(auth(&key).0, auth(&key).1)
        .json(&json!({"value": "val"}))
        .send()
        .await
        .unwrap();

    client
        .delete(format!("{base}/v1/secrets/to_delete"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
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

#[tokio::test]
async fn test_audit_permission_rule_created() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=permission_rule.created").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_type"], "permission_rule");
    assert_eq!(entries[0]["detail"]["action_pattern"], "http:**");
}

#[tokio::test]
async fn test_audit_permission_rule_deleted() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();
    let perm: Value = resp.json().await.unwrap();
    let perm_id = perm["id"].as_str().unwrap();

    client
        .delete(format!("{base}/v1/permissions/{perm_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
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

#[tokio::test]
async fn test_audit_webhook_created() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, _ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    client
        .post(format!("{base}/v1/webhooks"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"url": "https://example.com/hook", "events": ["approval.resolved"]}))
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=webhook.created").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_type"], "webhook");
    assert_eq!(entries[0]["detail"]["url"], "https://example.com/hook");
}

#[tokio::test]
async fn test_audit_webhook_deleted() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, _ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    let resp = client
        .post(format!("{base}/v1/webhooks"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"url": "https://example.com/hook", "events": ["approval.resolved"]}))
        .send()
        .await
        .unwrap();
    let wh: Value = resp.json().await.unwrap();
    let wh_id = wh["id"].as_str().unwrap();

    client
        .delete(format!("{base}/v1/webhooks/{wh_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
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

#[tokio::test]
async fn test_audit_byoc_credential_created() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    let resp = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"provider": "google", "client_id": "cid", "client_secret": "cs", "identity_id": ident_id}))
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

#[tokio::test]
async fn test_audit_byoc_credential_deleted() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    let resp = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"provider": "github", "client_id": "c", "client_secret": "s", "identity_id": ident_id}))
        .send()
        .await
        .unwrap();
    let cred: Value = resp.json().await.unwrap();
    let cred_id = cred["id"].as_str().unwrap();

    client
        .delete(format!("{base}/v1/byoc-credentials/{cred_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=byoc_credential.deleted").await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["resource_id"].as_str().unwrap(), cred_id);
}

#[tokio::test]
async fn test_audit_byoc_delete_nonexistent_no_entry() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, _ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    let fake_id = Uuid::new_v4();
    client
        .delete(format!("{base}/v1/byoc-credentials/{fake_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=byoc_credential.deleted").await;
    assert!(entries.is_empty());
}

// ===========================================================================
// Audit events: no-op deletes should not produce entries
// ===========================================================================

#[tokio::test]
async fn test_audit_noop_deletes_no_entries() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, _ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    // Delete non-existent webhook
    let fake = Uuid::new_v4();
    client
        .delete(format!("{base}/v1/webhooks/{fake}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();

    // Delete non-existent permission
    client
        .delete(format!("{base}/v1/permissions/{fake}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();

    // Delete non-existent secret
    client
        .delete(format!("{base}/v1/secrets/nope"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();

    let all = fetch_audit(&base, &client, &key).await;
    let delete_entries: Vec<&Value> = all
        .iter()
        .filter(|e| {
            e["action"]
                .as_str()
                .is_some_and(|a| a.ends_with(".deleted"))
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

#[tokio::test]
async fn test_audit_mixed_events() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_user, ident_id, key) = bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();
    let mock_addr = start_mock().await;

    // BYOC credential
    client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"provider": "spotify", "client_id": "c", "client_secret": "s", "identity_id": ident_id}))
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

    // Permission + call
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "http:**"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&key).0, auth(&key).1)
        .json(
            &json!({"service": "http", "method": "GET", "url": format!("http://{mock_addr}/echo")}),
        )
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

#[tokio::test]
async fn test_log_audit_overwrites_entry_org_id() {
    // log_audit must overwrite entry.org_id with self.org_id() so a caller
    // cannot smuggle a row into a different tenant's audit log.
    let pool = common::test_pool().await;
    let org_a = insert_org(&pool).await;
    let org_b = insert_org(&pool).await;

    overslash_db::OrgScope::new(org_a, pool.clone())
        .log_audit(entry(
            org_b, // attacker tries to write under org_b
            None,
            "smuggle.attempt",
            None,
            None,
            json!({}),
        ))
        .await
        .unwrap();

    let rows_a = overslash_db::OrgScope::new(org_a, pool.clone())
        .query_audit_log(filter(org_a))
        .await
        .unwrap();
    assert_eq!(rows_a.len(), 1, "row landed in scope's org");
    assert_eq!(rows_a[0].org_id, org_a);
    assert_eq!(rows_a[0].action, "smuggle.attempt");

    let rows_b = overslash_db::OrgScope::new(org_b, pool.clone())
        .query_audit_log(filter(org_b))
        .await
        .unwrap();
    assert!(rows_b.is_empty(), "row did NOT land in spoofed org");
}

#[tokio::test]
async fn test_query_audit_log_overwrites_filter_org_id() {
    // query_audit_log must overwrite filter.org_id with self.org_id() so a
    // caller cannot read another tenant's rows by spoofing the filter.
    let pool = common::test_pool().await;
    let org_a = insert_org(&pool).await;
    let org_b = insert_org(&pool).await;

    overslash_db::OrgScope::new(org_a, pool.clone())
        .log_audit(entry(org_a, None, "a.event", None, None, json!({})))
        .await
        .unwrap();
    overslash_db::OrgScope::new(org_b, pool.clone())
        .log_audit(entry(org_b, None, "b.event", None, None, json!({})))
        .await
        .unwrap();

    // Query as org_a but pass org_b in the filter — must be ignored.
    let rows = overslash_db::OrgScope::new(org_a, pool.clone())
        .query_audit_log(filter(org_b))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].org_id, org_a);
    assert_eq!(rows[0].action, "a.event");
}

// ===========================================================================
// New: identity_path resolution + event_id / uuid filters
// ===========================================================================

#[tokio::test]
async fn test_audit_api_includes_identity_path() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org_id, _ident_id, client) = setup_with_perm(pool, &fx, "http:**").await;
    let mock_addr = start_mock().await;

    client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&key).0, auth(&key).1)
        .json(
            &json!({"service": "http", "method": "GET", "url": format!("http://{mock_addr}/echo")}),
        )
        .send()
        .await
        .unwrap();

    let entries = fetch_audit_with(&base, &client, &key, "action=action.executed").await;
    assert_eq!(entries.len(), 1);
    let path = entries[0]["identity_path"]
        .as_str()
        .expect("identity_path should be present for resolvable identities");
    // bootstrap_agent_on_fixtures wires: user "test-user" → agent "test-agent".
    assert!(
        path.starts_with("spiffe://"),
        "expected SPIFFE-format path, got {path}"
    );
    assert!(path.contains("/user/test-user"), "got {path}");
    assert!(path.contains("/agent/test-agent"), "got {path}");

    // The id list should align: one id per `(kind, name)` unit (user + agent = 2).
    let ids = entries[0]["identity_path_ids"]
        .as_array()
        .expect("identity_path_ids should be an array");
    assert_eq!(ids.len(), 2, "expected 2 path ids for user→agent chain");
}

#[tokio::test]
async fn test_audit_api_filter_by_event_id() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, _org_id, _ident_id, client) = setup_with_perm(pool, &fx, "http:**").await;
    let mock_addr = start_mock().await;

    // Generate two action.executed entries.
    for _ in 0..2 {
        client
            .post(format!("{base}/v1/actions/call"))
            .header(auth(&key).0, auth(&key).1)
            .json(&json!({"service": "http", "method": "GET", "url": format!("http://{mock_addr}/echo")}))
            .send()
            .await
            .unwrap();
    }

    let all = fetch_audit_with(&base, &client, &key, "action=action.executed").await;
    assert_eq!(all.len(), 2);
    let target_id = all[0]["id"].as_str().unwrap();

    let filtered = fetch_audit_with(&base, &client, &key, &format!("event_id={target_id}")).await;
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["id"].as_str().unwrap(), target_id);
}

#[tokio::test]
async fn test_audit_api_filter_by_uuid_matches_resource_id() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let target_resource = Uuid::new_v4();

    // Insert two rows: one with the target resource_id, one without.
    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            None,
            "match.resource",
            Some("widget"),
            Some(target_resource),
            json!({}),
        ))
        .await
        .unwrap();
    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            None,
            "other.thing",
            Some("widget"),
            Some(Uuid::new_v4()),
            json!({}),
        ))
        .await
        .unwrap();

    let mut f = filter(org_id);
    f.uuid = Some(target_resource);
    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "match.resource");
}

#[tokio::test]
async fn test_audit_api_filter_by_uuid_matches_detail_execution_id() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let exec_id = Uuid::new_v4();

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            None,
            "action.executed",
            None,
            None,
            json!({"execution_id": exec_id.to_string(), "method": "GET"}),
        ))
        .await
        .unwrap();
    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            None,
            "action.executed",
            None,
            None,
            json!({"execution_id": Uuid::new_v4().to_string(), "method": "GET"}),
        ))
        .await
        .unwrap();

    let mut f = filter(org_id);
    f.uuid = Some(exec_id);
    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].detail["execution_id"], exec_id.to_string());
}

#[tokio::test]
async fn test_audit_api_filter_by_uuid_matches_replayed_from_approval() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let approval_id = Uuid::new_v4();

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            None,
            "action.executed",
            None,
            None,
            json!({"replayed_from_approval": approval_id.to_string()}),
        ))
        .await
        .unwrap();
    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            None,
            "unrelated.event",
            None,
            None,
            json!({}),
        ))
        .await
        .unwrap();

    let mut f = filter(org_id);
    f.uuid = Some(approval_id);
    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "action.executed");
}

#[tokio::test]
async fn test_audit_api_filter_by_uuid_tolerates_malformed_detail() {
    // The query guards JSONB casts with a regex so non-UUID strings in the
    // detail don't blow up the whole query. Insert garbage and confirm.
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let target = Uuid::new_v4();

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            None,
            "garbage.detail",
            None,
            None,
            json!({"execution_id": "not-a-uuid", "replayed_from_approval": ""}),
        ))
        .await
        .unwrap();
    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            None,
            "real.match",
            None,
            Some(target),
            json!({}),
        ))
        .await
        .unwrap();

    let mut f = filter(org_id);
    f.uuid = Some(target);
    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "real.match");
}

// ===========================================================================
// Recorded actor names (D56, migration 109)
// ===========================================================================

#[tokio::test]
async fn test_audit_actor_name_is_recorded_at_write_time() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let user_id = insert_named_identity(&pool, org_id, "alice", "user", None).await;
    let agent_id = insert_named_identity(&pool, org_id, "henry", "agent", Some(user_id)).await;

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(
            org_id,
            Some(agent_id),
            "secret.put",
            None,
            None,
            json!({}),
        ))
        .await
        .unwrap();

    sqlx::query("UPDATE identities SET name = 'bob' WHERE id = $1")
        .bind(agent_id)
        .execute(&pool)
        .await
        .unwrap();

    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(filter(org_id))
        .await
        .unwrap();
    assert_eq!(rows[0].actor_name.as_deref(), Some("henry"));

    // Search follows the record, not the rename — the row says henry acted, so
    // searching for henry has to find it.
    let mut f = filter(org_id);
    f.q_terms = Some(vec!["henry".to_string()]);
    assert_eq!(
        overslash_db::OrgScope::new(org_id, pool.clone())
            .query_audit_log(f)
            .await
            .unwrap()
            .len(),
        1
    );

    let mut f = filter(org_id);
    f.identity_name_contains = Some("bob".to_string());
    assert!(
        overslash_db::OrgScope::new(org_id, pool.clone())
            .query_audit_log(f)
            .await
            .unwrap()
            .is_empty(),
        "the current name is not what the row recorded"
    );

    // The id-keyed filter is unaffected by renames, which is what makes the
    // search bar's `identity = <name>` chip the durable way to filter by actor.
    let mut f = filter(org_id);
    f.identity_id = Some(agent_id);
    assert_eq!(
        overslash_db::OrgScope::new(org_id, pool.clone())
            .query_audit_log(f)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn test_audit_owner_user_name_is_root_of_chain() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let user_id = insert_named_identity(&pool, org_id, "alice", "user", None).await;
    let agent_id = insert_named_identity(&pool, org_id, "henry", "agent", Some(user_id)).await;
    let sub_id =
        insert_named_identity(&pool, org_id, "researcher", "sub_agent", Some(agent_id)).await;

    for id in [user_id, agent_id, sub_id] {
        overslash_db::OrgScope::new(org_id, pool.clone())
            .log_audit(entry(
                org_id,
                Some(id),
                "action.executed",
                None,
                None,
                json!({}),
            ))
            .await
            .unwrap();
    }

    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(filter(org_id))
        .await
        .unwrap();
    let by_actor: std::collections::HashMap<_, _> = rows
        .iter()
        .map(|r| (r.identity_id.unwrap(), r.owner_user_name.clone()))
        .collect();

    // Two hops up from the sub-agent, not one: the direct parent is an agent,
    // and "user" has to mean the human.
    assert_eq!(by_actor[&sub_id].as_deref(), Some("alice"));
    assert_eq!(by_actor[&agent_id].as_deref(), Some("alice"));
    assert_eq!(by_actor[&user_id].as_deref(), Some("alice"));

    // `user ~` therefore reaches the whole subtree.
    let mut f = filter(org_id);
    f.owner_user_contains = Some("alic".to_string());
    assert_eq!(
        overslash_db::OrgScope::new(org_id, pool.clone())
            .query_audit_log(f)
            .await
            .unwrap()
            .len(),
        3
    );
}

#[tokio::test]
async fn test_audit_actor_names_null_without_identity() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    overslash_db::OrgScope::new(org_id, pool.clone())
        .log_audit(entry(org_id, None, "org.created", None, None, json!({})))
        .await
        .unwrap();

    let rows = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(filter(org_id))
        .await
        .unwrap();
    assert!(rows[0].actor_name.is_none());
    assert!(rows[0].owner_user_name.is_none());
}

#[tokio::test]
async fn test_audit_q_prune_conjunct_does_not_change_results() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;
    let ident = insert_named_identity(&pool, org_id, "henry", "agent", None).await;

    for (action, desc) in [
        ("secret.put", "Rotated the warehouse credential"),
        ("action.executed", "Queried the warehouse"),
        ("approval.created", "Nothing relevant here"),
    ] {
        let mut e = entry(org_id, Some(ident), action, None, None, json!({}));
        e.description = Some(desc);
        overslash_db::OrgScope::new(org_id, pool.clone())
            .log_audit(e)
            .await
            .unwrap();
    }

    // The pruning conjunct only fires for terms of three characters or more, so
    // these two searches take different paths through the query and must still
    // agree with each other and with the per-column semantics.
    let run = |terms: Vec<String>| {
        let pool = pool.clone();
        async move {
            let mut f = filter(org_id);
            f.q_terms = Some(terms);
            overslash_db::OrgScope::new(org_id, pool)
                .query_audit_log(f)
                .await
                .unwrap()
        }
    };

    assert_eq!(run(vec!["warehouse".to_string()]).await.len(), 2);
    assert_eq!(run(vec!["wa".to_string()]).await.len(), 2);
    // Terms AND: only the row matching both.
    assert_eq!(
        run(vec!["warehouse".to_string(), "secret".to_string()])
            .await
            .len(),
        1
    );
    // A term matching the actor's recorded name still counts as a hit.
    assert_eq!(run(vec!["henry".to_string()]).await.len(), 3);
    assert!(run(vec!["zzzznotathing".to_string()]).await.is_empty());
}

// ===========================================================================
// Keyset pagination
// ===========================================================================

#[tokio::test]
async fn test_audit_keyset_pagination_ties_on_timestamp() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    // Rows written inside one transaction share `now()`. Five of them at the
    // same instant is the case a naive `created_at < cursor` cursor drops.
    let ts = time::OffsetDateTime::now_utc();
    for i in 0..5 {
        sqlx::query(
            "INSERT INTO audit_log (org_id, action, detail, created_at) VALUES ($1, $2, '{}', $3)",
        )
        .bind(org_id)
        .bind(format!("tied_{i}"))
        .bind(ts)
        .execute(&pool)
        .await
        .unwrap();
    }

    let mut seen: Vec<Uuid> = Vec::new();
    let mut cursor: Option<(time::OffsetDateTime, Uuid)> = None;
    loop {
        let mut f = filter(org_id);
        f.limit = 2;
        if let Some((before, before_id)) = cursor {
            f.before = Some(before);
            f.before_id = Some(before_id);
        }
        let page = overslash_db::OrgScope::new(org_id, pool.clone())
            .query_audit_log(f)
            .await
            .unwrap();
        if page.is_empty() {
            break;
        }
        let last = page.last().unwrap();
        cursor = Some((last.created_at, last.id));
        seen.extend(page.iter().map(|r| r.id));
    }

    assert_eq!(seen.len(), 5, "every row is returned exactly once");
    let unique: std::collections::HashSet<_> = seen.iter().collect();
    assert_eq!(unique.len(), 5, "no row is returned twice");
}

#[tokio::test]
async fn test_audit_keyset_matches_offset_paging() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    for i in 0..10 {
        overslash_db::OrgScope::new(org_id, pool.clone())
            .log_audit(entry(
                org_id,
                None,
                &format!("action_{i}"),
                None,
                None,
                json!({}),
            ))
            .await
            .unwrap();
    }

    let mut f = filter(org_id);
    f.limit = 4;
    let page1 = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f.clone())
        .await
        .unwrap();

    let mut keyset = f.clone();
    keyset.before = Some(page1.last().unwrap().created_at);
    keyset.before_id = Some(page1.last().unwrap().id);
    let page2_keyset = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(keyset)
        .await
        .unwrap();

    let mut offset = f;
    offset.offset = 4;
    let page2_offset = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(offset)
        .await
        .unwrap();

    assert_eq!(
        page2_keyset.iter().map(|r| r.id).collect::<Vec<_>>(),
        page2_offset.iter().map(|r| r.id).collect::<Vec<_>>(),
        "the cursor and the offset must land on the same page"
    );
}

#[tokio::test]
async fn test_audit_api_keyset_params() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    for i in 0..6 {
        overslash_db::OrgScope::new(fx.org_id, pool.clone())
            .log_audit(entry(
                fx.org_id,
                None,
                &format!("paged_{i}"),
                None,
                None,
                json!({}),
            ))
            .await
            .unwrap();
    }

    let page1 = fetch_audit_with(&base, &client, &fx.org_key, "limit=3").await;
    assert_eq!(page1.len(), 3);
    let last = page1.last().unwrap();
    let qs = format!(
        "limit=3&before={}&before_id={}",
        urlencoding::encode(last["created_at"].as_str().unwrap()),
        last["id"].as_str().unwrap()
    );
    let page2 = fetch_audit_with(&base, &client, &fx.org_key, &qs).await;

    let ids1: Vec<&str> = page1.iter().map(|e| e["id"].as_str().unwrap()).collect();
    let ids2: Vec<&str> = page2.iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert!(
        ids2.iter().all(|id| !ids1.contains(id)),
        "the second page must not repeat the first"
    );
}

#[tokio::test]
async fn test_audit_before_without_before_id_is_a_strict_bound() {
    let pool = common::test_pool().await;
    let org_id = insert_org(&pool).await;

    // `/v1/audit` is public and its two cursor params are independently
    // optional, so a caller may well send `before` alone. That has to page,
    // not repeat: the first conjunct of the cursor is inclusive so the
    // tiebreaker can resolve ties, which means without a tiebreaker the
    // boundary row would be admitted and never removed.
    let ts = time::OffsetDateTime::now_utc();
    for i in 0..4 {
        sqlx::query(
            "INSERT INTO audit_log (org_id, action, detail, created_at) VALUES ($1, $2, '{}', $3)",
        )
        .bind(org_id)
        .bind(format!("distinct_{i}"))
        .bind(ts - time::Duration::seconds(i))
        .execute(&pool)
        .await
        .unwrap();
    }

    let mut f = filter(org_id);
    f.limit = 2;
    let page1 = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f.clone())
        .await
        .unwrap();

    let mut f2 = f.clone();
    f2.before = Some(page1.last().unwrap().created_at);
    f2.before_id = None;
    let page2 = overslash_db::OrgScope::new(org_id, pool.clone())
        .query_audit_log(f2)
        .await
        .unwrap();

    let ids1: Vec<Uuid> = page1.iter().map(|r| r.id).collect();
    assert!(
        page2.iter().all(|r| !ids1.contains(&r.id)),
        "`before` without `before_id` repeated the previous page's boundary row"
    );

    // The degenerate case the inclusive bound used to loop on forever: enough
    // rows sharing one timestamp to fill a page.
    let tied_org = insert_org(&pool).await;
    let tied_at = time::OffsetDateTime::now_utc();
    for i in 0..4 {
        sqlx::query(
            "INSERT INTO audit_log (org_id, action, detail, created_at) VALUES ($1, $2, '{}', $3)",
        )
        .bind(tied_org)
        .bind(format!("tied_{i}"))
        .bind(tied_at)
        .execute(&pool)
        .await
        .unwrap();
    }

    let mut tf = filter(tied_org);
    tf.limit = 2;
    let tied_page1 = overslash_db::OrgScope::new(tied_org, pool.clone())
        .query_audit_log(tf.clone())
        .await
        .unwrap();
    let mut tf2 = tf;
    tf2.before = Some(tied_page1.last().unwrap().created_at);
    tf2.before_id = None;
    let tied_page2 = overslash_db::OrgScope::new(tied_org, pool.clone())
        .query_audit_log(tf2)
        .await
        .unwrap();
    assert!(
        tied_page2.is_empty(),
        "a timestamp-only cursor must exclude the whole boundary instant, not re-serve it"
    );
}
