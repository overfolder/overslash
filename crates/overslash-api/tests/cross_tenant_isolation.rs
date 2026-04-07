//! Cross-tenant isolation tests for resources migrated to the Scope API.
//!
//! Contract: as org A, attempting to fetch or mutate org B's resource by id
//! must not leak existence or affect state. Concretely every such request
//! must either:
//!
//! 1. Return `404 Not Found`, or
//! 2. Return `200 OK` with a silent no-op body such as `{"deleted": false}`
//!    (the handler ran the scope-filtered SQL, zero rows matched, and
//!    reported idempotent "nothing to do" — indistinguishable from the same
//!    request hitting an id that truly doesn't exist in org A).
//!
//! Both outcomes preserve the "no existence leak" invariant; which one a
//! particular endpoint returns is a handler-level design choice. These tests
//! exercise the `WHERE org_id = $1` invariant at the HTTP boundary so a
//! future regression that drops the clause fails loudly.
//!
//! The attacker side always uses the *org-admin* key for the attacker org so
//! that `AdminAcl`/`WriteAcl` extractor rejections (403) don't mask the
//! actual scope-level check we're exercising.

#![allow(clippy::disallowed_methods)]

mod common;

use common::{auth, bootstrap_org_identity, start_api};
use reqwest::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// Bootstrap two orgs on the same API instance. Returns
/// `(base, client, ident_a, agent_key_a, admin_a, ident_b, agent_key_b, admin_b)`.
async fn two_orgs(
    pool: PgPool,
) -> (
    String,
    reqwest::Client,
    Uuid,
    String,
    String,
    Uuid,
    String,
    String,
) {
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let (_, ident_a, key_a, admin_a) = bootstrap_org_identity(&base, &client).await;
    let (_, ident_b, key_b, admin_b) = bootstrap_org_identity(&base, &client).await;
    (
        base, client, ident_a, key_a, admin_a, ident_b, key_b, admin_b,
    )
}

/// Assert the response represents an isolation-safe "no access" outcome:
/// either a 404, or a 200 body carrying an explicit no-op flag.
async fn assert_isolated(resp: reqwest::Response) {
    let status = resp.status();
    if status == StatusCode::NOT_FOUND {
        return;
    }
    assert_eq!(
        status,
        StatusCode::OK,
        "unexpected status for cross-tenant request: {status}"
    );
    let body: Value = resp.json().await.unwrap();
    // Accept any of the common silent-noop shapes.
    let deleted_false = body.get("deleted") == Some(&Value::Bool(false));
    let revoked_false = body.get("revoked") == Some(&Value::Bool(false));
    assert!(
        deleted_false || revoked_false,
        "200 response did not indicate a no-op: {body}"
    );
}

// ─── secrets ────────────────────────────────────────────────────────────

#[tokio::test]
async fn cross_tenant_secret_delete_returns_404() {
    let pool = common::test_pool().await;
    let pool_for_seed = pool.clone();
    let (base, client, _ia, _ka, admin_a, _ib, key_b, _ab) = two_orgs(pool).await;

    // org B writes a secret under its agent identity.
    let put_b = client
        .put(format!("{base}/v1/secrets/shared"))
        .header(auth(&key_b).0, auth(&key_b).1)
        .json(&json!({"value": "org-b-secret"}))
        .send()
        .await
        .unwrap();
    assert_eq!(put_b.status(), 200);

    // org A's admin tries to delete a secret with the same name. Its
    // org-scoped namespace has nothing → 404.
    let del_a = client
        .delete(format!("{base}/v1/secrets/shared"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .send()
        .await
        .unwrap();
    assert_eq!(del_a.status(), 404);

    // Confirm org B's secret row is untouched.
    let remaining: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM secrets WHERE name = 'shared' AND deleted_at IS NULL")
            .fetch_one(&pool_for_seed)
            .await
            .unwrap();
    assert_eq!(remaining.0, 1);
}

// ─── approvals ─────────────────────────────────────────────────────────
//
// Seed an approval row directly in org B via SQL, then confirm org A
// cannot read or resolve it.

#[tokio::test]
async fn cross_tenant_approval_get_and_resolve_return_404() {
    let pool = common::test_pool().await;
    let pool_for_seed = pool.clone();
    let (base, client, _ia, _ka, admin_a, ident_b, _kb, _ab) = two_orgs(pool).await;

    let org_b: (Uuid,) = sqlx::query_as("SELECT org_id FROM identities WHERE id = $1")
        .bind(ident_b)
        .fetch_one(&pool_for_seed)
        .await
        .unwrap();
    let org_b_id = org_b.0;

    let approval: (Uuid,) = sqlx::query_as(
        "INSERT INTO approvals
            (org_id, identity_id, current_resolver_identity_id, action_summary,
             permission_keys, token, expires_at)
         VALUES ($1, $2, $2, $3, $4, $5, now() + interval '30 minutes')
         RETURNING id",
    )
    .bind(org_b_id)
    .bind(ident_b)
    .bind("seed")
    .bind(vec!["http:**".to_string()])
    .bind(format!("tok-{}", Uuid::new_v4()))
    .fetch_one(&pool_for_seed)
    .await
    .unwrap();
    let approval_id = approval.0;

    let get_a = client
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .send()
        .await
        .unwrap();
    assert_eq!(get_a.status(), 404);

    let resolve_a = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resolve_a.status(), 404);
}

// ─── service_instances ─────────────────────────────────────────────────

async fn create_org_service(
    base: &str,
    client: &reqwest::Client,
    key: &str,
    key_name: &str,
) -> Uuid {
    client
        .post(format!("{base}/v1/templates"))
        .header(auth(key).0, auth(key).1)
        .json(&json!({
            "key": key_name,
            "display_name": key_name,
            "hosts": [format!("{key_name}.example.com")],
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();

    let svc: Value = client
        .post(format!("{base}/v1/services"))
        .header(auth(key).0, auth(key).1)
        .json(&json!({
            "template_key": key_name,
            "name": key_name,
            "user_level": false,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    svc["id"].as_str().unwrap().parse().unwrap()
}

#[tokio::test]
async fn cross_tenant_service_instance_mutation_returns_404() {
    let pool = common::test_pool().await;
    let (base, client, _ia, _ka, admin_a, _ib, _kb, admin_b) = two_orgs(pool).await;

    let svc_id = create_org_service(&base, &client, &admin_b, "svc-b").await;

    let resp = client
        .put(format!("{base}/v1/services/{svc_id}/manage"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .json(&json!({"name": "hijacked"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    let resp = client
        .patch(format!("{base}/v1/services/{svc_id}/status"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .json(&json!({"status": "archived"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ─── groups ────────────────────────────────────────────────────────────

#[tokio::test]
async fn cross_tenant_group_access_returns_404() {
    let pool = common::test_pool().await;
    let (base, client, _ia, _ka, admin_a, _ib, _kb, admin_b) = two_orgs(pool).await;

    let group: Value = client
        .post(format!("{base}/v1/groups"))
        .header(auth(&admin_b).0, auth(&admin_b).1)
        .json(&json!({"name": "BOnly"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let gid = group["id"].as_str().unwrap();

    let r = client
        .get(format!("{base}/v1/groups/{gid}"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    let r = client
        .put(format!("{base}/v1/groups/{gid}"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .json(&json!({"name": "Hijacked"}))
        .send()
        .await
        .unwrap();
    assert_isolated(r).await;

    let r = client
        .delete(format!("{base}/v1/groups/{gid}"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .send()
        .await
        .unwrap();
    assert_isolated(r).await;
}

// ─── identities ────────────────────────────────────────────────────────

#[tokio::test]
async fn cross_tenant_identity_chain_returns_404() {
    let pool = common::test_pool().await;
    let (base, client, _ia, _ka, admin_a, ident_b, _kb, _ab) = two_orgs(pool).await;

    let r = client
        .get(format!("{base}/v1/identities/{ident_b}/chain"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    let r = client
        .get(format!("{base}/v1/identities/{ident_b}/children"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .send()
        .await
        .unwrap();
    // list_children returns an empty list (no rows match org A's scope) or 404.
    // Empty list is also isolation-safe since no children of B are leaked.
    if r.status() == StatusCode::OK {
        let body: Vec<Value> = r.json().await.unwrap();
        assert!(body.is_empty(), "leaked children: {body:?}");
    } else {
        assert_eq!(r.status(), 404);
    }
}

// ─── connections ───────────────────────────────────────────────────────

#[tokio::test]
async fn cross_tenant_connection_delete_returns_404() {
    let pool = common::test_pool().await;
    let pool_for_seed = pool.clone();
    let (base, client, _ia, _ka, admin_a, ident_b, _kb, _ab) = two_orgs(pool).await;

    let org_b: (Uuid,) = sqlx::query_as("SELECT org_id FROM identities WHERE id = $1")
        .bind(ident_b)
        .fetch_one(&pool_for_seed)
        .await
        .unwrap();
    let org_b_id = org_b.0;

    let provider_key: (String,) = sqlx::query_as("SELECT key FROM oauth_providers LIMIT 1")
        .fetch_one(&pool_for_seed)
        .await
        .unwrap();

    let conn_id: (Uuid,) = sqlx::query_as(
        "INSERT INTO connections (org_id, identity_id, provider_key, encrypted_access_token, scopes)
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(org_b_id)
    .bind(ident_b)
    .bind(&provider_key.0)
    .bind(vec![0u8; 16])
    .bind(Vec::<String>::new())
    .fetch_one(&pool_for_seed)
    .await
    .unwrap();

    let r = client
        .delete(format!("{base}/v1/connections/{}", conn_id.0))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .send()
        .await
        .unwrap();
    assert_isolated(r).await;

    // Confirm org B's connection still exists
    let still: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM connections WHERE id = $1")
        .bind(conn_id.0)
        .fetch_one(&pool_for_seed)
        .await
        .unwrap();
    assert_eq!(still.0, 1, "org A managed to delete org B's connection");
}

// ─── enrollment_tokens ─────────────────────────────────────────────────

#[tokio::test]
async fn cross_tenant_enrollment_token_revoke_returns_404() {
    let pool = common::test_pool().await;
    let (base, client, _ia, _ka, admin_a, ident_b, _kb, admin_b) = two_orgs(pool).await;

    let tok: Value = client
        .post(format!("{base}/v1/enrollment-tokens"))
        .header(auth(&admin_b).0, auth(&admin_b).1)
        .json(&json!({"identity_id": ident_b}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let tok_id = tok["id"].as_str().unwrap();

    let r = client
        .delete(format!("{base}/v1/enrollment-tokens/{tok_id}"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

// ─── byoc_credentials ──────────────────────────────────────────────────

#[tokio::test]
async fn cross_tenant_byoc_delete_returns_404() {
    let pool = common::test_pool().await;
    let (base, client, _ia, _ka, admin_a, _ib, _kb, admin_b) = two_orgs(pool).await;

    let cred: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header(auth(&admin_b).0, auth(&admin_b).1)
        .json(&json!({
            "provider": "google",
            "client_id": "cid",
            "client_secret": "csec",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cred_id = cred["id"].as_str().unwrap();

    let r = client
        .delete(format!("{base}/v1/byoc-credentials/{cred_id}"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .send()
        .await
        .unwrap();
    assert_isolated(r).await;
}

// ─── rate_limits ───────────────────────────────────────────────────────

#[tokio::test]
async fn cross_tenant_rate_limit_delete_returns_404() {
    let pool = common::test_pool().await;
    let (base, client, _ia, _ka, admin_a, _ib, _kb, admin_b) = two_orgs(pool).await;

    let rl: Value = client
        .put(format!("{base}/v1/rate-limits"))
        .header(auth(&admin_b).0, auth(&admin_b).1)
        .json(&json!({
            "scope": "org",
            "max_requests": 10,
            "window_seconds": 60,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rl_id = rl["id"].as_str().unwrap();

    let r = client
        .delete(format!("{base}/v1/rate-limits/{rl_id}"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

// ─── webhooks ──────────────────────────────────────────────────────────

#[tokio::test]
async fn cross_tenant_webhook_delete_returns_404() {
    let pool = common::test_pool().await;
    let (base, client, _ia, _ka, admin_a, _ib, _kb, admin_b) = two_orgs(pool).await;

    let wh: Value = client
        .post(format!("{base}/v1/webhooks"))
        .header(auth(&admin_b).0, auth(&admin_b).1)
        .json(&json!({
            "url": "http://example.com/hook",
            "events": ["approval.created"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let wh_id = wh["id"].as_str().unwrap();

    let r = client
        .delete(format!("{base}/v1/webhooks/{wh_id}"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .send()
        .await
        .unwrap();
    assert_isolated(r).await;
}

// ─── org_idp_config ────────────────────────────────────────────────────

#[tokio::test]
async fn cross_tenant_idp_config_mutations_return_404() {
    let pool = common::test_pool().await;
    let (base, client, _ia, _ka, admin_a, _ib, _kb, admin_b) = two_orgs(pool).await;

    let cfg: Value = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header(auth(&admin_b).0, auth(&admin_b).1)
        .json(&json!({
            "provider_key": "google",
            "client_id": "cid",
            "client_secret": "csec",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cfg_id = cfg["id"].as_str().unwrap();

    let r = client
        .put(format!("{base}/v1/org-idp-configs/{cfg_id}"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .json(&json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    let r = client
        .delete(format!("{base}/v1/org-idp-configs/{cfg_id}"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .send()
        .await
        .unwrap();
    assert_isolated(r).await;
}

// ─── permission_rules ──────────────────────────────────────────────────

#[tokio::test]
async fn cross_tenant_permission_rule_delete_returns_404() {
    let pool = common::test_pool().await;
    let (base, client, _ia, _ka, admin_a, ident_b, _kb, admin_b) = two_orgs(pool).await;

    let rule: Value = client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&admin_b).0, auth(&admin_b).1)
        .json(&json!({
            "identity_id": ident_b,
            "action_pattern": "http:**",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rule_id = rule["id"].as_str().unwrap();

    let r = client
        .delete(format!("{base}/v1/permissions/{rule_id}"))
        .header(auth(&admin_a).0, auth(&admin_a).1)
        .send()
        .await
        .unwrap();
    assert_isolated(r).await;
}
