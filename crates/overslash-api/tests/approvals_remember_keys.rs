//! `remember_keys` validation and rule writing for "Allow & Remember"
//! (`crates/overslash-api/src/routes/approvals.rs`).
//!
//! A remember key has to be *about the request being approved*: it must cover
//! at least one of the approval's `permission_keys`. That admits every
//! suggested-tier key (a tier is those keys broadened) plus a hand-typed key
//! the dashboard's "Custom… (advanced)" field produces, while still rejecting
//! an unrelated grant. Rules are written once per distinct key — a multi-key
//! approval whose tier collapses onto one key must not write it N times.
//!
//! The rule's expiry: an explicit `ttl` wins (`"forever"` = none), and an
//! omitted one takes the org's `default_remember_ttl_secs` — 7 days unless an
//! admin changed it.

use crate::common;

use serde_json::{Value, json};
use uuid::Uuid;

async fn call_echo(
    base: &str,
    api_key: &str,
    mock_addr: std::net::SocketAddr,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http",
            "method": "POST",
            "url": format!("http://{mock_addr}/echo"),
            "headers": {"Content-Type": "application/json"},
            "body": "{}",
            "secrets": [{"name": "test_token", "inject_as": "header", "header_name": "X-Token"}]
        }))
        .send()
        .await
        .unwrap()
}

async fn create_identity(
    base: &str,
    org_key: &str,
    name: &str,
    kind: &str,
    parent_id: Option<Uuid>,
) -> Uuid {
    let mut body = json!({"name": name, "kind": kind});
    if let Some(pid) = parent_id {
        body["parent_id"] = json!(pid);
    }
    let resp: Value = reqwest::Client::new()
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id: Uuid = resp["id"].as_str().unwrap().parse().unwrap();
    // Secrets live in per-user vaults: the inline `test_token` every agent
    // here sends resolves in its owner user's vault, so seed it there.
    if kind == "user" {
        let put = reqwest::Client::new()
            .put(format!("{base}/v1/secrets/test_token?owner={id}"))
            .header("Authorization", format!("Bearer {org_key}"))
            .json(&json!({"value": "secret123"}))
            .send()
            .await
            .unwrap();
        assert_eq!(put.status(), 200);
    }
    id
}

async fn create_api_key(
    base: &str,
    org_key: &str,
    org_id: Uuid,
    identity_id: Uuid,
    name: &str,
) -> String {
    let resp: Value = reqwest::Client::new()
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"org_id": org_id, "identity_id": identity_id, "name": name}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["key"].as_str().unwrap().to_string()
}

/// Boot the API + mock upstream, seed the injected secret, and return a
/// pending approval raised by an agent with no rules covering *this* request.
/// (It does hold the four `overslash:*_own` self-setup rules every first-level
/// agent is seeded with; those are about the platform metaservice and never
/// match the `http:` keys this file exercises — `written_rules` filters them.)
async fn pending_approval(
    pool: sqlx::PgPool,
    fx: &common::BootstrapFixtures,
) -> (String, String, String, Uuid, Uuid, std::net::SocketAddr) {
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let mock_addr = common::start_mock().await;
    let org_id = fx.org_id;
    let org_key = fx.org_key.clone();

    // Rules land only after the replay succeeds; defer execution so the
    // explicit `/call` below owns it instead of racing an auto-call.
    client
        .patch(format!("{base}/v1/orgs/{org_id}/execution-settings"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"default_deferred_execution": true}))
        .send()
        .await
        .unwrap();

    client
        .put(format!("{base}/v1/secrets/test_token"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"value": "secret123"}))
        .send()
        .await
        .unwrap();

    let user_id = create_identity(&base, &org_key, "alice", "user", None).await;
    let agent_id = create_identity(&base, &org_key, "agent-a", "agent", Some(user_id)).await;
    let agent_key = create_api_key(&base, &org_key, org_id, agent_id, "agent-a-key").await;

    let resp = call_echo(&base, &agent_key, mock_addr).await;
    assert_eq!(resp.status(), 202, "expected 202 approval-required");
    let approval_id = resp.json::<Value>().await.unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    (
        base,
        org_key,
        agent_key,
        approval_id.parse().unwrap(),
        agent_id,
        mock_addr,
    )
}

async fn resolve_remember(
    base: &str,
    org_key: &str,
    approval_id: Uuid,
    keys: Value,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"resolution": "allow_remember", "remember_keys": keys}))
        .send()
        .await
        .unwrap()
}

/// Every rule the remember flow wrote, across the requester and its ancestor
/// (placement lands on the closest non-inherit ancestor).
async fn written_rules(base: &str, org_key: &str, identity_id: Uuid) -> Vec<String> {
    let rows: Value = reqwest::Client::new()
        .get(format!("{base}/v1/permissions?identity_id={identity_id}"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    rows.as_array()
        .unwrap()
        .iter()
        .map(|r| r["action_pattern"].as_str().unwrap().to_string())
        // Drop the `overslash:*_own` rules a first-level agent is seeded with
        // at creation. Every test in this file is about what an *approval*
        // remembered, and the seed would otherwise show up as four extra rows.
        .filter(|p| !p.starts_with("overslash:"))
        .collect()
}

/// A hand-typed key that is broader than the request — the "Custom…
/// (advanced)" field's whole point — used to 400 for not appearing verbatim
/// in a suggested tier. It covers the requested key, so it is accepted.
#[tokio::test]
async fn broader_hand_typed_remember_key_is_accepted() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, org_key, agent_key, approval_id, agent_id, mock_addr) =
        pending_approval(pool, &fx).await;

    // Broader than the request and in no tier: the ladder only ever emits the
    // concrete method then `ANY`, never a `*` action.
    let custom = format!("http:*:{mock_addr}/**");
    let resp = resolve_remember(&base, &org_key, approval_id, json!([custom])).await;
    assert_eq!(
        resp.status(),
        200,
        "custom key covering the request must be accepted: {}",
        resp.text().await.unwrap_or_default()
    );

    // Rules are only committed once the replay succeeds.
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{approval_id}/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    assert_eq!(written_rules(&base, &org_key, agent_id).await, [custom]);
}

#[tokio::test]
async fn unrelated_remember_key_is_rejected() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, org_key, _agent_key, approval_id, _agent_id, _mock_addr) =
        pending_approval(pool, &fx).await;

    let resp = resolve_remember(&base, &org_key, approval_id, json!(["github:*:*"])).await;
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("does not cover"),
        "expected a coverage error, got: {body}"
    );
}

/// The broad tiers of a multi-key approval collapse onto a single key. Before
/// the dedupe that arrived as the same key repeated once per recipient, and
/// each repeat wrote its own identical rule.
#[tokio::test]
async fn repeated_remember_keys_write_one_rule() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, org_key, agent_key, approval_id, agent_id, mock_addr) =
        pending_approval(pool, &fx).await;

    let key = format!("http:ANY:{mock_addr}/**");
    let resp = resolve_remember(&base, &org_key, approval_id, json!([key, key, key])).await;
    assert_eq!(resp.status(), 200);

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{approval_id}/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    assert_eq!(
        written_rules(&base, &org_key, agent_id).await,
        [key],
        "one distinct key must write exactly one rule"
    );
}

/// Resolve "Allow & Remember" on the approval's own keys with the given
/// `ttl` (omitted when `None`), replay it, and return the written rule's
/// `expires_at` as seconds from now (`None` = forever).
async fn remember_and_read_expiry(
    base: &str,
    org_key: &str,
    agent_key: &str,
    approval_id: Uuid,
    agent_id: Uuid,
    ttl: Option<&str>,
) -> Option<i64> {
    let mut body = json!({"resolution": "allow_remember"});
    if let Some(ttl) = ttl {
        body["ttl"] = json!(ttl);
    }
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "{}",
        resp.text().await.unwrap_or_default()
    );

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{approval_id}/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let rows: Value = reqwest::Client::new()
        .get(format!("{base}/v1/permissions?identity_id={agent_id}"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rule = rows
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            !r["action_pattern"]
                .as_str()
                .unwrap()
                .starts_with("overslash:")
        })
        .expect("the remembered rule");
    rule["expires_at"].as_str().map(|at| {
        let at = time::OffsetDateTime::parse(at, &time::format_description::well_known::Rfc3339)
            .unwrap();
        (at - time::OffsetDateTime::now_utc()).whole_seconds()
    })
}

async fn patch_remember_ttl(base: &str, key: &str, org_id: Uuid, secs: Value) -> reqwest::Response {
    reqwest::Client::new()
        .patch(format!("{base}/v1/orgs/{org_id}/execution-settings"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({"default_remember_ttl_secs": secs}))
        .send()
        .await
        .unwrap()
}

/// Within a minute of `expected` seconds from now — the resolve and the read
/// are a few round trips apart.
fn assert_expires_in(got: Option<i64>, expected: i64) {
    let got = got.expect("rule should expire");
    assert!(
        (expected - 60..=expected).contains(&got),
        "expected ~{expected}s to expiry, got {got}s"
    );
}

#[tokio::test]
async fn omitted_ttl_takes_the_seven_day_org_default() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, org_key, agent_key, approval_id, agent_id, _mock_addr) =
        pending_approval(pool, &fx).await;

    let settings: Value = reqwest::Client::new()
        .get(format!("{base}/v1/orgs/{}/execution-settings", fx.org_id))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(settings["default_remember_ttl_secs"], 604_800);

    let expiry =
        remember_and_read_expiry(&base, &org_key, &agent_key, approval_id, agent_id, None).await;
    assert_expires_in(expiry, 604_800);
}

/// "forever" used to be spelled by leaving `ttl` out. Now that an omission
/// means the org default, it has to be accepted as an explicit value.
#[tokio::test]
async fn explicit_forever_writes_a_permanent_rule() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, org_key, agent_key, approval_id, agent_id, _mock_addr) =
        pending_approval(pool, &fx).await;

    let expiry = remember_and_read_expiry(
        &base,
        &org_key,
        &agent_key,
        approval_id,
        agent_id,
        Some("forever"),
    )
    .await;
    assert_eq!(expiry, None);
}

#[tokio::test]
async fn explicit_ttl_beats_the_org_default() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, org_key, agent_key, approval_id, agent_id, _mock_addr) =
        pending_approval(pool, &fx).await;

    let expiry = remember_and_read_expiry(
        &base,
        &org_key,
        &agent_key,
        approval_id,
        agent_id,
        Some("1h"),
    )
    .await;
    assert_expires_in(expiry, 3_600);
}

#[tokio::test]
async fn a_changed_org_default_applies_to_omitted_ttl() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, org_key, agent_key, approval_id, agent_id, _mock_addr) =
        pending_approval(pool, &fx).await;

    let resp = patch_remember_ttl(&base, &org_key, fx.org_id, json!(86_400)).await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["default_remember_ttl_secs"],
        86_400
    );

    let expiry =
        remember_and_read_expiry(&base, &org_key, &agent_key, approval_id, agent_id, None).await;
    assert_expires_in(expiry, 86_400);
}

#[tokio::test]
async fn a_forever_org_default_writes_permanent_rules() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, org_key, agent_key, approval_id, agent_id, _mock_addr) =
        pending_approval(pool, &fx).await;

    let resp = patch_remember_ttl(&base, &org_key, fx.org_id, Value::Null).await;
    assert_eq!(resp.status(), 200);
    assert!(resp.json::<Value>().await.unwrap()["default_remember_ttl_secs"].is_null());

    let expiry =
        remember_and_read_expiry(&base, &org_key, &agent_key, approval_id, agent_id, None).await;
    assert_eq!(expiry, None);
}

#[tokio::test]
async fn org_default_ttl_is_bounded_and_admin_only() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, org_key, agent_key, _approval_id, _agent_id, _mock_addr) =
        pending_approval(pool, &fx).await;

    for secs in [0, 59, 31_536_001] {
        let resp = patch_remember_ttl(&base, &org_key, fx.org_id, json!(secs)).await;
        assert_eq!(resp.status(), 400, "{secs}s must be rejected");
    }

    let resp = patch_remember_ttl(&base, &agent_key, fx.org_id, json!(3_600)).await;
    assert!(
        resp.status().is_client_error(),
        "a non-admin must not change the org default: {}",
        resp.status()
    );
}
