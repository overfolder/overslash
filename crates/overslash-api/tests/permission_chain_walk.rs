//! Hierarchical permission chain walk + approval bubbling tests (SPEC §5).
//!
//! These cover the multi-level resolution model:
//! - chain walk skips `inherit_permissions=true` levels
//! - first level without matching rules and without inherit → gap
//! - approval `identity_id` is the requester; `current_resolver_identity_id`
//!   is the closest ancestor whose own rules already cover the request
//! - "Allow & Remember" places the new rule on the requester's closest
//!   non-`inherit_permissions` ancestor (inclusive) -- not on the requester
//!   if it just borrows permissions
//! - explicit `bubble_up` and the auto-bubble timer advance the resolver
//! - resolver authorization: only the current resolver or one of its
//!   ancestors can act on the approval

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

// ── helpers ─────────────────────────────────────────────────────────

async fn execute(base: &str, api_key: &str, mock_addr: std::net::SocketAddr) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/v1/actions/execute"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
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

async fn add_rule(base: &str, org_key: &str, identity_id: Uuid, pattern: &str, effect: &str) {
    reqwest::Client::new()
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({
            "identity_id": identity_id,
            "action_pattern": pattern,
            "effect": effect,
        }))
        .send()
        .await
        .unwrap();
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
    resp["id"].as_str().unwrap().parse().unwrap()
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

/// Bootstrap an org with a `test_token` secret. Returns (base, org_key, org_id, mock_addr).
async fn bootstrap(pool: sqlx::PgPool) -> (String, String, Uuid, std::net::SocketAddr) {
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let mock_addr = common::start_mock().await;

    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "ChainOrg", "slug": format!("chain-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    let org_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "org-admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_key = org_key_resp["key"].as_str().unwrap().to_string();

    // Secret used to trigger Layer 2 gating.
    client
        .put(format!("{base}/v1/secrets/test_token"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"value": "secret123"}))
        .send()
        .await
        .unwrap();

    (base, org_key, org_id, mock_addr)
}

// ── Test 1: single agent gap → approval at agent, resolver = user ───

#[tokio::test]
async fn agent_no_rules_gap_resolver_is_user() {
    let pool = common::test_pool().await;
    let (base, org_key, org_id, mock_addr) = bootstrap(pool).await;

    let user_id = create_identity(&base, &org_key, "alice", "user", None).await;
    let agent_id = create_identity(&base, &org_key, "bot", "agent", Some(user_id)).await;
    let agent_key = create_api_key(&base, &org_key, org_id, agent_id, "agent-key").await;

    let resp = execute(&base, &agent_key, mock_addr).await;
    assert_eq!(resp.status(), 202);
    let body: Value = resp.json().await.unwrap();
    let approval_id = body["approval_id"].as_str().unwrap().to_string();

    // Look up the approval and assert resolver fields
    let appr: Value = reqwest::Client::new()
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(appr["identity_id"], json!(agent_id));
    assert_eq!(appr["requesting_identity_id"], json!(agent_id));
    assert_eq!(appr["current_resolver_identity_id"], json!(user_id));
}

// ── Test 2: spec example -- service-b request goes to Chief ─────────

#[tokio::test]
async fn spec_example_service_b_routes_to_chief() {
    let pool = common::test_pool().await;
    let (base, org_key, org_id, mock_addr) = bootstrap(pool.clone()).await;

    // User → Chief → Marketing → Researcher(inherit=true)
    let user_id = create_identity(&base, &org_key, "alice", "user", None).await;
    let chief_id = create_identity(&base, &org_key, "chief", "agent", Some(user_id)).await;
    let marketing_id =
        create_identity(&base, &org_key, "marketing", "sub_agent", Some(chief_id)).await;
    let researcher_id = create_identity(
        &base,
        &org_key,
        "researcher",
        "sub_agent",
        Some(marketing_id),
    )
    .await;
    let researcher_key = create_api_key(&base, &org_key, org_id, researcher_id, "rk").await;
    overslash_db::repos::identity::set_inherit_permissions(&pool, researcher_id, true)
        .await
        .unwrap();

    // Chief has rules covering ALL hosts; Marketing only the test mock host.
    // Researcher hits a different host (mock /echo) that Marketing covers, but
    // requires another action (POST) the chief covers via http:**.
    // Actually we need a service-b/service-c analogue. The Mode A test uses
    // raw HTTP keys: http:METHOD:host/path. We'll use distinct paths.

    // Marketing covers GETs only on the mock; Chief covers all methods.
    let host_glob = format!("http:GET:{mock_addr}/**");
    add_rule(&base, &org_key, marketing_id, &host_glob, "allow").await;
    add_rule(
        &base,
        &org_key,
        chief_id,
        &format!("http:**:{mock_addr}/**"),
        "allow",
    )
    .await;

    // Researcher does a POST → marketing's GET-only rule doesn't cover →
    // gap at marketing → resolver search above marketing: chief covers POST.
    let resp = execute(&base, &researcher_key, mock_addr).await;
    assert_eq!(resp.status(), 202);
    let body: Value = resp.json().await.unwrap();
    let approval_id = body["approval_id"].as_str().unwrap();

    let appr: Value = reqwest::Client::new()
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(appr["identity_id"], json!(researcher_id));
    assert_eq!(appr["current_resolver_identity_id"], json!(chief_id));
}

// ── Test 3: Approve+Remember places rule on Marketing, not Researcher ─

#[tokio::test]
async fn remember_places_rule_on_closest_non_inherit_ancestor() {
    let pool = common::test_pool().await;
    let (base, org_key, org_id, mock_addr) = bootstrap(pool.clone()).await;

    let user_id = create_identity(&base, &org_key, "alice", "user", None).await;
    let chief_id = create_identity(&base, &org_key, "chief", "agent", Some(user_id)).await;
    let marketing_id =
        create_identity(&base, &org_key, "marketing", "sub_agent", Some(chief_id)).await;
    let researcher_id = create_identity(
        &base,
        &org_key,
        "researcher",
        "sub_agent",
        Some(marketing_id),
    )
    .await;
    let researcher_key = create_api_key(&base, &org_key, org_id, researcher_id, "rk").await;
    overslash_db::repos::identity::set_inherit_permissions(&pool, researcher_id, true)
        .await
        .unwrap();

    // Marketing has nothing (gap will land on Marketing).
    // Chief covers everything (will be the resolver).
    add_rule(
        &base,
        &org_key,
        chief_id,
        &format!("http:**:{mock_addr}/**"),
        "allow",
    )
    .await;

    let resp = execute(&base, &researcher_key, mock_addr).await;
    assert_eq!(resp.status(), 202);
    let approval_id: String = resp.json::<Value>().await.unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Approve & remember (org admin key acts on behalf of the resolver).
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"resolution": "allow_remember"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // The new rule should be on Marketing (Researcher's closest non-inherit
    // ancestor), not on Researcher.
    let marketing_rules =
        overslash_db::repos::permission_rule::list_by_identity(&pool, marketing_id)
            .await
            .unwrap();
    assert!(!marketing_rules.is_empty(), "expected rule on marketing");
    let researcher_rules =
        overslash_db::repos::permission_rule::list_by_identity(&pool, researcher_id)
            .await
            .unwrap();
    assert!(
        researcher_rules.is_empty(),
        "no rule should be placed on researcher"
    );

    // Re-execute → researcher inherits, marketing now has the rule, chief has it → 200
    let resp = execute(&base, &researcher_key, mock_addr).await;
    assert_eq!(resp.status(), 200);
}

// ── Test 4: explicit bubble_up advances resolver to the user ────────

#[tokio::test]
async fn explicit_bubble_up_advances_resolver() {
    let pool = common::test_pool().await;
    let (base, org_key, org_id, mock_addr) = bootstrap(pool.clone()).await;

    let user_id = create_identity(&base, &org_key, "alice", "user", None).await;
    let chief_id = create_identity(&base, &org_key, "chief", "agent", Some(user_id)).await;
    let marketing_id =
        create_identity(&base, &org_key, "marketing", "sub_agent", Some(chief_id)).await;
    let researcher_id = create_identity(
        &base,
        &org_key,
        "researcher",
        "sub_agent",
        Some(marketing_id),
    )
    .await;
    let researcher_key = create_api_key(&base, &org_key, org_id, researcher_id, "rk").await;
    overslash_db::repos::identity::set_inherit_permissions(&pool, researcher_id, true)
        .await
        .unwrap();

    add_rule(
        &base,
        &org_key,
        chief_id,
        &format!("http:**:{mock_addr}/**"),
        "allow",
    )
    .await;

    let approval_id: String = execute(&base, &researcher_key, mock_addr)
        .await
        .json::<Value>()
        .await
        .unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // bubble_up from chief → user
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"resolution": "bubble_up"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["current_resolver_identity_id"], json!(user_id));
    assert_eq!(body["status"], "pending");
}

// ── Test 5: auto-bubble timer advances stuck approvals ──────────────

#[tokio::test]
async fn auto_bubble_advances_resolver() {
    let pool = common::test_pool().await;
    let (base, org_key, org_id, _mock_addr) = bootstrap(pool.clone()).await;

    let user_id = create_identity(&base, &org_key, "alice", "user", None).await;
    let chief_id = create_identity(&base, &org_key, "chief", "agent", Some(user_id)).await;
    let researcher_id =
        create_identity(&base, &org_key, "researcher", "sub_agent", Some(chief_id)).await;

    overslash_db::repos::org::set_approval_auto_bubble_secs(&pool, org_id, 1)
        .await
        .unwrap();

    // Force-create a pending approval at chief and push its resolver_assigned_at
    // into the past so process_auto_bubble picks it up.
    let token = format!("tok_{}", Uuid::new_v4());
    let approval = overslash_db::repos::approval::create(
        &pool,
        &overslash_db::repos::approval::CreateApproval {
            org_id,
            identity_id: researcher_id,
            current_resolver_identity_id: chief_id,
            action_summary: "test",
            action_detail: None,
            permission_keys: &["http:GET:example.com/x".to_string()],
            token: &token,
            expires_at: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        },
    )
    .await
    .unwrap();

    sqlx::query!(
        "UPDATE approvals SET resolver_assigned_at = now() - interval '10 seconds' WHERE id = $1",
        approval.id,
    )
    .execute(&pool)
    .await
    .unwrap();

    let bubbled = overslash_api::services::permission_chain::process_auto_bubble(&pool)
        .await
        .unwrap();
    assert!(bubbled >= 1);

    let updated = overslash_db::repos::approval::get_by_id(&pool, approval.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.current_resolver_identity_id, user_id);
}

// ── Test 6: Layer 1 deny short-circuits chain walk ──────────────────

#[tokio::test]
async fn deny_rule_in_chain_short_circuits() {
    let pool = common::test_pool().await;
    let (base, org_key, org_id, mock_addr) = bootstrap(pool.clone()).await;

    let user_id = create_identity(&base, &org_key, "alice", "user", None).await;
    let agent_id = create_identity(&base, &org_key, "agent", "agent", Some(user_id)).await;
    let sub_id = create_identity(&base, &org_key, "sub", "sub_agent", Some(agent_id)).await;
    let sub_key = create_api_key(&base, &org_key, org_id, sub_id, "sk").await;
    overslash_db::repos::identity::set_inherit_permissions(&pool, sub_id, true)
        .await
        .unwrap();

    add_rule(&base, &org_key, agent_id, "http:POST:**", "deny").await;

    let resp = execute(&base, &sub_key, mock_addr).await;
    assert_eq!(resp.status(), 403);
}

// ── Test: bubble_up at the top of the chain is rejected ────────────

#[tokio::test]
async fn bubble_up_at_top_returns_conflict() {
    // Single-agent chain: approval lands with current_resolver=user from
    // the start. A bubble_up has nowhere to go and must 409 instead of
    // resetting the auto-bubble timer or logging "bubbled X→X".
    let pool = common::test_pool().await;
    let (base, org_key, org_id, mock_addr) = bootstrap(pool).await;

    let user_id = create_identity(&base, &org_key, "alice", "user", None).await;
    let agent_id = create_identity(&base, &org_key, "bot", "agent", Some(user_id)).await;
    let agent_key = create_api_key(&base, org_id, agent_id, "ak").await;

    let approval_id: String = execute(&base, &agent_key, mock_addr)
        .await
        .json::<Value>()
        .await
        .unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"resolution": "bubble_up"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}

// ── Test: deny rule above the gap still blocks (cannot be approved) ─

#[tokio::test]
async fn deny_rule_above_gap_short_circuits() {
    // U → Chief(deny POST) → Marketing(no rules) → Researcher(inherit).
    // Researcher hits a gap at Marketing, but Chief has a deny rule that
    // applies to the same key. The walk MUST keep going past the gap and
    // honor the deny -- otherwise we'd create an approval for an action
    // that should be unconditionally rejected.
    let pool = common::test_pool().await;
    let (base, org_key, org_id, mock_addr) = bootstrap(pool.clone()).await;

    let user_id = create_identity(&base, &org_key, "alice", "user", None).await;
    let chief_id = create_identity(&base, &org_key, "chief", "agent", Some(user_id)).await;
    let marketing_id =
        create_identity(&base, &org_key, "marketing", "sub_agent", Some(chief_id)).await;
    let researcher_id = create_identity(
        &base,
        &org_key,
        "researcher",
        "sub_agent",
        Some(marketing_id),
    )
    .await;
    let researcher_key = create_api_key(&base, org_id, researcher_id, "rk").await;
    overslash_db::repos::identity::set_inherit_permissions(&pool, researcher_id, true)
        .await
        .unwrap();

    add_rule(&base, &org_key, chief_id, "http:POST:**", "deny").await;

    let resp = execute(&base, &researcher_key, mock_addr).await;
    assert_eq!(resp.status(), 403);
}

// ── Test 8: a sibling agent cannot resolve someone else's approval ──

#[tokio::test]
async fn unrelated_identity_cannot_resolve() {
    let pool = common::test_pool().await;
    let (base, org_key, org_id, mock_addr) = bootstrap(pool).await;

    let user_id = create_identity(&base, &org_key, "alice", "user", None).await;
    let agent_a = create_identity(&base, &org_key, "agent-a", "agent", Some(user_id)).await;
    let agent_a_key = create_api_key(&base, &org_key, org_id, agent_a, "ka").await;
    // Sibling agent under the same user — not in agent-a's chain.
    let agent_b = create_identity(&base, &org_key, "agent-b", "agent", Some(user_id)).await;
    let agent_b_key = create_api_key(&base, &org_key, org_id, agent_b, "kb").await;

    // Agent A triggers an approval (no rules → gap at A → resolver = user).
    let approval_id: String = execute(&base, &agent_a_key, mock_addr)
        .await
        .json::<Value>()
        .await
        .unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Agent B (a sibling, not an ancestor of the resolver) cannot resolve.
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", format!("Bearer {agent_b_key}"))
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Agent A (the requester itself) also cannot resolve — agents are never
    // allowed to resolve their own approvals.
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", format!("Bearer {agent_a_key}"))
        .json(&json!({"resolution": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

// ── Test 7: auto_bubble_secs=0 routes initial resolver straight to user ─

#[tokio::test]
async fn force_user_resolver_when_auto_bubble_zero() {
    let pool = common::test_pool().await;
    let (base, org_key, org_id, mock_addr) = bootstrap(pool.clone()).await;

    // U → Chief(covers POST) → Marketing(no rules) → Researcher(inherit).
    // Without forcing, the resolver would be Chief. With auto_bubble=0, the
    // initial resolver is the user instead.
    let user_id = create_identity(&base, &org_key, "alice", "user", None).await;
    let chief_id = create_identity(&base, &org_key, "chief", "agent", Some(user_id)).await;
    let marketing_id =
        create_identity(&base, &org_key, "marketing", "sub_agent", Some(chief_id)).await;
    let researcher_id = create_identity(
        &base,
        &org_key,
        "researcher",
        "sub_agent",
        Some(marketing_id),
    )
    .await;
    let researcher_key = create_api_key(&base, &org_key, org_id, researcher_id, "rk").await;
    overslash_db::repos::identity::set_inherit_permissions(&pool, researcher_id, true)
        .await
        .unwrap();

    add_rule(
        &base,
        &org_key,
        chief_id,
        &format!("http:**:{mock_addr}/**"),
        "allow",
    )
    .await;

    overslash_db::repos::org::set_approval_auto_bubble_secs(&pool, org_id, 0)
        .await
        .unwrap();

    let resp = execute(&base, &researcher_key, mock_addr).await;
    assert_eq!(resp.status(), 202);
    let approval_id: String = resp.json::<Value>().await.unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();

    let appr: Value = reqwest::Client::new()
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // With auto_bubble_secs=0, resolver bypasses agents and goes to user directly.
    assert_eq!(appr["current_resolver_identity_id"], json!(user_id));
}
