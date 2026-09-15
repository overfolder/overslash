//! A first-level agent is born able to set itself up.
//!
//! Covers the seed written by `org_bootstrap::bootstrap_agent_in_org`: which
//! identities get it, which deliberately do not, that the org flag gates it and
//! is never retroactive, that it actually removes the approval round-trip, and
//! — the half that matters most — that it does **not** widen into the `_share`
//! side of any of the four splits.
use crate::common;

use serde_json::{Value, json};
use uuid::Uuid;

/// The four anchors, as `org_bootstrap::AGENT_SELF_SETUP_PATTERNS` spells them.
/// Restated here on purpose: a test that imported the constant would pass no
/// matter what someone added to it, and the point of this list is that adding a
/// fifth anchor has to be a deliberate, reviewed edit in two places.
const EXPECTED: [&str; 4] = [
    "overslash:manage_connections_own:*",
    "overslash:manage_services_own:*",
    "overslash:manage_templates_own:*",
    "overslash:request_secrets_own:*",
];

async fn create_identity(
    client: &reqwest::Client,
    base: &str,
    admin_key: &str,
    body: Value,
) -> Value {
    let resp = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "create identity failed: {:?}",
        resp.text().await
    );
    resp.json().await.unwrap()
}

/// Sorted `overslash:`-scoped patterns on an identity, straight from the DB so
/// the assertion does not depend on how the API projects rules.
async fn overslash_rules(pool: &sqlx::PgPool, identity_id: Uuid) -> Vec<String> {
    let mut rules: Vec<String> = sqlx::query_scalar!(
        "SELECT action_pattern FROM permission_rules
          WHERE identity_id = $1 AND effect = 'allow' AND action_pattern LIKE 'overslash:%'",
        identity_id
    )
    .fetch_all(pool)
    .await
    .unwrap();
    rules.sort();
    rules
}

async fn set_self_setup(
    client: &reqwest::Client,
    base: &str,
    admin_key: &str,
    org_id: Uuid,
    on: bool,
) {
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/execution-settings"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "default_agent_self_setup": on }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "patch execution-settings failed: {:?}",
        resp.text().await
    );
}

#[tokio::test]
async fn first_level_agent_is_seeded_with_exactly_the_four_anchors() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org_id, agent_id, _agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    assert_eq!(
        overslash_rules(&pool, agent_id).await,
        EXPECTED.to_vec(),
        "a first-level agent must hold exactly the four self-setup anchors"
    );
}

#[tokio::test]
async fn sub_agent_is_not_seeded() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org_id, agent_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let sub = create_identity(
        &client,
        &base,
        &admin_key,
        json!({"name": "sub", "kind": "sub_agent", "parent_id": agent_id}),
    )
    .await;
    let sub_id: Uuid = sub["id"].as_str().unwrap().parse().unwrap();

    assert!(
        overslash_rules(&pool, sub_id).await.is_empty(),
        "sub-agents are not first-level and must not be seeded"
    );
}

/// The nuance a `kind`-only guard would get wrong. `POST /v1/identities`
/// refuses a `kind: "agent"` under a non-user parent, but the MCP enrollment
/// path does not — it always writes `kind = 'agent'` and lets the user pick one
/// of their existing agents as the parent, producing a depth-2 agent row.
/// Whichever door it comes through, depth is what decides.
#[tokio::test]
async fn agent_kind_below_depth_one_is_not_seeded() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, agent_id, _agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Mint the row the enrollment path would: kind = 'agent' at depth 2.
    let deep = overslash_db::repos::identity::create_with_parent(
        &pool,
        org_id,
        "deep-agent",
        "agent",
        None,
        agent_id,
        2,
        agent_id,
        false,
    )
    .await
    .unwrap();

    let seeded = overslash_db::repos::org_bootstrap::bootstrap_agent_in_org(&pool, org_id, deep.id)
        .await
        .unwrap();

    assert_eq!(
        seeded, 0,
        "depth 2 must not be seeded even when kind='agent'"
    );
    assert!(overslash_rules(&pool, deep.id).await.is_empty());
}

#[tokio::test]
async fn user_identity_is_not_seeded() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org_id, _agent_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let user = create_identity(
        &client,
        &base,
        &admin_key,
        json!({"name": "another-user", "kind": "user"}),
    )
    .await;
    let user_id: Uuid = user["id"].as_str().unwrap().parse().unwrap();

    assert!(
        overslash_rules(&pool, user_id).await.is_empty(),
        "users are never gated at Layer 2, so seeding them would be noise"
    );
}

#[tokio::test]
async fn org_flag_off_seeds_nothing() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org_id, agent_id, _agent_key, _admin_key) =
        common::bootstrap_org_identity_no_seed(&base, &client).await;

    assert!(
        overslash_rules(&pool, agent_id).await.is_empty(),
        "default_agent_self_setup = false must seed nothing"
    );
}

/// The no-backfill decision, pinned: the flag is read at creation time only.
#[tokio::test]
async fn flipping_the_flag_on_does_not_backfill() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, agent_id, _agent_key, admin_key) =
        common::bootstrap_org_identity_no_seed(&base, &client).await;

    set_self_setup(&client, &base, &admin_key, org_id, true).await;

    assert!(
        overslash_rules(&pool, agent_id).await.is_empty(),
        "an agent created while the flag was off must stay unseeded"
    );
}

#[tokio::test]
async fn seeding_is_idempotent() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, agent_id, _agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let again = overslash_db::repos::org_bootstrap::bootstrap_agent_in_org(&pool, org_id, agent_id)
        .await
        .unwrap();

    assert_eq!(again, 0, "a second call must write nothing");
    assert_eq!(overslash_rules(&pool, agent_id).await, EXPECTED.to_vec());
}

/// The point of the whole change: the call that cost an approval now returns
/// its result inline.
#[tokio::test]
async fn seeded_agent_reads_a_template_without_an_approval() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org_id, _agent_id, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({"service": "overslash", "action": "list_templates"}))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "a seeded agent must not be sent to an approval for list_templates: {body}"
    );
    assert_ne!(body["status"], "pending_approval");
}

/// The bound. Seeding hands over the `_own` half of each split and nothing
/// else, so every socialising move still refuses.
#[tokio::test]
async fn seeded_rules_do_not_reach_the_share_half() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (_org_id, _agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // A second user in the same org, to target with a cross-identity request.
    let other = create_identity(
        &client,
        &base,
        &admin_key,
        json!({"name": "someone-else", "kind": "user"}),
    )
    .await;
    let other_id = other["id"].as_str().unwrap();

    // `request_secrets_share`: minting a provide URL against an identity that
    // is neither the caller nor a descendant needs admin.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "overslash",
            "action": "request_secret",
            "params": { "secret_name": "SOME_KEY", "identity_id": other_id }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "request_secrets_own must not reach another identity: {:?}",
        resp.text().await
    );

    // Org-level instances are an admin act: `user_level: false` requires it,
    // and a seeded agent's ceiling tops out at the Everyone `write` grant.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "overslash",
            "action": "create_service",
            "params": { "template_key": "http", "name": "org-wide", "user_level": false }
        }))
        .send()
        .await
        .unwrap();
    assert!(
        !resp.status().is_success(),
        "manage_services_own must not create an org-level instance"
    );
}

/// The hole seeding would otherwise have opened.
///
/// `kernel_update_service` only ever checked `is_system`: the ownership test
/// lived in the REST route, and the platform/MCP bridge calls the kernel
/// directly. Before this change reaching it cost a human approval; a seeded
/// agent reaches it with nobody in the loop, so the guard moved into the
/// kernel. Rewriting `url` on someone else's credential-bearing instance is
/// the specific move being refused — it would aim their injected secret at a
/// host the caller picked.
#[tokio::test]
async fn seeded_agent_cannot_touch_another_users_instance() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (org_id, _agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // A second user with their own http instance, owned by them, not by our
    // agent's owner. `http` is a system instance, so build a user-level one
    // from a template the registry always ships.
    let victim = create_identity(
        &client,
        &base,
        &admin_key,
        json!({"name": "victim", "kind": "user"}),
    )
    .await;
    let victim_id: Uuid = victim["id"].as_str().unwrap().parse().unwrap();
    let victim_key: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"org_id": org_id, "identity_id": victim_id, "name": "victim-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let victim_key = victim_key["key"].as_str().unwrap().to_string();

    let created: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {victim_key}"))
        .json(
            &json!({"template_key": "metabase", "name": "victims-metabase",
                      "url": "https://victim.example.com", "secret_name": "VICTIM_KEY"}),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let victim_instance = created["id"]
        .as_str()
        .unwrap_or_else(|| panic!("create service failed: {created}"));

    // Read by id: must not confirm the row exists.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "overslash", "action": "get_service",
            "params": { "name": victim_instance }
        }))
        .send()
        .await
        .unwrap();
    assert!(
        !resp.status().is_success(),
        "a seeded agent must not read another user's instance by id"
    );

    // Rewrite its URL: the exfiltration primitive.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "overslash", "action": "update_service",
            "params": { "id": victim_instance, "url": "https://attacker.example.com" }
        }))
        .send()
        .await
        .unwrap();
    assert!(
        !resp.status().is_success(),
        "a seeded agent must not rebind another user's instance"
    );

    // And the row is untouched.
    let after: Value = client
        .get(format!("{base}/v1/services/{victim_instance}"))
        .header("Authorization", format!("Bearer {victim_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(after["url"], "https://victim.example.com");
}

// ── Backfill ────────────────────────────────────────────────────────────
//
// The seed is deliberately never retroactive, which leaves every org that
// predates D79 with agents the policy never reached. The backfill endpoint is
// the admin's one-click catch-up for exactly that population.

async fn backfill(
    client: &reqwest::Client,
    base: &str,
    key: &str,
    org_id: Uuid,
) -> reqwest::Response {
    client
        .post(format!("{base}/v1/orgs/{org_id}/agent-self-setup/backfill"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
}

/// An agent created while the flag was off stays unseeded (pinned above by
/// `flipping_the_flag_on_does_not_backfill`) — until an admin asks for it.
#[tokio::test]
async fn backfill_grants_the_four_anchors_to_pre_existing_agents() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, agent_id, _agent_key, admin_key) =
        common::bootstrap_org_identity_no_seed(&base, &client).await;

    assert!(overslash_rules(&pool, agent_id).await.is_empty());
    set_self_setup(&client, &base, &admin_key, org_id, true).await;

    let resp = backfill(&client, &base, &admin_key, org_id).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.unwrap();

    assert_eq!(body["agents_granted"], 1);
    assert_eq!(body["rules_written"], 4);
    assert_eq!(body["agents_missing_self_setup"], 0);
    assert_eq!(overslash_rules(&pool, agent_id).await, EXPECTED.to_vec());
}

/// A second click must not double-write. `permission_rules` has no unique
/// index (two writers legitimately re-insert the same pattern with a fresh
/// expiry), so idempotency is the statement's `NOT EXISTS`, not the schema's.
#[tokio::test]
async fn backfill_is_idempotent() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, agent_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = backfill(&client, &base, &admin_key, org_id).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["agents_granted"], 0, "already seeded at creation");
    assert_eq!(body["rules_written"], 0);
    assert_eq!(overslash_rules(&pool, agent_id).await, EXPECTED.to_vec());
}

/// Partial coverage is the interesting case: an agent holding some of the four
/// gets only the missing ones, and the rule count reflects that rather than
/// `agents * 4`.
#[tokio::test]
async fn backfill_fills_only_the_missing_rules() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, agent_id, _agent_key, admin_key) =
        common::bootstrap_org_identity_no_seed(&base, &client).await;

    // Hand-grant one of the four, the way an admin would have before D79.
    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "identity_id": agent_id,
            "action_pattern": "overslash:manage_services_own:*",
            "effect": "allow"
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "seed grant: {:?}",
        resp.text().await
    );

    set_self_setup(&client, &base, &admin_key, org_id, true).await;
    let body: Value = backfill(&client, &base, &admin_key, org_id)
        .await
        .json()
        .await
        .unwrap();

    assert_eq!(body["agents_granted"], 1);
    assert_eq!(body["rules_written"], 3, "the held rule is not rewritten");
    assert_eq!(overslash_rules(&pool, agent_id).await, EXPECTED.to_vec());
}

/// Sub-agents are outside the policy, so they are outside the catch-up too.
#[tokio::test]
async fn backfill_skips_sub_agents() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, agent_id, _agent_key, admin_key) =
        common::bootstrap_org_identity_no_seed(&base, &client).await;

    let sub = create_identity(
        &client,
        &base,
        &admin_key,
        json!({"name": "sub", "kind": "sub_agent", "parent_id": agent_id}),
    )
    .await;
    let sub_id: Uuid = sub["id"].as_str().unwrap().parse().unwrap();

    set_self_setup(&client, &base, &admin_key, org_id, true).await;
    backfill(&client, &base, &admin_key, org_id).await;

    assert_eq!(overslash_rules(&pool, agent_id).await, EXPECTED.to_vec());
    assert!(
        overslash_rules(&pool, sub_id).await.is_empty(),
        "a sub-agent must not be caught by the backfill"
    );
}

/// The toggle and the button cannot disagree about the org's policy: granting
/// against a default the org has declined would hand out exactly what it opted
/// out of. Refused with a 409 that says so, not a silent no-op.
#[tokio::test]
async fn backfill_refuses_while_the_default_is_off() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, agent_id, _agent_key, admin_key) =
        common::bootstrap_org_identity_no_seed(&base, &client).await;

    let resp = backfill(&client, &base, &admin_key, org_id).await;
    assert_eq!(resp.status(), reqwest::StatusCode::CONFLICT);
    assert!(overslash_rules(&pool, agent_id).await.is_empty());
}

/// Bulk privilege grant ⇒ admin only. A seeded agent holds
/// `manage_services_own`, which must not be a route to granting it to everyone.
#[tokio::test]
async fn backfill_is_admin_only() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, _agent_id, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = backfill(&client, &base, &agent_key, org_id).await;
    assert!(
        resp.status().is_client_error(),
        "a non-admin must not backfill: {}",
        resp.status()
    );
}

/// The count that labels the button has to mean "agents a click would touch",
/// so it drops to zero once they are covered.
#[tokio::test]
async fn pending_count_tracks_the_backfill() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (org_id, _agent_id, _agent_key, admin_key) =
        common::bootstrap_org_identity_no_seed(&base, &client).await;

    let settings: Value = client
        .get(format!("{base}/v1/orgs/{org_id}/execution-settings"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(settings["agents_missing_self_setup"], 1);

    set_self_setup(&client, &base, &admin_key, org_id, true).await;
    backfill(&client, &base, &admin_key, org_id).await;

    let settings: Value = client
        .get(format!("{base}/v1/orgs/{org_id}/execution-settings"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(settings["agents_missing_self_setup"], 0);
}

/// Bulk grants leave a trail naming who ran it and how much it touched.
#[tokio::test]
async fn backfill_is_audited() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, _agent_id, _agent_key, admin_key) =
        common::bootstrap_org_identity_no_seed(&base, &client).await;

    set_self_setup(&client, &base, &admin_key, org_id, true).await;
    backfill(&client, &base, &admin_key, org_id).await;

    let detail: serde_json::Value = sqlx::query_scalar!(
        "SELECT detail FROM audit_log
          WHERE org_id = $1 AND action = 'org.agent_self_setup.backfilled'
          ORDER BY created_at DESC LIMIT 1",
        org_id
    )
    .fetch_one(&pool)
    .await
    .expect("backfill must write an audit row");

    assert_eq!(detail["agents_granted"], 1);
    assert_eq!(detail["rules_written"], 4);
}
