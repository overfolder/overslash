//! End-to-end coverage for the `overslash_approve` /
//! `overslash_approve_self` MCP tool split + the server-side classifier
//! that gates them.
//!
//! What this file verifies, all on a real Postgres-backed API stack:
//!
//!   * `tools/list` hides `overslash_approve_self` until the binding's
//!     `self_approve_enabled` flag is on. `overslash_approve`
//!     is always listed.
//!   * Caller↔requester relationship classification at the resolve
//!     endpoint:
//!       - User → agent's pending approval → succeeds (Downstream).
//!       - Agent → its own approval, binding flag off → typed
//!         `not_in_your_chain` envelope (SelfApproval rejected).
//!       - Agent → its own approval, binding flag on → succeeds
//!         (SelfApproval allowed; audit row tags relationship + binding).
//!       - Sibling agent → either tool → typed `not_in_your_chain`
//!         (NotInYourChain).
//!   * The `relationship` field decoration on the pending-approval list
//!     response: agent sees `"self"` for its own approvals, ancestor user
//!     sees `"downstream"`.
//!
//! The split between tool name and security boundary is asserted by case
//! (b): the agent calls `overslash_approve_self` (the "right" tool for
//! its relationship) and is still rejected because the binding flag isn't
//! set — the classifier, not the tool name, decides.

#![allow(clippy::disallowed_methods)]

mod common;

use overslash_api::services::jwt;
use overslash_db::repos as db;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

const SIGNING_KEY_HEX: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

fn signing_bytes() -> Vec<u8> {
    hex::decode(SIGNING_KEY_HEX).unwrap()
}

/// Bootstrap an org with a user, two child agents (`agent` and
/// `sibling-agent`), an MCP OAuth client, and bindings for both agents.
/// Mints MCP-aud JWTs for each agent so `/mcp` callers carry
/// `mcp_client_id` in their `AuthContext`.
struct Fx {
    base: String,
    client: reqwest::Client,
    pool: PgPool,
    org_id: Uuid,
    user_id: Uuid,
    agent_id: Uuid,
    sibling_id: Uuid,
    org_admin_key: String,
    user_api_key: String,
    /// Client the *agent* is bound to. Production OAuth consent enforces
    /// `UNIQUE (user_identity_id, client_id)` on bindings, so each agent
    /// under the same user must register its own MCP client.
    agent_client_id: String,
    sibling_client_id: String,
    agent_binding_id: Uuid,
    sibling_binding_id: Uuid,
    agent_mcp_token: String,
    sibling_mcp_token: String,
}

async fn bootstrap() -> Fx {
    let pool = common::test_pool().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, agent_id, _agent_osk, org_admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Find the user that owns `agent` (created by bootstrap as `test-user`).
    let identities: Value = client
        .get(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = identities
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"].as_str() == Some("test-user"))
        .and_then(|i| i["id"].as_str())
        .unwrap()
        .parse()
        .unwrap();

    // Mint a user-bound API key so the user can resolve approvals via REST.
    // The MCP path is agent-only (extractors.rs rejects user-kind subjects on
    // MCP JWTs), so users hit `/v1/approvals/{id}/resolve` with their osk_
    // key directly.
    let user_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({
            "org_id": org_id,
            "identity_id": user_id,
            "name": "user-key",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_api_key = user_key_resp["key"].as_str().unwrap().to_string();

    // Create a sibling agent under the same user.
    let sibling: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_admin_key}"))
        .json(&json!({
            "name": "sibling-agent",
            "kind": "agent",
            "parent_id": user_id,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let sibling_id: Uuid = sibling["id"].as_str().unwrap().parse().unwrap();

    // Insert a users row so anything that derives an email from the user's
    // identity has something to read. Mirrors the helper in mcp_elicitation.rs.
    sqlx::query(
        "INSERT INTO users (id, email, overslash_idp_provider, overslash_idp_subject)
         VALUES ($1, $2, 'test', $3)",
    )
    .bind(user_id)
    .bind(format!("user-{user_id}@example.com"))
    .bind(format!("test-{user_id}"))
    .execute(&pool)
    .await
    .unwrap();

    // Register two MCP clients — one per agent — so each binding satisfies
    // the `UNIQUE (user_identity_id, client_id)` constraint that production
    // consent enforces. Two agents per user is real (a user can connect
    // different Claude instances); two agents on the same client_id is not.
    let agent_client_id = format!("osc_{}", Uuid::new_v4().simple());
    let sibling_client_id = format!("osc_{}", Uuid::new_v4().simple());
    for cid in [&agent_client_id, &sibling_client_id] {
        db::oauth_mcp_client::create(
            &pool,
            &db::oauth_mcp_client::CreateOauthMcpClient {
                client_id: cid,
                client_name: Some("test-mcp"),
                redirect_uris: &["http://127.0.0.1:0/cb".to_string()],
                software_id: Some("com.example.test"),
                software_version: Some("1.0.0"),
                created_ip: None,
                created_user_agent: None,
            },
        )
        .await
        .unwrap();
    }

    let agent_binding =
        db::mcp_client_agent_binding::upsert(&pool, org_id, user_id, &agent_client_id, agent_id)
            .await
            .unwrap();
    let sibling_binding = db::mcp_client_agent_binding::upsert(
        &pool,
        org_id,
        user_id,
        &sibling_client_id,
        sibling_id,
    )
    .await
    .unwrap();

    let agent_mcp_token = jwt::mint_mcp(
        &signing_bytes(),
        agent_id,
        org_id,
        format!("user-{user_id}@example.com"),
        3600,
        Some(agent_client_id.clone()),
    )
    .unwrap();
    let sibling_mcp_token = jwt::mint_mcp(
        &signing_bytes(),
        sibling_id,
        org_id,
        format!("user-{user_id}@example.com"),
        3600,
        Some(sibling_client_id.clone()),
    )
    .unwrap();

    Fx {
        base,
        client,
        pool,
        org_id,
        user_id,
        agent_id,
        sibling_id,
        org_admin_key,
        user_api_key,
        agent_client_id,
        sibling_client_id,
        agent_binding_id: agent_binding.id,
        sibling_binding_id: sibling_binding.id,
        agent_mcp_token,
        sibling_mcp_token,
    }
}

/// Insert a pending approval with the given requester + resolver. Returns
/// the new approval id. Direct SQL insert sidesteps the full call→approval
/// pipeline; we're testing the resolve path, not the create path.
async fn seed_approval(fx: &Fx, requester: Uuid, resolver: Uuid) -> Uuid {
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO approvals
           (org_id, identity_id, current_resolver_identity_id,
            action_summary, permission_keys, token, expires_at)
         VALUES ($1, $2, $3, $4, $5::text[], $6, now() + interval '1 hour')
         RETURNING id",
    )
    .bind(fx.org_id)
    .bind(requester)
    .bind(resolver)
    .bind("test action")
    .bind::<Vec<String>>(vec!["overslash:read".into()])
    .bind(format!("tok_{}", Uuid::new_v4().simple()))
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    row.0
}

/// JSON-RPC `tools/call` against `/mcp` with arbitrary tool name +
/// arguments. Returns the parsed response frame.
async fn rpc_tools_call(
    client: &reqwest::Client,
    base: &str,
    bearer: &str,
    id: i64,
    tool: &str,
    arguments: Value,
) -> Value {
    client
        .post(format!("{base}/mcp"))
        .header("Authorization", format!("Bearer {bearer}"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": tool, "arguments": arguments }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Pull the typed envelope out of a JSON-RPC tools/call response that came
/// back as `result.isError == true`.
fn typed_envelope(rpc_resp: &Value) -> Value {
    let result = rpc_resp
        .get("result")
        .unwrap_or_else(|| panic!("expected result frame: {rpc_resp:?}"));
    assert_eq!(
        result.get("isError").and_then(Value::as_bool),
        Some(true),
        "expected isError=true frame, got: {rpc_resp:?}"
    );
    let text = result["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap()
}

async fn flip_self_approve(fx: &Fx, agent_id: Uuid, enabled: bool) {
    db::mcp_client_agent_binding::set_self_approve_enabled_for_agent(&fx.pool, agent_id, enabled)
        .await
        .unwrap();
}

// ─── Cases ────────────────────────────────────────────────────────────

/// (a) The user — a proper ancestor of the requesting agent — resolves
/// the agent's pending approval through the REST endpoint. The classifier
/// returns `Downstream` and the existing ladder check passes.
#[tokio::test]
async fn user_resolves_agent_approval_succeeds() {
    let fx = bootstrap().await;
    let approval_id = seed_approval(&fx, fx.agent_id, fx.user_id).await;

    let resp = fx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/resolve", fx.base))
        .header("Authorization", format!("Bearer {}", fx.user_api_key))
        .json(&json!({ "resolution": "allow" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "user resolve should succeed");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"].as_str(), Some("allowed"));
    assert_eq!(
        body["relationship"].as_str(),
        Some("downstream"),
        "user viewing the row sees relationship=downstream"
    );
}

/// (b) The agent itself tries to resolve its own approval through
/// `overslash_approve_self`, but the binding flag is off (default) — the
/// classifier classifies as `SelfApproval` and the gate rejects with the
/// typed `not_in_your_chain` envelope. Approval row stays pending.
#[tokio::test]
async fn agent_self_approve_denied_when_flag_off() {
    let fx = bootstrap().await;
    let approval_id = seed_approval(&fx, fx.agent_id, fx.user_id).await;

    let frame = rpc_tools_call(
        &fx.client,
        &fx.base,
        &fx.agent_mcp_token,
        1,
        "overslash_approve_self",
        json!({ "approval_id": approval_id.to_string(), "resolution": "allow" }),
    )
    .await;
    let env = typed_envelope(&frame);
    assert_eq!(env["error"].as_str(), Some("not_in_your_chain"));
    assert_eq!(env["reason"].as_str(), Some("self_approval_disabled"));

    // Row didn't move.
    let status: (String,) = sqlx::query_as("SELECT status FROM approvals WHERE id = $1")
        .bind(approval_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(status.0, "pending");
}

/// (c) Same agent + same approval, but with `self_approve_enabled` flipped
/// on for this binding: `SelfApproval` is allowed, the approval moves to
/// `allowed`, and the audit row tags `relationship=self` plus the binding
/// metadata so reviewers can trace which trusted-keyboard session
/// authorized it.
#[tokio::test]
async fn agent_self_approve_allowed_when_flag_on() {
    let fx = bootstrap().await;
    flip_self_approve(&fx, fx.agent_id, true).await;
    let approval_id = seed_approval(&fx, fx.agent_id, fx.user_id).await;

    let frame = rpc_tools_call(
        &fx.client,
        &fx.base,
        &fx.agent_mcp_token,
        2,
        "overslash_approve_self",
        json!({ "approval_id": approval_id.to_string(), "resolution": "allow" }),
    )
    .await;
    // Success path: result.isError is absent/false.
    assert!(
        !frame
            .get("result")
            .and_then(|r| r.get("isError"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "self-approve with flag on should succeed: {frame:?}"
    );

    let status: (String,) = sqlx::query_as("SELECT status FROM approvals WHERE id = $1")
        .bind(approval_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(status.0, "allowed");

    // Audit row records relationship=self + binding/client.
    let detail: (Value,) = sqlx::query_as(
        "SELECT detail FROM audit_log
          WHERE action = 'approval.resolved' AND resource_id = $1
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(approval_id)
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(detail.0["relationship"].as_str(), Some("self"));
    assert_eq!(
        detail.0["mcp_client_id"].as_str(),
        Some(fx.agent_client_id.as_str())
    );
    assert_eq!(
        detail.0["binding_id"].as_str(),
        Some(fx.agent_binding_id.to_string().as_str())
    );
}

/// (d) The sibling agent — neither requester nor ancestor — gets
/// `not_in_your_chain` from both tools. The tool name doesn't gate
/// anything; the classifier does.
#[tokio::test]
async fn sibling_agent_gets_not_in_your_chain_from_either_tool() {
    let fx = bootstrap().await;
    let approval_id = seed_approval(&fx, fx.agent_id, fx.user_id).await;

    for tool in ["overslash_approve", "overslash_approve_self"] {
        // Make sure self-approve tool is even visible to the sibling so
        // `tools/call` doesn't trip the visibility check before the
        // classifier runs. Visibility is per-binding.
        flip_self_approve(&fx, fx.sibling_id, true).await;

        let frame = rpc_tools_call(
            &fx.client,
            &fx.base,
            &fx.sibling_mcp_token,
            10,
            tool,
            json!({
                "approval_id": approval_id.to_string(),
                "resolution": "allow",
            }),
        )
        .await;
        let env = typed_envelope(&frame);
        assert_eq!(
            env["error"].as_str(),
            Some("not_in_your_chain"),
            "tool={tool} should return not_in_your_chain"
        );
    }

    // Sanity: the sibling binding existed throughout — the rejection
    // wasn't an artefact of a missing row.
    let still_there = db::mcp_client_agent_binding::get_for_agent_and_client(
        &fx.pool,
        fx.sibling_id,
        &fx.sibling_client_id,
    )
    .await
    .unwrap();
    assert!(still_there.is_some());
    assert_eq!(still_there.unwrap().id, fx.sibling_binding_id);
}

/// (e) Visibility filter on `tools/list`: `overslash_approve_self` is
/// hidden by default and surfaces once the binding flag flips on.
/// `overslash_approve` is always present — both regardless of
/// the flag.
#[tokio::test]
async fn tools_list_filters_self_approve_by_binding_flag() {
    let fx = bootstrap().await;

    let list = || async {
        let resp: Value = fx
            .client
            .post(format!("{}/mcp", fx.base))
            .header("Authorization", format!("Bearer {}", fx.agent_mcp_token))
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };

    // Default: flag is false (migration default).
    let names = list().await;
    assert!(
        names.contains(&"overslash_approve".to_string()),
        "approve should always be listed: {names:?}"
    );
    assert!(
        !names.contains(&"overslash_approve_self".to_string()),
        "approve_self must be hidden until binding flag is on: {names:?}"
    );

    // Flip the binding flag on — now the self tool surfaces.
    flip_self_approve(&fx, fx.agent_id, true).await;
    let names = list().await;
    assert!(names.contains(&"overslash_approve".to_string()));
    assert!(
        names.contains(&"overslash_approve_self".to_string()),
        "approve_self should appear after flag flips on: {names:?}"
    );
}

/// (f) The agent's `GET /v1/approvals?scope=mine` view of its own
/// pending approvals carries `relationship: "self"`. An ancestor user
/// listing the same agent's pending approvals via
/// `?identity_id=<agent>` sees `relationship: "downstream"`. Same DB
/// row, two viewers, two perspectives — proves the field is computed at
/// response time, not frozen on the row.
#[tokio::test]
async fn list_pending_relationship_is_per_viewer() {
    let fx = bootstrap().await;
    let _approval_id = seed_approval(&fx, fx.agent_id, fx.user_id).await;

    // Need an agent-bound osk_ key to call `/v1/approvals?scope=mine` —
    // the MCP JWT path doesn't accept arbitrary query parameters here and
    // the test helper already minted one (returned from bootstrap above
    // as `_agent_osk` — re-mint instead of plumbing it).
    let agent_key_resp: Value = fx
        .client
        .post(format!("{}/v1/api-keys", fx.base))
        .header("Authorization", format!("Bearer {}", fx.org_admin_key))
        .json(&json!({
            "org_id": fx.org_id,
            "identity_id": fx.agent_id,
            "name": "agent-osk-list",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_osk = agent_key_resp["key"].as_str().unwrap().to_string();

    let mine: Value = fx
        .client
        .get(format!("{}/v1/approvals?scope=mine", fx.base))
        .header("Authorization", format!("Bearer {agent_osk}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mine = mine.as_array().unwrap();
    assert!(
        !mine.is_empty(),
        "agent should see its own pending approval"
    );
    assert_eq!(
        mine[0]["relationship"].as_str(),
        Some("self"),
        "agent's own pending approval is `self` from its perspective"
    );

    let user_view: Value = fx
        .client
        .get(format!(
            "{}/v1/approvals?identity_id={}",
            fx.base, fx.agent_id
        ))
        .header("Authorization", format!("Bearer {}", fx.user_api_key))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_view = user_view.as_array().unwrap();
    assert!(
        !user_view.is_empty(),
        "user should see agent's pending approvals"
    );
    assert_eq!(
        user_view[0]["relationship"].as_str(),
        Some("downstream"),
        "ancestor user viewing the same row sees `downstream`"
    );
}
