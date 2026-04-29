//! Approval replay for MCP-runtime tool calls.
//!
//! Mirrors the HTTP replay tests in `integration.rs` but exercises the MCP
//! branch added in `routes/approvals.rs`. The shape of an MCP approval's
//! `replay_payload` is `{ url, auth, tool, arguments }` (vs HTTP's
//! `{ action, filter, prefer_stream }`); both are persisted on
//! `approvals.replay_payload` and disambiguated at parse time by
//! `ReplayPayload::from_stored`.

// Tests use dynamic SQL to assert on `permission_rules` rows directly —
// query!() macros require static SQL and don't fit here.
#![allow(clippy::disallowed_methods)]

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::HeaderMap, response::IntoResponse, routing::post};
use reqwest::Client;
use serde_json::{Value, json};
use sqlx::Row;
use tokio::net::TcpListener;
use uuid::Uuid;

// ── MCP stub ────────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct StubBehavior {
    /// If Some, every `tools/call` returns `isError: true` with these blocks.
    force_error: Option<Vec<Value>>,
    /// If true, every `tools/call` returns HTTP 500 with no body so the MCP
    /// client surfaces a transport-level `BadGateway`.
    fail_transport: bool,
}

#[derive(Clone, Default)]
struct Stub {
    behavior: Arc<Mutex<StubBehavior>>,
}

impl Stub {
    fn force_error(&self, blocks: Vec<Value>) {
        self.behavior.lock().unwrap().force_error = Some(blocks);
    }
    fn fail_transport(&self) {
        self.behavior.lock().unwrap().fail_transport = true;
    }
}

async fn stub_handler(
    State(stub): State<Stub>,
    _headers: HeaderMap,
    Json(req): Json<Value>,
) -> axum::response::Response {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");

    let (force_error, fail_transport) = {
        let b = stub.behavior.lock().unwrap();
        (b.force_error.clone(), b.fail_transport)
    };

    if method == "tools/call" && fail_transport {
        return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response();
    }

    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-06-18",
            "serverInfo": { "name": "stub", "version": "0" },
            "capabilities": {}
        }),
        "tools/list" => json!({
            "tools": [{
                "name": "echo",
                "description": "Echo input",
                "inputSchema": {
                    "type": "object",
                    "properties": { "x": { "type": "string" } },
                    "required": ["x"]
                }
            }]
        }),
        "tools/call" => {
            let args = req
                .get("params")
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(Value::Null);
            if let Some(blocks) = force_error {
                json!({ "content": blocks, "isError": true })
            } else {
                json!({
                    "content": [{ "type": "text", "text": "ok" }],
                    "structuredContent": { "echo": args },
                    "isError": false
                })
            }
        }
        _ => json!({}),
    };

    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
}

async fn start_stub() -> (SocketAddr, Stub) {
    common::allow_loopback_ssrf();
    let stub = Stub::default();
    let app = Router::new()
        .route("/mcp", post(stub_handler))
        .with_state(stub.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, stub)
}

// ── Test scaffolding ────────────────────────────────────────────────────────

fn mcp_template_yaml(key: &str, url: &str, auth_secret: Option<&str>) -> String {
    let auth_block = match auth_secret {
        Some(name) => format!("  auth: {{ kind: bearer, secret_name: {name} }}"),
        None => "  auth: { kind: none }".to_string(),
    };
    format!(
        r#"openapi: 3.1.0
info:
  title: Stub MCP
  x-overslash-key: {key}
x-overslash-runtime: mcp
paths: {{}}
x-overslash-mcp:
  url: {url}
{auth_block}
  autodiscover: true
  tools:
    - name: echo
      risk: read
      description: Echo a string
      input_schema:
        type: object
        properties:
          x: {{ type: string }}
        required: [x]
"#
    )
}

/// Look up the parent user-identity of the given agent by name. Used to mint
/// a user-bound API key so the test can call owner-only group endpoints
/// (e.g. delete-and-re-add of the Myself grant).
async fn user_id_for_agent(base: &str, client: &Client, admin_key: &str, _agent_id: Uuid) -> Uuid {
    let identities: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header(common::auth(admin_key).0, common::auth(admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    identities
        .iter()
        .find(|i| i["kind"] == "user" && i["name"] == "test-user")
        .expect("test-user not found")["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

/// Bootstrap an org with an admin user (resolver) and an agent (caller), and
/// register an MCP-runtime template + service instance — but **do not** grant
/// the agent any permissions, so calling the action triggers an approval.
struct ReplayCtx {
    base: String,
    client: Client,
    pool: sqlx::PgPool,
    agent_key: String,
    agent_ident: Uuid,
    admin_key: String,
    service_key: String,
    stub: Stub,
}

async fn setup_pending_mcp_approval(template_key: &str) -> ReplayCtx {
    let pool = common::test_pool().await;
    let (addr, stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, agent_ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Upload MCP template (org tier, kind:none — no secret needed).
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "openapi": mcp_template_yaml(template_key, &stub_url, None),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "template create: {:?}",
        resp.text().await
    );

    // Create the service instance the agent will target. Binding is by
    // `service` key in the call, so we just need an instance to exist.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&agent_key).0, common::auth(&agent_key).1)
        .json(&json!({
            "name": template_key,
            "template_key": template_key,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "instance create: {:?}",
        resp.text().await
    );
    let svc: Value = resp.json().await.unwrap();
    let svc_id = svc["id"].as_str().expect("instance id").to_string();

    // The auto-created Myself grant defaults to `auto_approve_reads = true`,
    // which would short-circuit Layer 2 for this read-risk action and return
    // 200 instead of 202. This test is specifically about Layer 2 mechanics
    // (approval → resolve → replay), so flip the bypass off via the public
    // grants API: delete the auto-created grant and re-add it with the flag
    // off. The user-bound test agent is the owner of the Myself group (since
    // it's the calling identity-bound key), so it has authority to mutate.
    // The agent's owner-user (test-user) is the owner of the service we just
    // created (services default to `owner = ceiling_user_id`). Mint a
    // user-bound key for that user so the test can mutate its Myself grant.
    let test_user_id = user_id_for_agent(&base, &client, &admin_key, agent_ident).await;
    let user_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "org_id": org_id,
            "identity_id": test_user_id,
            "name": "user-key-for-replay",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_key = user_key_resp["key"].as_str().unwrap();
    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups?include_self=true"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let self_group = groups
        .iter()
        .find(|g| {
            g["system_kind"] == "self"
                && g["owner_identity_id"].as_str() == Some(&test_user_id.to_string())
        })
        .expect("Myself group should exist for the agent's owner-user");
    let self_group_id = self_group["id"].as_str().unwrap();
    let grants: Vec<Value> = client
        .get(format!("{base}/v1/groups/{self_group_id}/grants"))
        .header(common::auth(user_key).0, common::auth(user_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let grant_id = grants
        .iter()
        .find(|g| g["service_instance_id"].as_str() == Some(&svc_id))
        .expect("Myself grant for the new service")["id"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = client
        .delete(format!(
            "{base}/v1/groups/{self_group_id}/grants/{grant_id}"
        ))
        .header(common::auth(user_key).0, common::auth(user_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .post(format!("{base}/v1/groups/{self_group_id}/grants"))
        .header(common::auth(user_key).0, common::auth(user_key).1)
        .json(&json!({
            "service_instance_id": svc_id,
            "access_level": "admin",
            "auto_approve_reads": false,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    ReplayCtx {
        base,
        client,
        pool,
        agent_key,
        agent_ident,
        admin_key,
        service_key: template_key.to_string(),
        stub,
    }
}

async fn trigger_pending_approval(ctx: &ReplayCtx, x: &str) -> String {
    let resp = ctx
        .client
        .post(format!("{}/v1/actions/call", ctx.base))
        .header(
            common::auth(&ctx.agent_key).0,
            common::auth(&ctx.agent_key).1,
        )
        .json(&json!({
            "service": ctx.service_key,
            "action": "echo",
            "params": { "x": x }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        202,
        "expected pending_approval: {:?}",
        resp.text().await
    );
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "pending_approval");
    body["approval_id"].as_str().unwrap().to_string()
}

async fn resolve(ctx: &ReplayCtx, approval_id: &str, body: Value) {
    let resp = ctx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/resolve", ctx.base))
        .header(
            common::auth(&ctx.admin_key).0,
            common::auth(&ctx.admin_key).1,
        )
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "resolve: {:?}", resp.text().await);
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// Happy path: agent's MCP call hits a permission gap → approval created →
/// admin allows → `/call` runs the MCP replay → execution row carries the
/// MCP envelope and the audit chain matches an inline call.
#[tokio::test]
async fn mcp_approval_resolve_then_call_succeeds() {
    let ctx = setup_pending_mcp_approval("stub_replay_ok").await;
    let approval_id = trigger_pending_approval(&ctx, "hi").await;
    resolve(&ctx, &approval_id, json!({"resolution": "allow"})).await;

    // Trigger replay via the agent's key (the requester is always allowed
    // to call its own approved approval).
    let resp = ctx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/call", ctx.base))
        .header(
            common::auth(&ctx.agent_key).0,
            common::auth(&ctx.agent_key).1,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "/call: {:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["execution"]["status"], "executed");

    // The execution result mirrors mcp_caller::invoke's stable envelope.
    let result_body = body["execution"]["result"]["body"]
        .as_str()
        .expect("execution.result.body string");
    let envelope: Value = serde_json::from_str(result_body).unwrap();
    assert_eq!(envelope["runtime"], "mcp");
    assert_eq!(envelope["tool"], "echo");
    assert_eq!(envelope["structured"]["echo"]["x"], "hi");
    assert_eq!(envelope["is_error"], false);
}

/// Regression guard for the user-reported bug: clicking **Allow & Remember**
/// for an MCP approval used to leave no permission rule because the replay
/// rejected MCP outright. With the MCP replay branch in place, the rule is
/// materialized after the successful execution.
#[tokio::test]
async fn mcp_allow_remember_creates_permission_rule() {
    let ctx = setup_pending_mcp_approval("stub_replay_remember").await;
    let approval_id = trigger_pending_approval(&ctx, "remember me").await;

    resolve(&ctx, &approval_id, json!({"resolution": "allow_remember"})).await;

    let resp = ctx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/call", ctx.base))
        .header(
            common::auth(&ctx.agent_key).0,
            common::auth(&ctx.agent_key).1,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "/call: {:?}", resp.text().await);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["execution"]["status"],
        "executed"
    );

    // The permission_keys for an MCP service action follow `service:action:arg`
    // (see PermissionKey::from_service_action). With no scope_param the arg
    // collapses to `*`.
    let pattern = format!("{}:echo:*", ctx.service_key);
    let row = sqlx::query(
        "SELECT count(*) AS n FROM permission_rules
         WHERE identity_id = $1 AND action_pattern = $2 AND effect = 'allow'",
    )
    .bind(ctx.agent_ident)
    .bind(&pattern)
    .fetch_one(&ctx.pool)
    .await
    .unwrap();
    let n: i64 = row.get("n");
    assert_eq!(n, 1, "expected exactly one allow rule for {pattern}");

    // Second call from the agent now bypasses approval and runs immediately.
    let resp = ctx
        .client
        .post(format!("{}/v1/actions/call", ctx.base))
        .header(
            common::auth(&ctx.agent_key).0,
            common::auth(&ctx.agent_key).1,
        )
        .json(&json!({
            "service": ctx.service_key,
            "action": "echo",
            "params": { "x": "again" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "second call: {:?}", resp.text().await);
    assert_eq!(resp.json::<Value>().await.unwrap()["status"], "called");
}

/// Symmetric to `test_allow_remember_failed_call_does_not_create_rule`: a
/// transport-level failure during MCP replay finalizes the execution as
/// `failed` and skips rule creation, so the resolver can fix the upstream
/// and retry.
#[tokio::test]
async fn mcp_replay_transport_error_does_not_create_rule() {
    let ctx = setup_pending_mcp_approval("stub_replay_fail").await;
    let approval_id = trigger_pending_approval(&ctx, "boom").await;
    resolve(&ctx, &approval_id, json!({"resolution": "allow_remember"})).await;
    // After the approval is created, flip the stub to fail transport on the
    // next tools/call. The original trigger above already ran tools/list
    // (during template autodiscover) and tools/call success isn't part of
    // it — only the replay path will see the 500.
    ctx.stub.fail_transport();

    let resp = ctx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/call", ctx.base))
        .header(
            common::auth(&ctx.agent_key).0,
            common::auth(&ctx.agent_key).1,
        )
        .send()
        .await
        .unwrap();
    // /call returns 200 with execution row in `failed` status — same shape
    // as the HTTP replay-failure path.
    assert_eq!(resp.status(), 200, "/call: {:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["execution"]["status"], "failed");

    let row = sqlx::query("SELECT count(*) AS n FROM permission_rules WHERE identity_id = $1")
        .bind(ctx.agent_ident)
        .fetch_one(&ctx.pool)
        .await
        .unwrap();
    let n: i64 = row.get("n");
    assert_eq!(n, 0, "no rule should be created when replay fails");
}

/// Legacy MCP approvals were created before this feature with
/// `replay_payload = NULL`; their `action_detail` is the redacted
/// projection (`{ runtime: "mcp", tool, arguments, ... }`) and lacks
/// `url`/`auth`, so they cannot be replayed. Pre-feature behavior was
/// to return 409; we preserve that instead of letting the deserializer
/// fail with a 500. Simulated by creating a fresh MCP approval and
/// then nulling `replay_payload` directly in the database.
#[tokio::test]
async fn mcp_legacy_approval_returns_409_not_500() {
    let ctx = setup_pending_mcp_approval("stub_replay_legacy").await;
    let approval_id = trigger_pending_approval(&ctx, "legacy").await;
    resolve(&ctx, &approval_id, json!({"resolution": "allow"})).await;

    sqlx::query("UPDATE approvals SET replay_payload = NULL WHERE id = $1")
        .bind(approval_id.parse::<Uuid>().unwrap())
        .execute(&ctx.pool)
        .await
        .unwrap();

    let resp = ctx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/call", ctx.base))
        .header(
            common::auth(&ctx.agent_key).0,
            common::auth(&ctx.agent_key).1,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "/call: {:?}", resp.text().await);
}

/// Tool-level failure (`isError: true` in the MCP envelope) is in-band per
/// the MCP spec. From the approval's perspective the replay *executed*: the
/// policy decision was honored, the call ran. The execution row finalizes
/// as `executed` and the envelope carries `is_error: true` — same as an
/// inline call that returns isError.
#[tokio::test]
async fn mcp_replay_tool_level_error_still_executes() {
    let ctx = setup_pending_mcp_approval("stub_replay_tool_err").await;
    ctx.stub.force_error(vec![json!({
        "type": "text",
        "text": "tool blew up"
    })]);
    let approval_id = trigger_pending_approval(&ctx, "x").await;
    resolve(&ctx, &approval_id, json!({"resolution": "allow"})).await;

    let resp = ctx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/call", ctx.base))
        .header(
            common::auth(&ctx.agent_key).0,
            common::auth(&ctx.agent_key).1,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "/call: {:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["execution"]["status"], "executed");

    let envelope: Value = serde_json::from_str(
        body["execution"]["result"]["body"]
            .as_str()
            .expect("envelope string"),
    )
    .unwrap();
    assert_eq!(envelope["runtime"], "mcp");
    assert_eq!(envelope["is_error"], true);
}
