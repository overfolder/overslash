//! The MCP 2026-07-28 ("modern") protocol on `POST /mcp`.
//!
//! Drives the real endpoint the way Claude Code does on a modern connection:
//! no `initialize`, protocol version + capabilities in every request's
//! `_meta`, mirrored `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name`
//! headers — and, for an approval, the multi round-trip request: the gated
//! `tools/call` answers `input_required`, and the client's retry carries the
//! dialog's answer plus the `requestState` it was handed.
//!
//! The gated action is a real MCP-runtime service pointed at a local stub, so
//! "Allow" executes the call end to end rather than stopping at the resolve.

// Asserts on `approvals` / `permission_rules` rows directly.
#![allow(clippy::disallowed_methods)]

use crate::common;

use std::net::SocketAddr;

use axum::{Json, Router, routing::post};
use overslash_api::services::jwt;
use overslash_db::repos as db;
use reqwest::Client;
use serde_json::{Value, json};
use sqlx::Row;
use tokio::net::TcpListener;
use uuid::Uuid;

const MODERN: &str = "2026-07-28";

// ── Upstream MCP stub: one `echo` tool that always succeeds ────────────────

async fn stub_handler(Json(req): Json<Value>) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let result = match req.get("method").and_then(Value::as_str).unwrap_or("") {
        "initialize" => json!({
            "protocolVersion": "2025-06-18",
            "serverInfo": { "name": "stub", "version": "0" },
            "capabilities": {}
        }),
        "tools/list" => json!({ "tools": [{
            "name": "echo",
            "description": "Echo input",
            "inputSchema": {
                "type": "object",
                "properties": { "x": { "type": "string" } },
                "required": ["x"]
            }
        }]}),
        "tools/call" => json!({
            "content": [{ "type": "text", "text": "ok" }],
            "structuredContent": { "echo": req["params"]["arguments"].clone() },
            "isError": false
        }),
        _ => json!({}),
    };
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

async fn start_stub() -> SocketAddr {
    common::allow_loopback_ssrf();
    let app = Router::new().route("/mcp", post(stub_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn stub_template_yaml(key: &str, url: &str) -> String {
    format!(
        r#"openapi: 3.1.0
info:
  title: Stub MCP
  x-overslash-key: {key}
x-overslash-runtime: mcp
paths: {{}}
x-overslash-mcp:
  url: {url}
  auth: {{ kind: none }}
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

// ── Fixture ────────────────────────────────────────────────────────────────

struct Fx {
    base: String,
    client: Client,
    pool: sqlx::PgPool,
    agent_id: Uuid,
    client_id: String,
    service: String,
    /// MCP-aud JWT for the agent, bound to `client_id`.
    token: String,
}

/// An org whose agent reaches `/mcp` through an MCP OAuth client, plus an
/// MCP-runtime service the agent can call only with approval.
async fn setup() -> Fx {
    let pool = common::test_pool().await;
    let stub_addr = start_stub().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let service = format!("stub{}", &Uuid::new_v4().simple().to_string()[..8]);

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "openapi": stub_template_yaml(&service, &format!("http://{stub_addr}/mcp")),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "template: {:?}", resp.text().await);
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&agent_key).0, common::auth(&agent_key).1)
        .json(&json!({ "name": service, "template_key": service }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "instance: {:?}", resp.text().await);
    let svc_id = resp.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // The owner-user of the agent — the human who answers its dialogs.
    let identities: Vec<Value> = client
        .get(format!("{base}/v1/identities"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = identities
        .iter()
        .find(|i| i["kind"] == "user" && i["name"] == "test-user")
        .expect("test-user")["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // The Myself grant auto-approves reads, which would run `echo` without
    // asking. Re-add it with the bypass off so every call is gated.
    let user_key = client
        .post(format!("{base}/v1/api-keys"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({ "org_id": org_id, "identity_id": user_id, "name": "modern-user" }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()["key"]
        .as_str()
        .unwrap()
        .to_string();
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
                && g["owner_identity_id"].as_str() == Some(&user_id.to_string())
        })
        .expect("Myself group")["id"]
        .as_str()
        .unwrap()
        .to_string();
    let grants: Vec<Value> = client
        .get(format!("{base}/v1/groups/{self_group}/grants"))
        .header(common::auth(&user_key).0, common::auth(&user_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let grant_id = grants
        .iter()
        .find(|g| g["service_instance_id"].as_str() == Some(&svc_id))
        .expect("Myself grant")["id"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = client
        .delete(format!("{base}/v1/groups/{self_group}/grants/{grant_id}"))
        .header(common::auth(&user_key).0, common::auth(&user_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .post(format!("{base}/v1/groups/{self_group}/grants"))
        .header(common::auth(&user_key).0, common::auth(&user_key).1)
        .json(&json!({
            "service_instance_id": svc_id,
            "access_level": "admin",
            "auto_approve_reads": false,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // The MCP OAuth client and its binding. DCR is not what is under test.
    let client_id = format!("osc_{}", Uuid::new_v4().simple());
    db::oauth_mcp_client::create(
        &pool,
        &db::oauth_mcp_client::CreateOauthMcpClient {
            client_id: &client_id,
            client_name: Some("claude-code"),
            redirect_uris: &["http://127.0.0.1:0/cb".to_string()],
            software_id: Some("com.anthropic.claude-code"),
            software_version: Some("2.1.282"),
            created_ip: None,
            created_user_agent: None,
            org_id: None,
        },
    )
    .await
    .unwrap();
    db::mcp_client_agent_binding::upsert(&pool, org_id, user_id, &client_id, agent_id)
        .await
        .unwrap();

    let token = jwt::mint_mcp(
        &common::signing_key_bytes(),
        agent_id,
        org_id,
        "test-user@example.com".into(),
        3600,
        Some(client_id.clone()),
    )
    .unwrap();

    Fx {
        base,
        client,
        pool,
        agent_id,
        client_id,
        service,
        token,
    }
}

/// What Claude Code 2.1.282 declares on a modern connection.
fn claude_code_caps() -> Value {
    json!({ "elicitation": { "form": {}, "url": {} } })
}

/// POST a 2026-07-28 request: `_meta` in the body, mirrored headers on the
/// wire. `params` is merged next to `_meta`.
async fn modern(fx: &Fx, method: &str, params: Value, caps: Value) -> (u16, Value) {
    let mut body_params = json!({
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MODERN,
            "io.modelcontextprotocol/clientInfo": { "name": "claude-code", "version": "2.1.282" },
            "io.modelcontextprotocol/clientCapabilities": caps,
        }
    });
    if let (Value::Object(p), Value::Object(extra)) = (&mut body_params, params) {
        p.extend(extra);
    }
    let mut req = fx
        .client
        .post(format!("{}/mcp", fx.base))
        .bearer_auth(&fx.token)
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", MODERN)
        .header("Mcp-Method", method);
    if let Some(name) = body_params.get("name").and_then(Value::as_str) {
        req = req.header("Mcp-Name", name);
    }
    let resp = req
        .json(&json!({
            "jsonrpc": "2.0",
            "id": Uuid::new_v4().to_string(),
            "method": method,
            "params": body_params,
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap())
}

fn echo_args(x: &str) -> Value {
    json!({ "service": "SERVICE", "action": "echo", "params": { "x": x } })
}

impl Fx {
    fn call_args(&self, x: &str) -> Value {
        let mut a = echo_args(x);
        a["service"] = json!(self.service);
        a
    }

    /// The gated first leg: a fresh `overslash_call`.
    async fn gated_call(&self, x: &str, caps: Value) -> Value {
        let (status, body) = modern(
            self,
            "tools/call",
            json!({ "name": "overslash_call", "arguments": self.call_args(x) }),
            caps,
        )
        .await;
        assert_eq!(status, 200, "{body}");
        body["result"].clone()
    }

    /// The retry leg: same call, plus the answer and the echoed state.
    async fn retry(&self, x: &str, request_state: &str, input_responses: Value) -> Value {
        let (status, body) = modern(
            self,
            "tools/call",
            json!({
                "name": "overslash_call",
                "arguments": self.call_args(x),
                "inputResponses": input_responses,
                "requestState": request_state,
            }),
            claude_code_caps(),
        )
        .await;
        assert_eq!(status, 200, "{body}");
        body
    }

    async fn approval_status(&self, approval_id: &str) -> String {
        sqlx::query("SELECT status FROM approvals WHERE id = $1")
            .bind(Uuid::parse_str(approval_id).unwrap())
            .fetch_one(&self.pool)
            .await
            .unwrap()
            .get("status")
    }
}

/// The approval a `pending_approval` envelope (in a tool result) names.
fn envelope_of(result: &Value) -> Value {
    serde_json::from_str(result["content"][0]["text"].as_str().expect("text block")).unwrap()
}

/// The approval id an `input_required` result's dialog is about — read off
/// the only pending approval for the agent, since the dialog itself carries
/// no id (the `requestState` is opaque).
async fn only_pending_approval(fx: &Fx) -> String {
    let rows = sqlx::query(
        "SELECT id FROM approvals WHERE identity_id = $1 AND status = 'pending'
          ORDER BY created_at DESC",
    )
    .bind(fx.agent_id)
    .fetch_all(&fx.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 1, "expected exactly one pending approval");
    rows[0].get::<Uuid, _>("id").to_string()
}

// ── Handshake-free discovery ───────────────────────────────────────────────

#[tokio::test]
async fn discover_advertises_the_modern_era_and_records_the_client() {
    let fx = setup().await;
    let (status, body) = modern(&fx, "server/discover", json!({}), claude_code_caps()).await;
    assert_eq!(status, 200, "{body}");
    let r = &body["result"];
    assert_eq!(r["resultType"], "complete");
    assert!(
        r["supportedVersions"]
            .as_array()
            .unwrap()
            .contains(&json!(MODERN)),
        "Claude Code stays modern only when this lists 2026-07-28: {r}"
    );
    assert!(r["capabilities"]["tools"].is_object());
    assert!(r["ttlMs"].as_u64().is_some());
    assert_eq!(r["cacheScope"], "private");
    assert_eq!(
        r["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "overslash"
    );
    assert!(
        r["instructions"]
            .as_str()
            .unwrap()
            .contains("overslash_call")
    );

    // The declared capabilities land on the client row, which is what the
    // dashboard's "elicitation supported" reads.
    let row = db::oauth_mcp_client::get_by_client_id(&fx.pool, &fx.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.protocol_version.as_deref(), Some(MODERN));
    assert!(row.elicitation_supported());
    assert!(
        row.last_session_id.is_none(),
        "a sessionless client must not be given a session id"
    );
}

#[tokio::test]
async fn tools_list_is_cacheable_and_the_legacy_list_is_untouched() {
    let fx = setup().await;
    let (status, body) = modern(&fx, "tools/list", json!({}), claude_code_caps()).await;
    assert_eq!(status, 200, "{body}");
    let r = &body["result"];
    assert_eq!(r["resultType"], "complete");
    assert!(r["ttlMs"].as_u64().is_some());
    assert_eq!(r["cacheScope"], "private");
    let names: Vec<&str> = r["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(names.contains(&"overslash_call"), "{names:?}");

    // A legacy client sends no `_meta` version and gets exactly what it
    // always got: no `resultType`, no cache fields.
    let legacy: Value = fx
        .client
        .post(format!("{}/mcp", fx.base))
        .bearer_auth(&fx.token)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(legacy["result"]["tools"].is_array(), "{legacy}");
    assert!(legacy["result"].get("resultType").is_none(), "{legacy}");
    assert!(legacy["result"].get("ttlMs").is_none(), "{legacy}");
}

#[tokio::test]
async fn protocol_errors_carry_the_modern_codes_and_statuses() {
    let fx = setup().await;

    // A method the server does not implement: 404 + -32601, which is what
    // tells a modern client it is talking to a modern server that simply
    // lacks the method (vs. a legacy server's bare 404).
    let (status, body) = modern(&fx, "prompts/list", json!({}), json!({})).await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error"]["code"], -32601);

    // Headers that disagree with the body.
    let resp = fx
        .client
        .post(format!("{}/mcp", fx.base))
        .bearer_auth(&fx.token)
        .header("MCP-Protocol-Version", MODERN)
        .header("Mcp-Method", "tools/list")
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "server/discover",
            "params": { "_meta": { "io.modelcontextprotocol/protocolVersion": MODERN } }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], -32020, "{body}");

    // A version this server does not speak.
    let resp = fx
        .client
        .post(format!("{}/mcp", fx.base))
        .bearer_auth(&fx.token)
        .header("MCP-Protocol-Version", "2099-01-01")
        .header("Mcp-Method", "tools/list")
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/list",
            "params": { "_meta": { "io.modelcontextprotocol/protocolVersion": "2099-01-01" } }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], -32022, "{body}");
    assert_eq!(body["error"]["data"]["supported"], json!([MODERN]));
}

// ── Approvals as multi round-trip requests ─────────────────────────────────

#[tokio::test]
async fn allow_in_the_dialog_executes_the_call_on_the_retry() {
    let fx = setup().await;

    let first = fx.gated_call("hello", claude_code_caps()).await;
    assert_eq!(first["resultType"], "input_required", "{first}");
    let ask = &first["inputRequests"]["decision"];
    assert_eq!(ask["method"], "elicitation/create");
    assert_eq!(ask["params"]["mode"], "form");
    assert!(ask["params"]["requestedSchema"]["properties"]["decision"].is_object());
    let state = first["requestState"].as_str().expect("requestState");
    let approval_id = only_pending_approval(&fx).await;

    let body = fx
        .retry(
            "hello",
            state,
            json!({ "decision": { "action": "accept", "content": { "decision": "allow" } } }),
        )
        .await;
    let r = &body["result"];
    assert_eq!(r["resultType"], "complete", "{body}");
    assert!(r.get("isError").is_none(), "{body}");
    let text = r["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("hello"),
        "the stub's echo must be in the result — the call really ran: {text}"
    );
    assert_eq!(fx.approval_status(&approval_id).await, "allowed");
}

#[tokio::test]
async fn decline_denies_cancel_falls_back_and_then_backs_off() {
    let fx = setup().await;

    // Decline: a human said no.
    let first = fx.gated_call("no", claude_code_caps()).await;
    let state = first["requestState"].as_str().unwrap().to_string();
    let denied_id = only_pending_approval(&fx).await;
    let body = fx
        .retry("no", &state, json!({ "decision": { "action": "decline" } }))
        .await;
    assert_eq!(body["result"]["isError"], true, "{body}");
    assert_eq!(fx.approval_status(&denied_id).await, "denied");

    // Cancel: nobody answered (headless auto-cancels). Not a denial — the
    // model gets the ordinary envelope and the approval stays pending.
    let first = fx.gated_call("later", claude_code_caps()).await;
    let state = first["requestState"].as_str().unwrap().to_string();
    let pending_id = only_pending_approval(&fx).await;
    let body = fx
        .retry(
            "later",
            &state,
            json!({ "decision": { "action": "cancel" } }),
        )
        .await;
    let r = &body["result"];
    assert_eq!(r["resultType"], "complete", "{body}");
    assert!(r.get("isError").is_none(), "{body}");
    let env = envelope_of(r);
    assert_eq!(env["status"], "pending_approval");
    assert_eq!(env["approval_id"], json!(pending_id));
    assert_eq!(fx.approval_status(&pending_id).await, "pending");

    // The cooldown after an unanswered dialog applies on this era too: the
    // model's retry gets the envelope straight away, no second dialog.
    let again = fx.gated_call("later", claude_code_caps()).await;
    assert_eq!(again["resultType"], "complete", "{again}");
    assert_eq!(envelope_of(&again)["status"], "pending_approval");
}

#[tokio::test]
async fn allow_and_remember_asks_scope_and_duration_on_a_second_round_trip() {
    let fx = setup().await;

    let first = fx.gated_call("remember", claude_code_caps()).await;
    let state = first["requestState"].as_str().unwrap().to_string();
    let approval_id = only_pending_approval(&fx).await;

    let second = fx
        .retry(
            "remember",
            &state,
            json!({ "decision": { "action": "accept", "content": { "decision": "allow_remember" } } }),
        )
        .await;
    let r = &second["result"];
    assert_eq!(r["resultType"], "input_required", "{second}");
    let ask = &r["inputRequests"]["remember"];
    assert!(ask["params"]["requestedSchema"]["properties"]["ttl"].is_object());
    let next_state = r["requestState"].as_str().unwrap();
    assert_ne!(next_state, state, "the follow-up is its own round trip");
    assert_eq!(
        fx.approval_status(&approval_id).await,
        "pending",
        "nothing is resolved until the details are in"
    );

    let done = fx
        .retry(
            "remember",
            next_state,
            json!({ "remember": { "action": "accept", "content": { "ttl": "1h" } } }),
        )
        .await;
    assert_eq!(done["result"]["resultType"], "complete", "{done}");
    assert!(done["result"].get("isError").is_none(), "{done}");
    assert_eq!(fx.approval_status(&approval_id).await, "allowed");

    let rules = sqlx::query("SELECT expires_at FROM permission_rules WHERE identity_id = $1")
        .bind(fx.agent_id)
        .fetch_all(&fx.pool)
        .await
        .unwrap();
    assert!(
        rules.iter().any(|r| r
            .get::<Option<time::OffsetDateTime>, _>("expires_at")
            .is_some()),
        "a 1h rule was saved for the agent"
    );
}

#[tokio::test]
async fn the_request_state_is_bound_to_its_call() {
    let fx = setup().await;
    let first = fx.gated_call("bound", claude_code_caps()).await;
    let state = first["requestState"].as_str().unwrap().to_string();
    let approval_id = only_pending_approval(&fx).await;
    let allow = json!({ "decision": { "action": "accept", "content": { "decision": "allow" } } });

    // Tampered.
    let mut forged = state.clone();
    forged.pop();
    forged.push(if state.ends_with('A') { 'B' } else { 'A' });
    let body = fx.retry("bound", &forged, allow.clone()).await;
    assert_eq!(body["error"]["code"], -32602, "{body}");

    // Genuine, but pasted onto a different call.
    let body = fx.retry("something else", &state, allow.clone()).await;
    assert_eq!(body["error"]["code"], -32602, "{body}");

    assert_eq!(
        fx.approval_status(&approval_id).await,
        "pending",
        "neither misuse may resolve the approval"
    );

    // No answer in the retry: the spec's move is to ask again.
    let body = fx.retry("bound", &state, json!({})).await;
    assert_eq!(body["result"]["resultType"], "input_required", "{body}");
    assert_eq!(body["result"]["requestState"], json!(state));
}

#[tokio::test]
async fn a_client_without_form_elicitation_gets_the_envelope() {
    let fx = setup().await;

    for caps in [json!({}), json!({ "elicitation": { "url": {} } })] {
        let r = fx.gated_call("plain", caps.clone()).await;
        assert_eq!(r["resultType"], "complete", "caps {caps}: {r}");
        assert_eq!(envelope_of(&r)["status"], "pending_approval", "caps {caps}");
    }
}

#[tokio::test]
async fn an_opted_out_binding_gets_the_envelope() {
    let fx = setup().await;
    db::mcp_client_agent_binding::set_elicitation_opted_out_for_agent(&fx.pool, fx.agent_id, true)
        .await
        .unwrap();
    let r = fx.gated_call("off", claude_code_caps()).await;
    assert_eq!(r["resultType"], "complete", "{r}");
    assert_eq!(envelope_of(&r)["status"], "pending_approval");
}
