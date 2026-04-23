//! End-to-end integration tests for external MCP-runtime services.
//!
//! All tests run against an in-process axum stub that speaks Streamable-HTTP
//! MCP (JSON-RPC 2.0 over POST). Nothing here reaches the public network —
//! the stub URL is baked into each template at save time.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use reqwest::Client;
use serde_json::{Value, json};
use tokio::net::TcpListener;

// ── MCP stub ────────────────────────────────────────────────────────────

#[derive(Default)]
struct StubInner {
    /// Most recent Authorization header observed (for auth assertions).
    last_auth: Option<String>,
    /// If Some, tools/call returns `isError: true` with these content blocks.
    force_error: Option<Vec<Value>>,
    /// Number of tools/list calls received (to assert resync happened).
    list_calls: u32,
    /// Tool definitions returned by tools/list.
    tools: Vec<Value>,
}

#[derive(Clone, Default)]
struct Stub {
    inner: Arc<Mutex<StubInner>>,
}

impl Stub {
    fn last_auth(&self) -> Option<String> {
        self.inner.lock().unwrap().last_auth.clone()
    }

    fn list_calls(&self) -> u32 {
        self.inner.lock().unwrap().list_calls
    }

    fn set_tools(&self, v: Vec<Value>) {
        self.inner.lock().unwrap().tools = v;
    }

    fn force_error(&self, blocks: Vec<Value>) {
        self.inner.lock().unwrap().force_error = Some(blocks);
    }
}

async fn stub_handler(
    State(stub): State<Stub>,
    headers: HeaderMap,
    Json(req): Json<Value>,
) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");

    let mut inner = stub.inner.lock().unwrap();
    inner.last_auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-06-18",
            "serverInfo": { "name": "stub", "version": "0" },
            "capabilities": {}
        }),
        "tools/list" => {
            inner.list_calls += 1;
            let tools = if inner.tools.is_empty() {
                vec![json!({
                    "name": "echo",
                    "description": "Echo input",
                    "inputSchema": {
                        "type": "object",
                        "properties": { "x": { "type": "string" } },
                        "required": ["x"]
                    }
                })]
            } else {
                inner.tools.clone()
            };
            json!({ "tools": tools })
        }
        "tools/call" => {
            let args = req
                .get("params")
                .and_then(|p| p.get("arguments"))
                .cloned()
                .unwrap_or(Value::Null);
            if let Some(blocks) = inner.force_error.clone() {
                json!({
                    "content": blocks,
                    "isError": true
                })
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

    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

async fn start_stub() -> (SocketAddr, Stub) {
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

// ── Helpers ─────────────────────────────────────────────────────────────

fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

fn mcp_template_yaml(key: &str, url: &str, auth_bearer_secret: Option<&str>) -> String {
    let auth_block = match auth_bearer_secret {
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

struct SetupCtx<'a> {
    base: &'a str,
    client: &'a Client,
    admin_key: &'a str,
    agent_key: &'a str,
    agent_ident: uuid::Uuid,
    key: &'a str,
    url: &'a str,
    /// (secret_name, secret_value) for kind:bearer, or None for kind:none.
    auth_bearer_secret: Option<(&'a str, &'a str)>,
}

/// Create an MCP template visible at org tier, grant the agent permission to
/// call its tools, and create the bearer secret if the template needs one.
/// Returns the instance id so the dashboard-matching getServiceActions pattern
/// can be exercised.
async fn setup_template_and_grants(ctx: SetupCtx<'_>) -> uuid::Uuid {
    let SetupCtx {
        base,
        client,
        admin_key,
        agent_key,
        agent_ident,
        key,
        url,
        auth_bearer_secret,
    } = ctx;
    // Upload the template at org tier.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({
            "openapi": mcp_template_yaml(key, url, auth_bearer_secret.map(|(n, _)| n)),
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

    // Write the bearer secret if the template needs one.
    if let Some((name, value)) = auth_bearer_secret {
        let resp = client
            .put(format!("{base}/v1/secrets/{name}"))
            .header(auth(admin_key).0, auth(admin_key).1)
            .json(&json!({"value": value}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "secret put: {:?}", resp.text().await);
    }

    // Grant the agent full access to this service's actions.
    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({
            "identity_id": agent_ident,
            "action_pattern": format!("{key}:*:*"),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "permission create: {:?}",
        resp.text().await
    );

    // Create a service instance (required when resolving by service_key).
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(agent_key).0, auth(agent_key).1)
        .json(&json!({
            "name": key,
            "template_key": key,
        }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let instance_id = body["id"].as_str().expect("instance id").to_string();
    instance_id.parse().unwrap()
}

// ── Tests ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn mcp_none_auth_executes_and_audits_with_mcp_runtime() {
    let pool = common::test_pool().await;
    let (addr, stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, agent_ident, agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let _inst = setup_template_and_grants(SetupCtx {
        base: &base,
        client: &client,
        admin_key: &org_key,
        agent_key: &agent_key,
        agent_ident,
        key: "stub_mcp_none",
        url: &stub_url,
        auth_bearer_secret: None,
    })
    .await;

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "stub_mcp_none",
            "action": "echo",
            "params": { "x": "hi" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");

    let envelope: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["runtime"], "mcp");
    assert_eq!(envelope["tool"], "echo");
    assert_eq!(envelope["structured"]["echo"]["x"], "hi");
    assert_eq!(envelope["is_error"], false);

    // Stub saw no auth header for kind:none.
    assert!(stub.last_auth().is_none());

    // Audit row carries runtime:mcp.
    let audit: Value = client
        .get(format!("{base}/v1/audit"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let executed = audit
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "action.executed")
        .expect("action.executed entry");
    assert_eq!(executed["detail"]["runtime"], "mcp");
    assert_eq!(executed["detail"]["tool"], "echo");
}

#[tokio::test]
async fn mcp_bearer_auth_forwards_secret() {
    let pool = common::test_pool().await;
    let (addr, stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, agent_ident, agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;

    setup_template_and_grants(SetupCtx {
        base: &base,
        client: &client,
        admin_key: &org_key,
        agent_key: &agent_key,
        agent_ident,
        key: "stub_mcp_bearer",
        url: &stub_url,
        auth_bearer_secret: Some(("stub_token", "SEKRET")),
    })
    .await;

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "stub_mcp_bearer",
            "action": "echo",
            "params": { "x": "hello" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    assert_eq!(stub.last_auth().as_deref(), Some("Bearer SEKRET"));
}

#[tokio::test]
async fn mcp_is_error_surfaces_in_envelope_not_http() {
    let pool = common::test_pool().await;
    let (addr, stub) = start_stub().await;
    stub.force_error(vec![json!({
        "type": "text",
        "text": "tool blew up"
    })]);
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, agent_ident, agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;

    setup_template_and_grants(SetupCtx {
        base: &base,
        client: &client,
        admin_key: &org_key,
        agent_key: &agent_key,
        agent_ident,
        key: "stub_mcp_err",
        url: &stub_url,
        auth_bearer_secret: None,
    })
    .await;

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "stub_mcp_err",
            "action": "echo",
            "params": { "x": "boom" }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let envelope: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["is_error"], true);
    assert_eq!(envelope["content"][0]["text"], "tool blew up");
}

#[tokio::test]
async fn mcp_missing_secret_returns_400_before_upstream_call() {
    let pool = common::test_pool().await;
    let (addr, stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, agent_ident, agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Upload template that declares a bearer secret, but don't write it.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({
            "openapi": mcp_template_yaml("stub_mcp_nosecret", &stub_url, Some("absent_secret")),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Permission + instance.
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({
            "identity_id": agent_ident,
            "action_pattern": "stub_mcp_nosecret:*:*",
        }))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/services"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({"name": "stub_mcp_nosecret", "template_key": "stub_mcp_nosecret"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "stub_mcp_nosecret",
            "action": "echo",
            "params": { "x": "x" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // Upstream was not reached.
    assert!(stub.last_auth().is_none());
}

#[tokio::test]
async fn mcp_resync_populates_discovered_tools() {
    let pool = common::test_pool().await;
    let (addr, stub) = start_stub().await;
    stub.set_tools(vec![json!({
        "name": "search_docs",
        "description": "Search indexed docs",
        "inputSchema": { "type": "object", "properties": { "q": { "type": "string" } }, "required": ["q"] }
    })]);
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, _agent_ident, _agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({
            "openapi": mcp_template_yaml("stub_mcp_sync", &stub_url, None),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Resync.
    let resp = client
        .post(format!("{base}/v1/templates/stub_mcp_sync/mcp/resync"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["tool_count"], 1);
    assert!(body["discovered_at"].is_string());

    // Template JSON now contains discovered_tools.
    let resp = client
        .get(format!("{base}/v1/templates/stub_mcp_sync"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    let detail: Value = resp.json().await.unwrap();
    assert_eq!(detail["runtime"], "mcp");
    assert!(detail["mcp"]["discovered_at"].is_string());

    // The actions list now includes search_docs (from discovered_tools).
    let names: Vec<&str> = detail["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["key"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"search_docs"));
    assert!(names.contains(&"echo"));

    assert_eq!(stub.list_calls(), 1);
}

#[tokio::test]
async fn mcp_resync_rejected_on_http_runtime_template() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, _agent_ident, _agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Plain HTTP-runtime template.
    let yaml = r#"openapi: 3.1.0
info:
  title: Plain
  x-overslash-key: plain_http
servers:
  - url: https://example.com
paths:
  /ping:
    get:
      operationId: ping
      summary: Ping
"#;
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"openapi": yaml}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .post(format!("{base}/v1/templates/plain_http/mcp/resync"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn mcp_resync_rejected_when_autodiscover_false() {
    let pool = common::test_pool().await;
    let (addr, _stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, _agent_ident, _agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let yaml = format!(
        r#"openapi: 3.1.0
info:
  title: Pinned
  x-overslash-key: stub_pinned
x-overslash-runtime: mcp
paths: {{}}
x-overslash-mcp:
  url: {stub_url}
  auth: {{ kind: none }}
  autodiscover: false
  tools:
    - name: echo
      risk: read
      description: Echo
      input_schema:
        type: object
        properties: {{ x: {{ type: string }} }}
        required: [x]
"#
    );
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"openapi": yaml}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .post(format!("{base}/v1/templates/stub_pinned/mcp/resync"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn mcp_agent_without_permission_triggers_approval() {
    let pool = common::test_pool().await;
    let (addr, _stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, _agent_ident, agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Upload + instance (but deliberately NO permission rule).
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({
            "openapi": mcp_template_yaml("stub_mcp_noperm", &stub_url, None),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    client
        .post(format!("{base}/v1/services"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({"name": "stub_mcp_noperm", "template_key": "stub_mcp_noperm"}))
        .send()
        .await
        .unwrap();

    // Agent without permission → force-gated to approval even with kind:none.
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "stub_mcp_noperm",
            "action": "echo",
            "params": { "x": "x" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202, "{:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "pending_approval");
}
