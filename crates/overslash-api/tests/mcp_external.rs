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

    #[allow(dead_code)]
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

/// Telegram-shaped template: MCP runtime, `autodiscover: true`, but **no**
/// `url` and no bearer `secret_name` — both are supplied per service instance.
/// `auth_kind` is "none" or "bearer".
fn mcp_template_yaml_no_url(key: &str, auth_kind: &str) -> String {
    let auth_block = match auth_kind {
        "bearer" => "  auth: { kind: bearer }".to_string(),
        _ => "  auth: { kind: none }".to_string(),
    };
    format!(
        r#"openapi: 3.1.0
info:
  title: Stub MCP (no url)
  x-overslash-key: {key}
x-overslash-runtime: mcp
paths: {{}}
x-overslash-mcp:
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
async fn mcp_none_auth_calls_and_audits_with_mcp_runtime() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_user, agent_ident, agent_key) =
        common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let org_key = fx.org_key.clone();

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
        .post(format!("{base}/v1/actions/call"))
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
    assert_eq!(body["status"], "called");
    assert_eq!(body["is_error"], false);

    let envelope: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["runtime"], "mcp");
    assert_eq!(envelope["tool"], "echo");
    assert_eq!(envelope["structured"]["echo"]["x"], "hi");

    // Transport success + is_error=false maps to status_class="2xx" on the
    // upstream-response counter.
    let metrics = common::scrape_metrics(&base, &client).await;
    assert!(
        common::has_metric_series(
            &metrics,
            "overslash_upstream_responses_total",
            &[
                ("template_key", "_unknown"),
                ("mode", "mcp"),
                ("status_class", "2xx"),
            ],
        ),
        "expected mcp 2xx upstream series in:\n{metrics}"
    );
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
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_user, agent_ident, agent_key) =
        common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let org_key = fx.org_key.clone();

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
        .post(format!("{base}/v1/actions/call"))
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
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, stub) = start_stub().await;
    stub.force_error(vec![json!({
        "type": "text",
        "text": "tool blew up"
    })]);
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_user, agent_ident, agent_key) =
        common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let org_key = fx.org_key.clone();

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
        .post(format!("{base}/v1/actions/call"))
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
    assert_eq!(body["status"], "called");
    // The tool-level failure is surfaced on the envelope itself, so callers
    // don't have to parse the MCP body to notice it.
    assert_eq!(body["is_error"], true);
    let envelope: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["is_error"], true);
    assert_eq!(envelope["content"][0]["text"], "tool blew up");

    // The tool error rides in-band behind an outer 200 — metrics must still
    // record it as an upstream failure, not silent success. Org-uploaded
    // templates aren't in the global registry, so the bounded template_key
    // is `_unknown`.
    let metrics = common::scrape_metrics(&base, &client).await;
    assert!(
        common::has_metric_series(
            &metrics,
            "overslash_upstream_responses_total",
            &[
                ("template_key", "_unknown"),
                ("mode", "mcp"),
                ("status_class", "error"),
            ],
        ),
        "expected mcp upstream-error series in:\n{metrics}"
    );
    assert!(
        common::has_metric_series(
            &metrics,
            "overslash_action_executions_total",
            &[
                ("template_key", "_unknown"),
                ("mode", "action"),
                ("status", "upstream_error"),
            ],
        ),
        "expected upstream_error execution series in:\n{metrics}"
    );
}

#[tokio::test]
async fn mcp_missing_secret_returns_400_before_upstream_call() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_user, agent_ident, agent_key) =
        common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let org_key = fx.org_key.clone();

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
        .post(format!("{base}/v1/actions/call"))
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

/// The exact bug: a telegram-shaped template ships no `url`/`secret_name`;
/// the instance supplies them. Resync must run against the instance and 200,
/// where the old template route 400'd on the missing template URL.
#[tokio::test]
async fn mcp_resync_bearer_instance_populates_discovered_tools() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, stub) = start_stub().await;
    stub.set_tools(vec![json!({
        "name": "search_docs",
        "description": "Search indexed docs",
        "inputSchema": { "type": "object", "properties": { "q": { "type": "string" } }, "required": ["q"] }
    })]);
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let org_key = fx.org_key.clone();

    // Template carries no url / secret_name (both deferred to the instance).
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"openapi": mcp_template_yaml_no_url("stub_tel", "bearer")}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "template: {:?}", resp.text().await);

    // Bearer secret in the vault, referenced by the instance.
    let resp = client
        .put(format!("{base}/v1/secrets/tel_token"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"value": "s3cr3t"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "secret: {:?}", resp.text().await);

    // Instance supplies url + secret_name.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({
            "name": "stub_tel_1",
            "template_key": "stub_tel",
            "url": stub_url,
            "secret_name": "tel_token",
        }))
        .send()
        .await
        .unwrap();
    let inst: Value = resp.json().await.unwrap();
    let instance_id = inst["id"].as_str().expect("instance id").to_string();

    // Resync against the instance → 200 (the bug: this used to 400).
    let resp = client
        .post(format!("{base}/v1/services/{instance_id}/mcp/resync"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "resync: {:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["service_id"], instance_id);
    assert_eq!(body["tool_count"], 1);
    assert!(body["discovered_at"].is_string());

    // The upstream saw the instance's bearer token.
    assert_eq!(stub.last_auth().as_deref(), Some("Bearer s3cr3t"));

    // The instance's action list now includes the discovered `search_docs`
    // (overlaid) alongside the authored `echo`.
    let resp = client
        .get(format!("{base}/v1/services/{instance_id}/actions"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    let actions: Value = resp.json().await.unwrap();
    let names: Vec<&str> = actions
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["key"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"search_docs"), "actions: {names:?}");
    assert!(names.contains(&"echo"), "actions: {names:?}");

    // The instance detail surfaces `discovered_at`.
    let resp = client
        .get(format!(
            "{base}/v1/services/stub_tel_1?include_inactive=true"
        ))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    let detail: Value = resp.json().await.unwrap();
    assert!(detail["discovered_at"].is_string());
}

/// A no-url MCP template can't be instantiated without a `url` — instance
/// creation enforces it, so resync never sees a url-less active instance (its
/// own missing-url 400 is a defensive backstop). This documents that guard.
#[tokio::test]
async fn mcp_instance_requires_url_when_template_has_none() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let org_key = fx.org_key.clone();

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"openapi": mcp_template_yaml_no_url("stub_nourl", "none")}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "template: {:?}", resp.text().await);

    // Creating an instance with no url override is rejected up front.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"name": "stub_nourl_1", "template_key": "stub_nourl"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "{:?}", resp.text().await);
}

/// Resync against an instance of a non-MCP (HTTP) template → 400.
#[tokio::test]
async fn mcp_resync_rejected_on_http_runtime_instance() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let org_key = fx.org_key.clone();

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
        .post(format!("{base}/v1/services"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"name": "plain_http_1", "template_key": "plain_http"}))
        .send()
        .await
        .unwrap();
    let inst: Value = resp.json().await.unwrap();
    let instance_id = inst["id"].as_str().expect("instance id").to_string();

    let resp = client
        .post(format!("{base}/v1/services/{instance_id}/mcp/resync"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

/// Resync disabled when the template sets `autodiscover: false` → 400.
#[tokio::test]
async fn mcp_resync_rejected_when_autodiscover_false() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, _stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let org_key = fx.org_key.clone();

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
        .post(format!("{base}/v1/services"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"name": "stub_pinned_1", "template_key": "stub_pinned"}))
        .send()
        .await
        .unwrap();
    let inst: Value = resp.json().await.unwrap();
    let instance_id = inst["id"].as_str().expect("instance id").to_string();

    let resp = client
        .post(format!("{base}/v1/services/{instance_id}/mcp/resync"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

/// Per-instance isolation: resyncing one instance must not change a sibling
/// instance's action list. Each instance points at its own server.
#[tokio::test]
async fn mcp_resync_is_per_instance() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr_a, stub_a) = start_stub().await;
    stub_a.set_tools(vec![json!({
        "name": "only_on_a",
        "description": "A-only tool",
        "inputSchema": { "type": "object", "properties": {} }
    })]);
    let url_a = format!("http://{addr_a}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let org_key = fx.org_key.clone();

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"openapi": mcp_template_yaml_no_url("stub_iso", "none")}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "template: {:?}", resp.text().await);

    // Two instances of the same template.
    let mk_instance = |name: &str, url: &str| {
        client
            .post(format!("{base}/v1/services"))
            .header(auth(&org_key).0, auth(&org_key).1)
            .json(&json!({"name": name, "template_key": "stub_iso", "url": url}))
    };
    let a: Value = mk_instance("stub_iso_a", &url_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let b: Value = mk_instance("stub_iso_b", &url_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id_a = a["id"].as_str().unwrap().to_string();
    let id_b = b["id"].as_str().unwrap().to_string();

    // Resync only instance A.
    let resp = client
        .post(format!("{base}/v1/services/{id_a}/mcp/resync"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "resync: {:?}", resp.text().await);

    let action_names = |actions: Value| -> Vec<String> {
        actions
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["key"].as_str().unwrap().to_string())
            .collect()
    };

    // A has the discovered tool; B does not.
    let acts_a: Value = client
        .get(format!("{base}/v1/services/{id_a}/actions"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let acts_b: Value = client
        .get(format!("{base}/v1/services/{id_b}/actions"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names_a = action_names(acts_a);
    let names_b = action_names(acts_b);
    assert!(names_a.contains(&"only_on_a".to_string()), "A: {names_a:?}");
    assert!(
        !names_b.contains(&"only_on_a".to_string()),
        "B: {names_b:?}"
    );
}

/// Search must surface a tool discovered on an instance — but only to callers
/// who can see that instance. A second identity without access must not find
/// the instance-only tool. (Added requirement.)
#[tokio::test]
async fn mcp_instance_discovered_tool_search_visibility() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, stub) = start_stub().await;
    stub.set_tools(vec![json!({
        "name": "zzwidgetlookup",
        "description": "Look up a widget by id",
        "inputSchema": { "type": "object", "properties": { "id": { "type": "string" } }, "required": ["id"] }
    })]);
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let org_key = fx.org_key.clone();

    // Two independent agents (each under its own owner user).
    let (_user_a, _agent_a, key_a) = common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let (_user_b, _agent_b, key_b) = common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    // Org-tier MCP template with no url (instance supplies it).
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"openapi": mcp_template_yaml_no_url("stub_vis", "none")}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "template: {:?}", resp.text().await);

    // Agent A creates its own instance and resyncs it.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(&key_a).0, auth(&key_a).1)
        .json(&json!({"name": "stub_vis_a", "template_key": "stub_vis", "url": stub_url}))
        .send()
        .await
        .unwrap();
    let inst: Value = resp.json().await.unwrap();
    let instance_id = inst["id"].as_str().expect("instance id").to_string();

    let resp = client
        .post(format!("{base}/v1/services/{instance_id}/mcp/resync"))
        .header(auth(&key_a).0, auth(&key_a).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "resync: {:?}", resp.text().await);

    let tool_in_search = |body: Value| -> bool {
        body["results"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .any(|r| r["action"].as_str() == Some("zzwidgetlookup"))
            })
            .unwrap_or(false)
    };

    // Agent A (owner) finds the instance-discovered tool.
    let resp = client
        .get(format!("{base}/v1/search?q=zzwidgetlookup"))
        .header(auth(&key_a).0, auth(&key_a).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body_a: Value = resp.json().await.unwrap();
    assert!(
        tool_in_search(body_a.clone()),
        "owner should find instance-discovered tool: {body_a}"
    );

    // Agent B (no access to A's instance) must not.
    let resp = client
        .get(format!(
            "{base}/v1/search?q=zzwidgetlookup&include_catalog=true"
        ))
        .header(auth(&key_b).0, auth(&key_b).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body_b: Value = resp.json().await.unwrap();
    assert!(
        !tool_in_search(body_b.clone()),
        "non-owner must not see instance-only tool: {body_b}"
    );
}

#[tokio::test]
async fn mcp_agent_without_permission_triggers_approval() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, _stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_user, _agent_ident, agent_key) =
        common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let org_key = fx.org_key.clone();

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

    // Create an org-level instance and grant Everyone WRITE access *without*
    // auto-approve-reads. Under the Myself-group model, the read-bypass would
    // otherwise skip Layer 2 entirely; this test is specifically about Layer 2
    // approval mechanics, so we keep the bypass off so a missing permission
    // rule still triggers an approval.
    let svc: Value = client
        .post(format!("{base}/v1/services"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({
            "name": "stub_mcp_noperm",
            "template_key": "stub_mcp_noperm",
            "user_level": false,
            "status": "active",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let svc_id = svc["id"].as_str().expect("service id");

    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let everyone_id = groups
        .iter()
        .find(|g| g["system_kind"].as_str() == Some("everyone"))
        .and_then(|g| g["id"].as_str())
        .expect("Everyone group");
    let resp = client
        .post(format!("{base}/v1/groups/{everyone_id}/grants"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({
            "service_instance_id": svc_id,
            "access_level": "admin",
            "auto_approve_reads": false,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Agent without permission → force-gated to approval even with kind:none.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "stub_mcp_noperm",
            "action": "echo",
            "params": { "x": "hello-approval" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 202, "{:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "pending_approval");
    let approval_id = body["approval_id"]
        .as_str()
        .expect("approval_id")
        .to_string();

    // Reviewer-visible detail must contain the tool name and the arguments
    // — not an empty ActionRequest (vet finding: approval detail empty).
    // The approvals endpoint returns action_detail as a pretty-printed
    // JSON string (see ACTION_DETAIL_MAX_BYTES cap); parse it back.
    let resp = client
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    let detail: Value = resp.json().await.unwrap();
    let detail_str = detail["action_detail"]
        .as_str()
        .expect("action_detail string");
    let parsed: Value = serde_json::from_str(detail_str).expect("action_detail parses as JSON");
    assert_eq!(parsed["runtime"], "mcp");
    assert_eq!(parsed["tool"], "echo");
    assert_eq!(parsed["arguments"]["x"], "hello-approval");
}

/// Audit row for an MCP action.executed must carry `runtime: "mcp"`,
/// `is_error`, and the tool arguments. Regression for vet findings
/// "audit omits is_error" and "audit + approval detail omit tool arguments".
#[tokio::test]
async fn mcp_call_audit_contains_tool_arguments_and_is_error_success() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, _stub) = start_stub().await;
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_user, agent_ident, agent_key) =
        common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let org_key = fx.org_key.clone();

    setup_template_and_grants(SetupCtx {
        base: &base,
        client: &client,
        admin_key: &org_key,
        agent_key: &agent_key,
        agent_ident,
        key: "stub_mcp_audit",
        url: &stub_url,
        auth_bearer_secret: None,
    })
    .await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "stub_mcp_audit",
            "action": "echo",
            "params": { "x": "observable" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

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
    assert_eq!(executed["detail"]["arguments"]["x"], "observable");
    assert_eq!(executed["detail"]["is_error"], false);
}

/// Tool-level isError must flip `is_error: true` on the audit row too.
#[tokio::test]
async fn mcp_call_audit_is_error_true_on_tool_failure() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, stub) = start_stub().await;
    stub.force_error(vec![json!({ "type": "text", "text": "nope" })]);
    let stub_url = format!("http://{addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_user, agent_ident, agent_key) =
        common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let org_key = fx.org_key.clone();

    setup_template_and_grants(SetupCtx {
        base: &base,
        client: &client,
        admin_key: &org_key,
        agent_key: &agent_key,
        agent_ident,
        key: "stub_mcp_fail",
        url: &stub_url,
        auth_bearer_secret: None,
    })
    .await;

    client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({"service": "stub_mcp_fail", "action": "echo", "params": {"x": "a"}}))
        .send()
        .await
        .unwrap();

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
    assert_eq!(executed["detail"]["is_error"], true);
}

/// Editing an MCP template's YAML must NOT wipe `discovered_tools` /
/// `discovered_at` that the stored openapi already carries (e.g. a global that
/// ships its tool list in-repo). `preserve_mcp_discovered_fields` copies them
/// from the previous doc when the new YAML omits them.
/// Regression for vet finding: "Template update wipes discovered_tools".
#[tokio::test]
async fn mcp_template_update_preserves_discovered_tools() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let org_key = fx.org_key.clone();

    // Author discovered_tools + discovered_at directly in the template YAML.
    let seeded_at = "2024-01-02T03:04:05Z";
    let yaml_with_discovered = format!(
        r#"openapi: 3.1.0
info:
  title: Keep
  x-overslash-key: stub_mcp_keep
x-overslash-runtime: mcp
paths: {{}}
x-overslash-mcp:
  auth: {{ kind: none }}
  autodiscover: true
  discovered_at: "{seeded_at}"
  discovered_tools:
    - name: search_docs
      description: Search indexed docs
      input_schema:
        type: object
        properties: {{ q: {{ type: string }} }}
        required: [q]
  tools:
    - name: echo
      risk: read
      description: Echo a string
      input_schema:
        type: object
        properties: {{ x: {{ type: string }} }}
        required: [x]
"#
    );
    let create_resp: Value = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"openapi": yaml_with_discovered}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let template_id = create_resp["id"].as_str().unwrap().to_string();

    // Edit the YAML WITHOUT the discovered fields (tweak a description). This
    // exercises the PUT /v1/templates/:id/manage path that re-compiles the
    // openapi and must carry the discovered fields forward.
    let updated_yaml = r#"openapi: 3.1.0
info:
  title: Keep
  x-overslash-key: stub_mcp_keep
x-overslash-runtime: mcp
paths: {}
x-overslash-mcp:
  auth: { kind: none }
  autodiscover: true
  tools:
    - name: echo
      risk: read
      description: Echo a string (edited)
      input_schema:
        type: object
        properties: { x: { type: string } }
        required: [x]
"#;
    let resp = client
        .put(format!("{base}/v1/templates/{template_id}/manage"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"openapi": updated_yaml}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    // discovered_at must survive the edit.
    let detail: Value = client
        .get(format!("{base}/v1/templates/stub_mcp_keep"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["mcp"]["discovered_at"], seeded_at);
    let actions = detail["actions"].as_array().unwrap();
    assert!(!actions.is_empty());
}
