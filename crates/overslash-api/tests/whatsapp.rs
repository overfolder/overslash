//! Integration tests for the WhatsApp MCP service template — argument
//! validation against the lowered `input_schema` and disclose-block
//! propagation for MCP-runtime actions.
//!
//! Both behaviors regressed in the same incident: a real call passed `jid`
//! (the documented identifier in the schema's *description*) instead of
//! the schema-declared `recipient` field, and the system silently rendered
//! `{recipient}` in the approval description and collapsed the permission
//! scope to `*`. The tests here pin both fixes:
//!
//!   1. Mismatched arg keys land as a 400 with a typo-recovery suggestion
//!      back to the agent — they no longer reach `resolve_request`'s
//!      placeholder/scope derivation.
//!   2. The MCP `tools[]` extractor honors `disclose:` (previously
//!      hard-coded to empty for MCP tools), so the recipient + body land
//!      on the approval's `disclosed_fields` for the dashboard.

use crate::common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use reqwest::Client;
use serde_json::{Value, json};
use tokio::net::TcpListener;

// ── Minimal MCP stub mirroring whatsapp-mcp-docker's send_message tool ─

#[derive(Default)]
struct StubInner {
    list_calls: u32,
    /// The `jid` argument every `resolve_jid` call arrived with, so a test can
    /// pin that the gateway resolves against the *raw* argument rather than
    /// something it rewrote first.
    resolved_jids: Vec<String>,
}

#[derive(Clone, Default)]
struct Stub {
    inner: Arc<Mutex<StubInner>>,
    /// When true, `resolve_jid` answers `isError: true`. Models the container
    /// being unpaired, mid-resync, or simply down.
    failing_resolver: bool,
}

/// The `resolve_jid` answer for a JID the stub's contact cache knows about,
/// mirroring whatsapp-mcp-docker's `ResolvedJID` shape.
fn resolve_jid_result(jid: &str) -> Value {
    let structured = match jid {
        "239135323373760@lid" => json!({
            "jid": jid,
            "canonical_jid": "34600111222@s.whatsapp.net",
            "kind": "user",
            "name": "Sonia Pérez",
            "phone": "+34600111222",
        }),
        j if j.ends_with("@g.us") => json!({
            "jid": jid,
            "canonical_jid": jid,
            "kind": "group",
            "name": "Peluquería canina",
            // Groups have no phone number; the container spells that "".
            "phone": "",
        }),
        // Nothing known: a populated jid/kind and empty everything else. The
        // container answers this successfully rather than erroring.
        _ => json!({
            "jid": jid,
            "canonical_jid": jid,
            "kind": "unknown",
            "name": "",
            "phone": "",
        }),
    };
    json!({
        "content": [{ "type": "text", "text": structured.to_string() }],
        "structuredContent": structured,
        "isError": false
    })
}

async fn stub_handler(
    State(stub): State<Stub>,
    _headers: HeaderMap,
    Json(req): Json<Value>,
) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-06-18",
            "serverInfo": { "name": "stub-whatsapp", "version": "0" },
            "capabilities": {}
        }),
        "tools/list" => {
            stub.inner.lock().unwrap().list_calls += 1;
            json!({
                "tools": [{
                    "name": "send_message",
                    "description": "Send a WhatsApp text",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "recipient": { "type": "string" },
                            "text": { "type": "string", "minLength": 1 },
                            "reply_to_id": { "type": "string" }
                        },
                        "required": ["recipient", "text"]
                    }
                }]
            })
        }
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(Value::Null);
            match name {
                "resolve_jid" => {
                    let jid = args.get("jid").and_then(Value::as_str).unwrap_or("");
                    stub.inner
                        .lock()
                        .unwrap()
                        .resolved_jids
                        .push(jid.to_string());
                    if stub.failing_resolver {
                        json!({
                            "content": [{ "type": "text", "text": "not paired" }],
                            "isError": true
                        })
                    } else {
                        resolve_jid_result(jid)
                    }
                }
                _ => json!({
                    "content": [{ "type": "text", "text": "ok" }],
                    "isError": false
                }),
            }
        }
        _ => json!({}),
    };
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

async fn start_stub() -> SocketAddr {
    start_stub_with(Stub::default()).await.0
}

/// Start a stub and keep a handle on its state so a test can read back which
/// JIDs the gateway asked it to resolve.
async fn start_stub_with(stub: Stub) -> (SocketAddr, Arc<Mutex<StubInner>>) {
    common::allow_loopback_ssrf();
    let inner = stub.inner.clone();
    let app = Router::new()
        .route("/mcp", post(stub_handler))
        .with_state(stub);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, inner)
}

// ── Template fixture ────────────────────────────────────────────────────

/// A template that authors `send_message` exactly as the shipped
/// `services/whatsapp.yaml` does — same input_schema, same `disclose`
/// block, same quoted+optional description template. `autodiscover: false`
/// so the tool list is the YAML's source of truth and we don't need to
/// fake `tools/list` resync into the registry.
fn whatsapp_template_yaml(key: &str, url: &str, secret_name: &str) -> String {
    format!(
        r#"openapi: "3.1.0"
info:
  title: WhatsApp Stub
  x-overslash-key: {key}
x-overslash-runtime: mcp
paths: {{}}
x-overslash-mcp:
  url: {url}
  auth: {{ kind: bearer, secret_name: {secret_name} }}
  autodiscover: false
  tools:
    - name: send_message
      risk: write
      scope_param: recipient
      description: 'Send WhatsApp message "{{text}}" to {{recipient}}[, quoting {{reply_to_id}}]'
      input_schema:
        type: object
        properties:
          recipient: {{ type: string }}
          text: {{ type: string, minLength: 1 }}
          reply_to_id: {{ type: string }}
        required: [recipient, text]
      disclose:
        - label: Recipient
          filter: ".arguments.recipient"
        - label: Message
          filter: ".arguments.text"
"#
    )
}

/// The shipped template's resolver wiring: `send_message.recipient` declares
/// an MCP `resolve` pointing at the read-only `resolve_jid` tool, and the
/// disclose block prefers the resolved display string over the raw argument.
/// Mirrors `services/whatsapp.yaml` — keep the two in step.
fn whatsapp_resolver_template_yaml(key: &str, url: &str, secret_name: &str) -> String {
    format!(
        r#"openapi: "3.1.0"
info:
  title: WhatsApp Resolver Stub
  x-overslash-key: {key}
x-overslash-runtime: mcp
paths: {{}}
x-overslash-mcp:
  url: {url}
  auth: {{ kind: bearer, secret_name: {secret_name} }}
  autodiscover: false
  tools:
    - name: resolve_jid
      risk: read
      scope_param: jid
      description: "Resolve {{jid}} to its readable identity"
      input_schema:
        type: object
        properties:
          jid: {{ type: string, minLength: 1 }}
        required: [jid]

    - name: send_message
      risk: write
      scope_param: recipient
      description: 'Send WhatsApp message "{{text}}" to {{recipient}}'
      input_schema:
        type: object
        properties:
          recipient:
            type: string
            resolve:
              tool: resolve_jid
              args:
                jid: '{{recipient}}'
              display: '{{name}}[ ({{phone}})]'
              scope: phone
          text: {{ type: string, minLength: 1 }}
        required: [recipient, text]
      disclose:
        - label: Recipient
          filter: ".resolved.recipient // .arguments.recipient"
        - label: JID
          filter: ".arguments.recipient"
        - label: Message
          filter: ".arguments.text"
"#
    )
}

fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

struct RegisterCtx<'a> {
    base: &'a str,
    client: &'a Client,
    admin_key: &'a str,
    agent_key: &'a str,
    key: &'a str,
    url: &'a str,
    secret_name: &'a str,
    secret_value: &'a str,
}

async fn register_whatsapp_template(ctx: RegisterCtx<'_>) {
    let yaml = whatsapp_template_yaml(ctx.key, ctx.url, ctx.secret_name);
    register_template_with(ctx, yaml).await;
}

/// Same registration, but the template carries the `resolve` wiring.
async fn register_whatsapp_resolver_template(ctx: RegisterCtx<'_>) {
    let yaml = whatsapp_resolver_template_yaml(ctx.key, ctx.url, ctx.secret_name);
    register_template_with(ctx, yaml).await;
}

async fn register_template_with(ctx: RegisterCtx<'_>, yaml: String) {
    let RegisterCtx {
        base,
        client,
        admin_key,
        agent_key,
        key,
        url: _,
        secret_name,
        secret_value,
    } = ctx;
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({ "openapi": yaml, "user_level": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "template create: {:?}",
        resp.text().await
    );

    let resp = client
        .put(format!("{base}/v1/secrets/{secret_name}"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({ "value": secret_value }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "secret put: {:?}", resp.text().await);

    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(agent_key).0, auth(agent_key).1)
        .json(&json!({ "name": key, "template_key": key }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "service create: {:?}",
        resp.text().await
    );
}

// ── Tests ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn unknown_arg_jid_is_rejected_with_recipient_suggestion() {
    let pool = common::test_pool().await;
    let stub_addr = start_stub().await;
    let stub_url = format!("http://{stub_addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, _agent_ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    register_whatsapp_template(RegisterCtx {
        base: &base,
        client: &client,
        admin_key: &admin_key,
        agent_key: &agent_key,
        key: "whatsapp_validation",
        url: &stub_url,
        secret_name: "whatsapp_token",
        secret_value: "stub-token",
    })
    .await;

    // The original failing call: `jid` is the WhatsApp parlance the agent
    // reached for, but the schema declares `recipient`. Pre-fix, this
    // forwarded silently and rendered `{recipient}` in the description.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "whatsapp_validation",
            "action": "send_message",
            "params": {
                "jid": "34619967153@s.whatsapp.net",
                "text": "Hello World from Claude x Overslash"
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"], "invalid_action_args",
        "expected invalid_action_args envelope, got: {body}"
    );

    // The `detail` line keeps the human-readable summary so logs stay
    // grep-able; `errors` carries the machine-readable shape.
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("missing required argument `recipient`"),
        "expected missing-recipient detail, got: {body}"
    );

    // The schema is surfaced at the top level so an agent runner can
    // hand a clean shape to the LLM without re-parsing each error.
    let required: Vec<&str> = body["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        required.contains(&"recipient") && required.contains(&"text"),
        "expected required to include recipient + text, got: {required:?}"
    );

    let allowed: Vec<&str> = body["allowed"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        allowed.contains(&"recipient") && allowed.contains(&"text"),
        "expected allowed to include recipient + text, got: {allowed:?}"
    );

    // Per-error tagged structure: a Missing(recipient) and an
    // Unknown(jid). `jid` ↔ `recipient` are too far apart for a
    // Levenshtein suggestion, but `expected` should still list the
    // declared keys so the agent has a recovery path.
    let errors = body["errors"].as_array().unwrap();
    let missing = errors
        .iter()
        .find(|e| e["kind"] == "missing" && e["field"] == "recipient")
        .expect("expected Missing(recipient)");
    assert_eq!(missing["field"], "recipient");

    let unknown = errors
        .iter()
        .find(|e| e["kind"] == "unknown" && e["field"] == "jid")
        .unwrap_or_else(|| panic!("expected Unknown(jid), got: {body}"));
    assert!(
        unknown["suggestion"].is_null(),
        "jid→recipient is not a typo"
    );
    let expected: Vec<&str> = unknown["expected"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        expected.contains(&"recipient") && expected.contains(&"text"),
        "expected candidate list for unknown(jid), got: {expected:?}"
    );
}

#[tokio::test]
async fn correct_call_creates_approval_with_disclosed_recipient_and_message() {
    let pool = common::test_pool().await;
    let stub_addr = start_stub().await;
    let stub_url = format!("http://{stub_addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, _agent_ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    register_whatsapp_template(RegisterCtx {
        base: &base,
        client: &client,
        admin_key: &admin_key,
        agent_key: &agent_key,
        key: "whatsapp_disclose",
        url: &stub_url,
        secret_name: "whatsapp_disclose_token",
        secret_value: "stub-token",
    })
    .await;

    // No permission rule for the agent → MCP call gates on a chain walk
    // that hits a gap → pending_approval. Disclose runs at approval-create.
    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "whatsapp_disclose",
            "action": "send_message",
            "params": {
                "recipient": "34619967153@s.whatsapp.net",
                "text": "Hello World from Claude x Overslash"
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        exec["status"].as_str(),
        Some("pending_approval"),
        "expected pending_approval, got: {exec:?}"
    );
    let approval_id = exec["approval_id"].as_str().unwrap();

    // Description rendered with the body quoted + the recipient substituted —
    // pre-fix this was the literal `{recipient}` placeholder.
    let summary = exec["action_description"].as_str().unwrap();
    assert!(
        summary.contains("\"Hello World from Claude x Overslash\""),
        "body must be quoted in description, got: {summary}"
    );
    assert!(
        summary.contains("34619967153@s.whatsapp.net"),
        "recipient must be substituted in description, got: {summary}"
    );
    assert!(
        !summary.contains("{recipient}") && !summary.contains("{text}"),
        "raw placeholder leaked into description: {summary}"
    );

    let approval: Value = client
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let disclosed = approval["disclosed_fields"]
        .as_array()
        .unwrap_or_else(|| panic!("disclosed_fields missing on approval: {approval:?}"));
    assert_eq!(disclosed.len(), 2, "got: {disclosed:?}");
    assert_eq!(disclosed[0]["label"].as_str(), Some("Recipient"));
    assert_eq!(
        disclosed[0]["value"].as_str(),
        Some("34619967153@s.whatsapp.net")
    );
    assert_eq!(disclosed[1]["label"].as_str(), Some("Message"));
    assert_eq!(
        disclosed[1]["value"].as_str(),
        Some("Hello World from Claude x Overslash")
    );

    // The permission key on the approval includes the recipient — without
    // the validation gate, the missing-arg path collapsed this to `*`.
    let keys = approval["uncovered_keys"]
        .as_array()
        .or_else(|| approval["permission_keys"].as_array());
    if let Some(arr) = keys {
        let joined = arr
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(",");
        assert!(
            joined.contains("34619967153@s.whatsapp.net"),
            "recipient JID must appear in permission key, got: {joined}"
        );
    }
}

/// The headline case: a privacy LID is unreadable on its own, so the gateway
/// resolves it through `resolve_jid` before the approval is minted. The
/// reviewer sees the human, the raw JID is still disclosed for auditability,
/// and the permission key collapses onto the phone number.
#[tokio::test]
async fn lid_recipient_resolves_to_contact_and_phone() {
    let pool = common::test_pool().await;
    let (stub_addr, stub_state) = start_stub_with(Stub::default()).await;
    let stub_url = format!("http://{stub_addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, _agent_ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    register_whatsapp_resolver_template(RegisterCtx {
        base: &base,
        client: &client,
        admin_key: &admin_key,
        agent_key: &agent_key,
        key: "whatsapp_resolve",
        url: &stub_url,
        secret_name: "whatsapp_resolve_token",
        secret_value: "stub-token",
    })
    .await;

    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "whatsapp_resolve",
            "action": "send_message",
            "params": {
                "recipient": "239135323373760@lid",
                "text": "Hola Sonia, ¿tienes hueco esta semana?"
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        exec["status"].as_str(),
        Some("pending_approval"),
        "expected pending_approval, got: {exec:?}"
    );
    let approval_id = exec["approval_id"].as_str().unwrap();

    // The resolver ran against the raw argument, not something rewritten.
    assert_eq!(
        stub_state.lock().unwrap().resolved_jids,
        vec!["239135323373760@lid".to_string()],
        "resolver must be called once, with the caller's literal recipient"
    );

    // The summary names the human instead of the LID.
    let summary = exec["action_description"].as_str().unwrap();
    assert!(
        summary.contains("Sonia Pérez") && summary.contains("+34600111222"),
        "summary must carry the resolved identity, got: {summary}"
    );

    let approval: Value = client
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let disclosed = approval["disclosed_fields"].as_array().unwrap();
    assert_eq!(disclosed[0]["label"].as_str(), Some("Recipient"));
    assert_eq!(
        disclosed[0]["value"].as_str(),
        Some("Sonia Pérez (+34600111222)")
    );
    // The literal argument stays on the approval — the readable row is an
    // addition, never a replacement for what actually goes on the wire.
    assert_eq!(disclosed[1]["label"].as_str(), Some("JID"));
    assert_eq!(disclosed[1]["value"].as_str(), Some("239135323373760@lid"));

    let keys: Vec<&str> = approval["permission_keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        keys.contains(&"whatsapp_resolve:send_message:recipient=+34600111222"),
        "permission key must canonicalize onto the phone number, got: {keys:?}"
    );
    assert!(
        !keys.iter().any(|k| k.contains("@lid")),
        "the LID must not survive into a permission key: {keys:?}"
    );
}

/// Resolution is best-effort. A container that is down, unpaired or mid-resync
/// must degrade the *readability* of the approval, never stop one being
/// raised — and the key falls back to the raw argument, which matches no
/// existing grant and so still gates.
#[tokio::test]
async fn a_failing_resolver_still_gates_on_the_raw_jid() {
    let pool = common::test_pool().await;
    let (stub_addr, _stub_state) = start_stub_with(Stub {
        failing_resolver: true,
        ..Default::default()
    })
    .await;
    let stub_url = format!("http://{stub_addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, _agent_ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    register_whatsapp_resolver_template(RegisterCtx {
        base: &base,
        client: &client,
        admin_key: &admin_key,
        agent_key: &agent_key,
        key: "whatsapp_resolve_fail",
        url: &stub_url,
        secret_name: "whatsapp_resolve_fail_token",
        secret_value: "stub-token",
    })
    .await;

    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "whatsapp_resolve_fail",
            "action": "send_message",
            "params": { "recipient": "239135323373760@lid", "text": "Hola" }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        exec["status"].as_str(),
        Some("pending_approval"),
        "a dead resolver must not block the gate: {exec:?}"
    );
    let approval_id = exec["approval_id"].as_str().unwrap();

    let approval: Value = client
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let disclosed = approval["disclosed_fields"].as_array().unwrap();
    assert_eq!(disclosed[0]["label"].as_str(), Some("Recipient"));
    assert_eq!(
        disclosed[0]["value"].as_str(),
        Some("239135323373760@lid"),
        "unresolved recipient falls back to the literal argument"
    );

    let keys: Vec<&str> = approval["permission_keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        keys.iter().any(|k| k.contains("239135323373760@lid")),
        "with no canonical value the raw JID keys the permission: {keys:?}"
    );
}

/// A group has a name but no phone number. The `[ ({phone})]` segment drops
/// whole rather than rendering a dangling ` ()`, and with nothing to
/// canonicalize the key keeps the group JID.
#[tokio::test]
async fn group_recipient_resolves_to_a_name_without_a_phone() {
    let pool = common::test_pool().await;
    let (stub_addr, _stub_state) = start_stub_with(Stub::default()).await;
    let stub_url = format!("http://{stub_addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, _agent_ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    register_whatsapp_resolver_template(RegisterCtx {
        base: &base,
        client: &client,
        admin_key: &admin_key,
        agent_key: &agent_key,
        key: "whatsapp_resolve_group",
        url: &stub_url,
        secret_name: "whatsapp_resolve_group_token",
        secret_value: "stub-token",
    })
    .await;

    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "whatsapp_resolve_group",
            "action": "send_message",
            "params": { "recipient": "120363000000000000@g.us", "text": "Hola" }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let approval_id = exec["approval_id"]
        .as_str()
        .unwrap_or_else(|| panic!("expected pending_approval, got: {exec:?}"));

    let approval: Value = client
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let disclosed = approval["disclosed_fields"].as_array().unwrap();
    assert_eq!(
        disclosed[0]["value"].as_str(),
        Some("Peluquería canina"),
        "no phone on a group → the optional segment drops entirely"
    );

    let keys: Vec<&str> = approval["permission_keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        keys.iter().any(|k| k.contains("120363000000000000@g.us")),
        "nothing to canonicalize → the group JID keys the permission: {keys:?}"
    );
}

#[tokio::test]
async fn long_message_body_is_truncated_in_description() {
    let pool = common::test_pool().await;
    let stub_addr = start_stub().await;
    let stub_url = format!("http://{stub_addr}/mcp");

    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, _agent_ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    register_whatsapp_template(RegisterCtx {
        base: &base,
        client: &client,
        admin_key: &admin_key,
        agent_key: &agent_key,
        key: "whatsapp_long",
        url: &stub_url,
        secret_name: "whatsapp_long_token",
        secret_value: "stub-token",
    })
    .await;

    let long_body = "a".repeat(500);
    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "whatsapp_long",
            "action": "send_message",
            "params": {
                "recipient": "34619967153@s.whatsapp.net",
                "text": long_body,
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let summary = exec["action_description"]
        .as_str()
        .expect("description present");

    // Description carries the truncated form (≤60 visible chars from the
    // body, ending in '…'); the full text remains accessible via the
    // approval's disclosed_fields.
    assert!(summary.contains('…'), "expected ellipsis, got: {summary}");
    assert!(
        !summary.contains(&"a".repeat(100)),
        "untruncated body leaked into description: {summary}"
    );

    let approval_id = exec["approval_id"].as_str().unwrap();
    let approval: Value = client
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let disclosed = approval["disclosed_fields"].as_array().unwrap();
    let msg = disclosed
        .iter()
        .find(|f| f["label"].as_str() == Some("Message"))
        .expect("Message field");
    assert_eq!(
        msg["value"].as_str().map(str::len),
        Some(500),
        "full body must be carried verbatim on disclose: {msg:?}"
    );
}

// ── Media download ──────────────────────────────────────────────────────
//
// `download_media` is the one WhatsApp tool whose payload can't ride in a
// tool result. The container downloads from WhatsApp's CDN, stores the file
// content-addressed, and returns a *descriptor* pointing at its own
// `/media/{sha256}` route; `x-overslash-download` tells Overslash which field
// of that descriptor is the object, and Overslash swaps it for a capability
// URL of its own. The stub below plays both halves — the MCP tool and the
// byte route behind the same bearer.

const MEDIA_SHA: &str = "9f3a1c2b4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8";
const MEDIA_BYTES: &[u8] = b"fake-mp4-payload-not-valid-utf8-\xff\xfe\x00\x01";

async fn media_handler(
    axum::extract::Path(sha): axum::extract::Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    // Same bearer that guards /mcp. The point of the test is that Overslash
    // re-resolves it from the vault at fetch time, on a request the original
    // caller never authenticated.
    let ok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "Bearer stub-token");
    if !ok {
        return (axum::http::StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    if sha != MEDIA_SHA {
        return (axum::http::StatusCode::NOT_FOUND, "no such object").into_response();
    }
    (
        [
            ("content-type", "video/mp4"),
            ("content-disposition", "attachment; filename=\"clip.mp4\""),
        ],
        MEDIA_BYTES,
    )
        .into_response()
}

async fn media_stub_handler(_headers: HeaderMap, Json(req): Json<Value>) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-06-18",
            "serverInfo": { "name": "stub-whatsapp-media", "version": "0" },
            "capabilities": {}
        }),
        "tools/call" => json!({
            "content": [{ "type": "text", "text": "downloaded" }],
            "structuredContent": {
                "media_path": format!("/media/{MEDIA_SHA}"),
                "mime": "video/mp4",
                "size": MEDIA_BYTES.len(),
                "filename": "clip.mp4",
                "sha256": MEDIA_SHA,
            },
            "isError": false
        }),
        _ => json!({}),
    };
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

async fn start_media_stub() -> SocketAddr {
    common::allow_loopback_ssrf();
    let app = Router::new()
        .route("/mcp", post(media_stub_handler))
        .route("/media/{sha}", axum::routing::get(media_handler));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Mirrors the shipped `services/whatsapp.yaml` `download_media` entry,
/// including its `download:` block.
fn media_template_yaml(key: &str, url: &str, secret_name: &str) -> String {
    format!(
        r#"openapi: "3.1.0"
info:
  title: WhatsApp Media Stub
  x-overslash-key: {key}
x-overslash-runtime: mcp
paths: {{}}
x-overslash-mcp:
  url: {url}
  auth: {{ kind: bearer, secret_name: {secret_name} }}
  autodiscover: false
  tools:
    - name: download_media
      risk: read
      scope_param: chat_jid
      description: 'Download media from {{chat_jid}}'
      download:
        url: .structured.media_path
        mime: .structured.mime
        size: .structured.size
        filename: .structured.filename
        auth: inherit
      input_schema:
        type: object
        properties:
          chat_jid: {{ type: string }}
          message_id: {{ type: string }}
        required: [chat_jid, message_id]
"#
    )
}

async fn setup_media(pool: sqlx::PgPool) -> (String, Client, String, SocketAddr) {
    let stub_addr = start_media_stub().await;
    let stub_url = format!("http://{stub_addr}/mcp");

    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");
    let (_org, agent_ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let yaml = media_template_yaml("whatsapp_media", &stub_url, "whatsapp_token");
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": yaml, "user_level": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "template: {:?}", resp.text().await);

    client
        .put(format!("{base}/v1/secrets/whatsapp_token"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "value": "stub-token" }))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "identity_id": agent_ident,
            "action_pattern": "whatsapp_media:**",
            "effect": "allow",
        }))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({ "name": "whatsapp_media", "template_key": "whatsapp_media" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "service: {:?}", resp.text().await);

    (base, client, agent_key, stub_addr)
}

#[tokio::test]
async fn download_media_swaps_media_path_for_a_capability_url() {
    let pool = common::test_pool().await;
    let (base, client, agent_key, _stub) = setup_media(pool).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "whatsapp_media",
            "action": "download_media",
            "params": { "chat_jid": "34600@s.whatsapp.net", "message_id": "ABC123" },
            "deliver": "url",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let result: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();

    // The container's own `/media/...` path must not reach the caller — it
    // isn't fetchable without the instance's bearer, which the caller doesn't
    // have and must never be given.
    assert!(
        result.get("media_path").is_none(),
        "raw media_path should be replaced, got {result}"
    );
    let url = result["download_url"].as_str().expect("download_url");
    assert!(url.starts_with(&base));
    assert_eq!(result["mime"], "video/mp4");
    assert_eq!(result["size_bytes"], MEDIA_BYTES.len());
    assert_eq!(result["filename"], "clip.mp4");

    // Redeem. Overslash re-resolves the vault bearer and attaches it upstream;
    // the fetching client sends nothing.
    let file = client.get(url).send().await.unwrap();
    assert_eq!(file.status(), 200);
    assert_eq!(file.headers().get("content-type").unwrap(), "video/mp4");
    assert_eq!(
        file.headers().get("content-disposition").unwrap(),
        "attachment; filename=\"clip.mp4\""
    );

    // Byte-exact, including the non-UTF-8 bytes the buffered path would have
    // replaced with U+FFFD.
    let bytes = file.bytes().await.unwrap();
    assert_eq!(bytes.as_ref(), MEDIA_BYTES);
}

#[tokio::test]
async fn download_media_without_deliver_url_returns_the_raw_descriptor() {
    let pool = common::test_pool().await;
    let (base, client, agent_key, _stub) = setup_media(pool).await;

    // Deferred delivery is opt-in. Without it the tool result comes back
    // as-is — no token minted, no URL, no behavior change for existing callers.
    let body: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "whatsapp_media",
            "action": "download_media",
            "params": { "chat_jid": "34600@s.whatsapp.net", "message_id": "ABC123" },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let envelope: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        envelope["structured"]["media_path"],
        format!("/media/{MEDIA_SHA}")
    );
    assert!(envelope.get("download_url").is_none());
}
