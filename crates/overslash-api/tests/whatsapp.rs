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

/// The shipped template's resolver wiring: a write tool's recipient-shaped
/// param declares an MCP `resolve` pointing at the read-only `resolve_jid`
/// tool, and the disclose block prefers the resolved display string over the
/// raw argument. Three tools carry one so the fixture covers both param names
/// the shipped template resolves on — `recipient` (send_message, send_file)
/// and `chat_jid` (send_reaction) — plus an `enum` param, since v0.7.0's
/// `send_file` is the first shipped WhatsApp tool to declare one.
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

    - name: send_reaction
      risk: write
      scope_param: chat_jid
      description: 'React to {{message_id}} in {{chat_jid}}'
      input_schema:
        type: object
        properties:
          chat_jid:
            type: string
            resolve:
              tool: resolve_jid
              args:
                jid: '{{chat_jid}}'
              display: '{{name}}[ ({{phone}})]'
              scope: phone
          message_id: {{ type: string, minLength: 1 }}
          emoji: {{ type: string }}
        required: [chat_jid, message_id, emoji]
      disclose:
        - label: Chat
          filter: ".resolved.chat_jid // .arguments.chat_jid"
        - label: JID
          filter: ".arguments.chat_jid"
        - label: Emoji
          primary: true
          filter: ".arguments.emoji"

    - name: send_file
      risk: write
      scope_param: recipient
      description: 'Send {{media_path}} to {{recipient}}'
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
          media_path: {{ type: string, minLength: 1 }}
          media_type:
            type: string
            enum: [auto, image, video, audio, document, sticker]
            default: auto
          caption: {{ type: string }}
        required: [recipient, media_path]
      disclose:
        - label: Recipient
          filter: ".resolved.recipient // .arguments.recipient"
        - label: File
          primary: true
          filter: ".arguments.media_path"
        - label: Type
          filter: '.arguments.media_type // "auto"'
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

/// The MCP half of the resolver cache (D64). A second identical call must not
/// touch the server at all — not the `tools/call`, and not the `initialize`
/// that precedes it.
///
/// Asserting the *whole round trip* is absent, rather than just the resolver
/// invocation, is the point: on the MCP path the expensive part is
/// `mcp_caller::build_client`, which reads the vault and resolves the host
/// through a blocking `to_socket_addrs` while an approval is being minted. A
/// cache that skipped only `tools/call` would still pay for all of that.
#[tokio::test]
async fn a_repeated_lid_resolves_once_across_calls() {
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

    let send = |body: Value| {
        let client = client.clone();
        let base = base.clone();
        let agent_key = agent_key.clone();
        async move {
            client
                .post(format!("{base}/v1/actions/call"))
                .header(auth(&agent_key).0, auth(&agent_key).1)
                .json(&body)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let payload = json!({
        "service": "whatsapp_resolve",
        "action": "send_message",
        "params": {
            "recipient": "239135323373760@lid",
            "text": "Hola Sonia, ¿tienes hueco esta semana?"
        }
    });

    let first = send(payload.clone()).await;
    assert_eq!(
        first["status"].as_str(),
        Some("pending_approval"),
        "expected pending_approval, got: {first:?}"
    );
    assert_eq!(
        stub_state.lock().unwrap().resolved_jids.len(),
        1,
        "the first call resolves live"
    );

    let second = send(payload).await;
    assert_eq!(
        second["status"].as_str(),
        Some("pending_approval"),
        "expected pending_approval, got: {second:?}"
    );
    assert_eq!(
        stub_state.lock().unwrap().resolved_jids,
        vec!["239135323373760@lid".to_string()],
        "the second call must answer from cache, making no further resolve_jid"
    );

    // Both approvals name the human, not the LID — a cached answer has to be
    // as good as a fresh one or the resolver may as well not exist.
    let summary = second["action_description"].as_str().unwrap();
    assert!(
        summary.contains("Sonia Pérez") && summary.contains("+34600111222"),
        "the cached call must still carry the resolved identity, got: {summary}"
    );

    // And the canonicalized permission key survives the round trip: `scope:
    // phone` is what collapses every address Sonia answers at onto one grant,
    // so a cache that dropped it would silently re-fragment the rules list.
    let keys = second["permission_keys"]
        .as_array()
        .expect("permission_keys present")
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(",");
    assert!(
        keys.contains("+34600111222"),
        "cached canonical value must still key the permission, got: {keys}"
    );
}

// ── v0.7.0 surface ──────────────────────────────────────────────────────
//
// whatsapp-mcp-docker 0.7.0 widened the write surface well past
// `send_message`: media sends, reactions, polls, presence, disappearing
// timers and read receipts. Two things about that release are new for this
// template and are what the tests below pin.
//
// First, `send_message.recipient` stopped being the only param worth
// resolving. A reaction is as visible in a chat as a message is, and it is
// addressed by `chat_jid` — so the D55 machinery has to work on a param that
// isn't called `recipient`, and the permission key has to canonicalize the
// same way. Second, `send_file` is the first shipped WhatsApp tool with an
// `enum`, and a bad `media_type` has to come back as a 400 the agent can act
// on rather than reaching the container.

/// The reaction path's version of `lid_recipient_resolves_to_contact_and_phone`.
/// Nothing about resolution is specific to a param named `recipient`; this
/// pins that, because the shipped template resolves on `chat_jid` for six of
/// its v0.7.0 tools.
#[tokio::test]
async fn a_chat_jid_param_resolves_for_a_reaction_approval() {
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
        key: "whatsapp_reaction",
        url: &stub_url,
        secret_name: "whatsapp_reaction_token",
        secret_value: "stub-token",
    })
    .await;

    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "whatsapp_reaction",
            "action": "send_reaction",
            "params": {
                "chat_jid": "239135323373760@lid",
                "message_id": "3EB0C767D26B8CA1F8A2",
                "emoji": "👍"
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

    assert_eq!(
        stub_state.lock().unwrap().resolved_jids,
        vec!["239135323373760@lid".to_string()],
        "the resolver must run against chat_jid's literal value"
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
    assert_eq!(disclosed[0]["label"].as_str(), Some("Chat"));
    assert_eq!(
        disclosed[0]["value"].as_str(),
        Some("Sonia Pérez (+34600111222)"),
        "the reviewer must see the human whose chat is being reacted in"
    );
    assert_eq!(disclosed[1]["label"].as_str(), Some("JID"));
    assert_eq!(disclosed[1]["value"].as_str(), Some("239135323373760@lid"));
    // The emoji is the whole payload of a reaction — it is the hero field.
    assert_eq!(disclosed[2]["label"].as_str(), Some("Emoji"));
    assert_eq!(disclosed[2]["value"].as_str(), Some("👍"));

    let keys: Vec<&str> = approval["permission_keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        keys.contains(&"whatsapp_reaction:send_reaction:chat_jid=+34600111222"),
        "a chat_jid scope must canonicalize onto the phone number too, got: {keys:?}"
    );
    assert!(
        !keys.iter().any(|k| k.contains("@lid")),
        "the LID must not survive into a permission key: {keys:?}"
    );
}

/// `send_file` never carries bytes — it names them. The approval therefore has
/// to disclose the *reference*, and the envelope the container will pick, so a
/// reviewer can tell "forward the invoice PDF" from "send this as a sticker".
#[tokio::test]
async fn send_file_discloses_the_media_reference_and_envelope() {
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
        key: "whatsapp_media_send",
        url: &stub_url,
        secret_name: "whatsapp_media_send_token",
        secret_value: "stub-token",
    })
    .await;

    let media_path = format!("/media/{MEDIA_SHA}");
    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "whatsapp_media_send",
            "action": "send_file",
            "params": {
                "recipient": "239135323373760@lid",
                "media_path": media_path,
                "caption": "la factura de marzo"
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
    let row = |label: &str| -> String {
        disclosed
            .iter()
            .find(|d| d["label"].as_str() == Some(label))
            .unwrap_or_else(|| panic!("no `{label}` row in {disclosed:?}"))["value"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(row("Recipient"), "Sonia Pérez (+34600111222)");
    assert_eq!(
        row("File"),
        media_path,
        "the byte reference must be reviewable"
    );
    // `media_type` was omitted, and the filter spells the default rather than
    // dropping the row — "auto" is a real decision the container will make.
    assert_eq!(row("Type"), "auto");
}

/// The first shipped WhatsApp enum. A `media_type` outside the declared set has
/// to fail at the gateway with the member list attached: the container would
/// reject it too, but only after a round trip, and with an error the agent
/// cannot recover from as cheaply.
#[tokio::test]
async fn an_unknown_media_type_is_rejected_with_the_enum_members() {
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
        key: "whatsapp_media_enum",
        url: &stub_url,
        secret_name: "whatsapp_media_enum_token",
        secret_value: "stub-token",
    })
    .await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "whatsapp_media_enum",
            "action": "send_file",
            "params": {
                "recipient": "34600111222@s.whatsapp.net",
                "media_path": format!("/media/{MEDIA_SHA}"),
                "media_type": "gif"
            }
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_action_args", "got: {body}");

    let err = body["errors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "not_in_enum" && e["field"] == "media_type")
        .unwrap_or_else(|| panic!("expected NotInEnum(media_type), got: {body}"));
    let allowed: Vec<&str> = err["allowed"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        allowed.contains(&"sticker") && allowed.contains(&"auto"),
        "the member list is the agent's recovery path, got: {allowed:?}"
    );

    // Rejected at the gateway: the container never saw it, so no resolver ran
    // and nothing was dispatched.
    assert!(
        stub_state.lock().unwrap().resolved_jids.is_empty(),
        "a schema rejection must short-circuit before the resolver"
    );
}

// ── Container catalog drift ─────────────────────────────────────────────
//
// The shipped template is a hand-mirrored copy of the container's
// `tools/list`. Nothing in this repo pins a container image, tag or digest,
// so this constant *is* the version contract — and until v0.7.0 nothing
// noticed when the two drifted. The failure that matters here is an
// ADDITION: a release ships new tools, the template keeps working, and the
// capability is simply unreachable with no error anywhere. So this asserts
// both directions, not just that every exposed tool exists upstream.

/// whatsapp-mcp-docker v0.7.0 `tools/list`, verified 2026-08-14 against
/// <https://github.com/angel-manuel/whatsapp-mcp-docker/releases/tag/v0.7.0>
/// (`internal/tools/register.go` + `internal/mcptools/tools.go`, cross-checked
/// against `SUPPORTED.md`).
const CONTAINER_CATALOG_V0_7_0: &[&str] = &[
    // Cache-backed reads (internal/mcptools) — no whatsmeow call.
    "get_chat",
    "get_contact_chats",
    "get_conversation",
    "get_direct_chat_by_contact",
    "get_last_interaction",
    "get_message_context",
    "list_chats",
    "list_conversations",
    "list_messages",
    // whatsmeow-backed (internal/tools).
    "cache_sync",
    "cache_sync_status",
    "download_media",
    "get_contact_details",
    "get_group_info",
    "get_poll_results",
    "list_all_contacts",
    "mark_read",
    "pairing_complete",
    "pairing_start",
    "ping",
    "resolve_jid",
    "search_contacts",
    "send_audio_message",
    "send_chat_presence",
    "send_file",
    "send_message",
    "send_poll",
    "send_presence",
    "send_reaction",
    "set_default_disappearing_timer",
    "set_disappearing_timer",
    "set_status_message",
    "subscribe_presence",
    "vote_poll",
];

/// Tools the container serves that the template deliberately does not expose.
/// Every entry needs a reason — an unexplained omission is indistinguishable
/// from a missed sync, which is the whole failure this test exists to catch.
const INTENTIONALLY_NOT_EXPOSED: &[&str] = &[
    // `cache_sync_status` is the richer diagnostic and is gated identically,
    // so a bare liveness probe adds a tool without adding a capability.
    "ping",
];

/// Actions the gateway *serves itself* rather than forwarding.
///
/// They are in the template so they carry a permission key, a risk class and a
/// disclose block; they are not in tools/list because the container has no such
/// tool. Direction 1 skips them — that assertion means "nothing we forward can
/// 404", and nothing here is forwarded. Direction 2 is unaffected: these names
/// are not in the container catalog to begin with.
const GATEWAY_SYNTHESIZED: &[&str] = &[
    // `POST /media` is plain HTTP on the container's own origin behind the same
    // bearer, not a JSON-RPC tool. The entry exists so pushing bytes is
    // permission-checked and approvable.
    "upload_media",
];

#[tokio::test]
async fn shipped_template_matches_the_container_catalog() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool, None).await;
    let (_org, _agent_ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let tpl: Value = client
        .get(format!("{base}/v1/templates/whatsapp"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let actions = tpl["actions"]
        .as_array()
        .unwrap_or_else(|| panic!("whatsapp template has actions: {tpl}"));
    assert!(
        !actions.is_empty(),
        "whatsapp template exposes tools: {tpl}"
    );

    // The upstream name is `mcp_tool` when aliased, else the action key.
    let exposed: Vec<&str> = actions
        .iter()
        .map(|a| {
            a["mcp_tool"]
                .as_str()
                .or_else(|| a["key"].as_str())
                .unwrap_or_else(|| panic!("action with neither mcp_tool nor key: {a}"))
        })
        .collect();

    // Direction 1: nothing exposed that the container does not serve. A tool
    // that moved or was renamed upstream answers -32603 "Unknown tool" at
    // call time, which is a 502 the caller can do nothing about.
    for name in &exposed {
        if GATEWAY_SYNTHESIZED.contains(name) {
            continue;
        }
        assert!(
            CONTAINER_CATALOG_V0_7_0.contains(name),
            "template exposes `{name}`, which whatsapp-mcp-docker v0.7.0 does not serve — \
             re-run tools/list against the container and re-sync services/whatsapp.yaml \
             (see the CONTAINER_CATALOG_V0_7_0 constant)"
        );
    }

    // Direction 2: nothing served is silently unexposed. This is the case
    // v0.7.0 itself was: thirteen new tools, reachable by the container and
    // by nobody through the gateway.
    let missing: Vec<&&str> = CONTAINER_CATALOG_V0_7_0
        .iter()
        .filter(|name| !exposed.contains(name) && !INTENTIONALLY_NOT_EXPOSED.contains(name))
        .collect();
    assert!(
        missing.is_empty(),
        "whatsapp-mcp-docker serves tools the template does not expose: {missing:?} — \
         add them to services/whatsapp.yaml, or to INTENTIONALLY_NOT_EXPOSED with a reason"
    );
}
