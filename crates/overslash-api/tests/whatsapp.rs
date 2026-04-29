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

mod common;

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
}

#[derive(Clone, Default)]
struct Stub {
    inner: Arc<Mutex<StubInner>>,
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
        "tools/call" => json!({
            "content": [{ "type": "text", "text": "ok" }],
            "isError": false
        }),
        _ => json!({}),
    };
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

async fn start_stub() -> SocketAddr {
    common::allow_loopback_ssrf();
    let app = Router::new()
        .route("/mcp", post(stub_handler))
        .with_state(Stub::default());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
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
    let RegisterCtx {
        base,
        client,
        admin_key,
        agent_key,
        key,
        url,
        secret_name,
        secret_value,
    } = ctx;
    let yaml = whatsapp_template_yaml(key, url, secret_name);
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
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("missing required argument `recipient`"),
        "expected missing-recipient error, got: {body}"
    );
    // `jid` and `recipient` share no characters, so there's no Levenshtein
    // suggestion — but the candidate list should still surface
    // `recipient` and `text` so the agent knows what's accepted.
    assert!(
        body.contains("unknown argument `jid`")
            && body.contains("`recipient`")
            && body.contains("`text`"),
        "expected jid rejection with candidate list, got: {body}"
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
