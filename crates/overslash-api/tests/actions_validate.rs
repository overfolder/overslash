// Tests run dynamic SQL (`sqlx::query`) for cross-table counts that
// don't need compile-time schema checking — same exemption the rest of
// the integration test layer carries.
#![allow(clippy::disallowed_methods)]

//! Integration tests for `POST /v1/actions/validate` — the dry-run probe
//! that runs `validate_args` + permission check without executing the
//! upstream call, writing an approval, or burning rate-limit budget.
//!
//! These tests pin three contracts:
//!
//!   1. The 400 body for bad params is byte-equivalent to what
//!      `/v1/actions/call` returns, so callers can pre-flight and act on
//!      the same shape they'd see at execution time.
//!   2. A permission gap surfaces as `would_require_approval` *without*
//!      an approval row hitting the database — the dry-run is truly
//!      side-effect-free.
//!   3. Removed `connection` field is rejected at parse time (400 from
//!      `deny_unknown_fields`), so callers that haven't migrated to
//!      Service + HTTP verb get a clear error instead of silent acceptance.

use crate::common;

use std::net::SocketAddr;

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use reqwest::Client;
use serde_json::{Value, json};
use sqlx::Row;
use tokio::net::TcpListener;

// ── Minimal MCP stub mirroring the WhatsApp send_message tool ──────────
//
// The validate endpoint never actually invokes the upstream, but Mode C
// resolution still needs a service template to exist with a resolvable
// URL. Reusing the same shape as `tests/whatsapp.rs` keeps the fixtures
// familiar.

async fn stub_handler(
    State(_): State<()>,
    _headers: HeaderMap,
    Json(req): Json<Value>,
) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-06-18",
            "serverInfo": { "name": "stub", "version": "0" },
            "capabilities": {}
        }),
        _ => json!({}),
    };
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

async fn start_stub() -> SocketAddr {
    common::allow_loopback_ssrf();
    let app = Router::new()
        .route("/mcp", post(stub_handler))
        .with_state(());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

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
      description: 'Send WhatsApp message "{{text}}" to {{recipient}}'
      input_schema:
        type: object
        properties:
          recipient: {{ type: string }}
          text: {{ type: string, minLength: 1 }}
        required: [recipient, text]
"#
    )
}

/// Telegram-flavored stub with a typed `chat_id: string` and an enum
/// `parse_mode` — the two shapes that burned real approvals (`chat_id` sent as
/// an integer, `parse_mode` as a bad member).
fn telegram_template_yaml(key: &str, url: &str, secret_name: &str) -> String {
    format!(
        r#"openapi: "3.1.0"
info:
  title: Telegram Stub
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
      scope_param: chat_id
      input_schema:
        type: object
        properties:
          chat_id: {{ type: string }}
          text: {{ type: string }}
          parse_mode: {{ type: string, enum: [HTML, Markdown, MarkdownV2] }}
        required: [chat_id, text]
"#
    )
}

fn auth_header(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

struct Fixture {
    base: String,
    client: Client,
    agent_key: String,
    admin_key: String,
    pool: sqlx::PgPool,
}

async fn setup_with_template(template_key: &str) -> Fixture {
    setup_with_yaml(template_key, |url| {
        whatsapp_template_yaml(template_key, url, "whatsapp_token")
    })
    .await
}

/// Like [`setup_with_template`] but lets the caller supply the template YAML
/// (built from the live stub URL) — used by the type/enum coercion tests, which
/// need a template shape different from the shared WhatsApp stub.
async fn setup_with_yaml(template_key: &str, build_yaml: impl FnOnce(&str) -> String) -> Fixture {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let stub_addr = start_stub().await;
    let stub_url = format!("http://{stub_addr}/mcp");

    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (_user, _ident, agent_key) = common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    let yaml = build_yaml(&stub_url);
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth_header(&admin_key).0, auth_header(&admin_key).1)
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
        .put(format!("{base}/v1/secrets/whatsapp_token"))
        .header(auth_header(&admin_key).0, auth_header(&admin_key).1)
        .json(&json!({ "value": "stub" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "secret put: {:?}", resp.text().await);

    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth_header(&agent_key).0, auth_header(&agent_key).1)
        .json(&json!({ "name": template_key, "template_key": template_key }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "service create: {:?}",
        resp.text().await
    );

    Fixture {
        base,
        client,
        agent_key,
        admin_key,
        pool,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

/// Pin: `validate_args` runs **before** the approval-creation branch
/// in `/v1/actions/call`. The same agent that would otherwise have its
/// (well-formed) call land as a `pending_approval` row must instead get
/// a 400 — the user should never click "Allow" on a request that would
/// then fail validation. Today this ordering is structural (the
/// validation gate sits at the top of `call_action_impl`); this test
/// locks it in.
#[tokio::test]
async fn call_returns_400_for_bad_args_even_when_approval_would_fire() {
    let fx = setup_with_template("validate_ordering").await;

    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth_header(&fx.agent_key).0, auth_header(&fx.agent_key).1)
        .json(&json!({
            "service": "validate_ordering",
            "action": "send_message",
            "params": {
                "jid": "x@s.whatsapp.net",
                "text": "hi"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "expected 400, not approval (202)");

    // Confirm the approval branch was skipped: no row hit the table.
    let count: i64 = sqlx::query("SELECT COUNT(*)::bigint AS c FROM approvals")
        .fetch_one(&fx.pool)
        .await
        .unwrap()
        .get("c");
    assert_eq!(
        count, 0,
        "validation must run before approval; found {count} rows"
    );
}

/// Bad-params on `/validate` returns the same 400 body shape as
/// `/call` — same envelope, same `required` / `allowed` / `errors`. This
/// is what makes the dry-run useful: the client decodes the same error
/// in both endpoints.
#[tokio::test]
async fn invalid_args_400_is_byte_equivalent_to_call() {
    let fx = setup_with_template("validate_byte_equiv").await;

    let bad_body = json!({
        "service": "validate_byte_equiv",
        "action": "send_message",
        "params": {
            "jid": "34619967153@s.whatsapp.net",
            "text": "hi"
        }
    });

    let call_resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth_header(&fx.agent_key).0, auth_header(&fx.agent_key).1)
        .json(&bad_body)
        .send()
        .await
        .unwrap();
    assert_eq!(call_resp.status(), 400);
    let call_body: Value = call_resp.json().await.unwrap();

    let validate_resp = fx
        .client
        .post(format!("{}/v1/actions/validate", fx.base))
        .header(auth_header(&fx.agent_key).0, auth_header(&fx.agent_key).1)
        .json(&bad_body)
        .send()
        .await
        .unwrap();
    assert_eq!(validate_resp.status(), 400);
    let validate_body: Value = validate_resp.json().await.unwrap();

    assert_eq!(
        call_body, validate_body,
        "validate's 400 body must match call's exactly"
    );
    assert_eq!(call_body["error"], "invalid_action_args");
}

/// Well-formed args + a permission gap → 200 `would_require_approval`.
/// The same body sent to `/call` would write an approval row; `/validate`
/// must not. This pins the no-side-effect contract.
#[tokio::test]
async fn approval_gap_reported_without_writing_approval_row() {
    let fx = setup_with_template("validate_no_writes").await;

    let body = json!({
        "service": "validate_no_writes",
        "action": "send_message",
        "params": {
            "recipient": "user@s.whatsapp.net",
            "text": "hello"
        }
    });

    let resp = fx
        .client
        .post(format!("{}/v1/actions/validate", fx.base))
        .header(auth_header(&fx.agent_key).0, auth_header(&fx.agent_key).1)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "validate: {:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(
        body["permission"]["status"], "would_require_approval",
        "expected gap to surface as would_require_approval, got: {body}"
    );

    // No approval row hit the database. We query directly because the
    // `/v1/approvals` listing endpoint applies caller-scoped filters
    // that could mask a leaked row created on a different identity.
    let count: i64 = sqlx::query("SELECT COUNT(*)::bigint AS c FROM approvals")
        .fetch_one(&fx.pool)
        .await
        .unwrap()
        .get("c");
    assert_eq!(
        count, 0,
        "validate must not write approvals; found {count} rows"
    );
}

/// Disabled MCP actions return 404 on `/validate`, matching `/call`'s
/// behavior. Without this check, an agent could pre-flight a disabled
/// action successfully and then have the real `/call` fail with 404 —
/// breaking the dry-run contract.
#[tokio::test]
async fn disabled_mcp_action_404s_on_validate() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let stub_addr = start_stub().await;
    let stub_url = format!("http://{stub_addr}/mcp");
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_user, _ident, agent_key) = common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;
    let admin_key = fx.org_key.clone();

    // Same template shape as the other tests but with `disabled: true`
    // on the only action.
    let yaml = format!(
        r#"openapi: "3.1.0"
info:
  title: Disabled Stub
  x-overslash-key: validate_disabled
x-overslash-runtime: mcp
paths: {{}}
x-overslash-mcp:
  url: {stub_url}
  auth: {{ kind: bearer, secret_name: whatsapp_token }}
  autodiscover: false
  tools:
    - name: send_message
      disabled: true
      risk: write
      input_schema:
        type: object
        properties:
          recipient: {{ type: string }}
        required: [recipient]
"#
    );
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth_header(&admin_key).0, auth_header(&admin_key).1)
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
        .put(format!("{base}/v1/secrets/whatsapp_token"))
        .header(auth_header(&admin_key).0, auth_header(&admin_key).1)
        .json(&json!({ "value": "stub" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth_header(&agent_key).0, auth_header(&agent_key).1)
        .json(&json!({ "name": "validate_disabled", "template_key": "validate_disabled" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = client
        .post(format!("{base}/v1/actions/validate"))
        .header(auth_header(&agent_key).0, auth_header(&agent_key).1)
        .json(&json!({
            "service": "validate_disabled",
            "action": "send_message",
            "params": { "recipient": "x@s.whatsapp.net" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "disabled action must 404 on validate (mirrors /call)"
    );
}

/// The removed `connection` field is rejected at parse time. Serde's
/// `deny_unknown_fields` surfaces through axum's `Json` extractor as a
/// 4xx with the `unknown field` error before any handler logic runs —
/// the exact code (400 vs 422) depends on the fixture's rejection
/// handler, both are acceptable. Callers that haven't migrated to
/// Service + HTTP verb get a clear message instead of silent acceptance.
#[tokio::test]
async fn removed_connection_field_is_rejected() {
    let fx = setup_with_template("validate_mode_b").await;

    let resp = fx
        .client
        .post(format!("{}/v1/actions/validate", fx.base))
        .header(auth_header(&fx.agent_key).0, auth_header(&fx.agent_key).1)
        .json(&json!({
            "connection": uuid::Uuid::new_v4(),
            "method": "GET",
            "url": "https://api.example.com/whoami"
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 422,
        "expected 400 or 422 for parse-rejected unknown field, got: {status}"
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("unknown field") && body.contains("connection"),
        "expected unknown-field rejection naming `connection`, got: {body}"
    );
}

/// After the Mode A collapse, the legacy no-`service` raw-HTTP shape
/// (`{method, url}` without `service`) is rejected with a 400 carrying
/// the migration hint `service: 'http'`. Pinning this contract here so
/// callers that haven't migrated to the new shape get a single
/// recognisable error string instead of a different message every release.
#[tokio::test]
async fn no_service_field_is_rejected_with_migration_hint() {
    let fx = setup_with_template("validate_no_service_hint").await;

    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth_header(&fx.agent_key).0, auth_header(&fx.agent_key).1)
        .json(&json!({
            "method": "GET",
            "url": "https://api.example.com/whoami"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("'service' is required") && body.contains("'http'"),
        "expected migration hint pointing at service: 'http', got: {body}"
    );
}

/// Well-formed args + caller has full permissions → 200 `allowed`.
/// Pins the happy path and confirms the permission check actually runs
/// (and produces a different outcome than the gap test) rather than
/// always reporting `would_require_approval`.
#[tokio::test]
async fn passes_when_caller_has_permission() {
    let fx = setup_with_template("validate_allowed").await;

    // Grant Everyone admin on an org-level instance of the same
    // template, so the org-admin user clears Layer 1's ceiling. Users
    // skip Layer 2 anyway, so the resolved permission is `allowed`.
    common::grant_service_to_everyone(&fx.base, &fx.client, &fx.admin_key, "validate_allowed")
        .await;

    let resp = fx
        .client
        .post(format!("{}/v1/actions/validate", fx.base))
        .header(auth_header(&fx.admin_key).0, auth_header(&fx.admin_key).1)
        .json(&json!({
            "service": "validate_allowed",
            "action": "send_message",
            "params": {
                "recipient": "user@s.whatsapp.net",
                "text": "hi"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "validate: {:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["permission"]["status"], "allowed");
}

/// A bad enum member is rejected with a 400 `not_in_enum` **before** the
/// approval branch — the burned-approval class. Mirrors
/// `call_returns_400_for_bad_args_even_when_approval_would_fire` but for the
/// new enum check.
#[tokio::test]
async fn call_rejects_bad_enum_before_approval() {
    let fx = setup_with_yaml("telegram_bad_enum", |url| {
        telegram_template_yaml("telegram_bad_enum", url, "whatsapp_token")
    })
    .await;

    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth_header(&fx.agent_key).0, auth_header(&fx.agent_key).1)
        .json(&json!({
            "service": "telegram_bad_enum",
            "action": "send_message",
            "params": {
                "chat_id": "612616872",
                "text": "hi",
                "parse_mode": "Fancy"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "expected 400, not approval (202)");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "invalid_action_args");
    let has_enum_error = body["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["kind"] == "not_in_enum" && e["field"] == "parse_mode");
    assert!(
        has_enum_error,
        "expected not_in_enum(parse_mode), got: {body}"
    );

    let count: i64 = sqlx::query("SELECT COUNT(*)::bigint AS c FROM approvals")
        .fetch_one(&fx.pool)
        .await
        .unwrap()
        .get("c");
    assert_eq!(
        count, 0,
        "enum check must run before approval; found {count}"
    );
}

/// An integer `chat_id` sent to a `string` param is coerced (not rejected), so
/// the call proceeds past validation and lands as a pending approval — exactly
/// the request that previously failed post-approval. Proves the coerced value
/// carries through to the approval branch.
#[tokio::test]
async fn call_coerces_integer_chat_id_past_validation() {
    let fx = setup_with_yaml("telegram_coerce", |url| {
        telegram_template_yaml("telegram_coerce", url, "whatsapp_token")
    })
    .await;

    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth_header(&fx.agent_key).0, auth_header(&fx.agent_key).1)
        .json(&json!({
            "service": "telegram_coerce",
            "action": "send_message",
            "params": {
                "chat_id": 612616872,
                "text": "hi"
            }
        }))
        .send()
        .await
        .unwrap();
    // 202 = pending approval (agent has no grant) — the point is it is NOT a
    // 400 validation error; the integer was coerced to a string and accepted.
    assert_eq!(
        resp.status(),
        202,
        "expected pending-approval, got: {:?}",
        resp.text().await
    );

    let count: i64 = sqlx::query("SELECT COUNT(*)::bigint AS c FROM approvals")
        .fetch_one(&fx.pool)
        .await
        .unwrap()
        .get("c");
    assert_eq!(count, 1, "coerced call should reach the approval branch");
}

/// The new enum/type error kinds keep the `/call` vs `/validate` byte-identical
/// 400 contract — same envelope, same `errors`.
#[tokio::test]
async fn bad_enum_400_is_byte_equivalent_across_call_and_validate() {
    let fx = setup_with_yaml("telegram_byte_equiv", |url| {
        telegram_template_yaml("telegram_byte_equiv", url, "whatsapp_token")
    })
    .await;

    let bad_body = json!({
        "service": "telegram_byte_equiv",
        "action": "send_message",
        "params": {
            "chat_id": "612616872",
            "text": "hi",
            "parse_mode": "Fancy"
        }
    });

    let call_resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth_header(&fx.agent_key).0, auth_header(&fx.agent_key).1)
        .json(&bad_body)
        .send()
        .await
        .unwrap();
    assert_eq!(call_resp.status(), 400);
    let call_body: Value = call_resp.json().await.unwrap();

    let validate_resp = fx
        .client
        .post(format!("{}/v1/actions/validate", fx.base))
        .header(auth_header(&fx.agent_key).0, auth_header(&fx.agent_key).1)
        .json(&bad_body)
        .send()
        .await
        .unwrap();
    assert_eq!(validate_resp.status(), 400);
    let validate_body: Value = validate_resp.json().await.unwrap();

    assert_eq!(call_body, validate_body, "400 bodies must match exactly");
    assert_eq!(call_body["error"], "invalid_action_args");
}

/// A telegram-shaped template whose `chat_id`/`text` params declare
/// caller-facing aliases (`chat`/`to`, `body`/`message`). Exercises the
/// `x-overslash-aliases` extension end-to-end through the loader.
fn telegram_aliased_template_yaml(key: &str, url: &str, secret_name: &str) -> String {
    format!(
        r#"openapi: "3.1.0"
info:
  title: Telegram Aliased Stub
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
      scope_param: chat_id
      input_schema:
        type: object
        properties:
          chat_id: {{ type: string, x-overslash-aliases: [chat, to] }}
          text: {{ type: string, x-overslash-aliases: [body, message] }}
        required: [chat_id, text]
"#
    )
}

/// A call that supplies the aliases instead of the canonical param names is
/// rewritten to canonical before validation — so it clears the arg gate and
/// reaches the approval branch (202) instead of a 400 unknown-argument error.
#[tokio::test]
async fn call_accepts_param_aliases() {
    let fx = setup_with_yaml("telegram_alias", |url| {
        telegram_aliased_template_yaml("telegram_alias", url, "whatsapp_token")
    })
    .await;

    let resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth_header(&fx.agent_key).0, auth_header(&fx.agent_key).1)
        .json(&json!({
            "service": "telegram_alias",
            "action": "send_message",
            "params": {
                "chat": "612616872",
                "body": "hi"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        202,
        "aliased call should validate and reach approval, got: {:?}",
        resp.text().await
    );

    let count: i64 = sqlx::query("SELECT COUNT(*)::bigint AS c FROM approvals")
        .fetch_one(&fx.pool)
        .await
        .unwrap()
        .get("c");
    assert_eq!(count, 1, "aliased call should reach the approval branch");
}

/// An unknown key that is *not* a declared alias is still rejected — and the
/// 400 is byte-identical across `/call` and `/validate`.
#[tokio::test]
async fn unknown_non_alias_key_still_rejected_byte_equivalent() {
    let fx = setup_with_yaml("telegram_alias_neg", |url| {
        telegram_aliased_template_yaml("telegram_alias_neg", url, "whatsapp_token")
    })
    .await;

    let bad_body = json!({
        "service": "telegram_alias_neg",
        "action": "send_message",
        "params": {
            "chat": "612616872",
            "body": "hi",
            "nonsense": "x"
        }
    });

    let call_resp = fx
        .client
        .post(format!("{}/v1/actions/call", fx.base))
        .header(auth_header(&fx.agent_key).0, auth_header(&fx.agent_key).1)
        .json(&bad_body)
        .send()
        .await
        .unwrap();
    assert_eq!(call_resp.status(), 400);
    let call_body: Value = call_resp.json().await.unwrap();

    let validate_resp = fx
        .client
        .post(format!("{}/v1/actions/validate", fx.base))
        .header(auth_header(&fx.agent_key).0, auth_header(&fx.agent_key).1)
        .json(&bad_body)
        .send()
        .await
        .unwrap();
    assert_eq!(validate_resp.status(), 400);
    let validate_body: Value = validate_resp.json().await.unwrap();

    assert_eq!(call_body, validate_body, "400 bodies must match exactly");
    assert_eq!(call_body["error"], "invalid_action_args");
    // Only `nonsense` is unknown — the aliased keys were accepted.
    let fields: Vec<&str> = call_body["errors"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["field"].as_str())
        .collect();
    assert_eq!(fields, vec!["nonsense"]);
}
