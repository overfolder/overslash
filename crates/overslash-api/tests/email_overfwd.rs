//! End-to-end integration test for the shipped `email` service (the overfwd
//! Mailbox Gateway), exercised through the real `/v1/actions/call` path.
//!
//! Proves the three overfwd-enabling changes together, against an in-process
//! mock that impersonates an overfwd deployment:
//!   • Core A — credential composition: the mailbox username is a non-secret
//!     instance `config` value and the password a vault secret, joined by the
//!     scheme's jq template into `X-Mailbox-Auth: Basic base64(user:pass)`.
//!   • Core B — multi-injection auth: the gateway key (`source: org`) and the
//!     mailbox credential (`source: instance`) ride the SAME request as
//!     `Authorization: Bearer …` + `X-Mailbox-Auth: Basic …`.
//!   • Core C — per-instance `url` override: the request routes to the org's
//!     own deployment URL (scheme + port preserved), not the template default.
//!
//! Also asserts `send` is `write`-gated (approval) and discloses To/From/Subject.
//!
//! Run with `--test-threads=4` (see CLAUDE.md).

#![allow(clippy::disallowed_methods)]

use crate::common;

use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::common::{bootstrap_org_identity, start_api_with_registry};

// The mailbox login: a public username (instance `config`) and an
// independently-rotatable password (vault secret). The expected header is
// unchanged from when this was ONE `user:pass` secret, and from when it was
// two — that identity is the point: only where each half comes from changed.
const MAILBOX_USER: &str = "user@example.com";
const MAILBOX_PASS: &str = "app-password";
// base64("user@example.com:app-password"), STANDARD alphabet.
const MAILBOX_BASIC: &str = "Basic dXNlckBleGFtcGxlLmNvbTphcHAtcGFzc3dvcmQ=";
const GATEWAY_KEY: &str = "gw-secret-key";

#[derive(Clone, Default)]
struct Captured {
    path: String,
    authorization: Option<String>,
    mailbox_auth: Option<String>,
    /// The mailbox endpoint headers. Absent unless the instance pinned them
    /// via `config` (or the caller passed them) — overfwd otherwise falls back
    /// to autoconfig.
    imap: Option<String>,
    smtp: Option<String>,
    content_type: Option<String>,
    body: Value,
}

type Sink = Arc<Mutex<Vec<Captured>>>;

/// In-process stand-in for a deployed overfwd gateway. Records the two auth
/// headers, the path, and the JSON body of every request, then returns a
/// minimal overfwd-shaped success.
async fn start_mock_overfwd() -> (String, Sink) {
    common::allow_loopback_ssrf();
    let sink: Sink = Arc::new(Mutex::new(Vec::new()));

    async fn handler(
        State(sink): State<Sink>,
        uri: axum::http::Uri,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> Json<Value> {
        let header = |k: &str| {
            headers
                .get(k)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        sink.lock().unwrap().push(Captured {
            path: uri.path().to_string(),
            authorization: header("authorization"),
            mailbox_auth: header("x-mailbox-auth"),
            imap: header("x-mailbox-imap"),
            smtp: header("x-mailbox-smtp"),
            content_type: header("content-type"),
            body: serde_json::from_slice(&body).unwrap_or(Value::Null),
        });
        Json(json!({ "messages": [], "sent": true }))
    }

    let app = Router::new()
        .route("/email/search", post(handler))
        .route("/email/get", post(handler))
        .route("/email/send", post(handler))
        .with_state(sink.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), sink)
}

/// Boot the API with the shipped registry (so `services/email.yaml` loads),
/// seed the gateway key (and the mailbox password iff `bind_mailbox`), create
/// an `email` instance pointed at `gateway_url` with the mailbox login set, and
/// grant it to Everyone (admin + auto-approve reads).
/// Returns `(base, agent_key)`.
async fn setup_email_instance(
    pool: sqlx::PgPool,
    gateway_url: &str,
    bind_mailbox: bool,
    seed_gateway_key: bool,
) -> (String, String) {
    // The gateway key is an org-vault secret referenced by the template's fixed
    // `default_secret_name` (source: org, optional). A keyless overfwd
    // deployment omits it. The mailbox login is split: the username is a plain
    // instance `config` value and only the password is a bound secret
    // (source: instance) — both set only when the instance binds the mailbox.
    let mut secrets = Vec::new();
    if seed_gateway_key {
        secrets.push(("overfwd_gateway_key", GATEWAY_KEY));
    }
    if bind_mailbox {
        secrets.push(("mailbox_pass", MAILBOX_PASS));
    }
    let mut body = json!({
        "template_key": "email",
        "name": "email",
        "url": gateway_url,
        "user_level": false,
        "status": "active",
    });
    if bind_mailbox {
        body["credentials"] = json!({ "mailbox_pass": "mailbox_pass" });
        body["config"] = json!({ "mailbox_user": MAILBOX_USER });
    }
    let (base, agent_key, _admin_key, _instance) =
        setup_email_instance_custom(pool, &secrets, body).await;
    (base, agent_key)
}

/// Generalized variant: seed arbitrary org secrets and create the `email`
/// instance from a caller-supplied body (so tests can exercise the per-scheme
/// `credentials` map). Returns `(base, agent_key, admin_key, create_response)`.
async fn setup_email_instance_custom(
    pool: sqlx::PgPool,
    secrets: &[(&str, &str)],
    body: Value,
) -> (String, String, String, Value) {
    setup_email_instance_layered(pool, secrets, None, body).await
}

/// As [`setup_email_instance_custom`], but first creates an **org layer** over
/// `email` carrying `layer` as its delta (under the key `email_org`). The
/// caller-supplied instance body then names whichever template key it wants.
async fn setup_email_instance_layered(
    pool: sqlx::PgPool,
    secrets: &[(&str, &str)],
    layer: Option<Value>,
    body: Value,
) -> (String, String, String, Value) {
    setup_email_instance_configured(pool, secrets, layer, body, |_| {}).await
}

/// As [`setup_email_instance_layered`], but applies `customize` to the API's
/// `Config` before boot — how the platform-credential tests below install a
/// platform gateway key (and route the template's real `mailbox.overslash.com`
/// host at the in-process mock) without touching process-global env.
async fn setup_email_instance_configured<F>(
    pool: sqlx::PgPool,
    secrets: &[(&str, &str)],
    layer: Option<Value>,
    body: Value,
    customize: F,
) -> (String, String, String, Value)
where
    F: FnOnce(&mut overslash_api::config::Config),
{
    let (base, client) = common::start_api_with_registry_customized(pool, None, customize).await;
    let (_org_id, _ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    if let Some(delta) = layer {
        let resp = client
            .post(format!("{base}/v1/templates"))
            .header("Authorization", format!("Bearer {admin_key}"))
            .json(&json!({ "extends": "email", "key": "email_org", "delta": delta }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "org layer create failed: {:?}",
            resp.text().await
        );
    }

    for (name, value) in secrets {
        let resp = client
            .put(format!("{base}/v1/secrets/{name}"))
            .header("Authorization", format!("Bearer {admin_key}"))
            .json(&json!({ "value": value }))
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "secret {name} create failed: {}",
            resp.status()
        );
    }

    let instance: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let svc_id = instance["id"]
        .as_str()
        .unwrap_or_else(|| panic!("email instance create failed: {instance:?}"));

    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
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
        .expect("Everyone group not found");

    let grant = client
        .post(format!("{base}/v1/groups/{everyone_id}/grants"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "service_instance_id": svc_id,
            "access_level": "admin",
            "auto_approve_reads": true,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        grant.status() == 200 || grant.status() == 409,
        "grant failed: {}",
        grant.status()
    );

    (base, agent_key, admin_key, instance)
}

#[tokio::test]
async fn email_search_dual_injects_auth_and_routes_to_instance_url() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key) = setup_email_instance(pool, &gateway_url, true, true).await;

    // `search` is a read → auto-approved by the grant → executes inline.
    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "email",
            "action": "search",
            "params": { "query": "UNSEEN" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "read should auto-execute: {}",
        resp.text().await.unwrap()
    );

    let captured = sink.lock().unwrap().clone();
    assert_eq!(
        captured.len(),
        1,
        "gateway should receive exactly one request"
    );
    let req = &captured[0];

    // Core C — routed to the per-instance url (this mock), on the right path.
    assert_eq!(req.path, "/email/search");
    // Core B — the gateway key rode as Authorization: Bearer.
    assert_eq!(
        req.authorization.as_deref(),
        Some("Bearer gw-secret-key"),
        "gateway (secret_source: org) key must inject as Authorization: Bearer"
    );
    // Core A + B — the mailbox credential rode as X-Mailbox-Auth: Basic base64.
    assert_eq!(
        req.mailbox_auth.as_deref(),
        Some(MAILBOX_BASIC),
        "mailbox (secret_source: instance) must inject as Basic base64(user:pass)"
    );
    // The search key made it into the JSON body — under the canonical name.
    // The caller above sent the legacy `query`; `apply_aliases` rewrites it to
    // `criteria` before the body is assembled, which is what keeps the rename
    // from breaking existing callers.
    assert_eq!(req.body["criteria"], json!("UNSEEN"));
    assert!(
        req.body.get("query").is_none(),
        "the alias must be rewritten, not sent alongside the canonical name: {:?}",
        req.body
    );
}

/// Regression: `search` declares a `requestBody` whose every field is optional,
/// so "search my inbox" with no arguments is a legitimate call. Overslash used
/// to infer "no body params supplied" ⇒ "no body" ⇒ "no `Content-Type`", and
/// overfwd's `Json<T>` extractor checks the header *before* it looks at the
/// body — so the call died upstream with `Expected request with Content-Type:
/// application/json` before reaching the mailbox.
///
/// Whether a body is sent follows the template's declared `requestBody`, not
/// what the caller happened to pass.
#[tokio::test]
async fn email_search_without_params_still_sends_json_body_and_content_type() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key) = setup_email_instance(pool, &gateway_url, true, true).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "email",
            "action": "search",
            "params": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "zero-arg search should auto-execute: {}",
        resp.text().await.unwrap()
    );

    let captured = sink.lock().unwrap().clone();
    assert_eq!(captured.len(), 1);
    let req = &captured[0];

    assert_eq!(req.path, "/email/search");
    assert_eq!(
        req.content_type.as_deref(),
        Some("application/json"),
        "a declared requestBody must send Content-Type even with no args — \
         omitting it is what overfwd's Json extractor rejects"
    );
    // A JSON object, not an absent/empty body. The template's `default`s fill
    // folder/criteria, so an argument-free call still expresses the intent.
    assert!(
        req.body.is_object(),
        "body must be a JSON object, got {:?}",
        req.body
    );
    assert_eq!(req.body["folder"], json!("INBOX"));
    assert_eq!(req.body["criteria"], json!("ALL"));
}

/// The same guarantee, isolated from `email.yaml`'s `default`s.
///
/// The test above cannot fail for the *routing* reason once the template
/// supplies defaults — they populate the body on their own. This one declares a
/// body whose fields are all optional AND undefaulted, so nothing fills it: the
/// only thing that can produce `{}` + `Content-Type` is routing keying off the
/// declared `requestBody`. That is what protects every other service, not just
/// this one.
#[tokio::test]
async fn declared_request_body_is_sent_even_when_no_field_resolves() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    // Reuses the mock's /email/search route; every field optional, no defaults.
    let openapi = r#"
openapi: 3.1.0
info:
  title: Opt Body
  key: optbody
servers:
  - url: https://optbody.example.com
paths:
  /email/search:
    post:
      operationId: search
      summary: Search with no required fields
      risk: read
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                q:
                  type: string
"#;
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "openapi": openapi }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "template create failed: {}",
        resp.text().await.unwrap()
    );

    let instance: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "optbody",
            "name": "optbody",
            "url": gateway_url,
            "user_level": false,
            "status": "active",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let svc_id = instance["id"]
        .as_str()
        .unwrap_or_else(|| panic!("optbody instance create failed: {instance:?}"));

    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
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
        .expect("Everyone group not found");
    let grant = client
        .post(format!("{base}/v1/groups/{everyone_id}/grants"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "service_instance_id": svc_id,
            "access_level": "admin",
            "auto_approve_reads": true,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        grant.status() == 200 || grant.status() == 409,
        "grant failed: {}",
        grant.status()
    );

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({ "service": "optbody", "action": "search", "params": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "zero-arg call should execute: {}",
        resp.text().await.unwrap()
    );

    let captured = sink.lock().unwrap().clone();
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].content_type.as_deref(),
        Some("application/json"),
        "a declared requestBody must send Content-Type even when no field resolves"
    );
    assert_eq!(
        captured[0].body,
        json!({}),
        "an empty JSON object, not an absent body"
    );
}

#[tokio::test]
async fn email_send_is_write_gated_and_discloses_message() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key) = setup_email_instance(pool, &gateway_url, true, true).await;

    // `send` is a write → gated: the call returns a pending approval BEFORE any
    // HTTP request is made, and the approval discloses the message.
    let exec: Value = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "email",
            "action": "send",
            "params": {
                "from": "me@example.com",
                "to": ["boss@example.com"],
                "subject": "Q3 numbers",
                "text": "Attached."
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
        "write action must be gated: {exec:?}"
    );

    // The disclosed fields carry the human-meaningful parts of the message.
    let disclosed = exec["disclosed_fields"]
        .as_array()
        .expect("disclosed_fields present on the pending_approval envelope");
    let by_label = |label: &str| -> Option<String> {
        disclosed
            .iter()
            .find(|f| f["label"] == json!(label))
            .and_then(|f| f["value"].as_str())
            .map(str::to_string)
    };
    assert_eq!(by_label("Subject").as_deref(), Some("Q3 numbers"));
    assert_eq!(by_label("From").as_deref(), Some("me@example.com"));
    assert_eq!(
        by_label("To").as_deref(),
        Some("boss@example.com"),
        "To (array) should be joined for disclosure"
    );

    // Gated before any HTTP call — the gateway saw nothing.
    assert_eq!(sink.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn email_unbound_mailbox_never_injects_gateway_key_alone() {
    // Regression: the email template pairs an org-source gateway key with an
    // instance-source mailbox credential. When the instance has no mailbox
    // secret bound, auth must NOT resolve to the gateway key alone — a partial
    // injection would send `Authorization: Bearer` without `X-Mailbox-Auth`,
    // failing at the gateway instead of surfacing as needs-authentication.
    // The fix falls through to the empty-auth / needs-auth path, so the gateway
    // key is never injected on its own.
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    // Only the org gateway key exists; the instance binds no mailbox secret.
    let (base, agent_key) = setup_email_instance(pool, &gateway_url, false, true).await;

    let _ = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "email",
            "action": "search",
            "params": { "query": "UNSEEN" }
        }))
        .send()
        .await
        .unwrap();

    // No request may carry the gateway `Authorization` header without the
    // mailbox credential — the partial-credential bug this guards against.
    for req in sink.lock().unwrap().iter() {
        assert!(
            req.authorization.is_none(),
            "gateway key injected without the mailbox credential (partial auth): {:?}",
            req.authorization
        );
    }
}

/// The config half of the same contract: the password is bound but the
/// username is unset. `mailbox_user` is `required`, so the scheme must not
/// resolve — rendering it anyway would send `Basic base64(":app-password")`,
/// which the gateway reports as a bad password rather than as missing config.
#[tokio::test]
async fn email_missing_required_config_never_sends_a_truncated_credential() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key, _admin_key, _instance) = setup_email_instance_custom(
        pool,
        &[("mailbox_pass", MAILBOX_PASS)],
        json!({
            "template_key": "email",
            "name": "email",
            "url": gateway_url,
            "status": "active",
            "credentials": { "mailbox_pass": "mailbox_pass" },
            // No `config`: the username is missing.
        }),
    )
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "email",
            "action": "search",
            "params": { "query": "UNSEEN" }
        }))
        .send()
        .await
        .unwrap();

    // The scheme never becomes a `SecretRef`, so it never reaches `render` —
    // the caller cannot get the generic "failed to build a value", and no
    // half-built header exists to send.
    let body = resp.text().await.unwrap();
    assert!(
        !body.contains("failed to build a value"),
        "a scheme with a missing config value must never reach render: {body}"
    );

    for req in sink.lock().unwrap().iter() {
        assert!(
            req.mailbox_auth.is_none(),
            "truncated credential reached the gateway: {:?}",
            req.mailbox_auth
        );
        // Nor does the org gateway key ride alone, for the same reason it does
        // not when a *slot* is unbound: an unresolved scheme takes the whole
        // credential set down with it.
        assert!(
            req.authorization.is_none(),
            "partial auth with a missing config value: {:?}",
            req.authorization
        );
    }
}

#[tokio::test]
async fn email_blank_stored_binding_is_missing_not_partial() {
    // The API rejects blank bindings, so a blank map value can only be
    // corrupted/manually-edited storage. A required slot resolving to ""
    // must behave like an unbound credential (no partial injection of the
    // remaining schemes) — not be silently skipped.
    let pool = common::test_pool().await;
    let pool2 = pool.clone();
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key) = setup_email_instance(pool, &gateway_url, true, true).await;

    // Corrupt the stored map behind the API's back: required password → "".
    // The username stays set in `config`, so this also covers "half a composed
    // credential" — the case that would otherwise send `Basic base64("user:")`.
    sqlx::query(
        r#"UPDATE service_instances
           SET credentials = '{"mailbox_pass": ""}'::jsonb,
               secret_name = NULL
           WHERE name = 'email'"#,
    )
    .execute(&pool2)
    .await
    .unwrap();

    let _ = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "email",
            "action": "search",
            "params": { "query": "UNSEEN" }
        }))
        .send()
        .await
        .unwrap();

    // Same contract as the unbound case: the gateway key must never ride
    // alone. Without the fix the blank slot is skipped as if bound, and the
    // org gateway key IS injected — a partially-authenticated request.
    for req in sink.lock().unwrap().iter() {
        assert!(
            req.authorization.is_none(),
            "gateway key injected despite blank required mailbox binding: {:?}",
            req.authorization
        );
    }
}

#[tokio::test]
async fn email_keyless_gateway_omits_authorization_but_still_sends_mailbox_auth() {
    // A self-hosted overfwd running with OVERFWD_REQUIRE_API_KEY=false needs no
    // gateway key. The `gateway` scheme is `optional`, so when the org has NOT
    // stored `overfwd_gateway_key` the request omits `Authorization` entirely
    // (rather than failing on a missing secret) while still injecting the
    // per-mailbox `X-Mailbox-Auth`.
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    // Bind the mailbox credential but do NOT seed the gateway key.
    let (base, agent_key) = setup_email_instance(pool, &gateway_url, true, false).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "email",
            "action": "search",
            "params": { "query": "ALL" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "keyless read should auto-execute: {}",
        resp.text().await.unwrap()
    );

    let captured = sink.lock().unwrap().clone();
    assert_eq!(
        captured.len(),
        1,
        "gateway should receive exactly one request"
    );
    let req = &captured[0];
    // Optional gateway key not configured → no Authorization header.
    assert_eq!(
        req.authorization, None,
        "keyless deployment must not send a gateway Authorization header"
    );
    // The mailbox credential still rides.
    assert_eq!(req.mailbox_auth.as_deref(), Some(MAILBOX_BASIC));
}

// ── Per-slot credential bindings (`service_instances.credentials`) ─────────

/// Every slot bound explicitly through the `credentials` map — including a
/// per-instance gateway key under a NON-default name, which the org-fixed
/// `overfwd_gateway_key` fallback could never express, and a mailbox password
/// under a name of the operator's choosing, joined with the plain-config
/// username.
#[tokio::test]
async fn email_credentials_map_binds_every_slot_with_custom_names() {
    let pool = common::test_pool().await;
    let pool2 = pool.clone();
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key, _admin_key, instance) = setup_email_instance_custom(
        pool,
        &[
            ("my_own_gateway_token", "instance-gw-key"),
            ("angel_app_password", MAILBOX_PASS),
        ],
        json!({
            "template_key": "email",
            "name": "email",
            "url": gateway_url,
            "user_level": false,
            "status": "active",
            "credentials": {
                "gateway": "my_own_gateway_token",
                "mailbox_pass": "angel_app_password",
            },
            "config": { "mailbox_user": MAILBOX_USER },
        }),
    )
    .await;

    // The create response exposes the bindings (names only). `mailbox_pass` is
    // the sole instance-source slot, so the legacy scalar mirrors it; the
    // gateway (org-source) never mirrors.
    assert_eq!(
        instance["credentials"],
        json!({
            "gateway": "my_own_gateway_token",
            "mailbox_pass": "angel_app_password",
        })
    );
    assert_eq!(instance["secret_name"], json!("angel_app_password"));
    // The username rides in `config`, in the clear — it is not a secret.
    assert_eq!(instance["config"]["mailbox_user"], json!(MAILBOX_USER));

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "email",
            "action": "search",
            "params": { "query": "UNSEEN" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "read should auto-execute: {}",
        resp.text().await.unwrap()
    );

    let captured = sink.lock().unwrap().clone();
    assert_eq!(captured.len(), 1);
    let req = &captured[0];
    // The explicit per-instance binding beats the org-fixed default name.
    assert_eq!(
        req.authorization.as_deref(),
        Some("Bearer instance-gw-key"),
        "credentials[gateway] must override the overfwd_gateway_key fallback"
    );
    // A config value and a secret, one header: the joined value is
    // byte-identical to what a single `user:pass` secret produced before the
    // split, and to what two secrets produced after it.
    assert_eq!(req.mailbox_auth.as_deref(), Some(MAILBOX_BASIC));

    // The gateway binding never mirrors into the scalar `secret_name`, so the
    // secret detail's "Used by" must find it through the credentials map.
    // (The HTTP detail endpoint is dashboard-session-only, so assert at the
    // scope layer the route delegates to.)
    let org_id = instance["org_id"]
        .as_str()
        .unwrap()
        .parse::<uuid::Uuid>()
        .unwrap();
    let scope = overslash_db::scopes::OrgScope::new(org_id, pool2);
    let used_by = scope
        .list_services_using_secret("my_own_gateway_token")
        .await
        .unwrap();
    assert!(
        used_by.iter().any(|s| s.name == "email"),
        "map-only binding must surface in used_by: {used_by:?}"
    );
}

/// A `credentials` key that names no credential slot of the template is a
/// caller bug — reject at the boundary instead of storing a dead binding.
#[tokio::test]
async fn email_create_rejects_unknown_credential_slot() {
    let pool = common::test_pool().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, _agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "email",
            "name": "email",
            "user_level": false,
            "credentials": { "gatway": "typo_key" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "unknown scheme key must 400");
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("gatway") && body.contains("gateway"),
        "error should name the bad key and the declared schemes: {body}"
    );
}

/// Once the username stopped being a secret, `email` has exactly ONE
/// instance-source slot again — so the legacy scalar `secret_name` is
/// unambiguous and folds into it. This is the shape a pre-`credentials` caller
/// still sends, and it must keep working.
///
/// (The ambiguous case — several instance-source slots — is still refused;
/// `platform_services::reconcile_rejects_scalar_alias_when_several_instance_slots_exist`
/// covers it without needing a shipped template that has two.)
#[tokio::test]
async fn email_scalar_secret_name_folds_into_the_sole_mailbox_slot() {
    let pool = common::test_pool().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, _agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "email",
            "name": "email",
            "user_level": false,
            "secret_name": "mailbox_credential",
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "scalar alias should bind the sole instance slot: {}",
        resp.text().await.unwrap()
    );
    let instance: Value = resp.json().await.unwrap();
    assert_eq!(
        instance["credentials"]["mailbox_pass"],
        json!("mailbox_credential")
    );
}

/// Hard cutover: `mailbox_user` used to be a credential slot and is now a
/// config value. An instance still binding it as a credential must fail with a
/// message that says where the value went — this error is the only notice an
/// operator gets.
#[tokio::test]
async fn email_rejects_binding_the_username_as_a_credential() {
    let pool = common::test_pool().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, _agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "email",
            "name": "email",
            "user_level": false,
            "credentials": { "mailbox_user": "mailbox_user", "mailbox_pass": "mailbox_pass" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("no longer a credential") && body.contains("config"),
        "error must point the operator at `config`: {body}"
    );
}

/// `credentials` on update is a whole-map replace, and an empty map unbinds
/// everything. Exercised over the gateway + mailbox pair, which is what the
/// `email` template's two secret schemes reduce to now that the username is
/// plain config.
#[tokio::test]
async fn email_update_credentials_replaces_and_clears() {
    let pool = common::test_pool().await;
    let (gateway_url, _sink) = start_mock_overfwd().await;
    let (base, _agent_key, admin_key, instance) = setup_email_instance_custom(
        pool,
        &[("gw_key", GATEWAY_KEY), ("mailbox_pass", MAILBOX_PASS)],
        json!({
            "template_key": "email",
            "name": "email",
            "url": gateway_url,
            "user_level": false,
            "status": "active",
            "credentials": {
                "gateway": "gw_key",
                "mailbox_pass": "mailbox_pass",
            },
            "config": { "mailbox_user": MAILBOX_USER },
        }),
    )
    .await;
    let svc_id = instance["id"].as_str().unwrap();
    let client = reqwest::Client::new();

    // Whole-map replace: rebind both slots at once.
    let updated: Value = client
        .put(format!("{base}/v1/services/{svc_id}/manage"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "credentials": { "gateway": "other_gw", "mailbox_pass": "other_password" }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        updated["credentials"],
        json!({ "gateway": "other_gw", "mailbox_pass": "other_password" })
    );

    // Rotating just the mailbox password leaves the gateway key bound — the
    // whole point of binding per slot rather than one scalar.
    let rotated: Value = client
        .put(format!("{base}/v1/services/{svc_id}/manage"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "credentials": { "gateway": "other_gw", "mailbox_pass": "rotated_password" }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rotated["credentials"]["gateway"], json!("other_gw"));
    assert_eq!(
        rotated["credentials"]["mailbox_pass"],
        json!("rotated_password")
    );

    // Clearing: an explicit empty map unbinds everything.
    let cleared: Value = client
        .put(format!("{base}/v1/services/{svc_id}/manage"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "credentials": {} }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cleared["credentials"], json!(null), "empty map is omitted");
    assert_eq!(cleared["secret_name"], json!(null));
}
/// The dashboard renders one credential row per *slot* — pin the template
/// serialization contract that form depends on. `secrets` is not derivable
/// from `auth` on the client: `mailbox` is one injection reading two slots.
#[tokio::test]
async fn email_template_serializes_slots_and_sources() {
    let pool = common::test_pool().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, _agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    let tpl: Value = client
        .get(format!("{base}/v1/templates/email"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let auth = tpl["auth"].as_array().expect("auth array");
    assert_eq!(auth.len(), 2, "email declares gateway + mailbox: {auth:?}");
    // extract_auth sorts scheme keys for determinism: gateway, mailbox.
    assert_eq!(auth[0]["scheme"], json!("gateway"));
    assert_eq!(auth[0]["secret_source"], json!("org"));
    assert_eq!(auth[0]["optional"], json!(true));
    assert_eq!(auth[1]["scheme"], json!("mailbox"));
    // `instance` is the default source; it serializes explicitly.
    assert_eq!(auth[1]["secret_source"], json!("instance"));
    // The mailbox header joins a config value with a secret, so it reads one
    // slot and one config key; the gateway reads only its own implicit slot.
    assert_eq!(auth[0]["slots"], json!(["gateway"]));
    assert_eq!(auth[1]["slots"], json!(["mailbox_pass"]));
    assert_eq!(auth[1]["config_keys"], json!(["mailbox_user"]));

    // The slot list the credentials form renders: two pickers, each with the
    // label and source the dashboard shows. The username is NOT here — it is a
    // config field, not a secret picker.
    let secrets = tpl["secrets"].as_array().expect("secrets array");
    let rows: Vec<(&str, &str, &str)> = secrets
        .iter()
        .map(|s| {
            (
                s["key"].as_str().unwrap(),
                s["label"].as_str().unwrap_or(""),
                s["source"].as_str().unwrap_or("instance"),
            )
        })
        .collect();
    assert_eq!(
        rows,
        vec![
            ("gateway", "Overfwd API Token", "org"),
            ("mailbox_pass", "Mailbox password", "instance"),
        ],
        "slots drive the dashboard credential rows"
    );
    // The jq expression is an implementation detail — never a form field.
    assert!(
        secrets.iter().all(|s| s.get("template").is_none()),
        "slots must not carry the template: {secrets:?}"
    );
}

/// The mailbox endpoint pinned on the instance must reach the gateway as
/// headers, without the caller passing anything.
///
/// This is what makes a self-hosted mailbox reachable at all: overfwd falls
/// back to autoconfig (a live ISPDB/DNS lookup) when the headers are absent,
/// and autoconfig can't resolve a private host — or a login that isn't an
/// email address.
#[tokio::test]
async fn email_instance_config_pins_mailbox_endpoint_headers() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key, _admin_key, _instance) = setup_email_instance_custom(
        pool,
        &[("mailbox_pass", MAILBOX_PASS)],
        json!({
            "template_key": "email",
            "url": gateway_url,
            "credentials": { "mailbox_pass": "mailbox_pass" },
            "config": {
                "mailbox_user": MAILBOX_USER,
                "X-Mailbox-Imap": "imap.corp.internal:993",
                "X-Mailbox-Smtp": "smtp.corp.internal:465",
            },
            "status": "active",
        }),
    )
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({ "service": "email", "action": "search", "params": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let captured = sink.lock().unwrap();
    let req = captured.first().expect("gateway saw no request");
    assert_eq!(req.imap.as_deref(), Some("imap.corp.internal:993"));
    assert_eq!(req.smtp.as_deref(), Some("smtp.corp.internal:465"));
}

/// An explicit caller argument beats the instance pin.
///
/// The pin is a per-deployment default, not a lock — precedence is
/// `caller arg > instance config > template default`.
#[tokio::test]
async fn email_caller_arg_overrides_pinned_mailbox_endpoint() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key, _admin_key, _instance) = setup_email_instance_custom(
        pool,
        &[("mailbox_pass", MAILBOX_PASS)],
        json!({
            "template_key": "email",
            "url": gateway_url,
            "credentials": { "mailbox_pass": "mailbox_pass" },
            "config": {
                "mailbox_user": MAILBOX_USER,
                "X-Mailbox-Imap": "imap.corp.internal:993",
            },
            "status": "active",
        }),
    )
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "email",
            "action": "search",
            "params": { "X-Mailbox-Imap": "imap.other.test:143" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let captured = sink.lock().unwrap();
    let req = captured.first().expect("gateway saw no request");
    assert_eq!(req.imap.as_deref(), Some("imap.other.test:143"));
}

/// Only params the template marks `x-overslash-instance-config` are storable.
/// Anything else is a 400 naming what the template does declare — the same
/// shape `credentials` uses for an unknown scheme.
#[tokio::test]
async fn email_create_rejects_unknown_instance_config_key() {
    let pool = common::test_pool().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, _agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "email",
            "config": { "query": "ALL" },
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    let msg = body["error"].as_str().unwrap_or_default();
    assert!(
        msg.contains("unknown instance config 'query'") && msg.contains("X-Mailbox-Imap"),
        "expected a 400 naming the declared params, got: {msg}"
    );
}

/// `search` with no arguments is the obvious "list my mail" call. It must send
/// a JSON body — a body-less POST carries no `Content-Type`, which overfwd
/// rejects — so the template's documented `INBOX`/`ALL` defaults have to be
/// real declared defaults, not just prose.
#[tokio::test]
async fn email_search_with_no_args_sends_defaulted_body() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key, _admin_key, _instance) = setup_email_instance_custom(
        pool,
        &[("mailbox_pass", MAILBOX_PASS)],
        json!({
            "template_key": "email",
            "url": gateway_url,
            "credentials": { "mailbox_pass": "mailbox_pass" },
            "config": { "mailbox_user": MAILBOX_USER },
            "status": "active",
        }),
    )
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({ "service": "email", "action": "search", "params": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let captured = sink.lock().unwrap();
    let req = captured.first().expect("gateway saw no request");
    assert_eq!(req.body["folder"], json!("INBOX"));
    assert_eq!(req.body["criteria"], json!("ALL"));
}

/// A blank value is rejected rather than stored, so "not pinned" has exactly
/// one representation (key absent) instead of two.
#[tokio::test]
async fn email_create_rejects_blank_instance_config_value() {
    let pool = common::test_pool().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, _agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "email",
            "config": { "X-Mailbox-Imap": "   " },
            "status": "active",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("must have a value"),
        "unexpected error: {body:?}"
    );
}

/// `config` on update is a whole-map replace: `{}` clears every pin, and an
/// absent field leaves the stored map alone.
#[tokio::test]
async fn email_update_config_replaces_and_clears() {
    let pool = common::test_pool().await;
    let (base, _agent_key, admin_key, instance) = setup_email_instance_custom(
        pool,
        &[("mailbox_pass", MAILBOX_PASS)],
        json!({
            "template_key": "email",
            "url": "http://127.0.0.1:1",
            "credentials": { "mailbox_pass": "mailbox_pass" },
            "config": {
                "mailbox_user": MAILBOX_USER,
                "X-Mailbox-Imap": "imap.one.test:993",
            },
            "status": "active",
        }),
    )
    .await;
    let svc_id = instance["id"].as_str().unwrap();
    let client = reqwest::Client::new();

    // A rename touches neither credentials nor config.
    let renamed: Value = client
        .put(format!("{base}/v1/services/{svc_id}/manage"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "name": "email-renamed" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        renamed["config"]["X-Mailbox-Imap"],
        json!("imap.one.test:993")
    );

    // An explicit map replaces wholesale.
    let replaced: Value = client
        .put(format!("{base}/v1/services/{svc_id}/manage"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "config": { "X-Mailbox-Smtp": "smtp.two.test:465" } }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        replaced["config"]["X-Mailbox-Smtp"],
        json!("smtp.two.test:465")
    );
    assert!(
        replaced["config"].get("X-Mailbox-Imap").is_none(),
        "replace must drop keys absent from the new map: {:?}",
        replaced["config"]
    );

    // `{}` clears. The field is skipped when empty, so it disappears entirely.
    let cleared: Value = client
        .put(format!("{base}/v1/services/{svc_id}/manage"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "config": {} }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        cleared.get("config").is_none() || cleared["config"] == json!({}),
        "empty map should clear every pin: {:?}",
        cleared.get("config")
    );
}

/// The templates API advertises which params the dashboard should render as
/// instance-config fields, deduped across the actions that declare them.
#[tokio::test]
async fn email_template_advertises_instance_config_params() {
    let pool = common::test_pool().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, _agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    let tpl: Value = client
        .get(format!("{base}/v1/templates/email"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let params = tpl["instance_config_params"]
        .as_array()
        .expect("instance_config_params present");
    let names: Vec<&str> = params.iter().filter_map(|p| p["name"].as_str()).collect();
    // The endpoint params ride all three operations but must appear once on
    // the form — and the credential template's `mailbox_user` joins them,
    // because both kinds of value live in the instance's one `config` map.
    assert_eq!(
        names,
        vec!["X-Mailbox-Imap", "X-Mailbox-Smtp", "mailbox_user"],
        "{params:?}"
    );
    for p in params.iter().take(2) {
        assert_eq!(p["required"], json!(false), "{p:?}");
        assert!(
            p["description"]
                .as_str()
                .unwrap_or_default()
                .contains("host:port"),
            "description should reach the form: {p:?}"
        );
    }
    // The config var arrives with the label the raw key can't carry, and
    // `required` — an unset username would render a truncated credential.
    let user = &params[2];
    assert_eq!(user["label"], json!("Mailbox username"));
    assert_eq!(user["required"], json!(true));
    assert_eq!(user["type"], json!("string"));
    assert_eq!(tpl["configurable_url"], json!(true));
}

// ── Org-layer instance defaults ────────────────────────────────────────────

/// The org gateway story end-to-end: an admin creates one layer over `email`
/// naming the org's own overfwd deployment and its mailbox endpoint, and every
/// user's instance then carries **nothing but its own mailbox credential**.
///
/// This is the papercut the feature exists to remove — `email`'s mailbox
/// credential is `secret_source: instance`, so every user creates their own
/// instance, and without a layer default each of them has to paste the same
/// gateway URL and IMAP/SMTP host by hand.
#[tokio::test]
async fn email_org_layer_defaults_route_to_org_gateway() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key, _admin_key, _instance) = setup_email_instance_layered(
        pool,
        &[("mailbox_pass", MAILBOX_PASS)],
        Some(json!({
            "instance_defaults": {
                "url": gateway_url,
                "config": {
                    "X-Mailbox-Imap": "imap.corp.internal:993",
                    "X-Mailbox-Smtp": "smtp.corp.internal:465",
                    // A credential template's non-secret input is defaultable
                    // like any other config key — here the org's shared mailbox
                    // login, so a user's instance carries only its password.
                    "mailbox_user": MAILBOX_USER,
                }
            }
        })),
        json!({
            "template_key": "email_org",
            // No `url`, no `config` — everything but the password comes from
            // the org layer.
            "credentials": { "mailbox_pass": "mailbox_pass" },
            "status": "active",
        }),
    )
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({ "service": "email_org", "action": "search", "params": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "{:?}",
        resp.text().await
    );

    // Reaching the mock gateway at all proves the layer's `url` beat the
    // template's `servers[0]` (mailbox.overslash.com).
    let captured = sink.lock().unwrap();
    let req = captured.first().expect("org gateway saw no request");
    assert_eq!(req.imap.as_deref(), Some("imap.corp.internal:993"));
    assert_eq!(req.smtp.as_deref(), Some("smtp.corp.internal:465"));
    // And the layer's username joined the instance's password into the one
    // credential header — the same bytes as when both halves were local.
    assert_eq!(req.mailbox_auth.as_deref(), Some(MAILBOX_BASIC));
}

/// Precedence, top to bottom: an instance overrides its org layer, and a caller
/// arg overrides both. A developer pointing one instance at a local overfwd
/// must not be blocked by the org default.
#[tokio::test]
async fn email_instance_and_caller_override_org_layer_defaults() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key, _admin_key, _instance) = setup_email_instance_layered(
        pool,
        &[("mailbox_pass", MAILBOX_PASS)],
        Some(json!({
            "instance_defaults": {
                // A URL the mock gateway is NOT listening on: if the instance's
                // own `url` did not win, the call could not succeed.
                "url": "https://never.used.invalid",
                "config": {
                    "X-Mailbox-Imap": "imap.layer.internal:993",
                    "X-Mailbox-Smtp": "smtp.layer.internal:465",
                    // A shared login the instance's own mailbox overrides.
                    "mailbox_user": "shared-ops@acme.com",
                }
            }
        })),
        json!({
            "template_key": "email_org",
            "url": gateway_url,
            "credentials": { "mailbox_pass": "mailbox_pass" },
            // Instance pins IMAP and its own mailbox; SMTP is left to the layer.
            "config": {
                "X-Mailbox-Imap": "imap.instance.internal:993",
                "mailbox_user": MAILBOX_USER,
            },
            "status": "active",
        }),
    )
    .await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "email_org",
            "action": "search",
            "params": { "X-Mailbox-Smtp": "smtp.caller.internal:465" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "{:?}",
        resp.text().await
    );

    let captured = sink.lock().unwrap();
    let req = captured.first().expect("gateway saw no request");
    assert_eq!(
        req.imap.as_deref(),
        Some("imap.instance.internal:993"),
        "instance config must beat the layer default"
    );
    assert_eq!(
        req.smtp.as_deref(),
        Some("smtp.caller.internal:465"),
        "a caller arg must beat both"
    );
    // Same precedence inside a credential: the instance's own username built
    // the header, not the layer's shared one.
    assert_eq!(
        req.mailbox_auth.as_deref(),
        Some(MAILBOX_BASIC),
        "instance config must beat the layer default inside the credential too"
    );
}

// ── Platform-hosted gateway: the credential rung below the org vault (D39) ──

/// The host `services/email.yaml` ships as `servers[0]` — the shared Overslash
/// Cloud deployment. The tests below leave the instance's `url` unset so the
/// request resolves to exactly this host, then rewrite it at send time onto the
/// in-process mock via `service_base_overrides` (per-boot config, not env).
const PLATFORM_HOST: &str = "mailbox.overslash.com";
const PLATFORM_KEY: &str = "platform-gw-key";

/// Install the platform credential for `overfwd_gateway_key` on `PLATFORM_HOST`
/// and route that host at `mock_url`.
fn with_platform_gateway(mock_url: &str) -> impl FnOnce(&mut overslash_api::config::Config) {
    let mock_url = mock_url.to_string();
    move |cfg: &mut overslash_api::config::Config| {
        cfg.platform_credential = Some(overslash_api::config::PlatformCredential {
            secret_name: "overfwd_gateway_key".into(),
            host: PLATFORM_HOST.into(),
            value: PLATFORM_KEY.into(),
        });
        cfg.service_base_overrides
            .insert(PLATFORM_HOST.into(), mock_url);
    }
}

/// An instance body with no `url`: the request lands on the template's own
/// `servers[0]`, i.e. the shared gateway.
fn default_instance_body() -> Value {
    json!({
        "template_key": "email",
        "name": "email",
        "user_level": false,
        "status": "active",
        // The username is a plain config value since D38; only the password
        // is vaulted.
        "config": { "mailbox_user": MAILBOX_USER },
        "credentials": { "mailbox_pass": "mailbox_pass" },
    })
}

const MAILBOX_SECRETS: [(&str, &str); 1] = [("mailbox_pass", MAILBOX_PASS)];

async fn call_search(base: &str, agent_key: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "email",
            "action": "search",
            "params": { "query": "ALL" }
        }))
        .send()
        .await
        .unwrap()
}

/// The whole point of a platform-hosted gateway: an org that has stored NOTHING
/// still authenticates against it. Without this rung the `gateway` scheme is
/// optional-and-absent, the `Authorization` header is dropped, and the shared
/// deployment (which runs with OVERFWD_REQUIRE_API_KEY=true) answers 401.
#[tokio::test]
async fn email_platform_gateway_key_injected_when_org_stored_none() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key, _admin, _inst) = setup_email_instance_configured(
        pool,
        &MAILBOX_SECRETS,
        None,
        default_instance_body(),
        with_platform_gateway(&gateway_url),
    )
    .await;

    let resp = call_search(&base, &agent_key).await;
    assert_eq!(
        resp.status(),
        200,
        "read should auto-execute: {}",
        resp.text().await.unwrap()
    );

    let captured = sink.lock().unwrap().clone();
    let req = captured.first().expect("gateway saw no request");
    assert_eq!(
        req.authorization.as_deref(),
        Some(&format!("Bearer {PLATFORM_KEY}")[..]),
        "org stored no gateway key; the platform rung must supply it"
    );
    // The per-mailbox credential is still the org's own.
    assert_eq!(req.mailbox_auth.as_deref(), Some(MAILBOX_BASIC));
}

/// An org that stores its own `overfwd_gateway_key` wins. The rung is a
/// fallback, not an override — otherwise an org could never rotate away from
/// the platform key on its own deployment.
#[tokio::test]
async fn email_org_gateway_key_beats_the_platform_one() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let secrets = [
        ("overfwd_gateway_key", GATEWAY_KEY),
        ("mailbox_pass", MAILBOX_PASS),
    ];
    let (base, agent_key, _admin, _inst) = setup_email_instance_configured(
        pool,
        &secrets,
        None,
        default_instance_body(),
        with_platform_gateway(&gateway_url),
    )
    .await;

    let resp = call_search(&base, &agent_key).await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    let captured = sink.lock().unwrap().clone();
    let req = captured.first().expect("gateway saw no request");
    assert_eq!(
        req.authorization.as_deref(),
        Some(&format!("Bearer {GATEWAY_KEY}")[..]),
        "the org's own key must win over the platform fallback"
    );
}

/// The containment property. An org pointing its instance at its OWN overfwd
/// must not receive the platform's key — a shared credential leaking to an
/// arbitrary tenant-chosen host is the failure mode this rung has to avoid, and
/// `instance.url` is tenant-controlled. It gets the keyless behaviour instead:
/// no `Authorization` at all.
#[tokio::test]
async fn email_platform_gateway_key_never_leaves_the_platform_host() {
    let pool = common::test_pool().await;
    // Two mocks: the platform gateway the credential is pinned to, and the
    // org's own deployment, which is where this instance actually points.
    let (platform_url, platform_sink) = start_mock_overfwd().await;
    let (self_hosted_url, self_hosted_sink) = start_mock_overfwd().await;

    let mut body = default_instance_body();
    body["url"] = json!(self_hosted_url);

    let (base, agent_key, _admin, _inst) = setup_email_instance_configured(
        pool,
        &MAILBOX_SECRETS,
        None,
        body,
        with_platform_gateway(&platform_url),
    )
    .await;

    let resp = call_search(&base, &agent_key).await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    assert!(
        platform_sink.lock().unwrap().is_empty(),
        "request must go to the org's own gateway, not the platform one"
    );
    let captured = self_hosted_sink.lock().unwrap().clone();
    let req = captured
        .first()
        .expect("self-hosted gateway saw no request");
    assert_eq!(
        req.authorization, None,
        "the platform key must never be sent to a tenant-chosen host"
    );
    assert_eq!(req.mailbox_auth.as_deref(), Some(MAILBOX_BASIC));
}

// ── Recipient-scoped send permissions ────────────────────────────────────

/// `send` derives one permission key per recipient, so a domain-scoped grant
/// covers a send to that domain outright — no approval, and the message
/// actually goes out.
#[tokio::test]
async fn email_send_to_a_granted_domain_needs_no_approval() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;
    seed_email_instance(&base, &client, &admin_key, &gateway_url).await;

    // Scoped to one domain — NOT `email:send:*`.
    grant(
        &base,
        &client,
        &admin_key,
        ident_id,
        "email:send:*@example.com",
    )
    .await;

    let exec: Value = call_send(&base, &agent_key, json!(["a@example.com", "b@example.com"])).await;

    assert_eq!(
        exec["status"].as_str(),
        Some("called"),
        "every recipient is inside the grant, so no approval should be raised: {exec:?}"
    );
    assert_eq!(
        sink.lock().unwrap().len(),
        1,
        "the message should have reached the gateway"
    );
}

/// The same grant, one recipient outside it. The covered address must not
/// launder the uncovered one: the call is gated, and nothing is sent.
#[tokio::test]
async fn email_send_to_a_mixed_recipient_list_is_gated_on_the_uncovered_one() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;
    seed_email_instance(&base, &client, &admin_key, &gateway_url).await;

    grant(
        &base,
        &client,
        &admin_key,
        ident_id,
        "email:send:*@example.com",
    )
    .await;

    let exec: Value = call_send(
        &base,
        &agent_key,
        json!(["a@example.com", "stranger@example.org"]),
    )
    .await;

    assert_eq!(
        exec["status"].as_str(),
        Some("pending_approval"),
        "a recipient outside the grant must gate the whole send: {exec:?}"
    );
    assert_eq!(sink.lock().unwrap().len(), 0, "gated before any HTTP call");
}

/// A single recipient sent as a bare string, and several as one comma-joined
/// string, must derive the same keys as the list form — the mailbox gateway
/// splits recipients on commas, so this side has to agree or the permission
/// check would be about a recipient nobody is mailing.
#[tokio::test]
async fn email_send_accepts_a_comma_separated_recipient_string() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;
    seed_email_instance(&base, &client, &admin_key, &gateway_url).await;

    grant(
        &base,
        &client,
        &admin_key,
        ident_id,
        "email:send:*@example.com",
    )
    .await;

    // Covered domain only → goes through, and the gateway receives a real list.
    let exec: Value = call_send(&base, &agent_key, json!("a@example.com, b@example.com")).await;
    assert_eq!(exec["status"].as_str(), Some("called"), "{exec:?}");
    {
        let captured = sink.lock().unwrap();
        let req = captured.first().expect("gateway saw no request");
        assert_eq!(
            req.body["to"],
            json!(["a@example.com", "b@example.com"]),
            "a comma-joined string must reach the gateway as a list"
        );
    }

    // The same string with one address outside the grant is still gated —
    // proof the split happened before the permission check, not after.
    let exec: Value = call_send(
        &base,
        &agent_key,
        json!("a@example.com,stranger@example.org"),
    )
    .await;
    assert_eq!(
        exec["status"].as_str(),
        Some("pending_approval"),
        "{exec:?}"
    );
}

/// The gap that motivated list-valued `scope_param`: a bcc used to consume no
/// permission key, so a domain-scoped grant let a message reach anyone as long
/// as `to` looked clean. Every header is scoped now.
#[tokio::test]
async fn email_send_is_gated_on_an_uncovered_bcc() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;
    seed_email_instance(&base, &client, &admin_key, &gateway_url).await;

    grant(
        &base,
        &client,
        &admin_key,
        ident_id,
        "email:send:*@example.com",
    )
    .await;

    let exec: Value = call_send_full(
        &base,
        &agent_key,
        json!(["a@example.com"]),
        None,
        Some(json!(["stranger@example.org"])),
    )
    .await;

    assert_eq!(
        exec["status"].as_str(),
        Some("pending_approval"),
        "a bcc outside the grant must gate the send: {exec:?}"
    );
    assert_eq!(sink.lock().unwrap().len(), 0, "gated before any HTTP call");
}

/// The legacy value-only grant keeps working against the new labelled keys:
/// covered cc and bcc recipients go through with no approval.
#[tokio::test]
async fn email_send_with_covered_cc_and_bcc_needs_no_approval() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;
    seed_email_instance(&base, &client, &admin_key, &gateway_url).await;

    grant(
        &base,
        &client,
        &admin_key,
        ident_id,
        "email:send:*@example.com",
    )
    .await;

    let exec: Value = call_send_full(
        &base,
        &agent_key,
        json!(["a@example.com"]),
        Some(json!(["b@example.com"])),
        Some(json!(["c@example.com"])),
    )
    .await;

    assert_eq!(
        exec["status"].as_str(),
        Some("called"),
        "a grant written before scope labels existed must still cover the new keys: {exec:?}"
    );
    assert_eq!(sink.lock().unwrap().len(), 1);
}

/// A label-qualified grant is the narrow form: `recipient=` covers every
/// header, and one address on both `to` and `cc` is a single decision.
#[tokio::test]
async fn email_send_accepts_a_recipient_labelled_grant() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;
    seed_email_instance(&base, &client, &admin_key, &gateway_url).await;

    grant(
        &base,
        &client,
        &admin_key,
        ident_id,
        "email:send:recipient=*@example.com",
    )
    .await;

    let exec: Value = call_send_full(
        &base,
        &agent_key,
        json!(["a@example.com"]),
        Some(json!(["a@example.com", "b@example.com"])),
        None,
    )
    .await;

    assert_eq!(exec["status"].as_str(), Some("called"), "{exec:?}");
    assert_eq!(sink.lock().unwrap().len(), 1);
}

/// The same call without the grant: the approval names the recipients once
/// each, under the shared `recipient` label — an address on two headers is one
/// key, not two.
#[tokio::test]
async fn email_send_approval_names_each_recipient_once() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;
    seed_email_instance(&base, &client, &admin_key, &gateway_url).await;

    let exec: Value = call_send_full(
        &base,
        &agent_key,
        json!(["a@example.com"]),
        Some(json!(["a@example.com", "b@example.com"])),
        None,
    )
    .await;

    assert_eq!(
        exec["status"].as_str(),
        Some("pending_approval"),
        "{exec:?}"
    );
    let keys: Vec<&str> = exec["permission_keys"]
        .as_array()
        .expect("permission_keys")
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    assert_eq!(
        keys,
        vec![
            "email:send:recipient=a@example.com",
            "email:send:recipient=b@example.com"
        ]
    );
    assert_eq!(sink.lock().unwrap().len(), 0);
}

/// Discovery tells two mailboxes on one template apart. Both rows carry the
/// same `service_display_name` (it belongs to the template), so the mailbox
/// address has to come through as `account_email` or an agent has to call both
/// to find out which is which.
#[tokio::test]
async fn email_search_rows_name_their_mailbox() {
    let pool = common::test_pool().await;
    let (gateway_url, _sink) = start_mock_overfwd().await;
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, _agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    seed_email_instance_named(
        &base,
        &client,
        &admin_key,
        &gateway_url,
        "email_ops",
        "ops@example.com",
    )
    .await;
    seed_email_instance_named(
        &base,
        &client,
        &admin_key,
        &gateway_url,
        "email_billing",
        "billing@example.com",
    )
    .await;

    let found: Value = client
        .get(format!("{base}/v1/search?q=email+search+mailbox"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let rows: Vec<&Value> = found["results"]
        .as_array()
        .expect("results array")
        .iter()
        .filter(|r| r["template"] == json!("email"))
        .collect();
    assert!(!rows.is_empty(), "no email rows in {found:?}");

    let addr_for = |svc: &str| -> Option<String> {
        rows.iter()
            .find(|r| r["service"] == json!(svc))
            .and_then(|r| r["account_email"].as_str())
            .map(str::to_string)
    };
    assert_eq!(addr_for("email_ops").as_deref(), Some("ops@example.com"));
    assert_eq!(
        addr_for("email_billing").as_deref(),
        Some("billing@example.com")
    );
}

// ── helpers for the tests above ──────────────────────────────────────────

async fn grant(
    base: &str,
    client: &reqwest::Client,
    admin_key: &str,
    ident_id: uuid::Uuid,
    action_pattern: &str,
) {
    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "identity_id": ident_id, "action_pattern": action_pattern }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "grant {action_pattern} failed: {}",
        resp.status()
    );
}

async fn call_send(base: &str, agent_key: &str, to: Value) -> Value {
    call_send_full(base, agent_key, to, None, None).await
}

/// `send` with the carbon-copy headers filled in. `cc`/`bcc` are omitted from
/// the request entirely when `None` — an absent param and an empty list are
/// different inputs to the permission derivation, and both need covering.
async fn call_send_full(
    base: &str,
    agent_key: &str,
    to: Value,
    cc: Option<Value>,
    bcc: Option<Value>,
) -> Value {
    let mut params = json!({
        "from": MAILBOX_USER,
        "to": to,
        "subject": "Status",
        "text": "Body."
    });
    if let Some(cc) = cc {
        params["cc"] = cc;
    }
    if let Some(bcc) = bcc {
        params["bcc"] = bcc;
    }
    reqwest::Client::new()
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "email",
            "action": "send",
            "params": params
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn seed_email_instance(
    base: &str,
    client: &reqwest::Client,
    admin_key: &str,
    gateway_url: &str,
) {
    seed_email_instance_named(base, client, admin_key, gateway_url, "email", MAILBOX_USER).await;
}

async fn seed_email_instance_named(
    base: &str,
    client: &reqwest::Client,
    admin_key: &str,
    gateway_url: &str,
    name: &str,
    mailbox_user: &str,
) {
    let secret = format!("{name}_pass");
    let resp = client
        .put(format!("{base}/v1/secrets/{secret}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "value": MAILBOX_PASS }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "secret create: {}",
        resp.status()
    );

    let instance: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "name": name,
            "template_key": "email",
            "url": gateway_url,
            "credentials": { "mailbox_pass": secret },
            "config": { "mailbox_user": mailbox_user },
            "status": "active",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let svc_id = instance["id"]
        .as_str()
        .unwrap_or_else(|| panic!("instance {name} create failed: {instance:?}"));

    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
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
        .expect("Everyone group not found");

    let grant = client
        .post(format!("{base}/v1/groups/{everyone_id}/grants"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "service_instance_id": svc_id,
            "access_level": "admin",
            "auto_approve_reads": true,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        grant.status() == 200 || grant.status() == 409,
        "grant failed: {}",
        grant.status()
    );
}
