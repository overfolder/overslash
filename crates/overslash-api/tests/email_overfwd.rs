//! End-to-end integration test for the shipped `email` service (the overfwd
//! Mailbox Gateway), exercised through the real `/v1/actions/call` path.
//!
//! Proves the three overfwd-enabling changes together, against an in-process
//! mock that impersonates an overfwd deployment:
//!   • Core A — credential composition: the mailbox username and password are
//!     two separate vault secrets, joined by the scheme's jq template into
//!     `X-Mailbox-Auth: Basic base64(user:pass)`.
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

// The mailbox login, stored as two independently-rotatable secrets. The
// expected header is unchanged from when this was ONE `user:pass` secret —
// that identity is the point: only where the colon comes from changed.
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
/// seed the gateway key (and the mailbox login iff `bind_mailbox`), create an
/// `email` instance pointed at `gateway_url` binding both mailbox slots, and
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
    // deployment omits it. The mailbox login is two per-instance bound secrets
    // (source: instance) — seeded only when the instance binds them.
    let mut secrets = Vec::new();
    if seed_gateway_key {
        secrets.push(("overfwd_gateway_key", GATEWAY_KEY));
    }
    if bind_mailbox {
        secrets.push(("mailbox_user", MAILBOX_USER));
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
        body["credentials"] = json!({
            "mailbox_user": "mailbox_user",
            "mailbox_pass": "mailbox_pass",
        });
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
    let (base, client) = start_api_with_registry(pool, None).await;
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
    // The search key made it into the JSON body.
    assert_eq!(req.body["query"], json!("UNSEEN"));
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
    // folder/query, so an argument-free call still expresses the intent.
    assert!(
        req.body.is_object(),
        "body must be a JSON object, got {:?}",
        req.body
    );
    assert_eq!(req.body["folder"], json!("INBOX"));
    assert_eq!(req.body["query"], json!("ALL"));
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
    // The username stays bound, so this also covers "half a composed
    // credential" — the case that would otherwise send `Basic base64("user:")`.
    sqlx::query(
        r#"UPDATE service_instances
           SET credentials = '{"mailbox_user": "mailbox_user", "mailbox_pass": ""}'::jsonb,
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
/// `overfwd_gateway_key` fallback could never express, and a mailbox login
/// split across two secrets under names of the operator's choosing.
#[tokio::test]
async fn email_credentials_map_binds_every_slot_with_custom_names() {
    let pool = common::test_pool().await;
    let pool2 = pool.clone();
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key, _admin_key, instance) = setup_email_instance_custom(
        pool,
        &[
            ("my_own_gateway_token", "instance-gw-key"),
            ("angel_login", MAILBOX_USER),
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
                "mailbox_user": "angel_login",
                "mailbox_pass": "angel_app_password",
            },
        }),
    )
    .await;

    // The create response exposes the bindings (names only). With two
    // instance-source slots the legacy scalar has nothing unambiguous to
    // mirror, so it stays null.
    assert_eq!(
        instance["credentials"],
        json!({
            "gateway": "my_own_gateway_token",
            "mailbox_user": "angel_login",
            "mailbox_pass": "angel_app_password",
        })
    );
    assert_eq!(instance["secret_name"], json!(null));

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
    // Two secrets, one header: the joined value is byte-identical to what a
    // single `user:pass` secret produced before the split.
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

/// The scalar `secret_name` alias cannot express a composed credential, so a
/// template with several instance-source slots must reject it rather than
/// guess which half it meant. (The alias still works for a single-slot
/// template — see `service_instances::test_secret_name_rejected_on_oauth_template`.)
#[tokio::test]
async fn email_rejects_scalar_secret_name_for_composed_mailbox() {
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
    assert_eq!(resp.status(), 400, "ambiguous scalar alias must 400");
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("mailbox_user") && body.contains("mailbox_pass"),
        "error should name the slots to bind instead: {body}"
    );
}

/// `credentials` on update is a whole-map replace, and an empty map unbinds
/// everything — the same contract as before the mailbox split, now over two
/// slots instead of one.
#[tokio::test]
async fn email_update_credentials_replaces_and_clears() {
    let pool = common::test_pool().await;
    let (gateway_url, _sink) = start_mock_overfwd().await;
    let (base, _agent_key, admin_key, instance) = setup_email_instance_custom(
        pool,
        &[
            ("mailbox_user", MAILBOX_USER),
            ("mailbox_pass", MAILBOX_PASS),
        ],
        json!({
            "template_key": "email",
            "name": "email",
            "url": gateway_url,
            "user_level": false,
            "status": "active",
            "credentials": {
                "mailbox_user": "mailbox_user",
                "mailbox_pass": "mailbox_pass",
            },
        }),
    )
    .await;
    let svc_id = instance["id"].as_str().unwrap();
    let client = reqwest::Client::new();

    // Whole-map replace: rebind both halves at once.
    let updated: Value = client
        .put(format!("{base}/v1/services/{svc_id}/manage"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "credentials": { "mailbox_user": "other_login", "mailbox_pass": "other_password" }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        updated["credentials"],
        json!({ "mailbox_user": "other_login", "mailbox_pass": "other_password" })
    );

    // Rotating just the password leaves the username bound — the whole point
    // of splitting the credential in two.
    let rotated: Value = client
        .put(format!("{base}/v1/services/{svc_id}/manage"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "credentials": { "mailbox_user": "other_login", "mailbox_pass": "rotated_password" }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rotated["credentials"]["mailbox_user"], json!("other_login"));
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
    // The mailbox header is joined from two secrets, so it reads two slots
    // while the gateway reads only its own implicit one.
    assert_eq!(auth[0]["slots"], json!(["gateway"]));
    assert_eq!(auth[1]["slots"], json!(["mailbox_user", "mailbox_pass"]));

    // The slot list the credentials form renders: three pickers, each with
    // the label and source the dashboard shows. Ordered by the auth entry
    // that reads them, then by the expression — so the form asks for the
    // username before the password, the order the header joins them in.
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
            ("mailbox_user", "Mailbox username", "instance"),
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
        &[
            ("mailbox_user", MAILBOX_USER),
            ("mailbox_pass", MAILBOX_PASS),
        ],
        json!({
            "template_key": "email",
            "url": gateway_url,
            "credentials": { "mailbox_user": "mailbox_user", "mailbox_pass": "mailbox_pass" },
            "config": {
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
        &[
            ("mailbox_user", MAILBOX_USER),
            ("mailbox_pass", MAILBOX_PASS),
        ],
        json!({
            "template_key": "email",
            "url": gateway_url,
            "credentials": { "mailbox_user": "mailbox_user", "mailbox_pass": "mailbox_pass" },
            "config": { "X-Mailbox-Imap": "imap.corp.internal:993" },
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
        &[
            ("mailbox_user", MAILBOX_USER),
            ("mailbox_pass", MAILBOX_PASS),
        ],
        json!({
            "template_key": "email",
            "url": gateway_url,
            "credentials": { "mailbox_user": "mailbox_user", "mailbox_pass": "mailbox_pass" },
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
    assert_eq!(req.body["query"], json!("ALL"));
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
        &[
            ("mailbox_user", MAILBOX_USER),
            ("mailbox_pass", MAILBOX_PASS),
        ],
        json!({
            "template_key": "email",
            "url": "http://127.0.0.1:1",
            "credentials": { "mailbox_user": "mailbox_user", "mailbox_pass": "mailbox_pass" },
            "config": { "X-Mailbox-Imap": "imap.one.test:993" },
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
    // Each rides all three operations but must appear once on the form.
    assert_eq!(
        names,
        vec!["X-Mailbox-Imap", "X-Mailbox-Smtp"],
        "{params:?}"
    );
    for p in params {
        assert_eq!(p["required"], json!(false), "{p:?}");
        assert!(
            p["description"]
                .as_str()
                .unwrap_or_default()
                .contains("host:port"),
            "description should reach the form: {p:?}"
        );
    }
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
        &[
            ("mailbox_user", MAILBOX_USER),
            ("mailbox_pass", MAILBOX_PASS),
        ],
        Some(json!({
            "instance_defaults": {
                "url": gateway_url,
                "config": {
                    "X-Mailbox-Imap": "imap.corp.internal:993",
                    "X-Mailbox-Smtp": "smtp.corp.internal:465",
                }
            }
        })),
        json!({
            "template_key": "email_org",
            // No `url`, no `config` — everything comes from the org layer.
            "credentials": { "mailbox_user": "mailbox_user", "mailbox_pass": "mailbox_pass" },
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
        &[
            ("mailbox_user", MAILBOX_USER),
            ("mailbox_pass", MAILBOX_PASS),
        ],
        Some(json!({
            "instance_defaults": {
                // A URL the mock gateway is NOT listening on: if the instance's
                // own `url` did not win, the call could not succeed.
                "url": "https://never.used.invalid",
                "config": {
                    "X-Mailbox-Imap": "imap.layer.internal:993",
                    "X-Mailbox-Smtp": "smtp.layer.internal:465",
                }
            }
        })),
        json!({
            "template_key": "email_org",
            "url": gateway_url,
            "credentials": { "mailbox_user": "mailbox_user", "mailbox_pass": "mailbox_pass" },
            // Instance pins IMAP; SMTP is left to the layer.
            "config": { "X-Mailbox-Imap": "imap.instance.internal:993" },
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
}
