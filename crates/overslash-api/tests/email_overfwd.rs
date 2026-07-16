//! End-to-end integration test for the shipped `email` service (the overfwd
//! Mailbox Gateway), exercised through the real `/v1/actions/call` path.
//!
//! Proves the three overfwd-enabling changes together, against an in-process
//! mock that impersonates an overfwd deployment:
//!   • Core A — base64 `SecretRef` encoding: the mailbox `user:pass` secret is
//!     injected as `X-Mailbox-Auth: Basic base64(user:pass)`.
//!   • Core B — multi-injection auth: the gateway key (`secret_source: org`)
//!     and the mailbox credential (`secret_source: instance`) ride the SAME
//!     request as `Authorization: Bearer …` + `X-Mailbox-Auth: Basic …`.
//!   • Core C — per-instance `url` override: the request routes to the org's
//!     own deployment URL (scheme + port preserved), not the template default.
//!
//! Also asserts `send` is `write`-gated (approval) and discloses To/From/Subject.
//!
//! Run with `--test-threads=4` (see CLAUDE.md).

#![allow(clippy::disallowed_methods)]

mod common;

use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use common::{bootstrap_org_identity, start_api_with_registry};

// base64("user@example.com:app-password"), STANDARD alphabet.
const MAILBOX_CRED: &str = "user@example.com:app-password";
const MAILBOX_BASIC: &str = "Basic dXNlckBleGFtcGxlLmNvbTphcHAtcGFzc3dvcmQ=";
const GATEWAY_KEY: &str = "gw-secret-key";

#[derive(Clone, Default)]
struct Captured {
    path: String,
    authorization: Option<String>,
    mailbox_auth: Option<String>,
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
/// seed the gateway key (and the mailbox credential iff `mailbox_secret` is
/// `Some`), create an `email` instance pointed at `gateway_url` (binding
/// `secret_name` iff `mailbox_secret` is `Some`), and grant it to Everyone
/// (admin + auto-approve reads). Returns `(base, agent_key)`.
async fn setup_email_instance(
    pool: sqlx::PgPool,
    gateway_url: &str,
    mailbox_secret: Option<&str>,
    seed_gateway_key: bool,
) -> (String, String) {
    // The gateway key is an org-vault secret referenced by the template's fixed
    // `default_secret_name` (secret_source: org, optional). A keyless overfwd
    // deployment omits it. The mailbox credential is the per-instance bound
    // secret (secret_source: instance) — seeded only when the instance binds it.
    let mut secrets = Vec::new();
    if seed_gateway_key {
        secrets.push(("overfwd_gateway_key", GATEWAY_KEY));
    }
    if let Some(name) = mailbox_secret {
        secrets.push((name, MAILBOX_CRED));
    }
    let mut body = json!({
        "template_key": "email",
        "name": "email",
        "url": gateway_url,
        "user_level": false,
        "status": "active",
    });
    if let Some(name) = mailbox_secret {
        body["secret_name"] = json!(name);
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
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

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
    let (base, agent_key) =
        setup_email_instance(pool, &gateway_url, Some("mailbox_credential"), true).await;

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

#[tokio::test]
async fn email_send_is_write_gated_and_discloses_message() {
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key) =
        setup_email_instance(pool, &gateway_url, Some("mailbox_credential"), true).await;

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
    let (base, agent_key) = setup_email_instance(pool, &gateway_url, None, true).await;

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
async fn email_keyless_gateway_omits_authorization_but_still_sends_mailbox_auth() {
    // A self-hosted overfwd running with OVERFWD_REQUIRE_API_KEY=false needs no
    // gateway key. The `gateway` scheme is `optional`, so when the org has NOT
    // stored `overfwd_gateway_key` the request omits `Authorization` entirely
    // (rather than failing on a missing secret) while still injecting the
    // per-mailbox `X-Mailbox-Auth`.
    let pool = common::test_pool().await;
    let (gateway_url, sink) = start_mock_overfwd().await;
    // Bind the mailbox credential but do NOT seed the gateway key.
    let (base, agent_key) =
        setup_email_instance(pool, &gateway_url, Some("mailbox_credential"), false).await;

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

// ── Per-scheme credential bindings (`service_instances.credentials`) ────────

/// Both schemes bound explicitly through the `credentials` map — including a
/// per-instance gateway key under a NON-default name, which the org-fixed
/// `overfwd_gateway_key` fallback could never express. No legacy
/// `secret_name` in sight.
#[tokio::test]
async fn email_credentials_map_binds_both_schemes_with_custom_gateway_key() {
    let pool = common::test_pool().await;
    let pool2 = pool.clone();
    let (gateway_url, sink) = start_mock_overfwd().await;
    let (base, agent_key, _admin_key, instance) = setup_email_instance_custom(
        pool,
        &[
            ("my_own_gateway_token", "instance-gw-key"),
            ("angel_mailbox_login", MAILBOX_CRED),
        ],
        json!({
            "template_key": "email",
            "name": "email",
            "url": gateway_url,
            "user_level": false,
            "status": "active",
            "credentials": {
                "gateway": "my_own_gateway_token",
                "mailbox": "angel_mailbox_login",
            },
        }),
    )
    .await;

    // The create response exposes the bindings (names only) and mirrors the
    // sole instance-source scheme into the legacy scalar for rolling deploys.
    assert_eq!(
        instance["credentials"],
        json!({ "gateway": "my_own_gateway_token", "mailbox": "angel_mailbox_login" })
    );
    assert_eq!(instance["secret_name"], json!("angel_mailbox_login"));

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

/// A `credentials` key that names no securityScheme of the template is a
/// caller bug — reject at the boundary instead of storing a dead binding.
#[tokio::test]
async fn email_create_rejects_unknown_credential_scheme() {
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

/// The legacy `secret_name` alias keeps working and lands in the map: the
/// dashboard contract is that scalar writes and per-scheme reads agree.
#[tokio::test]
async fn email_update_secret_name_alias_syncs_credentials_map() {
    let pool = common::test_pool().await;
    let (gateway_url, _sink) = start_mock_overfwd().await;
    let (base, _agent_key, admin_key, instance) = setup_email_instance_custom(
        pool,
        &[("mailbox_credential", MAILBOX_CRED)],
        json!({
            "template_key": "email",
            "name": "email",
            "url": gateway_url,
            "user_level": false,
            "status": "active",
            "secret_name": "mailbox_credential",
        }),
    )
    .await;
    let svc_id = instance["id"].as_str().unwrap();
    // Legacy scalar create landed in the map slot too.
    assert_eq!(
        instance["credentials"],
        json!({ "mailbox": "mailbox_credential" })
    );

    // A scalar-only rebind must land in the map — and must NOT trip the
    // both-fields conflict check against the mirrored slot the create path
    // wrote (regression: the stored mirror is what the alias replaces, not a
    // competing caller intent).
    let client = reqwest::Client::new();
    let rebound: Value = client
        .put(format!("{base}/v1/services/{svc_id}/manage"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "secret_name": "scalar_rebound" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        rebound["credentials"],
        json!({ "mailbox": "scalar_rebound" }),
        "scalar-only rebind must replace the mirrored slot: {rebound:?}"
    );
    assert_eq!(rebound["secret_name"], json!("scalar_rebound"));

    // Whole-map replace: rebind mailbox and unbind nothing else; the mirrored
    // scalar follows the instance-source slot.
    let updated: Value = client
        .put(format!("{base}/v1/services/{svc_id}/manage"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "credentials": { "mailbox": "other_login" } }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated["credentials"], json!({ "mailbox": "other_login" }));
    assert_eq!(updated["secret_name"], json!("other_login"));

    // Clearing: an explicit empty map unbinds everything, and the mirrored
    // scalar follows. (A literal `"secret_name": null` can't clear — plain
    // serde folds explicit null into "absent" for Option<Option<T>>, a
    // pre-existing tri-state limitation; the map is the canonical clear.)
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

/// The dashboard renders one row per apiKey scheme keyed by `scheme` — pin
/// the template serialization contract it depends on.
#[tokio::test]
async fn email_template_serializes_scheme_keys_and_sources() {
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
}
