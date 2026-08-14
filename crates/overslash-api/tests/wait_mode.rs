//! `x-overslash-wait-mode` — the action template as rung 2 of the execution-mode
//! cascade.
//!
//! The claim under test is narrow and has two halves. A template may **supply**
//! a mode the caller never named, changing which envelope comes back; and it may
//! never **impose** one, either over a caller who said otherwise or over a flag
//! combination that makes deferral incoherent. The second half is where the
//! interesting cases are: every one of them is a hard 400 when the *caller*
//! names the mode, and a silent fall back to synchronous when the *template*
//! does.
//!
//! Run with `--test-threads=4` (or similar) — see CLAUDE.md.

#![allow(clippy::disallowed_methods)]

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};

/// One template, four operations, so a single registration covers the whole
/// matrix. The mock's `/slow?ms=` lets one action be reliably fast and another
/// reliably slower than the handoff.
const TEMPLATE_YAML: &str = r#"openapi: "3.1.0"
info:
  title: "Wait Mode Fixture"
  key: "waiter"
servers:
  - url: "http://HOST_PLACEHOLDER"
paths:
  /slow:
    get:
      operationId: quick
      summary: "A hybrid-declaring action that usually answers in time"
      description: "Sleeps for ?ms and returns."
      risk: read
      wait-mode: hybrid
      parameters:
        - name: ms
          in: query
          schema: {type: string}
  /echo:
    get:
      operationId: plain
      summary: "No declaration at all"
      description: "Echoes."
      risk: read
    post:
      operationId: deferred
      summary: "An async-declaring action"
      description: "Echoes."
      risk: read
      wait-mode: async
  /large-file:
    get:
      operationId: blob
      summary: "A binary-returning action that also declares hybrid"
      description: "Returns bytes."
      risk: read
      wait-mode: hybrid
      # `response_type` is *derived* from this block, never authored — writing
      # `response_type: binary` on the operation is the exact no-op D67's lint
      # exists to report, and it silently made this fixture pass as JSON.
      responses:
        "200":
          description: bytes
          content:
            application/octet-stream:
              schema: {type: string, format: binary}
"#;

/// Boot with async execution on, register the fixture, and grant it broadly
/// enough that nothing under test trips the permission gate instead.
async fn setup(pool: sqlx::PgPool, enabled: bool) -> (String, Client, String) {
    common::allow_loopback_ssrf();
    let mock = common::start_mock().await;
    // Template hosts are persisted without scheme/port ("127.0.0.1"), so the
    // executor needs the base override to reach the in-test fake — the same
    // mechanism the docker e2e stack uses.
    let override_base = format!("http://{mock}");
    let (base, client) = common::start_api_with_registry_customized(pool, None, move |cfg| {
        cfg.async_execution.enabled = enabled;
        // Long enough that a 0ms upstream always beats it, so "which envelope"
        // is decided by the cascade under test and not by a timing race.
        cfg.async_execution.hybrid_handoff_ms = 30_000;
        cfg.async_execution.hybrid_handoff_max_ms = 30_000;
        cfg.service_base_overrides
            .insert("127.0.0.1".to_string(), override_base);
    })
    .await;
    let (_org, _ident, agent_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let yaml = TEMPLATE_YAML.replace("HOST_PLACEHOLDER", &mock.to_string());
    let create: Value = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"openapi": yaml, "user_level": false}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        create["key"].as_str(),
        Some("waiter"),
        "template register failed: {create:?}"
    );

    let everyone_id = common::everyone_group_id(&base, &client, &admin_key).await;
    let svc: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "waiter",
            "name": "waiter",
            "user_level": false,
            "groups": [{
                "group_id": everyone_id.to_string(),
                "access_level": "write",
                "auto_approve_reads": true,
            }],
            "status": "active",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(svc["id"].as_str().is_some(), "service create failed: {svc}");

    (base, client, agent_key)
}

async fn call(base: &str, client: &Client, key: &str, body: Value) -> (u16, Value) {
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(key).0, common::auth(key).1)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

/// The whole point of the key: a request that names no mode at all inherits the
/// action's, and the response shape follows.
///
/// With a 30s handoff and a 0ms upstream the race is deterministic, so this
/// asserts the *adoption* rather than the timing — `execution_id` on a `called`
/// envelope is the tell, since only a hybrid call writes a row it can answer
/// from.
#[tokio::test]
async fn an_action_declaring_hybrid_defers_a_call_that_named_no_mode() {
    let pool = common::test_pool().await;
    let (base, client, key) = setup(pool, true).await;

    let (status, body) = call(
        &base,
        &client,
        &key,
        json!({"service": "waiter", "action": "quick", "params": {"ms": "0"}}),
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "called", "{body}");
    assert!(
        body["execution_id"].as_str().is_some(),
        "a hybrid call carries the row it ran on, and that is how we know the \
         template rung was adopted rather than ignored: {body}"
    );
}

/// An action declaring `async` answers 202 to a bare request, and says why.
#[tokio::test]
async fn an_action_declaring_async_answers_accepted_and_names_the_source() {
    let pool = common::test_pool().await;
    let (base, client, key) = setup(pool, true).await;

    let (status, body) = call(
        &base,
        &client,
        &key,
        json!({"service": "waiter", "action": "deferred"}),
    )
    .await;

    assert_eq!(status, 202, "{body}");
    assert_eq!(body["status"], "accepted", "{body}");
    assert!(body["execution_id"].as_str().is_some(), "{body}");
    // The field exists so a 202 nobody asked for can explain itself.
    assert_eq!(
        body["execution_mode_source"], "action_template",
        "an unrequested 202 must name the rung that chose it: {body}"
    );
}

/// The caller outranks the template — including *downward*. Without this the
/// key would be a cap rather than a default, and an agent that needs the answer
/// inline would have no way to ask for it.
#[tokio::test]
async fn an_explicit_sync_beats_an_action_declaring_hybrid() {
    let pool = common::test_pool().await;
    let (base, client, key) = setup(pool, true).await;

    let (status, body) = call(
        &base,
        &client,
        &key,
        json!({
            "service": "waiter", "action": "quick",
            "params": {"ms": "0"}, "execution": "sync"
        }),
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "called", "{body}");
    assert!(
        body["execution_id"].is_null(),
        "a synchronous call writes no execution row: {body}"
    );
    assert!(
        body["execution_mode_source"].is_null(),
        "a caller that named the mode does not need telling where it came from: {body}"
    );
}

/// An action with no declaration is untouched by any of this.
#[tokio::test]
async fn an_action_with_no_declaration_is_synchronous() {
    let pool = common::test_pool().await;
    let (base, client, key) = setup(pool, true).await;

    let (status, body) = call(
        &base,
        &client,
        &key,
        json!({"service": "waiter", "action": "plain"}),
    )
    .await;

    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "called", "{body}");
    assert!(body["execution_id"].is_null(), "{body}");
}

/// The asymmetry this whole design turns on, both halves in one test.
///
/// `prefer_stream` and a deferred mode are incoherent — there is no response to
/// stream onto once the call leaves the connection. When the caller names the
/// mode that is a 400, unchanged. When the *template* named it, the call runs
/// synchronously and succeeds, because a template value the caller never saw
/// must not be able to 400 every call in the org.
#[tokio::test]
async fn a_conflicting_flag_demotes_the_template_but_still_refuses_the_caller() {
    let pool = common::test_pool().await;
    let (base, client, key) = setup(pool, true).await;

    let (status, body) = call(
        &base,
        &client,
        &key,
        json!({
            "service": "waiter", "action": "quick",
            "params": {"ms": "0"}, "prefer_stream": true
        }),
    )
    .await;
    assert_eq!(
        status, 200,
        "a template's mode yields to the caller's flag rather than refusing: {body}"
    );

    let (status, body) = call(
        &base,
        &client,
        &key,
        json!({
            "service": "waiter", "action": "quick",
            "params": {"ms": "0"}, "prefer_stream": true, "execution": "hybrid"
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "the caller-named twin is still refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("prefer_stream"),
        "{body}"
    );
}

/// The template-shaped blocker, same two halves. A binary body would be mangled
/// by the buffered path on its way into the execution row, so it can never
/// defer — but an author who tags one `hybrid` should get a working action, not
/// a dead one.
#[tokio::test]
async fn a_binary_action_declaring_hybrid_runs_synchronously_instead_of_failing() {
    let pool = common::test_pool().await;
    let (base, client, key) = setup(pool, true).await;

    let (status, body) = call(
        &base,
        &client,
        &key,
        json!({"service": "waiter", "action": "blob"}),
    )
    .await;
    assert_eq!(
        status, 200,
        "a template that declares an impossible mode still serves its action: {body}"
    );
    assert!(body["execution_id"].is_null(), "{body}");

    let (status, body) = call(
        &base,
        &client,
        &key,
        json!({"service": "waiter", "action": "blob", "execution": "hybrid"}),
    )
    .await;
    assert_eq!(
        status, 400,
        "the caller-named twin is still refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("binary"),
        "{body}"
    );
}

/// A deployment that never opted into async is not opted in by a template.
///
/// The flag-off refusal is deliberately caller-only: refusing here instead
/// would let one shipped template take every call to an action down on a
/// deployment that has no worker to drain the queue.
#[tokio::test]
async fn a_flag_off_deployment_ignores_the_template_rung_rather_than_failing() {
    let pool = common::test_pool().await;
    let (base, client, key) = setup(pool, false).await;

    let (status, body) = call(
        &base,
        &client,
        &key,
        json!({"service": "waiter", "action": "deferred"}),
    )
    .await;
    assert_eq!(
        status, 200,
        "the template rung is dropped, not escalated to an error: {body}"
    );
    assert_eq!(body["status"], "called", "{body}");

    let (status, body) = call(
        &base,
        &client,
        &key,
        json!({"service": "waiter", "action": "deferred", "execution": "async"}),
    )
    .await;
    assert_eq!(
        status, 400,
        "the caller-named twin is still refused: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not enabled"),
        "{body}"
    );
}

/// `handoff_after_ms` alone used to be a 400, because the check ran before any
/// template was known and so only ever saw `sync`. Against an action that
/// declares hybrid it is a coherent request, and refusing it would make the
/// knob unusable on exactly the actions it exists for.
#[tokio::test]
async fn the_handoff_knob_is_accepted_when_the_action_supplies_the_mode() {
    let pool = common::test_pool().await;
    let (base, client, key) = setup(pool, true).await;

    let (status, body) = call(
        &base,
        &client,
        &key,
        json!({
            "service": "waiter", "action": "quick",
            "params": {"ms": "0"}, "handoff_after_ms": 5000
        }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(body["execution_id"].as_str().is_some(), "{body}");

    // Still refused where the resolved mode really has no handoff to schedule,
    // and the message now names the mode the call actually resolved to.
    let (status, body) = call(
        &base,
        &client,
        &key,
        json!({"service": "waiter", "action": "plain", "handoff_after_ms": 5000}),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("handoff_after_ms"),
        "{body}"
    );
}

/// The declaration is visible before anyone calls the action.
///
/// Without this the response-shape consequence is discoverable only by trying
/// it, which is the wrong order for something that changes what an integration
/// has to handle.
#[tokio::test]
async fn the_action_listing_surfaces_the_declared_mode() {
    let pool = common::test_pool().await;
    let (base, client, key) = setup(pool, true).await;

    let actions: Value = client
        .get(format!("{base}/v1/services/waiter/actions"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let by_key = |k: &str| -> Value {
        actions
            .as_array()
            .expect("actions list")
            .iter()
            .find(|a| a["key"] == k)
            .unwrap_or_else(|| panic!("no action {k} in {actions}"))
            .clone()
    };
    assert_eq!(by_key("quick")["wait_mode"], "hybrid");
    assert_eq!(by_key("deferred")["wait_mode"], "async");
    assert!(
        by_key("plain")["wait_mode"].is_null(),
        "an undeclared action carries no key at all, so a client can tell \
         'synchronous' from 'unspecified'"
    );
}
