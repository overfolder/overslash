//! Integration coverage for `x-overslash-additional-properties` — the
//! template-level opt-out from closed-world argument validation.
//!
//! The unit tests in `overslash_core::openapi::validate_input` pin what the
//! gate accepts. What only this layer can show is where an accepted argument
//! then *goes*: the whole feature is worthless if the gate stops rejecting an
//! undeclared key and the resolver silently drops it a few frames later. So
//! every assertion here reads the request the upstream actually received.
//!
//! Four contracts:
//!
//!   1. A relaxed `GET` forwards an undeclared argument as a query pair.
//!   2. A relaxed `POST` forwards it in the JSON body — including the case
//!      where the operation declares no `requestBody` at all, which before
//!      this change had no body to put it in.
//!   3. A declared `enum` is advisory on a relaxed action, and a strict
//!      action is completely unchanged: same `invalid_action_args` 400, same
//!      `did you mean` suggestion.
//!   4. `/v1/actions/validate` agrees with `/v1/actions/call` in both
//!      directions, which is the byte-identical-400 contract the two
//!      endpoints already owe each other.

use crate::common;

use crate::common::{bootstrap_org_identity, start_api_with_registry_customized, start_mock};
use serde_json::{Value, json};

/// No `securitySchemes` and no `secrets` on the call, so `needs_gate` is
/// false and the request executes straight through to the mock instead of
/// parking on an approval — this test is about what reaches the upstream.
const TEMPLATE_YAML_FMT: &str = r#"openapi: "3.1.0"
info:
  title: "Relaxed Fixture"
  key: "relaxer"
servers:
  - url: "http://HOST_PLACEHOLDER"
paths:
  /echo:
    get:
      operationId: loose_get
      summary: "Relaxed search"
      risk: read
      additional-properties: true
      parameters:
        - name: q
          in: query
          schema: {type: string}
        - name: mode
          in: query
          schema:
            type: string
            enum: [fast, slow]
    post:
      operationId: loose_post
      summary: "Relaxed write"
      risk: read
      additional-properties: true
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                title: {type: string}
  /strict:
    get:
      operationId: strict_get
      summary: "Strict search"
      risk: read
      parameters:
        - name: q
          in: query
          schema: {type: string}
        - name: mode
          in: query
          schema:
            type: string
            enum: [fast, slow]
  /bodyless:
    post:
      operationId: loose_bodyless_post
      summary: "Relaxed write with no declared body"
      risk: read
      additional-properties: true
"#;

/// Register the fixture and return `(base, client, agent_key)`.
async fn setup() -> (String, reqwest::Client, String) {
    // Every assertion here reads the request the upstream received, so unlike
    // the approval-path fixtures these calls must actually reach the mock.
    common::allow_loopback_ssrf();
    let pool = common::test_pool().await;
    let mock_addr = start_mock().await;
    // Template hosts are persisted without scheme or port ("127.0.0.1"), so
    // the executor needs the e2e base override to reach the in-test fake —
    // the same mechanism the docker e2e stack uses.
    let override_base = format!("http://{mock_addr}");
    let (base, client) = start_api_with_registry_customized(pool.clone(), None, move |cfg| {
        cfg.service_base_overrides
            .insert("127.0.0.1".to_string(), override_base);
    })
    .await;
    let (_org_id, _ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    let yaml = TEMPLATE_YAML_FMT.replace("HOST_PLACEHOLDER", &mock_addr.to_string());
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
        Some("relaxer"),
        "template register failed: {create:?}"
    );

    let everyone_id = common::everyone_group_id(&base, &client, &admin_key).await;
    let svc: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "relaxer",
            "name": "relaxer",
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
    assert!(
        svc["id"].as_str().is_some(),
        "service create failed: {svc:?}"
    );

    (base, client, agent_key)
}

async fn call(base: &str, client: &reqwest::Client, key: &str, body: Value) -> (u16, Value) {
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap())
}

async fn validate(base: &str, client: &reqwest::Client, key: &str, body: Value) -> (u16, Value) {
    let resp = client
        .post(format!("{base}/v1/actions/validate"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap())
}

#[tokio::test]
async fn relaxed_get_forwards_an_undeclared_argument_as_a_query_pair() {
    let (base, client, agent_key) = setup().await;

    let (status, body) = call(
        &base,
        &client,
        &agent_key,
        json!({
            "service": "relaxer",
            "action": "loose_get",
            "params": {"q": "hello", "undeclared_filter": "widgets"}
        }),
    )
    .await;
    assert_eq!(status, 200, "expected execution, got: {body:?}");

    let echo: Value =
        serde_json::from_str(body["result"]["body"].as_str().expect("echo body")).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(uri.contains("q=hello"), "declared param missing: {uri}");
    assert!(
        uri.contains("undeclared_filter=widgets"),
        "undeclared param was accepted at the gate and then dropped: {uri}",
    );
}

#[tokio::test]
async fn relaxed_post_forwards_an_undeclared_argument_in_the_json_body() {
    let (base, client, agent_key) = setup().await;

    let (status, body) = call(
        &base,
        &client,
        &agent_key,
        json!({
            "service": "relaxer",
            "action": "loose_post",
            "params": {"title": "t", "undeclared_field": "v"}
        }),
    )
    .await;
    assert_eq!(status, 200, "expected execution, got: {body:?}");

    let echo: Value =
        serde_json::from_str(body["result"]["body"].as_str().expect("echo body")).unwrap();
    let sent: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(sent["title"], "t");
    assert_eq!(
        sent["undeclared_field"], "v",
        "undeclared body field dropped: {sent}"
    );
}

/// The gap the design called out: an operation with no declared `requestBody`
/// builds no body at all, so before this change a relaxed undeclared argument
/// on a `POST` would pass the gate and then vanish — worse than the 400 it
/// replaced.
#[tokio::test]
async fn relaxed_post_synthesizes_a_body_when_none_is_declared() {
    let (base, client, agent_key) = setup().await;

    let (status, body) = call(
        &base,
        &client,
        &agent_key,
        json!({
            "service": "relaxer",
            "action": "loose_bodyless_post",
            "params": {"only_undeclared": "kept"}
        }),
    )
    .await;
    assert_eq!(status, 200, "expected execution, got: {body:?}");

    let echo: Value =
        serde_json::from_str(body["result"]["body"].as_str().expect("echo body")).unwrap();
    let sent: Value = serde_json::from_str(echo["body"].as_str().unwrap_or("null")).unwrap();
    assert_eq!(
        sent["only_undeclared"], "kept",
        "no body was synthesized: {echo}"
    );
    let ct = echo["headers"]["content-type"].as_str().unwrap_or("");
    assert!(
        ct.starts_with("application/json"),
        "a synthesized body still needs its media type, got {ct:?}",
    );
}

#[tokio::test]
async fn relaxed_action_accepts_an_enum_value_outside_the_declared_members() {
    let (base, client, agent_key) = setup().await;

    let (status, body) = call(
        &base,
        &client,
        &agent_key,
        json!({
            "service": "relaxer",
            "action": "loose_get",
            "params": {"mode": "turbo"}
        }),
    )
    .await;
    assert_eq!(status, 200, "advisory enum rejected: {body:?}");

    let echo: Value =
        serde_json::from_str(body["result"]["body"].as_str().expect("echo body")).unwrap();
    assert!(
        echo["uri"].as_str().unwrap().contains("mode=turbo"),
        "off-list enum value not forwarded: {echo}",
    );
}

/// The default must be exactly what it was. Both halves: the unknown key and
/// the off-list enum still 400, with the same error code.
#[tokio::test]
async fn a_strict_action_is_unchanged() {
    let (base, client, agent_key) = setup().await;

    let (status, body) = call(
        &base,
        &client,
        &agent_key,
        json!({
            "service": "relaxer",
            "action": "strict_get",
            "params": {"q": "hello", "undeclared_filter": "widgets"}
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "strict action accepted an unknown key: {body:?}"
    );
    assert_eq!(body["error"], "invalid_action_args");

    let (status, body) = call(
        &base,
        &client,
        &agent_key,
        json!({
            "service": "relaxer",
            "action": "strict_get",
            "params": {"mode": "turbo"}
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "strict action accepted an off-list enum: {body:?}"
    );
    assert_eq!(body["error"], "invalid_action_args");
}

/// `/validate` and `/call` must agree in *both* directions, or a caller that
/// pre-flights gets a different answer than the one execution will give.
#[tokio::test]
async fn validate_agrees_with_call_on_both_the_relaxed_and_strict_actions() {
    let (base, client, agent_key) = setup().await;

    // Relaxed: both accept.
    let relaxed = json!({
        "service": "relaxer",
        "action": "loose_get",
        "params": {"q": "hello", "undeclared_filter": "widgets"}
    });
    let (v_status, v_body) = validate(&base, &client, &agent_key, relaxed.clone()).await;
    assert_eq!(
        v_status, 200,
        "validate rejected a relaxed call: {v_body:?}"
    );
    let (c_status, _) = call(&base, &client, &agent_key, relaxed).await;
    assert_eq!(c_status, 200);

    // Strict: both reject, with the same body.
    let strict = json!({
        "service": "relaxer",
        "action": "strict_get",
        "params": {"q": "hello", "undeclared_filter": "widgets"}
    });
    let (v_status, v_body) = validate(&base, &client, &agent_key, strict.clone()).await;
    let (c_status, c_body) = call(&base, &client, &agent_key, strict).await;
    assert_eq!(v_status, 400);
    assert_eq!(c_status, 400);
    assert_eq!(
        v_body, c_body,
        "the byte-identical 400 contract broke once the flag was threaded",
    );
}

/// The relaxation must be visible to a model, or only a caller who already
/// guessed can use it.
#[tokio::test]
async fn search_projects_the_relaxation_to_the_model() {
    let (base, client, agent_key) = setup().await;

    let resp = client
        .get(format!("{base}/v1/search?q=relaxed"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    let text = body.to_string();
    assert!(
        text.contains("additional_properties"),
        "search never surfaces the flag, so the relaxation is undiscoverable: {text}",
    );
}
