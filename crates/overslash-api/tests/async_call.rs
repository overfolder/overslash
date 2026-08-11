//! `execution: "async"` on `POST /v1/actions/call` — the accepted envelope and
//! every combination that is refused.
//!
//! Run with `--test-threads=4` (or similar) — see CLAUDE.md.

#![allow(clippy::disallowed_methods)]

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

/// Boot an API with async execution enabled, plus a bootstrapped org/agent.
async fn setup(pool: sqlx::PgPool) -> (String, Client, String, String, Uuid) {
    common::allow_loopback_ssrf();
    let (addr, client) = common::start_api_with(pool, |cfg| {
        cfg.async_execution.enabled = true;
    })
    .await;
    let base = format!("http://{addr}");
    let (org_id, _ident, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    common::grant_service_to_everyone(&base, &client, &admin_key, "http").await;
    (base, client, agent_key, admin_key, org_id)
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
    let json: Value = resp.json().await.unwrap_or(Value::Null);
    (status, json)
}

fn base_call(url: &str) -> Value {
    json!({ "service": "http", "method": "GET", "url": url, "execution": "async" })
}

/// The accepted envelope. Shares its 202 with `pending_approval`, so a client
/// has to branch on `status` — this pins that both the code and the
/// discriminator are what the docs claim.
#[tokio::test]
async fn async_call_is_accepted_with_an_execution_id() {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    let (base, client, key, _admin, _org) = setup(pool).await;

    let (status, body) = call(
        &base,
        &client,
        &key,
        base_call(&format!("http://{mock}/echo")),
    )
    .await;

    assert_eq!(status, 202, "async accept shares 202 with pending_approval");
    assert_eq!(body["status"], "accepted");
    let id = body["execution_id"].as_str().expect("execution_id");
    assert!(id.parse::<Uuid>().is_ok());
    assert!(body["execution_url"].as_str().unwrap().contains(id));
    assert!(
        body["timeout_ms"].as_u64().unwrap() > 0,
        "the resolved budget is echoed so a caller knows how long to poll"
    );
    assert!(body["expires_at"].as_str().is_some());

    // The row exists, is queued, and is discoverable through its own resource.
    let resp = client
        .get(format!("{base}/v1/executions/{id}"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .send()
        .await
        .unwrap();
    let st = resp.status();
    let detail: Value = resp.json().await.unwrap_or(Value::Null);
    assert_eq!(st, 200, "GET /v1/executions/{id} -> {st}: {detail}");
    assert_eq!(detail["status"], "pending");
    assert_eq!(detail["origin"], "async_call");
    // A direct async call has no approval behind it — the whole reason
    // `approval_id` had to become nullable.
    assert!(detail["approval_id"].is_null());
}

/// `execution: "sync"` must behave exactly like omitting the field. This is the
/// regression that keeps the new knob from changing the default path.
#[tokio::test]
async fn explicit_sync_is_identical_to_omitting_it() {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    let (base, client, key, _admin, _org) = setup(pool).await;
    let url = format!("http://{mock}/echo");

    let (omitted_status, omitted) = call(
        &base,
        &client,
        &key,
        json!({"service": "http", "method": "GET", "url": url}),
    )
    .await;
    let (explicit_status, explicit) = call(
        &base,
        &client,
        &key,
        json!({"service": "http", "method": "GET", "url": url, "execution": "sync"}),
    )
    .await;

    assert_eq!(omitted_status, explicit_status);
    assert_eq!(omitted["status"], explicit["status"]);
    assert_eq!(omitted["status"], "called");
}

/// An unknown mode is a deserialization failure, not a silent fallback to sync.
#[tokio::test]
async fn unknown_execution_mode_is_rejected() {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    let (base, client, key, _admin, _org) = setup(pool).await;

    let (status, _) = call(
        &base,
        &client,
        &key,
        json!({
            "service": "http", "method": "GET",
            "url": format!("http://{mock}/echo"),
            "execution": "eventually"
        }),
    )
    .await;
    assert!(
        status == 400 || status == 422,
        "an unknown execution mode must not fall back to sync (got {status})"
    );
}

/// Each of these says something async cannot honour. Refusing beats silently
/// dropping one of a contradictory pair — the rule the deferred-delivery
/// guards established.
#[tokio::test]
async fn contradictory_flags_are_refused_with_an_explanation() {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    let (base, client, key, _admin, _org) = setup(pool).await;
    let url = format!("http://{mock}/echo");

    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "prefer_stream",
            json!({"service":"http","method":"GET","url":url,"execution":"async","prefer_stream":true}),
            "no response to stream onto",
        ),
        (
            "deliver:url",
            json!({"service":"http","method":"GET","url":url,"execution":"async","deliver":"url"}),
            "before the call runs",
        ),
        (
            "return_url",
            json!({"service":"http","method":"GET","url":url,"execution":"async","return_url":"https://example.com/back"}),
            "no caller waiting",
        ),
    ];

    for (name, body, needle) in cases {
        let (status, resp) = call(&base, &client, &key, body).await;
        assert_eq!(status, 400, "{name} should be refused, got {resp}");
        let text = resp.to_string();
        assert!(
            text.contains(needle),
            "{name} error should explain why; got {text}"
        );
    }
}

// Not covered here: `execution: "async"` against a platform-runtime action, and
// against an action declaring `response_type: binary`. Both are refused by
// `flags::validate_resolved`, but neither the `overslash` meta-service nor a
// binary-returning template is loaded into the default test registry, so a test
// here would assert registry wiring rather than the rule. Covering them needs
// `start_api_with_registry` and a purpose-built template.

/// With the flag off the field is refused outright rather than quietly running
/// synchronously — a caller that asked for async and got a synchronous 504
/// would have no way to tell.
#[tokio::test]
async fn async_is_refused_when_the_deployment_flag_is_off() {
    let pool = common::test_pool().await;
    common::allow_loopback_ssrf();
    let mock = common::start_mock().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org, _ident, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    common::grant_service_to_everyone(&base, &client, &admin_key, "http").await;

    let (status, resp) = call(
        &base,
        &client,
        &key,
        base_call(&format!("http://{mock}/echo")),
    )
    .await;
    assert_eq!(status, 400, "got {resp}");
    assert!(resp.to_string().contains("not enabled"));
}
