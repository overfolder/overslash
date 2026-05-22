//! End-to-end coverage for the `verbose` toggle on `POST /v1/actions/call`.
//! Pairs with the unit tests at `services::compact_response::tests`.

mod common;

use serde_json::{Value, json};

/// Default + explicit `verbose: true` must produce the existing
/// `ActionResult` shape — headers populated, raw body as a JSON-encoded
/// string. Guards the dashboard + direct REST consumers against
/// regressions when compact mode was introduced.
#[tokio::test]
async fn verbose_default_keeps_full_action_result_shape() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1_000_000).await;
    let base = format!("http://{api_addr}");

    let (_user, _ident_id, api_key) =
        common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    // No `verbose` field → falls back to the HTTP API default of verbose=true.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http",
            "method": "POST",
            "url": format!("http://{mock_addr}/echo"),
            "headers": {"content-type": "application/json"},
            "body": r#"{"hello":"world"}"#,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let result = &body["result"];

    // Verbose mode keeps every ActionResult field.
    assert!(result["status_code"].is_number());
    assert!(result["duration_ms"].is_number());
    assert!(
        result["headers"].is_object(),
        "verbose mode must include the response headers map"
    );
    assert!(
        result["body"].is_string(),
        "verbose mode keeps `body` as the raw upstream string (got: {})",
        result["body"]
    );
    assert!(
        result.get("_truncated").is_none(),
        "verbose mode must never carry a truncation marker"
    );
}

/// `verbose: false` switches to the compact shape: no `headers`, body is
/// upgraded from string to parsed JSON, status + duration retained.
#[tokio::test]
async fn verbose_false_returns_compact_shape() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1_000_000).await;
    let base = format!("http://{api_addr}");

    let (_user, _ident_id, api_key) =
        common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "service": "http",
            "method": "POST",
            "url": format!("http://{mock_addr}/echo"),
            "headers": {"content-type": "application/json"},
            "body": r#"{"hello":"world"}"#,
            "verbose": false,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called");
    let result = &body["result"];

    assert_eq!(result["status_code"], 200);
    assert!(result["duration_ms"].is_number());
    assert!(
        result.get("headers").is_none(),
        "compact mode must drop headers, got: {}",
        result["headers"]
    );
    // The /echo fake returns `{headers, body, uri}` — a JSON object. Compact
    // mode must parse it, not leave it as a stringified blob.
    assert!(
        result["body"].is_object(),
        "compact mode must parse body as JSON, got: {}",
        result["body"]
    );
    assert!(result["body"]["body"].is_string()); // inner echo "body" field
    assert!(result["body"]["uri"].as_str().unwrap().contains("/echo"));
}
