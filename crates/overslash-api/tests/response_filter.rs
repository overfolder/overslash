//! Integration tests for the server-side response filter (jq via jaq).
//! See `services::response_filter`.

mod common;

use serde_json::json;

#[tokio::test]
async fn test_filter_jq_happy_path() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1_000_000).await;
    let base = format!("http://{api_addr}");

    let (_org_id, _ident_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    // Mock /echo returns {"headers":..., "body": "<request body string>", "uri": "/echo"}.
    // We POST a JSON envelope, then ask jq to parse the inner body and
    // stream its items[].id — the same shape an agent would use against
    // Google Calendar's events.list.
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "method": "POST",
            "url": format!("http://{mock_addr}/echo"),
            "headers": {"content-type": "application/json"},
            "body": r#"{"items":[{"id":1,"name":"a"},{"id":2,"name":"b"},{"id":3,"name":"c"}]}"#,
            "filter": {
                "lang": "jq",
                "expr": ".body | fromjson | .items[] | .id",
            },
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");

    let result = &body["result"];
    let filtered = &result["filtered_body"];
    assert_eq!(filtered["status"], "ok");
    assert_eq!(filtered["lang"], "jq");
    assert_eq!(filtered["values"], json!([1, 2, 3]));

    let original_bytes = filtered["original_bytes"].as_u64().unwrap();
    let filtered_bytes = filtered["filtered_bytes"].as_u64().unwrap();
    assert!(
        filtered_bytes < original_bytes,
        "filter must shrink output ({filtered_bytes} >= {original_bytes})"
    );

    // Original body is preserved on `result.body` so callers can fall back.
    // The echo response wraps our POST body inside a JSON `body` field, so the
    // raw bytes contain the *escaped* form `\"items\"` rather than `"items"`.
    let raw_body = result["body"].as_str().expect("body present");
    assert!(
        raw_body.contains("items"),
        "original body preserved, got: {raw_body}"
    );
}

#[tokio::test]
async fn test_filter_jq_syntax_error_returns_400() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1_000_000).await;
    let base = format!("http://{api_addr}");

    let (_org_id, _ident_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            // Unclosed bracket — jq syntax error.
            "filter": {"lang": "jq", "expr": ".items["},
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "filter_syntax_error");
    assert!(!body["detail"].as_str().unwrap_or("").is_empty());
}

#[tokio::test]
async fn test_filter_body_not_json_returns_200_with_envelope() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1_000_000).await;
    let base = format!("http://{api_addr}");

    let (_org_id, _ident_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    // /large-file returns N bytes of 0xAB with content-type
    // application/octet-stream. After utf8-lossy decoding, this is N
    // U+FFFD characters — never valid JSON.
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=64"),
            "filter": {"lang": "jq", "expr": "."},
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");

    let filtered = &body["result"]["filtered_body"];
    assert_eq!(filtered["status"], "error");
    assert_eq!(filtered["kind"], "body_not_json");
    assert!(filtered["original_bytes"].as_u64().unwrap() > 0);
    // The original body is still returned so the caller can debug.
    assert!(body["result"]["body"].is_string());
}

#[tokio::test]
async fn test_filter_runtime_error_returns_envelope() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1_000_000).await;
    let base = format!("http://{api_addr}");

    let (_org_id, _ident_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    // POST /echo with a JSON body. The echo response has `.body` (the
    // string `"{\"a\":1}"`). Calling `tonumber` on a non-numeric string
    // errors at runtime in jq.
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "method": "POST",
            "url": format!("http://{mock_addr}/echo"),
            "headers": {"content-type": "application/json"},
            "body": r#"{"a":1}"#,
            "filter": {"lang": "jq", "expr": ".body | tonumber"},
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let filtered = &body["result"]["filtered_body"];
    assert_eq!(filtered["status"], "error");
    assert_eq!(filtered["kind"], "runtime_error");
}

#[tokio::test]
async fn test_filter_rejected_with_prefer_stream() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1_000_000).await;
    let base = format!("http://{api_addr}");

    let (_org_id, _ident_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/echo"),
            "prefer_stream": true,
            "filter": {"lang": "jq", "expr": "."},
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    let msg = body["error"].as_str().unwrap_or("");
    assert!(
        msg.contains("filter") && msg.contains("prefer_stream"),
        "error mentions both fields, got: {msg}"
    );
}

#[tokio::test]
async fn test_filter_does_not_rescue_oversized_upstream() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    // 1 KB body limit, request 10 KB upstream.
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1024).await;
    let base = format!("http://{api_addr}");

    let (_org_id, _ident_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=10240"),
            // Even with a filter that would shrink the result drastically,
            // the upstream size cap fires first — the filter never runs.
            "filter": {"lang": "jq", "expr": ". | length"},
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 502);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "response_too_large");
    assert_eq!(body["limit_bytes"], 1024);
}
