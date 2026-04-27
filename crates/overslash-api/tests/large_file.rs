//! Integration tests for large file handling: size limits and streaming proxy.

mod common;

use serde_json::json;

#[tokio::test]
async fn test_response_too_large() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    // Use a small body limit (1 KB) so we can test without allocating huge buffers
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1024).await;
    let base = format!("http://{api_addr}");

    let (_org_id, _ident_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    // Request a 10 KB file — should exceed 1 KB limit
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=10240"),
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        502,
        "should return 502 for oversized response"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "response_too_large");
    assert_eq!(body["limit_bytes"], 1024);
    assert!(body["hint"].as_str().unwrap().contains("prefer_stream"));
}

#[tokio::test]
async fn test_prefer_stream_large_file() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    // Use a small body limit — streaming should bypass it
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1024).await;
    let base = format!("http://{api_addr}");

    let (_org_id, _ident_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    // Request 100 KB with prefer_stream — should succeed even though limit is 1 KB
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=102400"),
            "prefer_stream": true,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );

    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), 102400, "should receive all 100 KB");
    assert!(bytes.iter().all(|&b| b == 0xAB), "all bytes should be 0xAB");
}

#[tokio::test]
async fn test_prefer_stream_with_auth() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1024).await;
    let base = format!("http://{api_addr}");

    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Create a secret
    client
        .put(format!("{base}/v1/secrets/my_token"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"value": "super-secret-token"}))
        .send()
        .await
        .unwrap();

    // Create permission rule
    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "identity_id": ident_id,
            "action_pattern": "http:**",
            "effect": "allow",
        }))
        .send()
        .await
        .unwrap();

    // Execute with streaming and secret injection
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=2048"),
            "prefer_stream": true,
            "secrets": [{
                "name": "my_token",
                "inject_as": "header",
                "header_name": "X-Token",
                "prefix": "Bearer "
            }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), 2048);
    // The secret should NOT appear in the response body or headers to the caller
    let resp_text = String::from_utf8_lossy(&bytes);
    assert!(
        !resp_text.contains("super-secret-token"),
        "secret should not leak in streamed response"
    );
}

#[tokio::test]
async fn test_google_drive_redirect_stream() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1024).await;
    let base = format!("http://{api_addr}");

    let (_org_id, ident_id, api_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Create a secret for the Authorization header
    client
        .put(format!("{base}/v1/secrets/drive_token"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({"value": "fake-oauth-token"}))
        .send()
        .await
        .unwrap();

    // Create permission rule
    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "identity_id": ident_id,
            "action_pattern": "http:**",
            "effect": "allow",
        }))
        .send()
        .await
        .unwrap();

    // Simulate Google Drive download: hits /drive/files/download which 302s to /drive/files/content
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "method": "GET",
            "url": format!("http://{mock_addr}/drive/files/download?size=8192"),
            "prefer_stream": true,
            "secrets": [{
                "name": "drive_token",
                "inject_as": "header",
                "header_name": "Authorization",
                "prefix": "Bearer "
            }]
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/pdf"
    );

    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), 8192, "should receive all bytes after redirect");
    assert!(
        bytes.iter().all(|&b| b == 0xCD),
        "all bytes should be 0xCD (from redirect target)"
    );
}
