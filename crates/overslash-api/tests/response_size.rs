//! `detail.size` on execution audit rows, and the `action.stream_completed`
//! row that records the bytes a streamed transfer actually carried. These are
//! what the buffering caps get tuned against, so each test pins the field an
//! analysis query reads.

use crate::common;

use serde_json::{Value, json};

async fn audit_rows(client: &reqwest::Client, base: &str, key: &str, action: &str) -> Vec<Value> {
    client
        .get(format!("{base}/v1/audit?action={action}"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// `action.stream_completed` is written from a spawned task once the body
/// finishes, so it can trail the response the client already holds.
async fn wait_for_completion(client: &reqwest::Client, base: &str, key: &str) -> Value {
    for _ in 0..50 {
        let rows = audit_rows(client, base, key, "action.stream_completed").await;
        if let Some(row) = rows.into_iter().next() {
            return row;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("no action.stream_completed row after 5s");
}

async fn call(client: &reqwest::Client, base: &str, key: &str, body: Value) -> reqwest::Response {
    client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn buffered_call_records_its_size() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 4096).await;
    let base = format!("http://{api_addr}");
    let (_org, _ident, api_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let resp = call(
        &client,
        &base,
        &api_key,
        json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=2048"),
        }),
    )
    .await;
    assert_eq!(resp.status(), 200);

    let rows = audit_rows(&client, &base, &admin_key, "action.executed").await;
    let size = &rows[0]["detail"]["size"];
    assert_eq!(
        *size,
        json!({"bytes": 2048, "content_length": 2048, "read": "complete", "limit_bytes": 4096}),
        "{rows:?}"
    );
}

#[tokio::test]
async fn oversized_with_declared_length_records_the_true_size() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1024).await;
    let base = format!("http://{api_addr}");
    let (_org, _ident, api_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let resp = call(
        &client,
        &base,
        &api_key,
        json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=10240"),
        }),
    )
    .await;
    assert_eq!(resp.status(), 502);
    let body: Value = resp.json().await.unwrap();

    let rows = audit_rows(&client, &base, &admin_key, "action.executed").await;
    let detail = &rows[0]["detail"];
    assert_eq!(detail["error"]["kind"], "response_too_large", "{detail}");
    // The declared length refused the body before a byte was read: `bytes`
    // is 0, `content_length` is the real size, and `read` says we stopped.
    assert_eq!(
        detail["size"],
        json!({"bytes": 0, "content_length": 10240, "read": "aborted_at_cap", "limit_bytes": 1024}),
        "{detail}"
    );

    // Redeeming the minted URL measures what actually flowed.
    let url = body["download_url"].as_str().unwrap();
    let fetched = client.get(url).send().await.unwrap();
    assert_eq!(fetched.bytes().await.unwrap().len(), 10240);

    let done = wait_for_completion(&client, &base, &admin_key).await;
    assert_eq!(done["detail"]["via"], "download", "{done}");
    assert_eq!(done["detail"]["bytes_streamed"], 10240, "{done}");
    assert_eq!(done["detail"]["completed"], true, "{done}");
    assert!(
        done["resource_id"].is_string(),
        "token id rides resource_id: {done}"
    );
}

#[tokio::test]
async fn oversized_chunked_body_records_a_lower_bound() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1024).await;
    let base = format!("http://{api_addr}");
    let (_org, _ident, api_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // 300 × "chunk" = 1500 bytes, sent without a Content-Length.
    let resp = call(
        &client,
        &base,
        &api_key,
        json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/slow-stream?chunks=300&gap_ms=0"),
        }),
    )
    .await;
    assert_eq!(resp.status(), 502);

    let rows = audit_rows(&client, &base, &admin_key, "action.executed").await;
    let size = &rows[0]["detail"]["size"];
    assert_eq!(size["read"], "aborted_at_cap", "{size}");
    assert_eq!(size["content_length"], Value::Null, "{size}");
    let bytes = size["bytes"].as_u64().unwrap();
    assert!(
        bytes > 1024 && bytes <= 1500,
        "bytes is what was read before stopping — over the cap, under the true size: {size}"
    );
}

#[tokio::test]
async fn prefer_stream_records_bytes_on_completion() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1024).await;
    let base = format!("http://{api_addr}");
    let (_org, _ident, api_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    let resp = call(
        &client,
        &base,
        &api_key,
        json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/large-file?size=102400"),
            "prefer_stream": true,
        }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().len(), 102400);

    let rows = audit_rows(&client, &base, &admin_key, "action.streamed").await;
    let size = &rows[0]["detail"]["size"];
    assert_eq!(
        *size,
        json!({"bytes": null, "content_length": 102400, "read": "streamed", "limit_bytes": null}),
        "{rows:?}"
    );

    let done = wait_for_completion(&client, &base, &admin_key).await;
    assert_eq!(done["detail"]["via"], "prefer_stream", "{done}");
    assert_eq!(done["detail"]["bytes_streamed"], 102400, "{done}");
    assert_eq!(done["detail"]["completed"], true, "{done}");
}

#[tokio::test]
async fn prefer_stream_without_content_length_completes() {
    // A chunked body runs the meter to the stream's end, where hyper may poll
    // once more. The meter must stay fused there rather than re-poll the
    // underlying `unfold`, which panics and drops the connection.
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let (api_addr, client) = common::start_api_with_body_limit(pool.clone(), 1024).await;
    let base = format!("http://{api_addr}");
    let (_org, _ident, api_key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // 5 × "chunk", no Content-Length.
    let resp = call(
        &client,
        &base,
        &api_key,
        json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock_addr}/slow-stream?chunks=5&gap_ms=0"),
            "prefer_stream": true,
        }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.bytes().await.unwrap().as_ref(),
        b"chunkchunkchunkchunkchunk"
    );

    let done = wait_for_completion(&client, &base, &admin_key).await;
    assert_eq!(done["detail"]["bytes_streamed"], 25, "{done}");
    assert_eq!(done["detail"]["completed"], true, "{done}");
}
