mod common;

use serde_json::{Value, json};

#[tokio::test]
async fn webhook_delivery_list_empty() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_, _, key) = common::bootstrap_org_identity(&base, &client).await;

    // Create a webhook subscription
    let wh: Value = client
        .post(format!("{base}/v1/webhooks"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({"url": "https://example.com/hook", "events": ["approval.created"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let wh_id = wh["id"].as_str().unwrap();

    // List deliveries — should be empty
    let deliveries: Vec<Value> = client
        .get(format!("{base}/v1/webhooks/{wh_id}/deliveries"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(deliveries.is_empty());
}

#[tokio::test]
async fn webhook_delivery_list_requires_org_ownership() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    // Org A
    let (_, _, key_a) = common::bootstrap_org_identity(&base, &client).await;

    // Org B
    let (_, _, key_b) = common::bootstrap_org_identity(&base, &client).await;

    // Create webhook in org A
    let wh: Value = client
        .post(format!("{base}/v1/webhooks"))
        .header("Authorization", format!("Bearer {key_a}"))
        .json(&json!({"url": "https://example.com/hook", "events": ["action.executed"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let wh_id = wh["id"].as_str().unwrap();

    // Try to list deliveries with org B key — should 404
    let resp = client
        .get(format!("{base}/v1/webhooks/{wh_id}/deliveries"))
        .header("Authorization", format!("Bearer {key_b}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}
