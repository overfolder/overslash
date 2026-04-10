//! Integration tests for the standalone "Provide Secret" flow.
//!
//! Mint via authenticated `POST /v1/secrets/requests`, then exercise the
//! public `GET`/`POST /public/secrets/provide/{req_id}` endpoints.

mod common;

use serde_json::{Value, json};

async fn mint(base: &str, client: &reqwest::Client, api_key: &str, name: &str) -> Value {
    client
        .post(format!("{base}/v1/secrets/requests"))
        .header(common::auth(api_key).0, common::auth(api_key).1)
        .json(&json!({"secret_name": name, "ttl_seconds": 3600}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Build the public provide URL with the token as a query param.
fn provide_url(base: &str, req_id: &str, token: &str) -> String {
    format!(
        "{base}/public/secrets/provide/{req_id}?token={token}",
        token = urlencoding::encode(token)
    )
}

#[tokio::test]
async fn happy_path_mint_get_submit_stored() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org, _ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let req = mint(&base, &client, &agent_key, "openai_api_key").await;
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();

    // GET metadata (no auth)
    let resp = client
        .get(provide_url(&base, req_id, token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let meta: Value = resp.json().await.unwrap();
    assert_eq!(meta["secret_name"], "openai_api_key");
    assert!(meta["identity_label"].as_str().is_some());

    // Submit value
    let resp = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .json(&json!({"token": token, "value": "sk-real-value"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["ok"], true);
    assert_eq!(body["version"], 1);

    // Confirm secret exists by writing a second version (PUT uses WriteAcl,
    // which accepts bearer tokens, unlike GET which is dashboard-only).
    let resp = client
        .put(format!("{base}/v1/secrets/openai_api_key"))
        .header(common::auth(&agent_key).0, common::auth(&agent_key).1)
        .json(&json!({"value": "sk-updated-value"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let got: Value = resp.json().await.unwrap();
    assert_eq!(got["name"], "openai_api_key");
    assert_eq!(got["version"], 2);
}

#[tokio::test]
async fn single_use_second_submit_rejected() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org, _ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let req = mint(&base, &client, &agent_key, "k1").await;
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();

    let r1 = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .json(&json!({"token": token, "value": "v1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r1.status(), 200);

    let r2 = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .json(&json!({"token": token, "value": "v2"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 410);
}

#[tokio::test]
async fn tampered_token_rejected() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org, _ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let req = mint(&base, &client, &agent_key, "k2").await;
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();
    // Flip a character in the signature segment.
    let mut bad = token.to_string();
    let last = bad.pop().unwrap();
    bad.push(if last == 'a' { 'b' } else { 'a' });

    let r = client
        .get(provide_url(&base, req_id, &bad))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn mismatched_req_id_rejected() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org, _ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let a = mint(&base, &client, &agent_key, "ka").await;
    let b = mint(&base, &client, &agent_key, "kb").await;
    // Use a's request ID but b's token — should be rejected.
    let r = client
        .get(provide_url(
            &base,
            a["id"].as_str().unwrap(),
            b["token"].as_str().unwrap(),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn empty_value_rejected() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org, _ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let req = mint(&base, &client, &agent_key, "k3").await;
    let r = client
        .post(format!(
            "{base}/public/secrets/provide/{}",
            req["id"].as_str().unwrap()
        ))
        .json(&json!({"token": req["token"], "value": ""}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}
