//! Identity path segments and query args accept a user's email wherever they
//! accept the identity UUID (`IdentityRef`), and resolve it inside the
//! caller's org only.

use crate::common;
use crate::common::{auth, start_api};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

/// Create a user `Ada Lovelace <ada@example.com>` with an agent under it.
/// Returns `(base, client, admin_key, user_id)`.
async fn setup() -> (String, Client, String, Uuid) {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = start_api(pool).await;
    let base = format!("http://{addr}");
    let admin_key = fx.org_key.clone();

    let user: Value = client
        .post(format!("{base}/v1/identities"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"name": "Ada Lovelace", "kind": "user", "email": "ada@example.com"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = user["id"].as_str().unwrap().parse().unwrap();

    let resp = client
        .post(format!("{base}/v1/identities"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"name": "henry", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    (base, client, admin_key, user_id)
}

async fn get(client: &Client, key: &str, url: String) -> (StatusCode, Value) {
    let resp = client
        .get(url)
        .header(auth(key).0, auth(key).1)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

#[tokio::test]
async fn path_segment_accepts_email_like_uuid() {
    let (base, client, key, user_id) = setup().await;

    let (s, by_id) = get(
        &client,
        &key,
        format!("{base}/v1/identities/{user_id}/children"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{by_id}");
    // Case-insensitive, like every other email lookup.
    let (s, by_email) = get(
        &client,
        &key,
        format!("{base}/v1/identities/Ada@Example.com/children"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{by_email}");
    assert_eq!(by_id, by_email);
    assert_eq!(by_email.as_array().unwrap().len(), 1);
    assert_eq!(by_email[0]["name"], "henry");

    let (s, chain) = get(
        &client,
        &key,
        format!("{base}/v1/identities/ada@example.com/chain"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{chain}");
    assert_eq!(chain[0]["id"], json!(user_id));
}

#[tokio::test]
async fn unknown_email_is_404_and_a_display_name_is_400() {
    let (base, client, key, _user_id) = setup().await;

    let (s, _) = get(
        &client,
        &key,
        format!("{base}/v1/identities/nobody@example.com/chain"),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // A display name is neither form — refused at the boundary, never looked up.
    let (s, _) = get(
        &client,
        &key,
        format!("{base}/v1/identities/Ada%20Lovelace/chain"),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn query_args_accept_email() {
    let (base, client, key, user_id) = setup().await;

    for path in ["/v1/permissions", "/v1/approvals", "/v1/audit"] {
        let (s, by_id) = get(&client, &key, format!("{base}{path}?identity_id={user_id}")).await;
        assert_eq!(s, StatusCode::OK, "{path} by id: {by_id}");
        let (s, by_email) = get(
            &client,
            &key,
            format!("{base}{path}?identity_id=ada%40example.com"),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{path} by email: {by_email}");
        assert_eq!(by_id, by_email, "{path}");
    }

    let (s, body) = get(
        &client,
        &key,
        format!("{base}/v1/permissions?identity_id=nobody%40example.com"),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn secrets_owner_accepts_email() {
    let (base, client, key, user_id) = setup().await;

    let (s, by_id) = get(&client, &key, format!("{base}/v1/secrets?owner={user_id}")).await;
    assert_eq!(s, StatusCode::OK, "{by_id}");
    let (s, by_email) = get(
        &client,
        &key,
        format!("{base}/v1/secrets?owner=ada%40example.com"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{by_email}");
    assert_eq!(by_id, by_email);

    // An unknown email is out of reach exactly like an unknown UUID: the
    // list answers the same empty shape, so neither probes membership.
    let (s, unknown_id) = get(
        &client,
        &key,
        format!("{base}/v1/secrets?owner={}", Uuid::new_v4()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, unknown_email) = get(
        &client,
        &key,
        format!("{base}/v1/secrets?owner=nobody%40example.com"),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(unknown_id, unknown_email);
}
