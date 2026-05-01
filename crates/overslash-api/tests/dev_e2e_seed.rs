//! Integration tests for the dev-only `/auth/dev/seed-e2e-idps` endpoint.
//!
//! Mirrors the gating + idempotency tests already in place for `dev_token`.

mod common;

use serde_json::{Value, json};

fn seed_payload(provider_url: &str) -> Value {
    json!({
        "providers": [
            {
                "key": "auth0_e2e",
                "display_name": "Auth0 (e2e)",
                "authorization_endpoint": format!("{provider_url}/authorize"),
                "token_endpoint": format!("{provider_url}/oauth/token"),
                "userinfo_endpoint": format!("{provider_url}/userinfo"),
                "issuer_url": provider_url,
            }
        ],
        "orgs": [
            {
                "slug": "org-a-e2e",
                "name": "Org A (Auth0)",
                "provider_key": "auth0_e2e",
                "client_id": "auth0-e2e-client-id",
                "client_secret": "auth0-e2e-client-secret",
                "allowed_email_domains": ["orga.example"],
            }
        ],
    })
}

#[tokio::test]
async fn seed_returns_404_when_dev_auth_disabled() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .post(format!("{base}/auth/dev/seed-e2e-idps"))
        .json(&seed_payload("http://127.0.0.1:1/auth0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn seed_creates_provider_org_and_idp_config() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let resp = client
        .post(format!("{base}/auth/dev/seed-e2e-idps"))
        .json(&seed_payload("http://127.0.0.1:1/auth0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["providers"][0]["key"], "auth0_e2e");
    assert_eq!(body["orgs"][0]["slug"], "org-a-e2e");
    assert_eq!(body["orgs"][0]["provider_key"], "auth0_e2e");
    let first_idp_config_id = body["orgs"][0]["idp_config_id"]
        .as_str()
        .unwrap()
        .to_string();
    let first_org_id = body["orgs"][0]["org_id"].as_str().unwrap().to_string();

    // /auth/providers?org=org-a-e2e must report the freshly seeded provider
    // — proves the provider row, the org row, and the wiring all landed.
    let providers: Value = client
        .get(format!("{base}/auth/providers?org=org-a-e2e"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(providers["scope"], "org");
    let keys: Vec<String> = providers["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["key"].as_str().unwrap().to_string())
        .collect();
    assert!(keys.contains(&"auth0_e2e".to_string()));

    // Re-running the seed must reuse the same org + idp_config (upsert path),
    // not create duplicates that would tip the unique constraint over.
    let resp2 = client
        .post(format!("{base}/auth/dev/seed-e2e-idps"))
        .json(&seed_payload("http://127.0.0.1:1/auth0"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp2.status(), 200);
    let body2: Value = resp2.json().await.unwrap();
    assert_eq!(body2["orgs"][0]["org_id"].as_str().unwrap(), first_org_id);
    assert_eq!(
        body2["orgs"][0]["idp_config_id"].as_str().unwrap(),
        first_idp_config_id
    );
}
