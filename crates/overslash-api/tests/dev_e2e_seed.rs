//! Integration tests for the dev-only e2e endpoints:
//! `/auth/dev/seed-e2e-idps` and the per-run org isolation pair
//! (`/auth/dev/token?org=…` + `DELETE /auth/dev/orgs/{slug}`, D34).
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

// ── Per-run org isolation (D34) ──────────────────────────────────────────

/// The destructive endpoint is behind the same gate as everything else here.
/// Without this, a `DEV_AUTH` regression would expose an unauthenticated
/// "delete any org by slug" route to the internet.
#[tokio::test]
async fn delete_dev_org_returns_404_when_dev_auth_disabled() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");

    let resp = client
        .delete(format!("{base}/auth/dev/orgs/whatever"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// Two scoped logins must land in two different orgs with two different
/// identities. `find_user_identity_by_email` is a *global* lookup, so if the
/// profile emails weren't derived per-org the second login would silently
/// resolve the first org's identity and cross the tenant boundary.
#[tokio::test]
async fn scoped_dev_token_mints_separate_orgs_and_identities() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    let me = |cookie: String| {
        let client = client.clone();
        let base = base.clone();
        async move {
            client
                .get(format!("{base}/auth/me/identity"))
                .header("Cookie", cookie)
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };

    let a = me(dev_session(&client, &base, Some("e2e-alpha")).await).await;
    let b = me(dev_session(&client, &base, Some("e2e-beta")).await).await;
    let shared = me(dev_session(&client, &base, None).await).await;

    assert_ne!(a["org_id"], b["org_id"], "scoped orgs must not be shared");
    assert_ne!(a["identity_id"], b["identity_id"]);
    assert_eq!(a["email"], json!("dev+e2e-alpha@overslash.local"));
    assert_eq!(b["email"], json!("dev+e2e-beta@overslash.local"));

    // The unscoped default is untouched — every existing spec depends on it.
    assert_eq!(shared["email"], json!("dev@overslash.local"));
    assert_ne!(shared["org_id"], a["org_id"]);

    // Re-entering the same slug resolves the same org rather than making another.
    let a_again = me(dev_session(&client, &base, Some("e2e-alpha")).await).await;
    assert_eq!(a_again["org_id"], a["org_id"]);
    assert_eq!(a_again["identity_id"], a["identity_id"]);
}

#[tokio::test]
async fn scoped_dev_token_rejects_invalid_and_reserved_slugs() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool).await;

    for bad in [
        "Bad_Slug",  // uppercase + underscore
        "-leading",  // leading hyphen
        "trailing-", // trailing hyphen
        "x",         // too short
        "dev-org",   // reserved: the shared org
    ] {
        let resp = client
            .get(format!("{base}/auth/dev/token?profile=admin&org={bad}"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::BAD_REQUEST,
            "slug {bad:?} should be rejected"
        );
    }
}

/// Teardown drops the org *and its contents*, and is safe to call twice —
/// a spec's `finally` must not fail because an earlier teardown already ran.
#[tokio::test]
async fn delete_dev_org_cascades_and_is_idempotent() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;

    let cookie = dev_session(&client, &base, Some("e2e-teardown")).await;
    let me: Value = client
        .get(format!("{base}/auth/me/identity"))
        .header("Cookie", &cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id = uuid::Uuid::parse_str(me["org_id"].as_str().unwrap()).unwrap();

    // Put something org-scoped in it so the cascade has work to do.
    let secret = client
        .put(format!("{base}/v1/secrets/teardown_probe"))
        .header("Cookie", &cookie)
        .json(&json!({ "value": "s3cret" }))
        .send()
        .await
        .unwrap();
    assert!(
        secret.status().is_success(),
        "seed secret: {}",
        secret.status()
    );

    let first: Value = client
        .delete(format!("{base}/auth/dev/orgs/e2e-teardown"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(first["deleted"], json!(true));

    let orgs_left: i64 = sqlx::query_scalar!("SELECT count(*) FROM orgs WHERE id = $1", org_id)
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(orgs_left, 0, "org row survived the delete");

    let secrets_left: i64 =
        sqlx::query_scalar!("SELECT count(*) FROM secrets WHERE org_id = $1", org_id)
            .fetch_one(&pool)
            .await
            .unwrap()
            .unwrap_or(0);
    assert_eq!(secrets_left, 0, "org-scoped secrets were not cascaded away");

    let second: Value = client
        .delete(format!("{base}/auth/dev/orgs/e2e-teardown"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        second["deleted"],
        json!(false),
        "second delete must be a no-op"
    );
}

/// The shared org is never deletable, so one spec's teardown can't detonate
/// every screenshot script and every other spec in the suite.
#[tokio::test]
async fn delete_dev_org_refuses_the_shared_org() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_dev_auth(pool.clone()).await;

    // Materialise dev-org first so this isn't passing on a missing row.
    let _ = dev_session(&client, &base, None).await;

    let resp = client
        .delete(format!("{base}/auth/dev/orgs/dev-org"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    let still_there: i64 = sqlx::query_scalar!("SELECT count(*) FROM orgs WHERE slug = 'dev-org'")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(still_there, 1, "dev-org must survive");
}

/// Sign in via `/auth/dev/token`, returning the `oss_session` cookie header.
async fn dev_session(client: &reqwest::Client, base: &str, org: Option<&str>) -> String {
    let url = match org {
        Some(slug) => format!("{base}/auth/dev/token?profile=admin&org={slug}"),
        None => format!("{base}/auth/dev/token?profile=admin"),
    };
    let resp = client.get(url).send().await.unwrap();
    assert!(resp.status().is_success(), "dev token: {}", resp.status());
    let raw = resp
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("oss_session="))
        .expect("no oss_session cookie");
    raw.split(';').next().unwrap().to_string()
}
