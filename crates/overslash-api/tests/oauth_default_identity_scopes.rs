//! Provider-declared identity scopes are merged into every OAuth flow and
//! exposed on `GET /v1/oauth-providers`.
//!
//! The OAuth callback needs `openid email profile` (or the provider's
//! equivalent) to resolve `account_email` from the userinfo endpoint —
//! otherwise the dashboard renders the connection as `—`. Migration 076
//! declares the per-provider set on the `oauth_providers` row and the
//! kernel unions it into `oauth_connection_flows.scopes` so this holds
//! regardless of what the caller (REST / MCP / Create Service wizard) passes.

#![allow(clippy::disallowed_methods)]

use crate::common;

use serde_json::{Value, json};

#[tokio::test]
async fn initiate_merges_provider_default_identity_scopes_onto_flow_row() {
    let pool = common::test_pool().await;
    // SAFETY: test-only, before the server boots. Mirrors the credential
    // setup used by `oauth_x.rs` and the rest of the integration suite.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_ID", "google_test_client");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_SECRET", "google_test_secret");
    }

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_org_id, _ident_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;

    let only_calendar = ["https://www.googleapis.com/auth/calendar".to_string()];
    let resp: Value = client
        .post(format!("{base}/v1/connections"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "provider": "google",
            "scopes": only_calendar,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let flow_id = resp["state"].as_str().expect("state on response");
    let flow = overslash_db::repos::oauth_connection_flow::get_by_id(&pool, flow_id)
        .await
        .unwrap()
        .expect("flow row should exist");

    // The caller asked for `auth/calendar` only — the kernel must have
    // unioned in google's identity scopes from the provider row so the
    // callback's `fetch_account_email` can succeed.
    let scopes: std::collections::BTreeSet<&str> = flow.scopes.iter().map(String::as_str).collect();
    for required in [
        "openid",
        "email",
        "profile",
        "https://www.googleapis.com/auth/calendar",
    ] {
        assert!(
            scopes.contains(required),
            "flow scopes missing {required}: {scopes:?}"
        );
    }
}

#[tokio::test]
async fn upgrade_scopes_response_includes_provider_identity_scopes() {
    use overslash_core::crypto;

    let pool = common::test_pool().await;
    // SAFETY: test-only env wiring, before the server boots.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_ID", "g_upgrade_client");
        std::env::set_var("OAUTH_GOOGLE_CLIENT_SECRET", "g_upgrade_secret");
    }

    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, _ident_id, api_key, _) = common::bootstrap_org_identity(&base, &client).await;
    // Connections live at the owner identity (D22/D23); the calling agent shares
    // and may upgrade its owner's connection.
    let owner_id = common::owner_user_id(&pool, org_id).await;

    // Seed a google connection that's missing the identity scopes entirely —
    // mirrors the bad state existing emailless rows are in. The upgrade
    // handler must surface the identity scopes back so the UI's
    // `requested_scopes` matches what the OAuth popup will actually request.
    let enc_key = crypto::Keyring::test();
    let access = crypto::encrypt(&enc_key, b"mock_access_token").unwrap();
    let conn_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO connections (org_id, identity_id, provider_key,
             encrypted_access_token, scopes, account_email, is_default)
         VALUES ($1, $2, 'google', $3,
                 ARRAY['https://www.googleapis.com/auth/calendar']::text[],
                 NULL, true)
         RETURNING id",
    )
    .bind(org_id)
    .bind(owner_id)
    .bind(&access)
    .fetch_one(&pool)
    .await
    .unwrap();

    let resp: Value = client
        .post(format!("{base}/v1/connections/{conn_id}/upgrade_scopes"))
        .header("Authorization", format!("Bearer {api_key}"))
        .json(&json!({
            "scopes": ["https://www.googleapis.com/auth/drive.readonly"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let requested: std::collections::BTreeSet<&str> = resp["requested_scopes"]
        .as_array()
        .expect("requested_scopes on response")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for required in [
        "openid",
        "email",
        "profile",
        "https://www.googleapis.com/auth/calendar",
        "https://www.googleapis.com/auth/drive.readonly",
    ] {
        assert!(
            requested.contains(required),
            "requested_scopes missing {required}: {requested:?}"
        );
    }
}

#[tokio::test]
async fn oauth_providers_route_exposes_default_identity_scopes() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (api_addr, client, _guard) = common::start_api_shared(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_user, _ident_id, agent_key) =
        common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    let list: Vec<Value> = client
        .get(format!("{base}/v1/oauth-providers"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Expected identity-scope sets per provider — these mirror the seed in
    // migration 076 and the dashboard's rendered chips.
    let want: &[(&str, &[&str])] = &[
        ("google", &["openid", "email", "profile"]),
        ("microsoft", &["openid", "email", "profile"]),
        ("github", &["read:user", "user:email"]),
        ("slack", &["users:read", "users:read.email"]),
        ("spotify", &["user-read-email", "user-read-private"]),
        // X's userinfo endpoint requires users.read and the authorize
        // endpoint rejects empty scope outright.
        ("x", &["users.read"]),
        // Eventbrite doesn't enforce scopes on userinfo, but a token
        // with none can't do anything else — preserve the old dashboard
        // default of event_read.
        ("eventbrite", &["event_read"]),
    ];
    for (key, expected) in want {
        let row = list
            .iter()
            .find(|r| r["key"].as_str() == Some(key))
            .unwrap_or_else(|| panic!("provider {key} missing from response"));
        let got: Vec<&str> = row["default_identity_scopes"]
            .as_array()
            .unwrap_or_else(|| panic!("default_identity_scopes missing on {key}"))
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        for s in *expected {
            assert!(
                got.contains(s),
                "provider {key} missing identity scope {s}: {got:?}"
            );
        }
    }
}

/// `GET /v1/oauth-providers/{key}` returns the full OAuth metadata a
/// white-label partner needs to run the authorize + code-exchange dance
/// itself (token-vault model). Read-only catalog data — no secrets.
#[tokio::test]
async fn oauth_provider_detail_exposes_full_metadata() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (api_addr, client, _guard) = common::start_api_shared(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_user, _ident_id, agent_key) =
        common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    let resp = client
        .get(format!("{base}/v1/oauth-providers/google"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let p: Value = resp.json().await.unwrap();

    assert_eq!(p["key"].as_str(), Some("google"));
    assert!(
        !p["display_name"].as_str().unwrap_or("").is_empty(),
        "display_name should be populated"
    );
    // Endpoints the partner posts the authorize/exchange requests to.
    assert!(
        p["authorization_endpoint"]
            .as_str()
            .unwrap_or("")
            .starts_with("https://"),
        "authorization_endpoint should be an https URL: {p:?}"
    );
    assert!(
        p["token_endpoint"]
            .as_str()
            .unwrap_or("")
            .starts_with("https://"),
        "token_endpoint should be an https URL: {p:?}"
    );
    // Flags and method are always present (non-optional in the schema).
    assert!(p["supports_pkce"].is_boolean(), "supports_pkce missing");
    assert!(
        p["supports_refresh"].is_boolean(),
        "supports_refresh missing"
    );
    assert!(
        p["token_auth_method"].is_string(),
        "token_auth_method missing"
    );
    // Identity scopes mirror the list endpoint so the partner can union them
    // into its authorize URL.
    let scopes: Vec<&str> = p["default_identity_scopes"]
        .as_array()
        .expect("default_identity_scopes missing")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    for s in ["openid", "email", "profile"] {
        assert!(
            scopes.contains(&s),
            "missing identity scope {s}: {scopes:?}"
        );
    }

    // Secrets must never be surfaced through the catalog endpoint.
    assert!(p.get("client_id").is_none(), "client_id leaked");
    assert!(p.get("client_secret").is_none(), "client_secret leaked");
}

/// Unknown provider key → 404, not a 500 or empty body.
#[tokio::test]
async fn oauth_provider_detail_unknown_key_404() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (api_addr, client, _guard) = common::start_api_shared(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_user, _ident_id, agent_key) =
        common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    let resp = client
        .get(format!("{base}/v1/oauth-providers/does-not-exist"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}
