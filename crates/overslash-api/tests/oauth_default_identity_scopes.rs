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

mod common;

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
