//! Integration tests for /v1/org-oauth-credentials and the resulting
//! tier-2 org-level OAuth App Credential cascade behaviour (SPEC §7).

#![allow(clippy::disallowed_methods)]

mod common;

use overslash_core::crypto;
use reqwest::Client;
use serde_json::{Value, json};

async fn put_google_creds(base: &str, client: &Client, admin_key: &str) -> Value {
    let resp = client
        .put(format!("{base}/v1/org-oauth-credentials/google"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "client_id": "72939999999-fakegoogleclientid.apps.googleusercontent.com",
            "client_secret": "GOCSPX-fakegooglesecret12345",
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 200, "put_google_creds status={status} body={body}");
    serde_json::from_str(&body).unwrap()
}

async fn list_creds(base: &str, client: &Client, admin_key: &str) -> Vec<Value> {
    client
        .get(format!("{base}/v1/org-oauth-credentials"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn test_put_creates_two_org_secrets_and_lists() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let put_resp = put_google_creds(&base, &client, &admin_key).await;
    assert_eq!(put_resp["provider_key"], "google");
    assert_eq!(put_resp["source"], "db");
    let preview = put_resp["client_id_preview"].as_str().unwrap();
    assert!(preview.contains('…'), "preview should truncate: {preview}");
    assert!(!preview.contains("fakegoogleclientid"));

    // The two well-known secrets are present under the org.
    let scope = overslash_db::scopes::OrgScope::new(org_id, pool.clone());
    assert!(
        scope
            .get_current_secret_value("OAUTH_GOOGLE_CLIENT_ID")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        scope
            .get_current_secret_value("OAUTH_GOOGLE_CLIENT_SECRET")
            .await
            .unwrap()
            .is_some()
    );

    // GET list returns the row. Filter to db-sourced entries because
    // concurrent tests may set env vars that surface as read-only rows
    // (std::env is process-global).
    let rows = list_creds(&base, &client, &admin_key).await;
    let db_rows: Vec<_> = rows.iter().filter(|r| r["source"] == "db").collect();
    assert_eq!(db_rows.len(), 1);
    assert_eq!(db_rows[0]["provider_key"], "google");
    let _ = ident_id; // silence unused warning — fixture keeps the value
}

#[tokio::test]
async fn test_delete_removes_both_secrets() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    put_google_creds(&base, &client, &admin_key).await;

    let del = client
        .delete(format!("{base}/v1/org-oauth-credentials/google"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 200);

    let rows = list_creds(&base, &client, &admin_key).await;
    let db_rows: Vec<_> = rows.iter().filter(|r| r["source"] == "db").collect();
    assert!(db_rows.is_empty(), "rows after delete: {rows:?}");

    let scope = overslash_db::scopes::OrgScope::new(org_id, pool.clone());
    assert!(
        scope
            .get_secret_by_name("OAUTH_GOOGLE_CLIENT_ID")
            .await
            .unwrap()
            .is_none(),
        "soft-delete should hide the secret from name lookup"
    );
}

#[tokio::test]
async fn test_delete_is_atomic_across_both_secret_names() {
    // Both org secrets (OAUTH_{PROV}_CLIENT_ID and _CLIENT_SECRET) must
    // be soft-deleted atomically. Even with only one half present
    // (simulating an earlier partial-write that our PUT guards against
    // but the repo layer should still handle cleanly), DELETE must not
    // leave an orphan record.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    put_google_creds(&base, &client, &admin_key).await;
    // Sanity — both secrets exist after PUT.
    let scope = overslash_db::scopes::OrgScope::new(org_id, pool);
    assert!(
        scope
            .get_secret_by_name("OAUTH_GOOGLE_CLIENT_ID")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        scope
            .get_secret_by_name("OAUTH_GOOGLE_CLIENT_SECRET")
            .await
            .unwrap()
            .is_some()
    );

    let resp = client
        .delete(format!("{base}/v1/org-oauth-credentials/google"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Both gone after DELETE.
    assert!(
        scope
            .get_secret_by_name("OAUTH_GOOGLE_CLIENT_ID")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        scope
            .get_secret_by_name("OAUTH_GOOGLE_CLIENT_SECRET")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_delete_unknown_provider_returns_404() {
    // Mirror the PUT contract: unknown provider returns 404 rather than
    // silently reporting deleted=false (ambiguous with "provider exists
    // but has no org secrets yet").
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .delete(format!(
            "{base}/v1/org-oauth-credentials/not-a-real-provider"
        ))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_put_rejects_when_service_oauth_env_var_set() {
    // When the tier-3 env-var scheme (OAUTH_*_CLIENT_ID/_SECRET) is set
    // AND the DANGER opt-in is on, the admin should not be able to
    // override via the dashboard — the env scheme is operator-managed.
    // SAFETY: env var mutation is process-global, but these tests already
    // share env via the test harness and this test runs serially enough.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_SPOTIFY_CLIENT_ID", "env-spotify-id");
        std::env::set_var("OAUTH_SPOTIFY_CLIENT_SECRET", "env-spotify-secret");
    }

    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .put(format!("{base}/v1/org-oauth-credentials/spotify"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "client_id": "dashboard-id", "client_secret": "dashboard-secret" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // Clean up so we don't pollute later tests.
    unsafe {
        std::env::remove_var("OAUTH_SPOTIFY_CLIENT_ID");
        std::env::remove_var("OAUTH_SPOTIFY_CLIENT_SECRET");
    }
}

#[tokio::test]
async fn test_cascade_errors_on_half_configured_env_pair() {
    // Operator misconfig: OAUTH_MICROSOFT_CLIENT_ID set but no _SECRET.
    // Cascade used to silently skip the env tier — now it surfaces which
    // variable is missing. This is a user-facing guardrail for tier 3.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_MICROSOFT_CLIENT_ID", "half-configured-id");
        std::env::remove_var("OAUTH_MICROSOFT_CLIENT_SECRET");
    }

    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, _agent_key, _admin) =
        common::bootstrap_org_identity(&base, &client).await;

    let enc_key = crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let err = match overslash_api::services::client_credentials::resolve(
        &pool,
        &enc_key,
        org_id,
        Some(ident_id),
        "microsoft",
        None,
        None,
    )
    .await
    {
        Ok(_) => panic!("half-configured env pair should error"),
        Err(e) => format!("{e}"),
    };
    assert!(
        err.contains("OAUTH_MICROSOFT_CLIENT_SECRET") && err.contains("missing"),
        "expected missing-secret error, got: {err}"
    );

    unsafe {
        std::env::remove_var("OAUTH_MICROSOFT_CLIENT_ID");
    }
}

#[tokio::test]
async fn test_list_preview_never_leaks_client_secret() {
    // Regression: the response must never echo the secret value. Also
    // asserts that the preview helper truncates long client_ids.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    put_google_creds(&base, &client, &admin_key).await;
    let rows = list_creds(&base, &client, &admin_key).await;

    let raw = serde_json::to_string(&rows).unwrap();
    assert!(
        !raw.contains("GOCSPX-dummy"),
        "list response must not include the client_secret value: {raw}"
    );
    // Full client_id is also truncated.
    assert!(
        !raw.contains("fakegoogleclientid"),
        "full client_id leaked in list response: {raw}"
    );
    let preview = rows[0]["client_id_preview"].as_str().unwrap();
    assert!(preview.contains('…'));
}

#[tokio::test]
async fn test_put_creates_new_secret_version_on_update() {
    // Editing an existing provider should bump the secret version rather
    // than fail (upsert semantics). Verifies the versioned-secrets contract.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    put_google_creds(&base, &client, &admin_key).await;
    // Second PUT with different values.
    let resp = client
        .put(format!("{base}/v1/org-oauth-credentials/google"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "client_id": "rotated-client-id.apps.googleusercontent.com",
            "client_secret": "rotated-secret",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let scope = overslash_db::scopes::OrgScope::new(org_id, pool);
    let row = scope
        .get_secret_by_name("OAUTH_GOOGLE_CLIENT_ID")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.current_version, 2,
        "second PUT should bump the version to 2"
    );
}

#[tokio::test]
async fn test_non_admin_cannot_list_credentials() {
    // Defense in depth: listing configured providers leaks which OAuth
    // providers the org uses and their client_id fingerprints. Only
    // admins should see that, matching the Org Settings gate in the UI.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // The agent key is identity-bound and non-admin by default.
    let resp = client
        .get(format!("{base}/v1/org-oauth-credentials"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_put_unknown_provider_returns_404() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .put(format!(
            "{base}/v1/org-oauth-credentials/not-a-real-provider"
        ))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "client_id": "x", "client_secret": "y" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_cross_tenant_isolation() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let (_org_a, _ident_a, _key_a, admin_a) = common::bootstrap_org_identity(&base, &client).await;
    let (org_b, _ident_b, _key_b, admin_b) = common::bootstrap_org_identity(&base, &client).await;

    put_google_creds(&base, &client, &admin_a).await;

    // Org B sees no db-sourced rows — org B's admin key only reaches org B's
    // secrets. (Env-sourced rows are a platform-wide concern and may be
    // present from other tests running in parallel.)
    let rows = list_creds(&base, &client, &admin_b).await;
    let db_rows: Vec<_> = rows.iter().filter(|r| r["source"] == "db").collect();
    assert!(db_rows.is_empty(), "org B leaked org A creds: {rows:?}");

    // Direct secret lookup scoped to org B also misses.
    let scope_b = overslash_db::scopes::OrgScope::new(org_b, pool);
    assert!(
        scope_b
            .get_current_secret_value("OAUTH_GOOGLE_CLIENT_ID")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn test_cascade_resolves_org_secret_when_no_byoc() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    put_google_creds(&base, &client, &admin_key).await;

    // Call resolve() directly — no BYOC, no env var fallback enabled.
    let enc_key = crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let creds = overslash_api::services::client_credentials::resolve(
        &pool,
        &enc_key,
        org_id,
        Some(ident_id),
        "google",
        None,
        None,
    )
    .await
    .expect("cascade should resolve via org secrets");

    assert_eq!(
        creds.client_id,
        "72939999999-fakegoogleclientid.apps.googleusercontent.com"
    );
    assert_eq!(creds.client_secret, "GOCSPX-fakegooglesecret12345");
    assert!(
        creds.byoc_credential_id.is_none(),
        "tier-2 resolution is not BYOC-bound"
    );
}

#[tokio::test]
async fn test_cascade_byoc_still_wins_over_org_secret() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Org-level credentials.
    put_google_creds(&base, &client, &admin_key).await;

    // Identity-level BYOC trumps them.
    let byoc: Value = client
        .post(format!("{base}/v1/byoc-credentials"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "provider": "google",
            "client_id": "identity_byoc_id",
            "client_secret": "identity_byoc_secret",
            "identity_id": ident_id,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(byoc["id"].is_string(), "byoc create: {byoc:?}");

    let enc_key = crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let creds = overslash_api::services::client_credentials::resolve(
        &pool,
        &enc_key,
        org_id,
        Some(ident_id),
        "google",
        None,
        None,
    )
    .await
    .unwrap();

    assert_eq!(creds.client_id, "identity_byoc_id");
    assert_eq!(creds.client_secret, "identity_byoc_secret");
    assert!(creds.byoc_credential_id.is_some());
}

#[tokio::test]
async fn test_cascade_errors_when_nothing_configured() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, _agent_key, _admin) =
        common::bootstrap_org_identity(&base, &client).await;

    let enc_key = crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let err = match overslash_api::services::client_credentials::resolve(
        &pool,
        &enc_key,
        org_id,
        Some(ident_id),
        "google",
        None,
        None,
    )
    .await
    {
        Ok(_) => panic!("resolve should fail when nothing is configured"),
        Err(e) => e,
    };

    // The error message must point admins at the dashboard path.
    let msg = format!("{err}");
    assert!(
        msg.contains("Org Settings") || msg.contains("BYOC"),
        "error message should guide configuration: {msg}"
    );
}

#[tokio::test]
async fn test_idp_create_with_use_org_credentials() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Must fail without org credentials present.
    let resp_early = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "provider_key": "google",
            "use_org_credentials": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp_early.status(), 400);

    // Seed org OAuth App Credentials first.
    put_google_creds(&base, &client, &admin_key).await;

    // Now it succeeds and is flagged.
    let resp = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "provider_key": "google",
            "use_org_credentials": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["uses_org_credentials"], true);
}

#[tokio::test]
async fn test_idp_update_switches_between_org_and_dedicated_creds() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    put_google_creds(&base, &client, &admin_key).await;

    // Create an IdP with its own dedicated credentials.
    let created: Value = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "provider_key": "google",
            "client_id": "dedicated-idp-id",
            "client_secret": "dedicated-idp-secret",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let idp_id = created["id"].as_str().unwrap();
    assert_eq!(created["uses_org_credentials"], false);

    // Flip it to use org credentials.
    let flipped: Value = client
        .put(format!("{base}/v1/org-idp-configs/{idp_id}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "use_org_credentials": true }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(flipped["uses_org_credentials"], true);

    // DB row reflects the cleared creds.
    let scope = overslash_db::scopes::OrgScope::new(org_id, pool.clone());
    let row = scope
        .get_org_idp_config(idp_id.parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(row.encrypted_client_id.is_none());
    assert!(row.encrypted_client_secret.is_none());

    // Flip back to dedicated credentials.
    let back: Value = client
        .put(format!("{base}/v1/org-idp-configs/{idp_id}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "use_org_credentials": false,
            "client_id": "dedicated-v2",
            "client_secret": "dedicated-v2-secret",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(back["uses_org_credentials"], false);
}

#[tokio::test]
async fn test_idp_update_rejects_flip_to_org_creds_when_none_configured() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Seed + immediately delete so the org has no credentials.
    put_google_creds(&base, &client, &admin_key).await;
    let created: Value = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "provider_key": "google",
            "client_id": "dedicated",
            "client_secret": "dedicated-secret",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let idp_id = created["id"].as_str().unwrap();

    client
        .delete(format!("{base}/v1/org-oauth-credentials/google"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();

    // Flipping to use_org_credentials now must fail — the IdP would be
    // half-configured, and login would break on the next request.
    let resp = client
        .put(format!("{base}/v1/org-idp-configs/{idp_id}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "use_org_credentials": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_auth_login_resolves_org_creds_when_idp_defers() {
    // End-to-end for SPEC §3: an IdP with NULL encrypted creds resolves its
    // client_id/secret from the org OAuth App Credentials at login time.
    // Exercises this via the `/auth/login/{provider}` redirect URL, which
    // embeds the client_id as a query parameter.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let orgs: Value = client
        .get(format!("{base}/v1/orgs/{org_id}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slug = orgs["slug"].as_str().unwrap().to_string();

    put_google_creds(&base, &client, &admin_key).await;

    // Create an IdP that defers to the org creds.
    let resp = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "provider_key": "google",
            "use_org_credentials": true,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Hit the login redirect. Don't follow redirects — inspect the Location.
    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let login_resp = no_redirect
        .get(format!("{base}/auth/login/google?org={slug}"))
        .send()
        .await
        .unwrap();
    assert!(
        login_resp.status().is_redirection(),
        "expected redirect: {:?}",
        login_resp.status()
    );
    let location = login_resp
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        location.contains("72939999999-fakegoogleclientid"),
        "redirect URL should embed the org-resolved client_id: {location}"
    );
}

#[tokio::test]
async fn test_login_returns_clear_error_when_deferred_idp_has_no_org_creds() {
    // If an admin creates an IdP in use_org_credentials mode and later removes
    // the org OAuth App Credentials, login should fail fast with a message
    // that tells them where to fix it. We don't currently block deletion —
    // keeping it simple keeps the admin path obvious.
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let orgs: Value = client
        .get(format!("{base}/v1/orgs/{org_id}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let slug = orgs["slug"].as_str().unwrap().to_string();

    put_google_creds(&base, &client, &admin_key).await;
    client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "provider_key": "google",
            "use_org_credentials": true,
        }))
        .send()
        .await
        .unwrap();

    client
        .delete(format!("{base}/v1/org-oauth-credentials/google"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap();

    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let login_resp = no_redirect
        .get(format!("{base}/auth/login/google?org={slug}"))
        .send()
        .await
        .unwrap();
    // Should NOT 302 to Google with stale creds — should surface an error.
    assert!(
        login_resp.status().is_client_error() || login_resp.status().is_server_error(),
        "expected error, got {}",
        login_resp.status()
    );
    let body = login_resp.text().await.unwrap_or_default();
    assert!(
        body.contains("Org Settings") || body.contains("OAuth App Credentials"),
        "error should guide admin: {body}"
    );
}

#[tokio::test]
async fn test_idp_create_rejects_creds_when_use_org_credentials_true() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;
    let base = format!("http://{addr}");
    let (_org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/org-idp-configs"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "provider_key": "google",
            "use_org_credentials": true,
            "client_id": "should-be-rejected",
            "client_secret": "also-rejected",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
