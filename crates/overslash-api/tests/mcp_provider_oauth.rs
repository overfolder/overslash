//! MCP servers authenticated through a provider connection
//! (`x-overslash-mcp.auth: {kind: oauth, provider: …}`) — the mechanism
//! HubSpot's remote MCP rides on. `hubspot.rs` covers token forwarding and the
//! no-connection gate against the shipped template. This file covers the two
//! template-agnostic regressions that came with the mechanism:
//!   * the template-detail DTO surfaces the oauth provider and its scopes, so
//!     the dashboard connect flow does not request an empty scope set;
//!   * pinning a connection at service-create time is accepted, because the
//!     provider-match check sees the MCP `auth.kind: oauth` provider and not
//!     only an HTTP oauth scheme (regression: connection_provider_mismatch).

// Test setup requires dynamic SQL for DB seeding.
#![allow(clippy::disallowed_methods)]

use crate::common;

use serde_json::{Value, json};

/// An org-tier MCP template on the `oauth` auth kind. The URL is never dialled.
fn mcp_oauth_template_yaml(key: &str) -> String {
    format!(
        r#"openapi: 3.1.0
info:
  title: MCP OAuth (test)
  x-overslash-key: {key}
x-overslash-runtime: mcp
paths: {{}}
x-overslash-mcp:
  url: https://mcp.example.test/mcp
  auth:
    kind: oauth
    provider: hubspot
    scopes: [crm.objects.contacts.read, crm.objects.contacts.write]
  autodiscover: false
  tools:
    - name: list_things
      risk: read
      description: List things
      input_schema:
        type: object
        properties: {{}}
        required: []
"#
    )
}

async fn create_template(base: &str, client: &reqwest::Client, admin_key: &str, key: &str) {
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(common::auth(admin_key).0, common::auth(admin_key).1)
        .json(&json!({"openapi": mcp_oauth_template_yaml(key)}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "template create: {:?}",
        resp.text().await
    );
}

/// A future-dated `hubspot` connection (+ BYOC) on `owner_id`.
async fn seed_connection(
    pool: &sqlx::PgPool,
    org_id: uuid::Uuid,
    owner_id: uuid::Uuid,
) -> uuid::Uuid {
    let enc_key = overslash_core::crypto::Keyring::test();
    let token = overslash_core::crypto::encrypt(&enc_key, b"mcp-oauth-token").unwrap();
    let cid = overslash_core::crypto::encrypt(&enc_key, b"mock_client_id").unwrap();
    let csec = overslash_core::crypto::encrypt(&enc_key, b"mock_client_secret").unwrap();
    let future = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let byoc = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(owner_id, "hubspot", &cid, &csec, &json!({}))
        .await
        .unwrap();
    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "hubspot",
            encrypted_access_token: &token,
            encrypted_refresh_token: None,
            token_expires_at: Some(future),
            scopes: None,
            account_email: None,
            account_picture: None,
            byoc_credential_id: Some(byoc.id),
        })
        .await
        .unwrap()
        .id
}

#[tokio::test]
async fn template_detail_surfaces_mcp_oauth_provider_and_scopes() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (_org_id, _ident_id, _key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let key_name = "mcp_oauth_detail";
    create_template(&base, &client, &admin_key, key_name).await;

    let detail: Value = client
        .get(format!("{base}/v1/templates/{key_name}"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["mcp"]["auth_kind"], "oauth");
    assert_eq!(detail["mcp"]["provider"], "hubspot");
    let strings = |v: &Value| -> Vec<String> {
        v.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let want = "crm.objects.contacts.write".to_string();
    let dto_scopes = strings(&detail["mcp"]["scopes"]);
    assert!(
        dto_scopes.contains(&want),
        "mcp.scopes should round-trip through McpDetail, got {dto_scopes:?}"
    );
    // The top-level `scopes` (for white-label / token-vault consumers) must
    // include them too: MCP tools carry no per-action scopes.
    let top_scopes = strings(&detail["scopes"]);
    assert!(
        top_scopes.contains(&want),
        "template-level scopes should include mcp oauth scopes, got {top_scopes:?}"
    );
}

#[tokio::test]
async fn pinned_connection_is_accepted_on_an_mcp_oauth_template() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{base}");
    let (org_id, _ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;

    let key_name = "mcp_oauth_pin";
    create_template(&base, &client, &admin_key, key_name).await;

    let conn_id = seed_connection(&pool, org_id, owner_id).await;
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "name": key_name,
            "template_key": key_name,
            "connection_id": conn_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "pinning a connection on an mcp-oauth template should be accepted: {:?}",
        resp.text().await
    );
}
