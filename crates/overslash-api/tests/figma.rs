//! Figma service integration tests — reads, comment writes, and the refresh
//! endpoint that is Figma's alone.
//!
//! **Default CI** (non-ignored):
//!   1. `figma_yaml_parses` — the shipped `services/figma.yaml` loads, exposes
//!      its 24 actions, and classifies each write at the risk that routes it.
//!   2. `figma_get_file_defaults_depth` — `get_file` sends `depth=2` when the
//!      caller names no depth. This is the guard against the whole-document
//!      response, which is past the size cap and past anything jq could rescue.
//!   3. `test_figma_mock_read_and_write` — Mode C `get_file` (read) and
//!      `post_comment` (write) execute against a local mock upstream with the
//!      OAuth token auto-resolved from a connection.
//!   4. `test_figma_post_comment_routes_through_approval` — service granted,
//!      no covering permission rule: the read auto-approves, the comment
//!      routes through approval carrying its file and text.
//!   5. `test_figma_refreshes_at_its_own_refresh_endpoint` — an expired token
//!      refreshes at `refresh_endpoint`, not `token_endpoint`.
//!   6. `test_null_refresh_endpoint_still_refreshes_at_token_endpoint` — the
//!      mirror: every provider seeded before Figma stayed where it was.
//!
//! **Real API E2E** (`#[ignore]`): hits the live Figma API. Run with:
//!   cargo nextest run -p overslash-api --test api figma -- --ignored
//!
//! Env vars for the real test:
//!   FIGMA_TEST_ACCESS_TOKEN — an OAuth access token (or a personal access
//!                             token, which Figma accepts as a bearer too)
//!                             granted at least `file_content:read` and
//!                             `file_metadata:read`.
//!   FIGMA_TEST_FILE_KEY     — a file the token can read.
//!
//! The live test is the only thing that proves Figma accepts our refresh at
//! `/v1/oauth/refresh`, and it needs a real OAuth app to do it. Figma access
//! tokens last 90 days, so a refresh pointed at the wrong URL would pass every
//! test here and fail a quarter after the first real connection.
// Test setup requires dynamic SQL for provider endpoint overrides and DB seeding.
#![allow(clippy::disallowed_methods)]

use crate::common;

use overslash_core::registry::ServiceRegistry;
use serde_json::{Value, json};
use std::path::Path;

fn shipped_registry() -> ServiceRegistry {
    let ws_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    ServiceRegistry::load_from_dir(
        &ws_root.join("services"),
        overslash_core::template_vars::Vars::for_tests(),
    )
    .expect("services/ should load cleanly")
}

/// Seed an OAuth connection for `figma` on the org's owner user (D22), with a
/// BYOC client so credential resolution has something to find. `expires_in`
/// controls whether the access token is already stale.
async fn seed_figma_connection(
    pool: &sqlx::PgPool,
    org_id: uuid::Uuid,
    ident_id: uuid::Uuid,
    access_token: &[u8],
    refresh_token: Option<&[u8]>,
    expires_in: time::Duration,
) {
    let owner_id = common::owner_user_id(pool, org_id).await;
    let enc_key = overslash_core::crypto::Keyring::test();
    let encrypted_token = overslash_core::crypto::encrypt(&enc_key, access_token).unwrap();
    let encrypted_refresh =
        refresh_token.map(|rt| overslash_core::crypto::encrypt(&enc_key, rt).unwrap());
    let encrypted_cid = overslash_core::crypto::encrypt(&enc_key, b"mock_client_id").unwrap();
    let encrypted_csec = overslash_core::crypto::encrypt(&enc_key, b"mock_client_secret").unwrap();
    let byoc = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_byoc_credential(
            ident_id,
            "figma",
            &encrypted_cid,
            &encrypted_csec,
            &serde_json::json!({}),
        )
        .await
        .unwrap();
    overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: owner_id,
            provider_key: "figma",
            encrypted_access_token: &encrypted_token,
            encrypted_refresh_token: encrypted_refresh.as_deref(),
            token_expires_at: Some(time::OffsetDateTime::now_utc() + expires_in),
            // Every scope the template declares. Narrower sets are the
            // subject of the per-operation scope gate, not of these tests —
            // a connection missing `file_dev_resources:write` is refused at
            // the gate before approval is ever reached, which is the gate
            // doing its job.
            scopes: Some(&[
                "current_user:read".to_string(),
                "file_content:read".to_string(),
                "file_metadata:read".to_string(),
                "file_versions:read".to_string(),
                "file_comments:read".to_string(),
                "file_comments:write".to_string(),
                "file_dev_resources:read".to_string(),
                "file_dev_resources:write".to_string(),
                "file_variables:read".to_string(),
                "library_content:read".to_string(),
                "team_library_content:read".to_string(),
                "projects:read".to_string(),
            ]),
            account_email: None,
            account_picture: None,
            byoc_credential_id: Some(byoc.id),
        })
        .await
        .unwrap();
}

// ============================================================================
// Parse smoke test — the shipped template loads and exposes its actions
// ============================================================================

#[test]
fn figma_yaml_parses() {
    use overslash_core::types::service::Risk;

    let reg = shipped_registry();
    let svc = reg.get("figma").expect("figma should be registered");
    assert_eq!(svc.display_name, "Figma");
    assert_eq!(svc.hosts, vec!["api.figma.com".to_string()]);

    // The whole curated set, so dropping or renaming one is a failing test
    // rather than a silently smaller service.
    let expected_reads = [
        "get_me",
        "get_file",
        "get_file_nodes",
        "get_file_meta",
        "list_file_versions",
        "render_images",
        "get_image_fills",
        "list_team_projects",
        "list_project_files",
        "list_comments",
        "list_comment_reactions",
        "list_file_components",
        "list_file_styles",
        "list_team_components",
        "list_team_styles",
        "get_local_variables",
        "list_dev_resources",
    ];
    for action in expected_reads {
        let a = svc
            .actions
            .get(action)
            .unwrap_or_else(|| panic!("missing action '{action}'"));
        assert_eq!(a.risk, Risk::Read, "{action} should be risk: read");
    }

    for action in [
        "post_comment",
        "post_comment_reaction",
        "create_dev_resources",
        "update_dev_resources",
    ] {
        let a = svc
            .actions
            .get(action)
            .unwrap_or_else(|| panic!("missing action '{action}'"));
        assert_eq!(a.risk, Risk::Write, "{action} should be risk: write");
    }

    // Deletes are their own class: a deleted comment thread takes its replies
    // with it and Figma has no undo, so these must not read as ordinary writes.
    for action in [
        "delete_comment",
        "delete_comment_reaction",
        "delete_dev_resource",
    ] {
        let a = svc
            .actions
            .get(action)
            .unwrap_or_else(|| panic!("missing action '{action}'"));
        assert_eq!(a.risk, Risk::Delete, "{action} should be risk: delete");
    }

    assert_eq!(
        svc.actions.len(),
        expected_reads.len() + 7,
        "the curated set is 24 actions; update this test deliberately"
    );

    // Nothing here may edit the canvas. Figma's design-mutating surface lives
    // in its MCP server, and a template that could redraw a file is a
    // different review from one that can comment on it.
    for key in svc.actions.keys() {
        assert!(
            !key.contains("create_file")
                && !key.contains("update_node")
                && !key.contains("post_variables")
                && !key.contains("modify_variables"),
            "canvas-mutating action '{key}' must not be in this template"
        );
    }
}

/// A resolver runs on every call, so one left on a shared path-item block
/// would make the read on that path fetch the file's metadata as well. Pin
/// that the `file_key` resolvers sit on the mutating operations only.
#[test]
fn figma_file_key_resolvers_are_on_mutating_actions_only() {
    let reg = shipped_registry();
    let svc = reg.get("figma").unwrap();

    for action in [
        "post_comment",
        "delete_comment",
        "post_comment_reaction",
        "delete_comment_reaction",
        "delete_dev_resource",
    ] {
        let p = &svc.actions[action].params["file_key"];
        let r = p
            .resolve
            .as_ref()
            .unwrap_or_else(|| panic!("{action}.file_key should resolve to the file's name"));
        assert_eq!(r.get.as_deref(), Some("/v1/files/{file_key}/meta"));
        assert_eq!(r.pick.as_deref(), Some("file.name"));
    }

    for action in ["get_file", "list_comments", "list_dev_resources"] {
        assert!(
            svc.actions[action].params["file_key"].resolve.is_none(),
            "{action} must not resolve file_key — a resolver runs on every call"
        );
    }
}

/// `get_file` with no `depth` returns every node in the document — tens of
/// megabytes on a real design file, past the response cap, and past anything
/// jq could rescue because the filter runs after the cap. The template's
/// declared default is the only thing standing between an agent and that.
#[test]
fn figma_get_file_defaults_depth() {
    let reg = shipped_registry();
    let svc = reg.get("figma").unwrap();
    for action in ["get_file", "get_file_nodes"] {
        let depth = &svc.actions[action].params["depth"];
        assert_eq!(
            depth.default,
            Some(json!(2)),
            "{action} must default depth, or an undefaulted call returns the whole file"
        );
    }
}

// ============================================================================
// Mock-based Mode C — get_file (read) + post_comment (write) both execute
// ============================================================================

#[tokio::test]
async fn test_figma_mock_read_and_write() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("figma", mock_host.clone()))).await;

    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "figma:**"}))
        .send()
        .await
        .unwrap();
    common::grant_service_to_everyone(&base, &client, &admin_key, "figma").await;

    seed_figma_connection(
        &pool,
        org_id,
        ident_id,
        b"figma-oauth-token-123",
        None,
        time::Duration::hours(1),
    )
    .await;

    // ===== get_file (GET): depth default applied, token injected =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "figma",
            "action": "get_file",
            "params": {"file_key": "abc123DEF"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called", "get_file response: {body:?}");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/v1/files/abc123DEF"),
        "get_file: URL should contain the file key, got: {uri}"
    );
    assert!(
        uri.contains("depth=2"),
        "get_file: the declared default must be sent — an undefaulted call \
         returns the whole document. Got: {uri}"
    );
    assert_eq!(
        echo["headers"]["authorization"], "Bearer figma-oauth-token-123",
        "get_file: OAuth token should be auto-resolved from the connection"
    );

    // ===== post_comment (POST): JSON body + token =====
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "figma",
            "action": "post_comment",
            "params": {"file_key": "abc123DEF", "message": "Spacing here is 12px, not 16px."}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "called", "post_comment response: {body:?}");
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let uri = echo["uri"].as_str().unwrap();
    assert!(
        uri.contains("/v1/files/abc123DEF/comments"),
        "post_comment: unexpected URL {uri}"
    );
    let req_body: Value = serde_json::from_str(echo["body"].as_str().unwrap()).unwrap();
    assert_eq!(req_body["message"], "Spacing here is 12px, not 16px.");
    assert_eq!(
        echo["headers"]["authorization"],
        "Bearer figma-oauth-token-123"
    );
}

// ============================================================================
// post_comment (write) routes through approval; get_file (read) does not
// ============================================================================

#[tokio::test]
async fn test_figma_post_comment_routes_through_approval() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("figma", mock_host.clone()))).await;

    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // Layer-1 service access but deliberately no permission rule: reads bypass
    // Layer 2, writes must be approved.
    common::grant_service_to_everyone(&base, &client, &admin_key, "figma").await;

    seed_figma_connection(
        &pool,
        org_id,
        ident_id,
        b"figma-oauth-token-abc",
        None,
        time::Duration::hours(1),
    )
    .await;

    // get_file (read) → auto-approve-reads bypass → executes, no approval.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "figma",
            "action": "get_file",
            "params": {"file_key": "abc123DEF"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["status"], "called",
        "read should auto-approve, got: {body:?}"
    );

    // post_comment (write) → Layer-2 gap → pending approval.
    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "figma",
            "action": "post_comment",
            "params": {"file_key": "abc123DEF", "message": "This comment should require approval"}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        exec["status"].as_str(),
        Some("pending_approval"),
        "write should route through approval, got: {exec:?}"
    );
    assert_eq!(exec["risk"].as_str(), Some("med"));

    // The reviewer sees the text that would be posted, and which file.
    let disclosed = exec["disclosed_fields"]
        .as_array()
        .expect("disclosed_fields present");
    let comment = disclosed
        .iter()
        .find(|f| f["label"] == "Comment")
        .expect("Comment disclosure present");
    assert_eq!(
        comment["value"].as_str(),
        Some("This comment should require approval")
    );
    assert!(
        disclosed.iter().any(|f| f["label"] == "File"),
        "the file being commented on must be disclosed: {disclosed:?}"
    );

    // Approving one file is not approving all of them: the permission key
    // carries the file it was scoped to.
    assert_eq!(
        exec["permission_keys"],
        json!(["figma:post_comment:file_key=abc123DEF"]),
        "post_comment must be scoped to its file_key, not to every file the \
         connection can reach: {exec:?}"
    );

    // And the narrowest tier a reviewer can grant is that same single file —
    // not the whole service.
    let narrowest = &exec["suggested_tiers"][0]["keys"];
    assert_eq!(narrowest, &json!(["figma:post_comment:file_key=abc123DEF"]));
}

/// `create_dev_resources` is the one write here that cannot be bounded to a
/// file — its `file_key` lives at an array-indexed body position the
/// dotted-path grammar cannot address — so the disclosure is the only thing
/// standing between a reviewer and a blind approval. Pin that the array
/// filters actually render under jaq, and that the key really is unscoped so
/// nobody reads the wildcard as an oversight.
#[tokio::test]
async fn test_figma_bulk_dev_resources_disclose_the_whole_array() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("figma", mock_host.clone()))).await;
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    common::grant_service_to_everyone(&base, &client, &admin_key, "figma").await;

    seed_figma_connection(
        &pool,
        org_id,
        ident_id,
        b"figma-oauth-token-abc",
        None,
        time::Duration::hours(1),
    )
    .await;

    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "figma",
            "action": "create_dev_resources",
            "params": {"dev_resources": [
                {"name": "PR #642", "url": "https://github.com/acme/web/pull/642",
                 "file_key": "abc123DEF", "node_id": "1:2"},
                {"name": "Card.tsx", "url": "https://github.com/acme/web/blob/main/Card.tsx",
                 "file_key": "xyz789GHI", "node_id": "3:4"}
            ]}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        exec["status"].as_str(),
        Some("pending_approval"),
        "bulk dev-resource writes must route through approval: {exec:?}"
    );

    let disclosed = exec["disclosed_fields"]
        .as_array()
        .expect("disclosed_fields present");
    let field = |label: &str| -> String {
        disclosed
            .iter()
            .find(|f| f["label"] == label)
            .unwrap_or_else(|| panic!("{label} disclosure present in {disclosed:?}"))["value"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    };

    // Every link, so the reviewer sees what would be attached.
    let links = field("Links");
    assert!(
        links.contains("PR #642 → https://github.com/acme/web/pull/642")
            && links.contains("Card.tsx → https://github.com/acme/web/blob/main/Card.tsx"),
        "both links must render: {links:?}"
    );
    // Both files, deduplicated — this is the blast radius the wildcard key
    // cannot express.
    assert_eq!(field("Files"), "abc123DEF, xyz789GHI");
    assert_eq!(field("Nodes"), "1:2, 3:4");

    // Unscoped on purpose: there is no `scope_param` that could bound a body
    // array. If this ever gains one, the disclosure above stops being the only
    // safeguard and this assertion should change deliberately.
    assert_eq!(
        exec["permission_keys"],
        json!(["figma:create_dev_resources:*"]),
        "bulk dev-resource writes cannot be file-scoped; see the template comment"
    );
}

// ============================================================================
// The refresh endpoint — the reason migration 120 adds a column
// ============================================================================

/// Figma mints tokens at `/v1/oauth/token` and refreshes at `/v1/oauth/refresh`.
/// Point `token_endpoint` at a path the mock does not serve and
/// `refresh_endpoint` at the one it does: if the call succeeds, the refresh
/// went where the provider row said, not where RFC 6749 assumes.
#[tokio::test]
async fn test_figma_refreshes_at_its_own_refresh_endpoint() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    sqlx::query(
        "UPDATE oauth_providers
            SET token_endpoint = $1, refresh_endpoint = $2
          WHERE key = 'figma'",
    )
    .bind(format!("http://{mock_addr}/this-path-does-not-exist"))
    .bind(format!("http://{mock_addr}/oauth/token"))
    .execute(&pool)
    .await
    .unwrap();

    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("figma", mock_host.clone()))).await;
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "figma:**"}))
        .send()
        .await
        .unwrap();
    common::grant_service_to_everyone(&base, &client, &admin_key, "figma").await;

    // Already expired, with a refresh token to spend.
    seed_figma_connection(
        &pool,
        org_id,
        ident_id,
        b"figma-stale-token",
        Some(b"figma-refresh-token"),
        time::Duration::minutes(-5),
    )
    .await;

    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "figma",
            "action": "get_file",
            "params": {"file_key": "abc123DEF"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["status"], "called",
        "the refresh must reach refresh_endpoint; token_endpoint 404s here. Got: {body:?}"
    );
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        echo["headers"]["authorization"], "Bearer mock_refreshed_access_token",
        "the call should carry the refreshed token, not the stale one"
    );
}

/// The mirror, and the reason the column is nullable: a provider that does not
/// name a refresh endpoint still refreshes at its token endpoint, exactly as
/// every provider seeded before Figma did.
#[tokio::test]
async fn test_null_refresh_endpoint_still_refreshes_at_token_endpoint() {
    let pool = common::test_pool().await;
    let mock_addr = common::start_mock().await;
    let mock_host = format!("http://{mock_addr}");

    sqlx::query(
        "UPDATE oauth_providers
            SET token_endpoint = $1, refresh_endpoint = NULL
          WHERE key = 'figma'",
    )
    .bind(format!("http://{mock_addr}/oauth/token"))
    .execute(&pool)
    .await
    .unwrap();

    let (base, client) =
        common::start_api_with_registry(pool.clone(), Some(("figma", mock_host.clone()))).await;
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "figma:**"}))
        .send()
        .await
        .unwrap();
    common::grant_service_to_everyone(&base, &client, &admin_key, "figma").await;

    seed_figma_connection(
        &pool,
        org_id,
        ident_id,
        b"figma-stale-token",
        Some(b"figma-refresh-token"),
        time::Duration::minutes(-5),
    )
    .await;

    let body: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "figma",
            "action": "get_file",
            "params": {"file_key": "abc123DEF"}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        body["status"], "called",
        "a NULL refresh_endpoint must still refresh at token_endpoint: {body:?}"
    );
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        echo["headers"]["authorization"],
        "Bearer mock_refreshed_access_token"
    );
}

// ============================================================================
// Real API E2E — the only thing that proves /v1/oauth/refresh is right
// ============================================================================

#[tokio::test]
#[ignore = "requires FIGMA_TEST_ACCESS_TOKEN and FIGMA_TEST_FILE_KEY"]
async fn test_figma_real_api() {
    let Ok(token) = std::env::var("FIGMA_TEST_ACCESS_TOKEN") else {
        eprintln!("SKIP: FIGMA_TEST_ACCESS_TOKEN not set");
        return;
    };
    let Ok(file_key) = std::env::var("FIGMA_TEST_FILE_KEY") else {
        eprintln!("SKIP: FIGMA_TEST_FILE_KEY not set");
        return;
    };

    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "figma:**"}))
        .send()
        .await
        .unwrap();
    common::grant_service_to_everyone(&base, &client, &admin_key, "figma").await;

    seed_figma_connection(
        &pool,
        org_id,
        ident_id,
        token.as_bytes(),
        None,
        time::Duration::hours(1),
    )
    .await;

    // get_me — the credential probe, against the real account.
    let body: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({"service": "figma", "action": "get_me", "params": {}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["status"], "called", "get_me: {body:?}");
    let me: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        me["id"].is_string(),
        "/v1/me should name an account: {me:?}"
    );
    eprintln!("connected as {} <{}>", me["handle"], me["email"]);

    // get_file_meta — cheapest real read, and the endpoint the approval
    // resolvers depend on.
    let body: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "figma",
            "action": "get_file_meta",
            "params": {"file_key": file_key}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["status"], "called", "get_file_meta: {body:?}");
    let meta: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        meta["file"]["name"].is_string(),
        "get_file_meta should carry file.name — the resolvers pick it: {meta:?}"
    );

    // get_file at the declared depth. The assertion that matters is that this
    // comes back at all: undefaulted it would be past the response cap.
    let body: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "figma",
            "action": "get_file",
            "params": {"file_key": file_key}
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["status"], "called", "get_file: {body:?}");
}
