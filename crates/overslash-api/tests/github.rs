//! GitHub E2E tests — get authenticated user, list repos, get repo.
//! Requires a real GitHub PAT. Run with: cargo test --test github -- --ignored
//!
//! Env vars:
//!   GITHUB_TEST_PAT   — Personal Access Token (classic or fine-grained).
//!                       Needs at least `read:user` and `repo` (or fine-grained
//!                       "Contents: read" on the test repo).
//!                       Create one at https://github.com/settings/tokens
//!   GITHUB_TEST_REPO  — `owner/repo` string pointing at a repo the PAT can read
//!                       (e.g. your own "hello-world" fork).

mod common;

use serde_json::{Value, json};

#[ignore] // E2E test: hits real GitHub API. Run with --ignored.
#[tokio::test]
async fn test_github_e2e() {
    let pool = common::test_pool().await;

    // --- Guard: skip if credentials not set ---
    let access_token = match std::env::var("GITHUB_TEST_PAT") {
        Ok(t) if !t.is_empty() => t,
        _ => {
            eprintln!("SKIP: GITHUB_TEST_PAT not set");
            return;
        }
    };
    let test_repo = match std::env::var("GITHUB_TEST_REPO") {
        Ok(r) if !r.is_empty() => r,
        _ => {
            eprintln!("SKIP: GITHUB_TEST_REPO not set");
            return;
        }
    };

    // Start API with real service registry (no host override — hits real GitHub)
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;

    // Bootstrap org + identity + API key
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;

    // Encrypt PAT and insert connection directly into DB
    // (GitHub PATs don't expire and don't have refresh tokens — no BYOC needed)
    let enc_key = overslash_core::crypto::parse_hex_key(&"ab".repeat(32)).unwrap();
    let encrypted_access =
        overslash_core::crypto::encrypt(&enc_key, access_token.as_bytes()).unwrap();

    let _conn = overslash_db::scopes::OrgScope::new(org_id, pool.clone())
        .create_connection(overslash_db::repos::connection::CreateConnection {
            org_id,
            identity_id: ident_id,
            provider_key: "github",
            encrypted_access_token: &encrypted_access,
            encrypted_refresh_token: None,
            token_expires_at: None,
            scopes: &[],
            account_email: None,
            byoc_credential_id: None,
        })
        .await
        .unwrap();

    // Grant Mode C permissions for github actions
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "github:*:*"}))
        .send()
        .await
        .unwrap();

    // ===== TEST 1: get_authenticated_user (Mode C) =====
    eprintln!("  [1/3] get_authenticated_user ...");
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "github",
            "action": "get_authenticated_user",
            "params": {}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let user: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert!(
        user["login"].is_string(),
        "get_authenticated_user should return login, got: {user}"
    );
    assert!(
        user["id"].is_number(),
        "get_authenticated_user should return numeric id, got: {user}"
    );
    let login = user["login"].as_str().unwrap();
    eprintln!("  get_authenticated_user: {login} (id={})", user["id"]);

    // ===== TEST 2: list_repos (Mode C) =====
    eprintln!("  [2/3] list_repos ...");
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "github",
            "action": "list_repos",
            "params": {"per_page": 5}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let repos: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let repos_arr = repos.as_array().expect("list_repos should return an array");
    assert!(
        repos_arr.len() <= 5,
        "per_page=5 but got {} repos",
        repos_arr.len()
    );
    eprintln!("  list_repos: {} repos (per_page=5)", repos_arr.len());

    // ===== TEST 3: get_repo (Mode C) =====
    eprintln!("  [3/3] get_repo ({test_repo}) ...");
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(common::auth(&key).0, common::auth(&key).1)
        .json(&json!({
            "service": "github",
            "action": "get_repo",
            "params": {"repo": test_repo}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let repo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    let full_name = repo["full_name"]
        .as_str()
        .expect("get_repo should return full_name");
    assert_eq!(
        full_name.to_lowercase(),
        test_repo.to_lowercase(),
        "full_name mismatch"
    );
    eprintln!("  get_repo: {full_name} (id={})", repo["id"]);

    eprintln!("  All GitHub E2E tests completed!");
}
