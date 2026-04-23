//! End-to-end test against a real public MCP server.
//!
//! Points Overslash at DeepWiki's public MCP endpoint (kind:none auth,
//! three tools) and exercises the full execute + resync path. Marked
//! `#[ignore]` so CI stays green when upstream has an outage — run with
//! `cargo test --test mcp_external_e2e -- --ignored`. Respects
//! `OVERSLASH_E2E_DEEPWIKI_URL` for pointing at a mirror.

mod common;

use common::auth;
use serde_json::{Value, json};

const DEFAULT_URL: &str = "https://mcp.deepwiki.com/mcp";

fn deepwiki_url() -> String {
    std::env::var("OVERSLASH_E2E_DEEPWIKI_URL").unwrap_or_else(|_| DEFAULT_URL.to_string())
}

fn template_yaml(key: &str, url: &str) -> String {
    // Minimal: one tool, enough to prove the round-trip. We rely on resync
    // to pull the real schemas for the remaining tools.
    format!(
        r#"openapi: 3.1.0
info:
  title: DeepWiki (E2E)
  x-overslash-key: {key}
x-overslash-runtime: mcp
paths: {{}}
x-overslash-mcp:
  url: {url}
  auth: {{ kind: none }}
  autodiscover: true
  tools:
    - name: ask_question
      risk: read
      description: Ask a question
      input_schema:
        type: object
        properties:
          repoName: {{ type: string }}
          question: {{ type: string }}
        required: [repoName, question]
"#
    )
}

/// Run the live DeepWiki round-trip. Ignored by default — enable with
/// `cargo test --test mcp_external_e2e -- --ignored`. Extra env vars:
///
/// - `OVERSLASH_E2E_DEEPWIKI_URL`: override the target URL (for mirrors).
/// - `OVERSLASH_E2E_SKIP`: if set to "1", the test returns cleanly so
///   running the whole ignored suite in an air-gapped CI doesn't fail.
#[ignore]
#[tokio::test]
async fn deepwiki_live_resync_and_execute() {
    if std::env::var("OVERSLASH_E2E_SKIP").as_deref() == Ok("1") {
        eprintln!("SKIP: OVERSLASH_E2E_SKIP=1");
        return;
    }
    let url = deepwiki_url();

    let pool = common::test_pool().await;
    let (base, client) = common::start_api(pool).await;
    let base = format!("http://{base}");
    let (_org, agent_ident, agent_key, org_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Upload template.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({"openapi": template_yaml("deepwiki_live", &url)}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "template create: {:?}",
        resp.text().await
    );

    // Resync — real tools/list call against DeepWiki.
    let resp = client
        .post(format!("{base}/v1/templates/deepwiki_live/mcp/resync"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .send()
        .await
        .unwrap();
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        panic!("resync failed: {status} {body}");
    }
    let body: Value = resp.json().await.unwrap();
    let tool_count = body["tool_count"].as_u64().unwrap_or(0);
    assert!(
        tool_count >= 1,
        "expected at least one discovered tool, got {body}"
    );

    // Permission grant + instance.
    client
        .post(format!("{base}/v1/permissions"))
        .header(auth(&org_key).0, auth(&org_key).1)
        .json(&json!({
            "identity_id": agent_ident,
            "action_pattern": "deepwiki_live:*:*",
        }))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/v1/services"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({"name": "deepwiki_live", "template_key": "deepwiki_live"}))
        .send()
        .await
        .unwrap();

    // Execute ask_question against a small, well-indexed repo.
    let resp = client
        .post(format!("{base}/v1/actions/execute"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "deepwiki_live",
            "action": "ask_question",
            "params": {
                "repoName": "sigoden/dufs",
                "question": "What is this project in one sentence?"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "executed");
    let envelope: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(envelope["runtime"], "mcp");
    assert_eq!(envelope["tool"], "ask_question");
    assert_eq!(
        envelope["is_error"], false,
        "deepwiki reported a tool error: {envelope}"
    );
    // content[0] must be a text block with a non-empty string.
    let content = envelope["content"]
        .as_array()
        .expect("content should be an array");
    assert!(
        content
            .iter()
            .any(|c| c["text"].as_str().map(|s| !s.is_empty()).unwrap_or(false)),
        "no non-empty text block in content: {content:?}"
    );
}
