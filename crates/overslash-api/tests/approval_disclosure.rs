//! Integration test for configurable detail disclosure (SPEC §N).
//!
//! Validates the full flow end-to-end:
//!   1. An org-level template with `x-overslash-disclose` + `x-overslash-redact`
//!      registers cleanly via `POST /v1/templates` (exercises the jq syntax
//!      validator hook).
//!   2. A Mode C execute that lands on an uncovered permission key creates
//!      an approval whose `disclosed_fields` carry the labeled, extracted
//!      values — not a serialized raw request.
//!   3. The approval's `action_detail` contains `[REDACTED]` in place of
//!      the path listed in `x-overslash-redact`, while the disclosed
//!      summary is unaffected (extraction runs before redaction).
//!
//! Template lives entirely in-test — no coupling to any shipped service.
//! The mock target's echo endpoint matches the template's host, so the
//! request never leaves the test process.

mod common;

use common::{bootstrap_org_identity, start_api_with_registry, start_mock};
use serde_json::{Value, json};

const TEMPLATE_YAML_FMT: &str = r#"openapi: "3.1.0"
info:
  title: "Disclose Fixture"
  key: "discloser"
servers:
  - url: "http://HOST_PLACEHOLDER"
paths:
  /echo:
    post:
      operationId: emit
      summary: "Emit a message on {channel}"
      risk: write
      scope_param: channel
      disclose:
        - label: Channel
          filter: ".body.channel"
        - label: Text
          filter: ".body.text"
          max_chars: 50
      redact:
        - body.api_key
        - params.api_key
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [channel, text]
              properties:
                channel: {type: string}
                text: {type: string}
                api_key: {type: string}
"#;

#[tokio::test]
async fn approval_carries_disclosed_fields_and_redacts_action_detail() {
    let pool = common::test_pool().await;
    let mock_addr = start_mock().await;
    // Start with the shipped registry — the org template registers on top.
    let (base, client) = start_api_with_registry(pool.clone(), None).await;
    let (_org_id, _ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    // Register the fixture template, pointing at the in-test mock.
    let yaml = TEMPLATE_YAML_FMT.replace("HOST_PLACEHOLDER", &mock_addr.to_string());
    let create: Value = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"openapi": yaml, "user_level": false}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        create["key"].as_str(),
        Some("discloser"),
        "template register failed: {create:?}"
    );

    // Execute Mode C as the agent. No permission rule exists + explicit
    // `secrets` forces `needs_gate=true` → chain walk finds a gap at the
    // user level → 202 Pending Approval *before* any HTTP call, so we never
    // need the mock's real port (extract_hosts strips it anyway).
    let exec: Value = client
        .post(format!("{base}/v1/actions/execute"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "discloser",
            "action": "emit",
            "params": {
                "channel": "#general",
                "text": "hello from the integration test",
                "api_key": "sk_SENSITIVE_123"
            },
            "secrets": [
                {"name": "nonexistent", "inject_as": "header", "header_name": "X-Disclose-Test"}
            ]
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
        "expected pending_approval, got: {exec:?}"
    );
    let approval_id = exec["approval_id"].as_str().unwrap();

    // Fetch the approval back and verify the disclosed + redacted shape.
    let approval: Value = client
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // disclosed_fields carries both extracted values in declaration order.
    let disclosed = approval["disclosed_fields"]
        .as_array()
        .expect("disclosed_fields present");
    assert_eq!(disclosed.len(), 2);
    assert_eq!(disclosed[0]["label"].as_str(), Some("Channel"));
    assert_eq!(disclosed[0]["value"].as_str(), Some("#general"));
    assert_eq!(disclosed[1]["label"].as_str(), Some("Text"));
    assert_eq!(
        disclosed[1]["value"].as_str(),
        Some("hello from the integration test")
    );

    // action_detail is the redacted projection (not the raw ActionRequest).
    // `body.api_key` was marked as redact → [REDACTED]. The disclosed
    // Channel/Text still carried through because redaction runs after
    // disclosure extraction.
    let raw = approval["action_detail"]
        .as_str()
        .expect("action_detail present");
    assert!(
        raw.contains("[REDACTED]"),
        "expected redaction sentinel in action_detail; got:\n{raw}"
    );
    assert!(
        !raw.contains("sk_SENSITIVE_123"),
        "plaintext api_key leaked into action_detail:\n{raw}"
    );
}

#[tokio::test]
async fn template_with_invalid_jq_is_rejected_at_register() {
    let pool = common::test_pool().await;
    let mock_addr = start_mock().await;
    let (base, client) = start_api_with_registry(pool.clone(), None).await;
    let (_org_id, _ident_id, _agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    // Inject a malformed jq expression into the disclose block.
    let bad_yaml = TEMPLATE_YAML_FMT
        .replace("HOST_PLACEHOLDER", &mock_addr.to_string())
        .replace(".body.channel", ".body.channel[");

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"openapi": bad_yaml, "user_level": false}))
        .send()
        .await
        .unwrap();

    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(status, 400, "expected 400, got {status} body={body:?}");
    // The error payload should mention the `disclose_invalid_jq` code.
    let body_s = body.to_string();
    assert!(
        body_s.contains("disclose_invalid_jq"),
        "expected disclose_invalid_jq in error body, got: {body_s}"
    );
}
