//! Regression test for #538: a disclose filter's *failure* must not quote its
//! operand.
//!
//! Disclosure extraction deliberately runs against the **un-redacted**
//! projection (SPEC §12a — the shipped Gmail template redacts `body.raw` while
//! disclosing To/Subject/Body extracted from it). jq's runtime errors embed the
//! values they choked on, so before the fix a filter that hit an unexpected
//! shape wrote the redacted value onto `DisclosedField.error` — and from there
//! onto `approvals.disclosed_fields`, `audit_log.detail.disclosed`, and the
//! inline `pending_approval` envelope the calling agent reads.
//!
//! The template here is the shape that makes this an *accident* rather than an
//! authored leak: it redacts `api_key` and discloses `.body.api_key.last4`,
//! which is well-formed jq against the `{last4: …}` object the author expected
//! and a type error against the plain string a caller actually sends. An author
//! who did everything right still loses the redaction on a shape mismatch.
//!
//! Both disclosure sites are covered: approval-create (gated call) and
//! audit-write (executed call).

use crate::common;

use crate::common::{bootstrap_org_identity, start_api_with_registry_customized, start_mock};
use serde_json::{Value, json};

/// The plaintext that must never appear on any approval or audit surface.
/// Distinctive enough that a whole-response `contains` is a meaningful assert.
const SECRET: &str = "sk_SENSITIVE_538_LEAK_CANARY";

/// `.body.api_key.last4` is a perfectly ordinary "show the last four" filter
/// against a provider that returns the key as a structured object. Against the
/// plain string this test sends, jaq raises `cannot index <the whole value>
/// with "last4"` — quoting the very field the template redacted.
const TEMPLATE_YAML_FMT: &str = r#"openapi: "3.1.0"
info:
  title: "Disclose Error Fixture"
  key: "leaksvc"
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
        - label: Key tail
          filter: ".body.api_key.last4"
      redact:
        - body.api_key
        - params.api_key
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [channel, api_key]
              properties:
                channel: {type: string}
                api_key: {type: string}
"#;

/// Boot the API with the fixture template registered and the service granted.
/// Returns `(base, client, identity_id, agent_key, admin_key)`.
async fn setup() -> (String, reqwest::Client, uuid::Uuid, String, String) {
    let pool = common::test_pool().await;
    let mock_addr = start_mock().await;
    let mock_base = format!("http://{mock_addr}");

    // Template hosts are persisted without scheme/port, so the executed-call
    // leg needs the base override to reach the in-test fake.
    let override_base = mock_base.clone();
    let (base, client) = start_api_with_registry_customized(pool.clone(), None, move |cfg| {
        cfg.service_base_overrides
            .insert("127.0.0.1".to_string(), override_base);
    })
    .await;
    let (_org_id, ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

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
        Some("leaksvc"),
        "template register failed: {create:?}"
    );

    common::grant_service_to_everyone(&base, &client, &admin_key, "leaksvc").await;
    (base, client, ident_id, agent_key, admin_key)
}

/// Assert the canary appears nowhere in a whole response body. Asserting on
/// the serialized document rather than the one field is the point: the same
/// `DisclosedField` list is rendered onto several surfaces, and a future one
/// should fail this test rather than quietly inherit the leak.
fn assert_no_canary(v: &Value, what: &str) {
    let rendered = serde_json::to_string(v).expect("serializes");
    assert!(
        !rendered.contains(SECRET),
        "redacted value leaked into {what}:\n{rendered}"
    );
}

/// Approval-create site. The permission gap yields a 202 before any HTTP call,
/// so this exercises the disclosure that lands on the durable approval row.
#[tokio::test]
async fn approval_disclosure_error_does_not_quote_the_redacted_value() {
    let (base, client, _ident_id, agent_key, admin_key) = setup().await;

    // No permission rule + an unresolvable `secrets` entry forces the gate,
    // so the chain walk finds a gap and we get the approval without the call.
    // `api_key` arrives as a plain string, not the `{last4: …}` object the
    // disclose filter assumed — the shape mismatch is the point of the test.
    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "leaksvc",
            "action": "emit",
            "params": {"channel": "#general", "api_key": SECRET},
            "secrets": [
                {"name": "nonexistent", "inject_as": "header", "header_name": "X-Leak-Test"}
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

    // Redaction itself still works — this test is about the *error* channel,
    // and it would be worthless if the raw-payload blob were leaking too.
    let detail = exec["action_detail"].as_str().expect("action_detail");
    assert!(
        detail.contains("[REDACTED]") && !detail.contains(SECRET),
        "action_detail should be redacted:\n{detail}"
    );

    // The failing field is present (per-field isolation is preserved) and its
    // sibling still resolved — but the error text names nothing.
    let disclosed = exec["disclosed_fields"]
        .as_array()
        .expect("inline disclosed_fields present");
    assert_eq!(disclosed[0]["value"].as_str(), Some("#general"));
    let failed = disclosed
        .iter()
        .find(|f| f["label"] == "Key tail")
        .expect("the failing field is still listed");
    assert_eq!(
        failed["error"].as_str(),
        Some("filter runtime error (cannot index)"),
        "error must be a fixed classification, got: {failed:?}"
    );
    assert!(failed["value"].is_null(), "a failed filter has no value");

    assert_no_canary(&exec, "the inline pending_approval envelope");

    // And on the durable row, read back through the API the reviewer uses.
    let approval: Value = client
        .get(format!("{base}/v1/approvals/{approval_id}"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_no_canary(&approval, "the persisted approval row");
    assert_eq!(
        exec["disclosed_fields"], approval["disclosed_fields"],
        "inline vs GET disclosed_fields drift"
    );
}

/// Audit-write site. With the permission granted the call executes and the
/// same filters run again on the way to `audit_log.detail.disclosed`.
#[tokio::test]
async fn audit_disclosure_error_does_not_quote_the_redacted_value() {
    let (base, client, ident_id, agent_key, admin_key) = setup().await;

    let perm = client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"identity_id": ident_id, "action_pattern": "leaksvc:*:*"}))
        .send()
        .await
        .unwrap();
    assert_eq!(perm.status(), 200, "permission grant failed");

    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "leaksvc",
            "action": "emit",
            "params": {"channel": "#general", "api_key": SECRET},
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        exec["status"].as_str(),
        Some("called"),
        "expected executed call, got: {exec:?}"
    );

    let audit: Vec<Value> = client
        .get(format!("{base}/v1/audit?limit=50"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let executed = audit
        .iter()
        .find(|e| e["action"].as_str() == Some("action.executed"))
        .expect("action.executed audit row present");
    let disclosed = executed["detail"]["disclosed"]
        .as_array()
        .expect("audit detail.disclosed present");
    let failed = disclosed
        .iter()
        .find(|f| f["label"] == "Key tail")
        .expect("the failing field is listed on the audit row");
    assert_eq!(
        failed["error"].as_str(),
        Some("filter runtime error (cannot index)"),
        "error must be a fixed classification, got: {failed:?}"
    );
    assert_no_canary(executed, "the audit row");
}
