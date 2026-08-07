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

use crate::common;

use crate::common::{
    bootstrap_org_identity, start_api_with_registry, start_api_with_registry_customized, start_mock,
};
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

    // Create an org-level instance and grant it to Everyone so the agent's
    // ceiling user (test-user) clears Layer 1. Post-Myself the ceiling is
    // always enforced, so reaching Layer 2 (the gap → approval path this test
    // is actually about) requires an explicit grant — we don't fall through a
    // permissive default anymore.
    // Write, *without* auto-approve-reads: the read-bypass would otherwise
    // skip Layer 2, and Layer 2 is what this test is about.
    let everyone_id = common::everyone_group_id(&base, &client, &admin_key).await;
    let svc_instance: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "discloser",
            "name": "discloser",
            "user_level": false,
            "groups": [{
                "group_id": everyone_id.to_string(),
                "access_level": "write",
                "auto_approve_reads": false,
            }],
            "status": "active",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let _svc_id = svc_instance["id"].as_str().expect("service create failed");

    // Execute Mode C as the agent. No permission rule exists + explicit
    // `secrets` forces `needs_gate=true` → chain walk finds a gap at the
    // user level → 202 Pending Approval *before* any HTTP call, so we never
    // need the mock's real port (extract_hosts strips it anyway).
    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
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

    // The inline pending_approval envelope now carries the render-form fields
    // a white-label integration needs to draw the approval card without a
    // second GET /v1/approvals/{id}. Assert the same disclosed/risk/keys/detail
    // shape lands here.
    let inline_disclosed = exec["disclosed_fields"]
        .as_array()
        .expect("inline disclosed_fields present");
    assert_eq!(inline_disclosed.len(), 2);
    assert_eq!(inline_disclosed[0]["label"].as_str(), Some("Channel"));
    assert_eq!(inline_disclosed[0]["value"].as_str(), Some("#general"));
    // Action risk is `write` → "med" class.
    assert_eq!(exec["risk"].as_str(), Some("med"));
    assert!(
        !exec["permission_keys"]
            .as_array()
            .expect("inline permission_keys present")
            .is_empty(),
        "expected at least one permission key in inline envelope: {exec:?}"
    );
    let inline_detail = exec["action_detail"]
        .as_str()
        .expect("inline action_detail present");
    assert!(
        inline_detail.contains("[REDACTED]") && !inline_detail.contains("sk_SENSITIVE_123"),
        "inline action_detail should be redacted:\n{inline_detail}"
    );

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

    // Parity: the inline envelope and the GET read path are rendered through
    // the same helpers, so risk + action_detail must be byte-identical for the
    // same approval. Guards against the two paths drifting.
    assert_eq!(exec["risk"], approval["risk"], "inline vs GET risk drift");
    assert_eq!(
        exec["action_detail"], approval["action_detail"],
        "inline vs GET action_detail drift"
    );
    assert_eq!(
        exec["disclosed_fields"], approval["disclosed_fields"],
        "inline vs GET disclosed_fields drift"
    );
    assert_eq!(
        exec["permission_keys"], approval["permission_keys"],
        "inline vs GET permission_keys drift"
    );
}

/// Fixture for the resolver-backed disclosure flow: `thing_id` carries a
/// `resolve` declaration (GET /things/{thing_id}, pick `name` — served by the
/// generic upstream fake), and the disclose filter reads `.resolved.*` with a
/// `.params.*` fallback.
const RESOLVER_TEMPLATE_YAML_FMT: &str = r#"openapi: "3.1.0"
info:
  title: "Resolver Disclose Fixture"
  key: "thingsvc"
servers:
  - url: "http://HOST_PLACEHOLDER"
paths:
  /things/{thing_id}/archive:
    parameters:
      - name: thing_id
        in: path
        required: true
        schema: {type: string}
        resolve:
          get: /things/{thing_id}
          pick: name
      - name: other_id
        in: query
        required: false
        schema: {type: string}
        # The fake's catch-all echo has no `name` key, so this resolution
        # always fails — the chained disclose filter below must fall back to
        # the raw param (resolve_display_params silently skips failures).
        resolve:
          get: /missing/{other_id}
          pick: name
    post:
      operationId: archive_thing
      summary: "Archive {thing_id}"
      risk: write
      scope_param: thing_id
      disclose:
        - label: Thing
          filter: '.resolved.thing_id // .params.thing_id'
        - label: Other
          filter: '.resolved.other_id // .params.other_id'
"#;

/// End-to-end: display-param resolution feeds `.resolved.*` in the disclose
/// projection at BOTH disclosure sites — approval-create (gated call) and
/// audit-write (executed call). Also pins the timing property: the resolver
/// GET fires exactly once per call, at resolve time, and the display name
/// rides in the resolved metadata to audit-write (so a delete/archive action
/// still names its target after the object is gone upstream).
#[tokio::test]
async fn resolver_display_names_flow_into_disclosed_fields() {
    let pool = common::test_pool().await;
    let mock_addr = start_mock().await;
    let mock_base = format!("http://{mock_addr}");

    // Template hosts are persisted without scheme/port ("127.0.0.1"), so both
    // the executor and the resolver GETs need the e2e base override to reach
    // the in-test fake — same mechanism the docker e2e stack uses.
    let override_base = mock_base.clone();
    let (base, client) = start_api_with_registry_customized(pool.clone(), None, move |cfg| {
        cfg.service_base_overrides
            .insert("127.0.0.1".to_string(), override_base);
    })
    .await;
    let (_org_id, ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    let yaml = RESOLVER_TEMPLATE_YAML_FMT.replace("HOST_PLACEHOLDER", &mock_addr.to_string());
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
        Some("thingsvc"),
        "template register failed: {create:?}"
    );

    common::grant_service_to_everyone(&base, &client, &admin_key, "thingsvc").await;

    // ── Site 1: approval-create ─────────────────────────────────────────
    // No permission rule yet + forced secrets → gap → 202 pending approval.
    // The resolver GET has already run (resolution happens at resolve time,
    // before the permission gate), so the disclosed field must carry the
    // fake's display name, not the opaque ID.
    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "thingsvc",
            "action": "archive_thing",
            "params": {"thing_id": "tt-42", "other_id": "ot-7"},
            "secrets": [
                {"name": "nonexistent", "inject_as": "header", "header_name": "X-Resolve-Test"}
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
    let disclosed = exec["disclosed_fields"]
        .as_array()
        .expect("inline disclosed_fields present");
    assert_eq!(disclosed.len(), 2);
    assert_eq!(disclosed[0]["label"].as_str(), Some("Thing"));
    assert_eq!(
        disclosed[0]["value"].as_str(),
        Some("Thing tt-42"),
        "disclosed value should be the resolver display name, got: {disclosed:?}"
    );
    // Chained-field degradation: `other_id`'s resolver GET returns a payload
    // without the picked key, so `.resolved.other_id` is absent and the
    // `// .params.other_id` arm must surface the raw value.
    assert_eq!(disclosed[1]["label"].as_str(), Some("Other"));
    assert_eq!(
        disclosed[1]["value"].as_str(),
        Some("ot-7"),
        "failed resolution should fall back to the raw param, got: {disclosed:?}"
    );
    // The raw-payload projection now carries the resolved map too.
    let detail = exec["action_detail"].as_str().expect("action_detail");
    assert!(
        detail.contains("\"resolved\"") && detail.contains("Thing tt-42"),
        "action_detail should include the resolved projection:\n{detail}"
    );

    // ── Site 2: audit-write ─────────────────────────────────────────────
    // Grant the permission so the same call executes end-to-end (POST lands
    // on the fake's echo), then read the audit row's disclosed fields.
    let perm = client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({"identity_id": ident_id, "action_pattern": "thingsvc:*:*"}))
        .send()
        .await
        .unwrap();
    assert_eq!(perm.status(), 200, "permission grant failed");

    // Reset the fake's request log so the GET-count assertion below only
    // sees this call's traffic.
    client
        .delete(format!("{mock_base}/__received_requests"))
        .send()
        .await
        .unwrap();

    let exec: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "service": "thingsvc",
            "action": "archive_thing",
            "params": {"thing_id": "tt-42"},
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
    let audit_disclosed = executed["detail"]["disclosed"]
        .as_array()
        .expect("audit detail.disclosed present");
    assert_eq!(audit_disclosed[0]["label"].as_str(), Some("Thing"));
    assert_eq!(
        audit_disclosed[0]["value"].as_str(),
        Some("Thing tt-42"),
        "audit-write disclosure should reuse the resolve-time display name"
    );
    // Interpolated description consumes the same resolved map.
    assert!(
        executed["description"]
            .as_str()
            .is_some_and(|d| d.contains("Thing tt-42")),
        "description should interpolate the resolved name: {executed:?}"
    );

    // Timing property: exactly ONE resolver GET for the executed call — the
    // display name rode in the resolved metadata to audit-write; it was not
    // re-fetched after execution.
    let received: Value = client
        .get(format!("{mock_base}/__received_requests"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let requests = received["requests"].as_array().unwrap();
    let resolver_gets = requests
        .iter()
        .filter(|r| {
            r["method"].as_str() == Some("GET") && r["uri"].as_str() == Some("/things/tt-42")
        })
        .count();
    assert_eq!(
        resolver_gets, 1,
        "expected exactly one resolve-time GET, got requests: {requests:?}"
    );
    assert!(
        requests.iter().any(|r| r["method"].as_str() == Some("POST")
            && r["uri"].as_str() == Some("/things/tt-42/archive")),
        "the action itself should have executed against the fake: {requests:?}"
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
