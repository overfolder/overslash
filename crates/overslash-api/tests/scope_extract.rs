//! `scope_param` value extractors: a permission key minted from a value
//! *inside* a structured param, and what happens when the extractor cannot
//! produce one.
//!
//! The unit tests in `overslash-core` cover the key grammar and the failure
//! classification. What only an end-to-end run proves is the part that matters
//! most: that the derived key actually reaches the gate, that a failure parks
//! the call on an approval instead of widening it, and that the approval it
//! parks on cannot be turned into a standing grant.

use crate::common::{self, bootstrap_org_identity, start_api_with_registry_customized, start_mock};
use serde_json::{Value, json};

/// Recipients shaped the way Graph shapes them — the case a bare `scope_param`
/// cannot express, because the key's value would be the whole JSON object.
///
/// `risk: write` with no blanket rule is what makes the gate observable: the
/// call parks on an approval whose `permission_keys` are the assertion.
const TEMPLATE_YAML_FMT: &str = r#"openapi: "3.1.0"
info:
  title: "Scope Extract Fixture"
  key: "scoper"
servers:
  - url: "http://HOST_PLACEHOLDER"
components:
  securitySchemes:
    token:
      type: apiKey
      in: header
      name: X-Token
      default_secret_name: scoper_token
security:
  - token: []
paths:
  /send:
    post:
      operationId: send_mail
      summary: "Send"
      risk: write
      scope_param:
        - param: message
          label: recipient
          extract: >-
            .toRecipients[]?, .ccRecipients[]? | .emailAddress.address
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: object
                  properties:
                    toRecipients:
                      type: array
                      items:
                        type: object
                        properties:
                          emailAddress:
                            type: object
                            properties:
                              address: {type: string}
                    ccRecipients:
                      type: array
                      items:
                        type: object
                        properties:
                          emailAddress:
                            type: object
                            properties:
                              address: {type: string}
  /brittle:
    post:
      operationId: brittle_send
      summary: "Send with an extractor that cannot survive a scalar"
      risk: write
      scope_param:
        - param: message
          label: recipient
          extract: ".toRecipients[] | .emailAddress.address"
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                message: {type: object}
"#;

async fn setup() -> (String, reqwest::Client, String, String) {
    common::allow_loopback_ssrf();
    let pool = common::test_pool().await;
    let mock_addr = start_mock().await;
    let override_base = format!("http://{mock_addr}");
    let (base, client) = start_api_with_registry_customized(pool.clone(), None, move |cfg| {
        cfg.service_base_overrides
            .insert("127.0.0.1".to_string(), override_base);
    })
    .await;
    let (_org_id, _ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

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
        Some("scoper"),
        "template register failed: {create:?}"
    );

    // Stored before the instance exists, so the slot has something to bind to:
    // the scheme is what makes `needs_gate` true, and an unbound slot fails
    // resolution with `needs_authentication` before the gate is ever reached.
    let stored = client
        .put(format!("{base}/v1/secrets/scoper_token"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "value": "t0ken" }))
        .send()
        .await
        .unwrap();
    assert!(stored.status().is_success(), "secret store failed");

    let everyone_id = common::everyone_group_id(&base, &client, &admin_key).await;
    let svc: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": "scoper",
            "name": "scoper",
            "user_level": false,
            "credentials": { "token": "scoper_token" },
            "groups": [{
                "group_id": everyone_id.to_string(),
                "access_level": "write",
            }],
            "status": "active",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        svc["id"].as_str().is_some(),
        "service create failed: {svc:?}"
    );

    (base, client, agent_key, admin_key)
}

async fn call(base: &str, client: &reqwest::Client, key: &str, body: Value) -> Value {
    client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn recipients(addresses: &[&str]) -> Value {
    Value::Array(
        addresses
            .iter()
            .map(|a| json!({ "emailAddress": { "address": a } }))
            .collect(),
    )
}

#[tokio::test]
async fn a_key_is_minted_per_address_inside_the_structured_param() {
    let (base, client, agent_key, _) = setup().await;
    let body = call(
        &base,
        &client,
        &agent_key,
        json!({
            "service": "scoper",
            "action": "send_mail",
            "params": { "message": {
                "toRecipients": recipients(&["a@x.com"]),
                "ccRecipients": recipients(&["b@y.com"]),
            }},
        }),
    )
    .await;

    assert_eq!(
        body["status"].as_str(),
        Some("pending_approval"),
        "a write with no rule must gate: {body:?}"
    );
    let mut keys: Vec<&str> = body["permission_keys"]
        .as_array()
        .expect("permission_keys on the approval")
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "scoper:send_mail:recipient=a@x.com",
            "scoper:send_mail:recipient=b@y.com"
        ],
        "both headers fan out under one label, from inside the param"
    );
}

#[tokio::test]
async fn an_absent_optional_header_contributes_nothing_rather_than_failing() {
    let (base, client, agent_key, _) = setup().await;
    let body = call(
        &base,
        &client,
        &agent_key,
        json!({
            "service": "scoper",
            "action": "send_mail",
            "params": { "message": { "toRecipients": recipients(&["a@x.com"]) } },
        }),
    )
    .await;
    let keys = body["permission_keys"].as_array().unwrap();
    assert_eq!(
        keys.len(),
        1,
        "an omitted `cc` must not break the send: {keys:?}"
    );
    assert_eq!(keys[0], "scoper:send_mail:recipient=a@x.com");
}

#[tokio::test]
async fn a_failed_extractor_gates_on_a_sentinel_instead_of_widening() {
    let (base, client, agent_key, _) = setup().await;
    // `.toRecipients[]` over a scalar is a jq runtime error, which is the
    // shape a real template hits when an upstream changes a field's type.
    let body = call(
        &base,
        &client,
        &agent_key,
        json!({
            "service": "scoper",
            "action": "brittle_send",
            "params": { "message": { "toRecipients": "a@x.com" } },
        }),
    )
    .await;

    assert_eq!(
        body["status"].as_str(),
        Some("pending_approval"),
        "a failure is an approval, not a 403 — a template typo must not be an \
         outage with no human path forward: {body:?}"
    );
    let keys: Vec<&str> = body["permission_keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    assert_eq!(
        keys,
        vec!["scoper:brittle_send:scope_error=recipient/message"]
    );
    assert!(
        !keys.iter().any(|k| k.ends_with(":*")),
        "the wildcard fallback must be suppressed, or 'we could not tell' would \
         resolve to the key an unscoped action mints: {keys:?}"
    );
}

#[tokio::test]
async fn a_sentinel_approval_cannot_be_turned_into_a_standing_grant() {
    let (base, client, agent_key, admin_key) = setup().await;
    let body = call(
        &base,
        &client,
        &agent_key,
        json!({
            "service": "scoper",
            "action": "brittle_send",
            "params": { "message": { "toRecipients": "a@x.com" } },
        }),
    )
    .await;
    let approval_id = body["approval_id"].as_str().unwrap().to_string();

    // An explicitly typed key covering only the sentinel is refused, and the
    // message says why rather than claiming the key is unrelated.
    let refused: Value = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "resolution": "allow_remember",
            "remember_keys": ["scoper:brittle_send:scope_error=**"],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let message = refused["detail"]
        .as_str()
        .or_else(|| refused["error"].as_str())
        .unwrap_or_default()
        .to_string()
        + refused["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("scope_error"),
        "the refusal must name the reason: {refused:?}"
    );

    // And a bare "Allow & Remember" degrades to a one-shot allow rather than
    // silently writing a rule for "whenever we cannot tell".
    let resolved: Value = client
        .post(format!("{base}/v1/approvals/{approval_id}/resolve"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "resolution": "allow_remember" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        resolved["status"].as_str(),
        Some("allowed"),
        "the call itself is still approvable: {resolved:?}"
    );

    let rules: Value = client
        .get(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let written = rules["rules"]
        .as_array()
        .or_else(|| rules.as_array())
        .map(|rs| {
            rs.iter()
                .filter(|r| {
                    r["action_pattern"]
                        .as_str()
                        .is_some_and(|p| p.contains("scope_error"))
                })
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        written, 0,
        "no rule may be written for a sentinel: {rules:?}"
    );
}
