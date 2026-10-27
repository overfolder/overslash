//! A subaction's own `required_scopes` gate the call, whichever way it is
//! reached. `resolve_request`'s scope check only ever sees the parent action,
//! so a classified call (or a callable variant lowered into its parent) has to
//! have its variants' scopes checked separately — before the instance is
//! consumed — or a variant needing a scope the connection lacks would go
//! upstream and fail there as a generic error.

#![allow(clippy::disallowed_methods)] // runtime sqlx::query for one-off test seeds

use crate::common;

use serde_json::{Value, json};

const BASIC: &str = "https://example.test/auth/basic";
const ADMIN: &str = "https://example.test/auth/admin";

const TEMPLATE: &str = r#"openapi: 3.1.0
info:
  title: Scoped Batch
  key: scopedbatch
servers:
  - url: https://scopedbatch.invalid
components:
  securitySchemes:
    oauth:
      type: oauth2
      provider: google
      flows:
        authorizationCode:
          authorizationUrl: https://accounts.google.com/o/oauth2/v2/auth
          tokenUrl: https://oauth2.googleapis.com/token
          scopes:
            https://example.test/auth/basic: ""
            https://example.test/auth/admin: ""
paths:
  /batch:
    post:
      operationId: run_batch
      description: Run a batch of operations
      risk: write
      security:
        - oauth: [https://example.test/auth/basic]
      disclose:
        - label: Ops
          filter: '.body | tojson'
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                ops:
                  type: array
                  items: {type: object, properties: {kind: {type: string}, id: {type: string}}}
      subactions:
        each: '.ops[]'
        variants:
          - name: purge_thing
            match: '.kind == "purge"'
            description: Permanently purge a thing
            risk: delete
            required_scopes: [https://example.test/auth/admin]
            input_schema:
              type: object
              properties:
                id: {type: string}
              required: [id]
            transform: '{ops: [{kind: "purge", id: .id}]}'
"#;

struct Fx {
    base: String,
    client: reqwest::Client,
    key: String,
}

async fn setup() -> Fx {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"openapi": TEMPLATE, "user_level": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "template: {}",
        resp.text().await.unwrap()
    );

    let put = client
        .put(format!("{base}/v1/org-oauth-credentials/google"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({
            "client_id": "test_id.apps.googleusercontent.com",
            "client_secret": "GOCSPX-test_secret",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.status(),
        200,
        "org oauth creds: {}",
        put.text().await.unwrap()
    );

    // The owner's default Google connection holds the basic scope only.
    sqlx::query(
        "INSERT INTO connections \
         (id, org_id, identity_id, provider_key, encrypted_access_token, \
          scopes, account_email, is_default) \
         VALUES ($1, $2, $3, 'google', $4, $5, 'alice@example.test', true)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(org_id)
    .bind(owner_id)
    .bind(b"fake_token".as_ref())
    .bind(vec![BASIC.to_string()])
    .execute(&pool)
    .await
    .unwrap();

    let inst: Value = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"name": "scopedbatch", "template_key": "scopedbatch"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(inst["id"].is_string(), "service: {inst}");
    common::grant_service_to_everyone(&base, &client, &admin_key, "scopedbatch").await;
    client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
        .json(&json!({"identity_id": ident_id, "action_pattern": "scopedbatch:**"}))
        .send()
        .await
        .unwrap();
    Fx { base, client, key }
}

impl Fx {
    async fn call(&self, action: &str, params: Value) -> (u16, Value) {
        let resp = self
            .client
            .post(format!("{}/v1/actions/call", self.base))
            .header(common::auth(&self.key).0, common::auth(&self.key).1)
            .json(&json!({"service": "scopedbatch", "action": action, "params": params}))
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }
}

fn assert_missing_admin(status: u16, body: &Value) {
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "missing_scopes", "{body}");
    assert_eq!(body["missing"], json!([ADMIN]), "{body}");
}

#[tokio::test]
async fn a_classified_call_is_held_to_its_variants_scopes() {
    let fx = setup().await;
    let (status, body) = fx
        .call("run_batch", json!({"ops": [{"kind": "purge", "id": "a"}]}))
        .await;
    assert_missing_admin(status, &body);

    // A batch no variant claims needs only the parent's scope, which the
    // connection has: it gets past the gate (and fails later, upstream).
    let (_, body) = fx
        .call("run_batch", json!({"ops": [{"kind": "rename", "id": "a"}]}))
        .await;
    assert_ne!(body["error"], "missing_scopes", "{body}");
}

#[tokio::test]
async fn a_callable_variant_is_held_to_its_own_scopes() {
    let fx = setup().await;
    let (status, body) = fx.call("purge_thing", json!({"id": "a"})).await;
    assert_missing_admin(status, &body);
}
