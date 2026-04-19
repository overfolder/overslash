//! Integration tests for `POST /v1/templates/import` and the
//! `/v1/templates/drafts*` endpoints.

mod common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

async fn bootstrap() -> (
    String,
    Client,
    Uuid,
    String, // admin_key
    String, // write_key
) {
    let (pool, fixtures) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool).await;
    (
        format!("http://{addr}"),
        client,
        fixtures.org_id,
        fixtures.admin_key,
        fixtures.write_key,
    )
}

const SAMPLE_OPENAPI: &str = r#"
openapi: 3.1.0
info:
  title: Widgets API
servers:
  - url: https://api.widgets.test
components:
  securitySchemes:
    bearer:
      type: http
      scheme: bearer
      x-overslash-default_secret_name: widgets_token
paths:
  /widgets:
    get:
      operationId: list_widgets
      summary: List widgets
      x-overslash-risk: read
    post:
      operationId: create_widget
      summary: Create a widget
      x-overslash-risk: write
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name:
                  type: string
                  description: Widget name
  /widgets/{id}:
    get:
      operationId: get_widget
      summary: Get widget {id}
      x-overslash-risk: read
      parameters:
        - name: id
          in: path
          required: true
          description: Widget ID
          schema:
            type: string
"#;

#[tokio::test]
async fn test_import_inline_body_creates_draft() {
    let (base, client, _org_id, admin_key, _) = bootstrap().await;

    let resp = client
        .post(format!("{base}/v1/templates/import"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "source": {
                "type": "body",
                "content_type": "application/yaml",
                "body": SAMPLE_OPENAPI,
            },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "import failed: {:?}", resp.text().await);

    let body: Value = resp.json().await.unwrap();
    assert!(body["id"].is_string());
    assert_eq!(body["tier"], "org");
    assert!(body["validation"]["valid"].as_bool().unwrap_or(false));
    assert_eq!(body["operations"].as_array().unwrap().len(), 3);
    assert_eq!(body["preview"]["key"], "widgets-api");
    assert_eq!(body["preview"]["actions"].as_array().unwrap().len(), 3);

    // The draft is invisible to the regular listing.
    let list_resp = client
        .get(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    let templates: Value = list_resp.json().await.unwrap();
    assert!(
        !templates
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["key"] == "widgets-api")
    );

    // But it shows up via /v1/templates/drafts.
    let draft_list = client
        .get(format!("{base}/v1/templates/drafts"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    let drafts: Value = draft_list.json().await.unwrap();
    assert_eq!(drafts.as_array().unwrap().len(), 1);
    assert_eq!(drafts[0]["preview"]["key"], "widgets-api");
}

#[tokio::test]
async fn test_import_partial_selection_filters_actions() {
    let (base, client, _org_id, admin_key, _) = bootstrap().await;

    let resp = client
        .post(format!("{base}/v1/templates/import"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "source": { "type": "body", "body": SAMPLE_OPENAPI },
            "include_operations": ["list_widgets"],
            "key": "selected-widgets",
            "display_name": "Selected Widgets",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    // All 3 operations appear in the enumeration, but only 1 is included.
    let ops = body["operations"].as_array().unwrap();
    assert_eq!(ops.len(), 3);
    assert_eq!(ops.iter().filter(|o| o["included"] == true).count(), 1);
    // The compiled preview only has the selected one as an action.
    assert_eq!(body["preview"]["actions"].as_array().unwrap().len(), 1);
    assert_eq!(body["preview"]["key"], "selected-widgets");
    assert_eq!(body["preview"]["display_name"], "Selected Widgets");
}

#[tokio::test]
async fn test_promote_draft_makes_it_active() {
    let (base, client, _org_id, admin_key, _) = bootstrap().await;

    let resp = client
        .post(format!("{base}/v1/templates/import"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "source": { "type": "body", "body": SAMPLE_OPENAPI },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let draft: Value = resp.json().await.unwrap();
    let draft_id = draft["id"].as_str().unwrap();

    let promote_resp = client
        .post(format!("{base}/v1/templates/drafts/{draft_id}/promote"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        promote_resp.status(),
        200,
        "promote failed: {:?}",
        promote_resp.text().await
    );
    let promoted: Value = promote_resp.json().await.unwrap();
    assert_eq!(promoted["key"], "widgets-api");
    assert_eq!(promoted["tier"], "org");

    // Template now surfaces via the regular list.
    let list_resp = client
        .get(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    let templates: Value = list_resp.json().await.unwrap();
    assert!(
        templates
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["key"] == "widgets-api")
    );

    // And it's gone from the drafts list.
    let drafts_resp = client
        .get(format!("{base}/v1/templates/drafts"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    let drafts: Value = drafts_resp.json().await.unwrap();
    assert!(drafts.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_promote_fails_validation_keeps_draft() {
    let (base, client, _org_id, admin_key, _) = bootstrap().await;

    // An OpenAPI doc missing operationId on an action produces a validation
    // error at promote time, but the import endpoint accepts it because we
    // synthesize ids. Instead, craft a source that compiles lenient but
    // fails the strict validator by giving an action an invalid `risk`.
    let bad_src = r#"
openapi: 3.1.0
info:
  title: Bad
  key: bad-api
servers:
  - url: https://bad.example.com
paths:
  /x:
    get:
      operationId: x
      summary: x
      x-overslash-risk: nope
"#;
    let resp = client
        .post(format!("{base}/v1/templates/import"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "source": { "type": "body", "body": bad_src },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let draft: Value = resp.json().await.unwrap();
    let draft_id = draft["id"].as_str().unwrap();
    assert!(!draft["validation"]["valid"].as_bool().unwrap());

    let promote_resp = client
        .post(format!("{base}/v1/templates/drafts/{draft_id}/promote"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(promote_resp.status(), 400);
    let body: Value = promote_resp.json().await.unwrap();
    assert_eq!(body["error"], "validation_failed");

    // Draft still exists.
    let get_resp = client
        .get(format!("{base}/v1/templates/drafts/{draft_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 200);
}

#[tokio::test]
async fn test_update_draft_replaces_yaml() {
    let (base, client, _org_id, admin_key, _) = bootstrap().await;

    let import_resp = client
        .post(format!("{base}/v1/templates/import"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "source": { "type": "body", "body": SAMPLE_OPENAPI } }))
        .send()
        .await
        .unwrap();
    let draft: Value = import_resp.json().await.unwrap();
    let draft_id = draft["id"].as_str().unwrap();

    // Replace the YAML with a minimal hand-edited version.
    let edited = r#"
openapi: 3.1.0
info:
  title: Edited
  x-overslash-key: edited-api
servers:
  - url: https://edited.example.com
paths:
  /only:
    get:
      operationId: only
      summary: only
      x-overslash-risk: read
"#;
    let put_resp = client
        .put(format!("{base}/v1/templates/drafts/{draft_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": edited }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        put_resp.status(),
        200,
        "put failed: {:?}",
        put_resp.text().await
    );
    let body: Value = put_resp.json().await.unwrap();
    assert_eq!(body["preview"]["key"], "edited-api");
    assert_eq!(body["preview"]["actions"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_discard_draft_deletes_row() {
    let (base, client, _org_id, admin_key, _) = bootstrap().await;

    let import_resp = client
        .post(format!("{base}/v1/templates/import"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "source": { "type": "body", "body": SAMPLE_OPENAPI } }))
        .send()
        .await
        .unwrap();
    let draft: Value = import_resp.json().await.unwrap();
    let draft_id = draft["id"].as_str().unwrap();

    let del_resp = client
        .delete(format!("{base}/v1/templates/drafts/{draft_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(del_resp.status(), 200);

    let get_resp = client
        .get(format!("{base}/v1/templates/drafts/{draft_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(get_resp.status(), 404);
}

#[tokio::test]
async fn test_import_url_rejects_private_ip() {
    let (base, client, _org_id, admin_key, _) = bootstrap().await;

    let resp = client
        .post(format!("{base}/v1/templates/import"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "source": { "type": "url", "url": "http://10.0.0.1/spec.yaml" },
        }))
        .send()
        .await
        .unwrap();
    // Either 400 (private IP rejected) or a DNS resolution error wrapped as
    // 400 is acceptable.  Anything 2xx would be a security regression.
    let status = resp.status();
    assert!(
        status == 400,
        "expected 400 for private IP, got {status}: {:?}",
        resp.text().await
    );
}

#[tokio::test]
async fn test_import_url_rejects_non_http_scheme() {
    let (base, client, _org_id, admin_key, _) = bootstrap().await;

    let resp = client
        .post(format!("{base}/v1/templates/import"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "source": { "type": "url", "url": "file:///etc/passwd" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_nonadmin_cannot_create_org_draft() {
    let (base, client, _org_id, _admin_key, write_key) = bootstrap().await;

    // Non-admin attempting an org-level import should be rejected, the same
    // way `POST /v1/templates` does.
    let resp = client
        .post(format!("{base}/v1/templates/import"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({
            "source": { "type": "body", "body": SAMPLE_OPENAPI },
            "user_level": false,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn test_discard_refuses_if_draft_was_promoted_between_check_and_delete() {
    let (base, client, _org_id, admin_key, _) = bootstrap().await;

    let resp = client
        .post(format!("{base}/v1/templates/import"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "source": { "type": "body", "body": SAMPLE_OPENAPI } }))
        .send()
        .await
        .unwrap();
    let draft: Value = resp.json().await.unwrap();
    let draft_id = draft["id"].as_str().unwrap().to_string();

    // Simulate a successful race: promote the draft first, then try to discard.
    // `delete_draft`'s SQL filters `status = 'draft'`, so the delete matches
    // zero rows and the handler must return 4xx instead of dropping the now-
    // active row.
    let promote = client
        .post(format!("{base}/v1/templates/drafts/{draft_id}/promote"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(promote.status(), 200);

    let discard = client
        .delete(format!("{base}/v1/templates/drafts/{draft_id}"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    // Draft-scoped load_draft_for_write filters status='draft' too, so the
    // handler 404s before it ever reaches delete_draft. Either way, we must
    // not return 200 — that would mean we deleted an active template.
    let status = discard.status();
    assert!(
        status == 404 || status == 409,
        "discard against a promoted draft must fail; got {status}"
    );

    // The active template must still be reachable via the normal lookup.
    let detail = client
        .get(format!("{base}/v1/templates/widgets-api"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(detail.status(), 200);
}

#[tokio::test]
async fn test_import_draft_id_replaces_source() {
    let (base, client, _org_id, admin_key, _) = bootstrap().await;

    let import_resp = client
        .post(format!("{base}/v1/templates/import"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "source": { "type": "body", "body": SAMPLE_OPENAPI } }))
        .send()
        .await
        .unwrap();
    let draft: Value = import_resp.json().await.unwrap();
    let draft_id = draft["id"].as_str().unwrap().to_string();

    // Re-import with a different source targeting the same draft_id.
    let alt = r#"
openapi: 3.1.0
info:
  title: Replaced
  x-overslash-key: replaced-api
servers: [{"url": "https://replaced.example.com"}]
paths:
  /a:
    get: {operationId: a, summary: a, x-overslash-risk: read}
"#;
    let resp = client
        .post(format!("{base}/v1/templates/import"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "source": { "type": "body", "body": alt },
            "draft_id": draft_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["id"].as_str().unwrap(), draft_id);
    assert_eq!(body["preview"]["key"], "replaced-api");
    assert_eq!(body["preview"]["actions"].as_array().unwrap().len(), 1);

    // Only one draft row in the listing.
    let drafts_resp = client
        .get(format!("{base}/v1/templates/drafts"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    let drafts: Value = drafts_resp.json().await.unwrap();
    assert_eq!(drafts.as_array().unwrap().len(), 1);
}
