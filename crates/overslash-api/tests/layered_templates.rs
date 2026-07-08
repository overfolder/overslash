//! Integration tests for layered service templates (derived layers + the fold):
//! masks, extensions, live-pointer inheritance, authority, and the delete guard.
//! See docs/design/layered-service-templates.md.

mod common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

async fn bootstrap() -> (String, Client, Uuid, String, String) {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool).await;
    (
        format!("http://{addr}"),
        client,
        fx.org_id,
        fx.admin_key,
        fx.write_key,
    )
}

/// A standalone OpenAPI base with three actions: `list_a` (read), `create_b`
/// (write), `delete_c` (delete).
fn base_openapi(key: &str) -> String {
    format!(
        r#"openapi: 3.1.0
info:
  title: {key} base
  key: {key}
servers:
  - url: https://{key}.example.com
paths:
  /a:
    get:
      operationId: list_a
      summary: List A
      risk: read
  /b:
    post:
      operationId: create_b
      summary: Create B
      risk: write
  /c/{{id}}:
    delete:
      operationId: delete_c
      summary: Delete C
      risk: delete
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
"#
    )
}

/// Create a standalone org base template, returning its id.
async fn create_base(base: &str, client: &Client, admin_key: &str, key: &str) {
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({ "openapi": base_openapi(key) }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "create base failed: {:?}",
        resp.text().await
    );
}

async fn get_template(base: &str, client: &Client, key: &str, admin_key: &str) -> Value {
    client
        .get(format!("{base}/v1/templates/{key}"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn action_keys(detail: &Value) -> Vec<String> {
    detail["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["key"].as_str().unwrap().to_string())
        .collect()
}

async fn enable_full_user_policy(base: &str, client: &Client, org_id: Uuid, admin_key: &str) {
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({ "user_template_policy": "full" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ── Masks: allowlist shrinks the surface; masked action vanishes ───────────

#[tokio::test]
async fn derived_layer_masks_actions_and_hides_from_action_surface() {
    let (base, client, _org, admin_key, _write) = bootstrap().await;
    create_base(&base, &client, &admin_key, "zbase").await;

    // Distinct-key derived layer that allowlists only 2 of the 3 base actions.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "extends": "zbase",
            "key": "zbase_curated",
            "display_name": "Curated",
            "delta": { "allowlist": ["list_a", "create_b"] },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "create derived failed: {:?}",
        resp.text().await
    );

    let detail = get_template(&base, &client, "zbase_curated", &admin_key).await;
    assert_eq!(detail["extends"], "zbase");
    let mut keys = action_keys(&detail);
    keys.sort();
    assert_eq!(keys, vec!["create_b", "list_a"]);

    // The masked-out action vanishes from the resolver surface execution uses.
    let resp = client
        .get(format!(
            "{base}/v1/templates/zbase_curated/actions/delete_c"
        ))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "masked action must be unreachable");

    // The base itself is untouched and still visible with all 3 actions.
    let base_detail = get_template(&base, &client, "zbase", &admin_key).await;
    assert_eq!(action_keys(&base_detail).len(), 3);
}

// ── Distinct-key layer coexists with its base in the catalog ───────────────

#[tokio::test]
async fn distinct_key_layer_coexists_with_base() {
    let (base, client, _org, admin_key, _write) = bootstrap().await;
    create_base(&base, &client, &admin_key, "zbase").await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "extends": "zbase",
            "key": "zbase_alt",
            "delta": { "allowlist": ["list_a"] },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let list: Value = client
        .get(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = list.as_array().unwrap();
    let zbase = rows.iter().find(|r| r["key"] == "zbase").unwrap();
    let alt = rows.iter().find(|r| r["key"] == "zbase_alt").unwrap();
    assert_eq!(zbase["action_count"], 3);
    assert_eq!(alt["action_count"], 1);
    assert_eq!(alt["extends"], "zbase");
}

// ── Live pointer: editing the base propagates to the derived layer ─────────

#[tokio::test]
async fn live_pointer_base_change_propagates() {
    let (base, client, _org, admin_key, _write) = bootstrap().await;
    create_base(&base, &client, &admin_key, "zbase").await;

    // Derived layer with an empty delta inherits the whole base surface.
    let created: Value = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "extends": "zbase", "key": "zbase_all", "delta": {} }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created["extends"], "zbase");
    assert_eq!(
        get_template(&base, &client, "zbase_all", &admin_key).await["actions"]
            .as_array()
            .unwrap()
            .len(),
        3
    );

    // Grow the base to 4 actions.
    let base_id = get_template(&base, &client, "zbase", &admin_key).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let mut grown = base_openapi("zbase");
    grown.push_str(
        "  /d:\n    get:\n      operationId: list_d\n      summary: List D\n      risk: read\n",
    );
    let resp = client
        .put(format!("{base}/v1/templates/{base_id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": grown }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // The derived layer now reflects the new action WITHOUT being re-saved.
    let detail = get_template(&base, &client, "zbase_all", &admin_key).await;
    assert_eq!(
        detail["actions"].as_array().unwrap().len(),
        4,
        "live pointer must track upstream"
    );
    assert!(action_keys(&detail).contains(&"list_d".to_string()));
}

// ── Target validation & risk clamp direction ───────────────────────────────

#[tokio::test]
async fn extends_missing_base_rejected() {
    let (base, client, _org, admin_key, _write) = bootstrap().await;
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "extends": "nope_no_such", "key": "x", "delta": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn risk_clamps_up_but_not_down() {
    let (base, client, _org, admin_key, _write) = bootstrap().await;
    create_base(&base, &client, &admin_key, "zbase").await;

    // Clamp UP: create_b write → delete is accepted.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "extends": "zbase",
            "key": "zbase_up",
            "delta": { "action_patch": { "create_b": { "risk": "delete" } } },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let action: Value = client
        .get(format!("{base}/v1/templates/zbase_up/actions/create_b"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(action["risk"], "delete");

    // Clamp DOWN: delete_c delete → write is rejected.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "extends": "zbase",
            "key": "zbase_down",
            "delta": { "action_patch": { "delete_c": { "risk": "write" } } },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "risk clamp-down must be rejected");
}

// ── Authority: user_template_policy gates user-namespace layers ─────────────

#[tokio::test]
async fn user_policy_gates_derived_layer_creation() {
    let (base, client, org_id, admin_key, write_key) = bootstrap().await;
    create_base(&base, &client, &admin_key, "zbase").await;

    let make_user_layer = |key: &'static str| {
        let base = base.clone();
        let client = client.clone();
        let write_key = write_key.clone();
        async move {
            client
                .post(format!("{base}/v1/templates"))
                .header(auth(&write_key).0, auth(&write_key).1)
                .json(&json!({
                    "extends": "zbase",
                    "key": key,
                    "user_level": true,
                    "delta": { "allowlist": ["list_a"] },
                }))
                .send()
                .await
                .unwrap()
        }
    };

    // Default policy `none` → blocked.
    assert_eq!(make_user_layer("mine_a").await.status(), 403);

    // `restrictive` is reserved → still blocked.
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "user_template_policy": "restrictive" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(make_user_layer("mine_b").await.status(), 403);

    // `full` → allowed.
    enable_full_user_policy(&base, &client, org_id, &admin_key).await;
    let resp = make_user_layer("mine_c").await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["tier"], "user");
}

// ── Hard ceiling: a user layer over an org layer can't re-expose ───────────

#[tokio::test]
async fn user_layer_inherits_org_curation_as_ceiling() {
    let (base, client, org_id, admin_key, write_key) = bootstrap().await;
    create_base(&base, &client, &admin_key, "zbase").await;
    enable_full_user_policy(&base, &client, org_id, &admin_key).await;

    // Org curates the base down to {list_a, create_b}.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "extends": "zbase",
            "key": "team_api",
            "delta": { "allowlist": ["list_a", "create_b"] },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // A user layer extends the ORG layer and tries to re-add delete_c.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({
            "extends": "team_api",
            "key": "my_api",
            "user_level": true,
            "delta": { "allowlist": ["list_a", "delete_c"] },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Effective surface is {list_a} — delete_c was hidden by the org ceiling and
    // the user layer folds over the org layer's *output*, so it can't re-expose it.
    let detail = get_template(&base, &client, "my_api", &write_key).await;
    assert_eq!(action_keys(&detail), vec!["list_a".to_string()]);
}

// ── Delete referential guard ───────────────────────────────────────────────

#[tokio::test]
async fn delete_base_with_dependents_blocked() {
    let (base, client, _org, admin_key, _write) = bootstrap().await;
    create_base(&base, &client, &admin_key, "zbase").await;

    let dep: Value = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "extends": "zbase", "key": "zbase_dep", "delta": {} }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let dep_id = dep["id"].as_str().unwrap();
    let base_id = get_template(&base, &client, "zbase", &admin_key).await["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Deleting the base while a dependent exists is blocked.
    let resp = client
        .delete(format!("{base}/v1/templates/{base_id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "delete-with-dependents must be blocked");

    // Detach the dependent, then the base deletes cleanly.
    let resp = client
        .delete(format!("{base}/v1/templates/{dep_id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = client
        .delete(format!("{base}/v1/templates/{base_id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

// ── Extensions: add a new action + host ────────────────────────────────────

#[tokio::test]
async fn extension_adds_action() {
    let (base, client, _org, admin_key, _write) = bootstrap().await;
    create_base(&base, &client, &admin_key, "zbase").await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "extends": "zbase",
            "key": "zbase_ext",
            "delta": {
                "extensions": {
                    "actions": {
                        "archive_e": {
                            "method": "POST",
                            "path": "/e/archive",
                            "operation": { "description": "Archive E", "x-overslash-risk": "write" }
                        }
                    },
                    "hosts": ["extra.example.com"]
                }
            },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "extension create failed: {:?}",
        resp.text().await
    );

    let detail = get_template(&base, &client, "zbase_ext", &admin_key).await;
    assert!(action_keys(&detail).contains(&"archive_e".to_string()));
    assert_eq!(detail["actions"].as_array().unwrap().len(), 4);

    // Collision: an extension key equal to a base key is rejected at write time.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "extends": "zbase",
            "key": "zbase_collide",
            "delta": {
                "extensions": {
                    "actions": { "list_a": { "method": "GET", "path": "/dup" } }
                }
            },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "extension colliding with a base key must be rejected"
    );
}
