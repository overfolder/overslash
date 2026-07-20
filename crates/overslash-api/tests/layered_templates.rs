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

    // The `/actions` list endpoint resolves through the fold too (not a raw
    // compile_row, which would 400 on a derived layer).
    let list: Value = client
        .get(format!("{base}/v1/templates/zbase_curated/actions"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut listed: Vec<String> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["key"].as_str().unwrap().to_string())
        .collect();
    listed.sort();
    assert_eq!(listed, vec!["create_b", "list_a"]);

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

// ── Relabel via delta reflects in the list (no stale denormalized column) ──

#[tokio::test]
async fn delta_relabel_reflects_in_list_and_search() {
    let (base, client, _org, admin_key, _write) = bootstrap().await;
    create_base(&base, &client, &admin_key, "zbase").await;

    let created: Value = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "extends": "zbase",
            "key": "zbase_named",
            "display_name": "First Name",
            "delta": { "allowlist": ["list_a"] },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap();

    // Relabel via the delta only (no scalar column write on the update path).
    let resp = client
        .put(format!("{base}/v1/templates/{id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "delta": { "allowlist": ["list_a"], "display_name": "Renamed Layer" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // The list endpoint must show the effective (resolved) name, not the stale
    // denormalized column.
    let list: Value = client
        .get(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = list
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["key"] == "zbase_named")
        .unwrap();
    assert_eq!(row["display_name"], "Renamed Layer");
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

// ── Delete guard is per-actual-base, not per-shared-key (cross-user) ───────

#[tokio::test]
async fn delete_guard_does_not_over_block_across_users() {
    // admin_key (user 0) and write_key (user 1) are distinct user identities.
    let (base, client, org_id, admin_key, write_key) = bootstrap().await;
    enable_full_user_policy(&base, &client, org_id, &admin_key).await;

    // Both users create a user-level standalone base with the SAME key `ubase`
    // (unique per owner, so both succeed).
    for key in [&admin_key, &write_key] {
        let resp = client
            .post(format!("{base}/v1/templates"))
            .header(auth(key).0, auth(key).1)
            .json(&json!({ "openapi": base_openapi("ubase"), "user_level": true }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            200,
            "user base create: {:?}",
            resp.text().await
        );
    }

    // Write user adds a derived layer over *their own* ubase.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({
            "extends": "ubase",
            "key": "ubase_d",
            "user_level": true,
            "delta": { "allowlist": ["list_a"] },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Admin's ubase (user 0) has NO dependent — write user's ubase_d resolves to
    // write user's ubase, not admin's. Deleting admin's ubase must succeed.
    let admin_ubase_id = get_template(&base, &client, "ubase", &admin_key).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = client
        .delete(format!("{base}/v1/templates/{admin_ubase_id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "unrelated same-keyed layer from another user must not block delete"
    );

    // Write user's ubase DOES have a real dependent (ubase_d) → blocked.
    let write_ubase_id = get_template(&base, &client, "ubase", &write_key).await["id"]
        .as_str()
        .unwrap()
        .to_string();
    let resp = client
        .delete(format!("{base}/v1/templates/{write_ubase_id}/manage"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        409,
        "a real dependent must still block delete"
    );
}

// ── A derived layer over an MCP base keeps a consistent mcp detail ─────────

#[tokio::test]
async fn derived_mcp_layer_reports_mcp_detail() {
    let (base, client, _org, admin_key, _write) = bootstrap().await;

    // Pinned MCP base (autodiscover: false → no upstream call on create).
    let mcp_yaml = r#"openapi: 3.1.0
info:
  title: MCP Base
  x-overslash-key: mcpbase
x-overslash-runtime: mcp
paths: {}
x-overslash-mcp:
  url: https://mcp.example.com/mcp
  auth: { kind: none }
  autodiscover: false
  tools:
    - name: echo
      risk: read
      description: Echo
      input_schema:
        type: object
        properties: { x: { type: string } }
        required: [x]
"#;
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": mcp_yaml }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "mcp base create: {:?}",
        resp.text().await
    );

    // Derived layer over the MCP base.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "extends": "mcpbase", "key": "mcpbase_d", "delta": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // The derived layer has no openapi of its own, but its effective def is MCP,
    // so `runtime: "mcp"` must come with a non-null `mcp` object.
    let detail = get_template(&base, &client, "mcpbase_d", &admin_key).await;
    assert_eq!(detail["runtime"], "mcp");
    assert!(
        detail["mcp"].is_object(),
        "derived MCP layer must return an mcp object, got: {}",
        detail["mcp"]
    );
    assert_eq!(detail["mcp"]["url"], "https://mcp.example.com/mcp");
    assert_eq!(detail["mcp"]["auth_kind"], "none");
}

// ── Editing a user layer is gated by user_template_policy (forward-only) ───

#[tokio::test]
async fn update_of_user_layer_blocked_after_policy_downgrade() {
    let (base, client, org_id, admin_key, write_key) = bootstrap().await;
    create_base(&base, &client, &admin_key, "zbase").await;
    enable_full_user_policy(&base, &client, org_id, &admin_key).await;

    // A non-admin creates a user-namespace derived layer while policy is `full`.
    let created: Value = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({
            "extends": "zbase",
            "key": "umine",
            "user_level": true,
            "delta": { "allowlist": ["list_a"] },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();

    // Admin downgrades the policy to `none`.
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "user_template_policy": "none" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // The owner (non-admin) can no longer edit it — not even to add an extension
    // host (a new egress channel), which is exactly what `none` forbids.
    let resp = client
        .put(format!("{base}/v1/templates/{id}/manage"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({
            "delta": {
                "allowlist": ["list_a"],
                "extensions": { "hosts": ["evil.example.com"] }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        403,
        "non-admin editing a user layer under `none` must be blocked (policy bypass)"
    );

    // An admin retains edit rights for compliance management.
    let resp = client
        .put(format!("{base}/v1/templates/{id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "delta": { "allowlist": ["list_a"] } }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "admins keep edit rights under any policy"
    );
}

// ── validate-delta resolves the base in the layer's owner context ──────────

#[tokio::test]
async fn validate_delta_respects_owner_context() {
    let (base, client, org_id, admin_key, write_key) = bootstrap().await;
    enable_full_user_policy(&base, &client, org_id, &admin_key).await;

    // Org base `zbase` has 3 actions (incl. create_b).
    create_base(&base, &client, &admin_key, "zbase").await;

    // The write user has a PRIVATE standalone `zbase` with only `list_a`,
    // shadowing the org base by key.
    let user_openapi = r#"openapi: 3.1.0
info:
  title: zbase user
  key: zbase
servers:
  - url: https://zbase.example.com
paths:
  /a:
    get:
      operationId: list_a
      summary: List A
      risk: read
"#;
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({ "openapi": user_openapi, "user_level": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let validate = |user_level: bool| {
        let base = base.clone();
        let client = client.clone();
        let write_key = write_key.clone();
        async move {
            let report: Value = client
                .post(format!("{base}/v1/templates/validate-delta"))
                .header(auth(&write_key).0, auth(&write_key).1)
                .json(&json!({
                    "extends": "zbase",
                    "delta": { "allowlist": ["create_b"] },
                    "user_level": user_level,
                }))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            report
        }
    };

    fn has_dead_allowlist(report: &Value) -> bool {
        report["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "dead_allowlist_entry")
    }

    // Org context → base is the org zbase (has create_b) → no dead entry.
    let org_ctx = validate(false).await;
    assert!(
        !has_dead_allowlist(&org_ctx),
        "org base has create_b: {org_ctx:?}"
    );

    // User context → base is the write user's zbase (only list_a) → dead entry.
    let user_ctx = validate(true).await;
    assert!(
        has_dead_allowlist(&user_ctx),
        "user base lacks create_b, expected dead_allowlist_entry: {user_ctx:?}"
    );
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

// ── Instance defaults: org-tier authority + surfacing ──────────────────────

/// A base whose `list_a` declares an instance-pinnable header, so a layer has
/// something legal to default.
fn base_openapi_with_pinnable(key: &str) -> String {
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
      parameters:
        - name: X-Region
          in: header
          schema:
            type: string
          x-overslash-instance-config: true
"#
    )
}

#[tokio::test]
async fn org_layer_instance_defaults_are_stored_and_surfaced() {
    let (base, client, _org, admin_key, _write) = bootstrap().await;
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": base_openapi_with_pinnable("pinbase") }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "extends": "pinbase",
            "key": "pinbase_org",
            "delta": {
                "instance_defaults": {
                    "url": "https://gw.acme.internal:8443/",
                    "config": { "X-Region": "  eu-west-1  " }
                }
            },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let detail = get_template(&base, &client, "pinbase_org", &admin_key).await;
    // The effective (folded) defaults are what the instance form reads, so they
    // must be normalized here, not just at execution.
    assert_eq!(
        detail["instance_defaults"]["url"], "https://gw.acme.internal:8443",
        "trailing slash must be trimmed: {detail:?}"
    );
    assert_eq!(
        detail["instance_defaults"]["config"]["X-Region"], "eu-west-1",
        "value must be trimmed, symmetric with the instance write path"
    );
    // The endpoint is unioned into hosts as an origin, so the verb shape's
    // host-and-port matcher accepts the gateway.
    let hosts: Vec<String> = detail["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap().to_string())
        .collect();
    assert!(
        hosts.contains(&"https://gw.acme.internal:8443".to_string()),
        "expected the origin in hosts, got {hosts:?}"
    );
}

#[tokio::test]
async fn user_layer_may_not_set_instance_defaults() {
    let (base, client, org_id, admin_key, write_key) = bootstrap().await;
    enable_full_user_policy(&base, &client, org_id, &admin_key).await;
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": base_openapi_with_pinnable("pinbase") }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body = json!({
        "extends": "pinbase",
        "key": "pinbase_mine",
        "delta": { "instance_defaults": { "url": "https://evil.example.com" } },
        "user_level": true,
    });

    // Write path rejects it...
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        400,
        "a user layer must not be able to redirect egress"
    );

    // ...and the lint preview agrees, so the editor can't offer a save that 400s.
    let report: Value = client
        .post(format!("{base}/v1/templates/validate-delta"))
        .header(auth(&write_key).0, auth(&write_key).1)
        .json(&json!({
            "extends": "pinbase",
            "delta": { "instance_defaults": { "url": "https://evil.example.com" } },
            "user_level": true,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(report["valid"], false);
    assert!(
        report["errors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["code"] == "instance_defaults_user_tier"),
        "{report:?}"
    );

    // The same delta on an ORG layer is accepted — proving the gate keys off
    // tier, not on the field being unsupported.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "extends": "pinbase",
            "key": "pinbase_org",
            "delta": { "instance_defaults": { "url": "https://gw.acme.internal" } },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
}

#[tokio::test]
async fn instance_defaults_config_key_must_be_declared() {
    let (base, client, _org, admin_key, _write) = bootstrap().await;
    // `zbase` declares no instance-config params at all.
    create_base(&base, &client, &admin_key, "zbase").await;

    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "extends": "zbase",
            "key": "zbase_bad_default",
            "delta": { "instance_defaults": { "config": { "X-Nope": "v" } } },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // A misspelled *field* fails just as loudly, rather than silently
    // deserializing to an empty struct and leaving traffic on the default.
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "extends": "zbase",
            "key": "zbase_typo",
            "delta": { "instance_defaults": { "URL": "https://gw.acme.internal" } },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "{:?}", resp.text().await);
}
