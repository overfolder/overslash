//! `x-overslash-subactions` end to end, on the shipped HubSpot template.
//!
//! `manage_crm_objects` creates or updates any CRM object, a batch at a time.
//! Its variants (`create_contact`, `update_deal`, …) classify each object in
//! the batch, so an approval names what is written and a rule can grant one
//! kind of write without the rest. These tests drive the real call path
//! against the MCP fake in `hubspot.rs` and pin:
//!
//! - the classified description, permission keys and disclosure;
//! - that a batch needs every matched variant's key, and an object no variant
//!   claims keeps the parent's;
//! - that a grant on the parent still covers every variant;
//! - that a callable variant is rewritten into the parent's envelope, keys
//!   included, and that `/validate` agrees with `/call` on all of it.

use crate::common;
use crate::hubspot::{CallLog, seed_hubspot_connection, start_mcp_fake, start_with_hubspot_mcp};

use serde_json::{Value, json};

struct Fx {
    base: String,
    client: reqwest::Client,
    key: String,
    admin_key: String,
    calls: CallLog,
}

/// Layer 1 cleared and a live connection, but no Layer-2 rule beyond `rules`.
async fn setup(rules: &[&str]) -> Fx {
    let pool = common::test_pool().await;
    let (mock_host, calls) = start_mcp_fake().await;
    let (base, client) = start_with_hubspot_mcp(pool.clone(), mock_host).await;
    let (org_id, ident_id, key, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let owner_id = common::owner_user_id(&pool, org_id).await;
    common::grant_service_to_everyone(&base, &client, &admin_key, "hubspot").await;
    for rule in rules {
        let resp = client
            .post(format!("{base}/v1/permissions"))
            .header(common::auth(&admin_key).0, common::auth(&admin_key).1)
            .json(&json!({"identity_id": ident_id, "action_pattern": rule}))
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "rule {rule}: {}",
            resp.text().await.unwrap()
        );
    }
    seed_hubspot_connection(&pool, org_id, ident_id, owner_id).await;
    Fx {
        base,
        client,
        key,
        admin_key,
        calls,
    }
}

impl Fx {
    async fn post(&self, path: &str, action: &str, params: Value) -> (u16, Value) {
        let resp = self
            .client
            .post(format!("{}/v1/actions/{path}", self.base))
            .header(common::auth(&self.key).0, common::auth(&self.key).1)
            .json(&json!({"service": "hubspot", "action": action, "params": params}))
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn call(&self, action: &str, params: Value) -> (u16, Value) {
        self.post("call", action, params).await
    }

    /// `/validate`'s uncovered keys, sorted; empty when allowed.
    async fn uncovered(&self, action: &str, params: Value) -> Vec<String> {
        let (status, body) = self.post("validate", action, params).await;
        assert_eq!(status, 200, "validate: {body}");
        let mut keys: Vec<String> = body["permission"]["uncovered_keys"]
            .as_array()
            .map(|a| a.iter().map(|k| k.as_str().unwrap().to_string()).collect())
            .unwrap_or_default();
        keys.sort();
        keys
    }
}

fn disclosed(env: &Value) -> std::collections::HashMap<String, String> {
    env["disclosed_fields"]
        .as_array()
        .expect("disclosed_fields")
        .iter()
        .map(|f| {
            (
                f["label"].as_str().unwrap().to_string(),
                f["value"].as_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}

fn create(objects: Value) -> Value {
    json!({"createRequest": {"objects": objects}})
}

fn contact(email: &str) -> Value {
    json!({"objectType": "contacts", "properties": {"email": email}})
}

#[tokio::test]
async fn a_raw_call_is_described_keyed_and_disclosed_as_its_variant() {
    let fx = setup(&[]).await;
    let (status, env) = fx
        .call(
            "manage_crm_objects",
            create(json!([contact("jane@acme.com")])),
        )
        .await;
    assert_eq!(status, 202, "{env}");
    assert_eq!(env["status"], "pending_approval");
    assert_eq!(
        env["action_description"], "Create contact 'jane@acme.com' (HubSpot)",
        "the approval names the record, not the overloaded tool"
    );
    assert_eq!(
        env["suggested_tiers"][0]["keys"],
        json!(["hubspot:manage_crm_objects/create_contact:*"])
    );
    let tiers: Vec<Value> = env["suggested_tiers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["keys"].clone())
        .collect();
    assert!(
        tiers.contains(&json!(["hubspot:manage_crm_objects:*"])),
        "the ladder widens a variant to its parent: {tiers:?}"
    );
    let fields = disclosed(&env);
    assert_eq!(
        fields.get("Contacts to create").map(String::as_str),
        Some("jane@acme.com")
    );
    assert_eq!(
        fields.get("Operation").map(String::as_str),
        Some("create"),
        "the parent's own disclosure still runs"
    );
}

#[tokio::test]
async fn a_mixed_batch_needs_every_variants_key() {
    let fx = setup(&["hubspot:manage_crm_objects/create_contact:*"]).await;
    let params = json!({
        "createRequest": {"objects": [
            contact("jane@acme.com"),
            {"objectType": "deals", "properties": {"dealname": "Acme renewal"}}
        ]},
        "updateRequest": {"objects": [
            {"objectType": "deals", "objectId": 42, "properties": {"dealname": "Big Co"}}
        ]}
    });
    assert_eq!(
        fx.uncovered("manage_crm_objects", params.clone()).await,
        vec![
            "hubspot:manage_crm_objects/create_deal:*",
            "hubspot:manage_crm_objects/update_deal:*",
        ],
        "the granted contact key is covered; the deal keys are not"
    );
    let (status, env) = fx.call("manage_crm_objects", params).await;
    assert_eq!(status, 202, "{env}");
    assert_eq!(
        env["action_description"],
        "Create contact 'jane@acme.com' and deal 'Acme renewal'; update deal 'Big Co' (HubSpot)"
    );
}

#[tokio::test]
async fn an_object_no_variant_claims_keeps_the_parent_key_and_label() {
    let fx = setup(&["hubspot:manage_crm_objects/create_contact:*"]).await;
    let params = create(json!([
        contact("jane@acme.com"),
        {"objectType": "notes", "properties": {"hs_note_body": "hi"}}
    ]));
    assert_eq!(
        fx.uncovered("manage_crm_objects", params.clone()).await,
        vec!["hubspot:manage_crm_objects:*"]
    );
    let (_, env) = fx.call("manage_crm_objects", params).await;
    assert_eq!(
        env["action_description"],
        "Create contact 'jane@acme.com'; Create or update CRM records (HubSpot)"
    );
}

#[tokio::test]
async fn a_grant_on_the_parent_still_covers_every_variant() {
    let fx = setup(&["hubspot:manage_crm_objects:*"]).await;
    let (status, env) = fx
        .call(
            "manage_crm_objects",
            create(json!([
                contact("jane@acme.com"),
                {"objectType": "tickets", "properties": {"subject": "Broken"}}
            ])),
        )
        .await;
    assert_eq!(status, 200, "{env}");
    assert_eq!(env["status"], "called");
}

#[tokio::test]
async fn a_callable_variant_is_rewritten_into_the_parent_call() {
    let fx = setup(&["hubspot:manage_crm_objects/create_contact:*"]).await;
    let params = json!({"properties": {"email": "ada@analytical.example", "firstname": "Ada"}});

    // `/validate` previews the parent's key, not a `create_contact:*` one.
    assert!(
        fx.uncovered("create_contact", params.clone())
            .await
            .is_empty()
    );

    let (status, env) = fx.call("create_contact", params).await;
    assert_eq!(status, 200, "{env}");
    let recorded = fx.calls.lock().unwrap().clone();
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    assert_eq!(recorded[0]["tool"], "manage_crm_objects");
    assert_eq!(
        recorded[0]["arguments"],
        json!({
            "createRequest": {"objects": [{
                "objectType": "contacts",
                "properties": {"email": "ada@analytical.example", "firstname": "Ada"}
            }]},
            "confirmationStatus": "CONFIRMED"
        })
    );

    // A deal grant does not reach a contact, however it is called.
    let fx = setup(&["hubspot:manage_crm_objects/create_deal:*"]).await;
    assert_eq!(
        fx.uncovered("create_contact", json!({"properties": {"email": "x@y.z"}}))
            .await,
        vec!["hubspot:manage_crm_objects/create_contact:*"]
    );
}

#[tokio::test]
async fn a_callable_variant_validates_its_own_arguments_first() {
    let fx = setup(&["hubspot:*:*"]).await;
    let (status, body) = fx.call("update_deal", json!({"properties": {}})).await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["error"], "invalid_action_args", "{body}");
    assert!(fx.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_approved_callable_variant_replays_as_the_parent() {
    let fx = setup(&[]).await;
    let (status, env) = fx
        .call(
            "update_deal",
            json!({"id": 42, "properties": {"dealstage": "closedwon"}}),
        )
        .await;
    assert_eq!(status, 202, "{env}");
    assert_eq!(env["action_description"], "Update deal #42 (HubSpot)");
    let approval_id = env["approval_id"].as_str().unwrap().to_string();

    let resp = fx
        .client
        .post(format!("{}/v1/approvals/{approval_id}/resolve", fx.base))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({
            "resolution": "allow_remember",
            "remember_keys": ["hubspot:manage_crm_objects/update_deal:*"]
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());

    // An auto-calling agent replays in the background; otherwise the caller
    // dispatches it. Either way it is the stored parent request that runs.
    if env["auto_call_on_approve"] != true {
        let resp = fx
            .client
            .post(format!("{}/v1/approvals/{approval_id}/call", fx.base))
            .header(common::auth(&fx.key).0, common::auth(&fx.key).1)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    }
    let mut recorded = Vec::new();
    for _ in 0..50 {
        recorded = fx.calls.lock().unwrap().clone();
        if !recorded.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(
        recorded.len(),
        1,
        "the approved call replays once: {recorded:?}"
    );
    assert_eq!(recorded[0]["tool"], "manage_crm_objects");
    assert_eq!(
        recorded[0]["arguments"]["updateRequest"]["objects"][0],
        json!({"objectType": "deals", "objectId": 42, "properties": {"dealstage": "closedwon"}})
    );

    // The remembered rule now covers the next update_deal, and only that.
    assert!(
        fx.uncovered("update_deal", json!({"id": 7, "properties": {}}))
            .await
            .is_empty()
    );
    assert_eq!(
        fx.uncovered("create_deal", json!({"properties": {"dealname": "x"}}))
            .await,
        vec!["hubspot:manage_crm_objects/create_deal:*"]
    );
}

#[tokio::test]
async fn listings_show_variants_under_their_parent() {
    let fx = setup(&[]).await;
    let detail: Value = fx
        .client
        .get(format!(
            "{}/v1/templates/hubspot/actions/manage_crm_objects",
            fx.base
        ))
        .header(common::auth(&fx.key).0, common::auth(&fx.key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let variants: Vec<&str> = detail["subactions"]
        .as_array()
        .unwrap_or_else(|| panic!("{detail}"))
        .iter()
        .map(|v| v["key"].as_str().unwrap())
        .collect();
    assert!(variants.contains(&"create_contact") && variants.contains(&"update_ticket"));
    assert!(detail["subactions"][0]["callable"].as_bool().unwrap());

    let callable: Value = fx
        .client
        .get(format!(
            "{}/v1/templates/hubspot/actions/create_contact",
            fx.base
        ))
        .header(common::auth(&fx.key).0, common::auth(&fx.key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(callable["subaction_of"], "manage_crm_objects");
    assert!(
        callable["params"]["properties"]["required"]
            .as_bool()
            .unwrap()
    );
}
