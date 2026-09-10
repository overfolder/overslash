//! `tools/list` names the caller's connected service types.
//!
//! The MCP catalog is five generic tools whose names say nothing about what
//! this deployment can reach, so `overslash_search`'s description carries a
//! caller-derived roster of connected template keys. What matters here is that
//! the roster is *derived from the caller*, not that some string got appended:
//! a template the caller has no active, visible instance of must not show up,
//! and neither must another user's user-level service.
//!
//! Uses `common::start_api_for_search` so the real `services/*.yaml` registry
//! is loaded — `google_calendar` and `gmail` have to resolve as templates
//! before an instance of either can exist.

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

struct Fx {
    base: String,
    client: Client,
    fixtures: common::BootstrapFixtures,
    agent_key: String,
}

async fn bootstrap() -> Fx {
    let (pool, fixtures) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api_for_search(pool).await;
    let (_user_id, _agent_id, agent_key) =
        common::bootstrap_agent_on_fixtures(&base, &client, &fixtures).await;
    Fx {
        base,
        client,
        fixtures,
        agent_key,
    }
}

const ROSTER_PREFIX: &str = "Connected service types for this caller: ";
const ROSTER_SUFFIX: &str = ". Those are template keys";

/// The template keys named in a description's roster sentence.
///
/// Parsed out rather than substring-matched against the whole description:
/// the static half already contains `gmail_work` and `whatsapp_angel` as
/// examples, so `desc.contains("gmail")` is true before any instance exists.
fn roster_keys(desc: &str) -> Vec<String> {
    let Some(start) = desc.find(ROSTER_PREFIX) else {
        return Vec::new();
    };
    let rest = &desc[start + ROSTER_PREFIX.len()..];
    let end = rest
        .find(ROSTER_SUFFIX)
        .expect("roster sentence is unterminated");
    rest[..end].split(", ").map(str::to_string).collect()
}

/// `tools/list` as `key`, returning `overslash_search`'s description.
async fn search_description(fx: &Fx, key: &str) -> String {
    let resp: Value = fx
        .client
        .post(format!("{}/mcp", fx.base))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }))
        .send()
        .await
        .expect("tools/list")
        .json()
        .await
        .expect("tools/list body");

    resp["result"]["tools"]
        .as_array()
        .unwrap_or_else(|| panic!("no tools in {resp}"))
        .iter()
        .find(|t| t["name"].as_str() == Some("overslash_search"))
        .and_then(|t| t["description"].as_str())
        .expect("overslash_search description")
        .to_string()
}

/// Create a service instance owned by the caller (`user_level: true`), so the
/// group ceiling — not an Everyone grant — decides who sees it.
async fn create_user_level_service(
    fx: &Fx,
    key: &str,
    template_key: &str,
    name: &str,
    status: &str,
) -> Value {
    fx.client
        .post(format!("{}/v1/services", fx.base))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({
            "template_key": template_key,
            "name": name,
            "user_level": true,
            "status": status,
        }))
        .send()
        .await
        .expect("create service")
        .json()
        .await
        .expect("create service body")
}

#[tokio::test]
async fn roster_names_the_callers_connected_template_keys() {
    let fx = bootstrap().await;

    // Baseline: nothing of this template is wired up yet.
    let before = search_description(&fx, &fx.agent_key).await;
    assert!(
        !roster_keys(&before).contains(&"google_calendar".to_string()),
        "template named before any instance exists: {before}"
    );
    // The static half is always there.
    assert!(
        before.contains("Discover Overslash service instances"),
        "static description missing: {before}"
    );

    common::grant_service_to_everyone(
        &fx.base,
        &fx.client,
        &fx.fixtures.admin_key,
        "google_calendar",
    )
    .await;

    let after = search_description(&fx, &fx.agent_key).await;
    assert!(
        after.contains("Connected service types for this caller:"),
        "roster sentence missing: {after}"
    );
    assert!(
        roster_keys(&after).contains(&"google_calendar".to_string()),
        "connected template not named: {after}"
    );
    // The roster must not read as a list of callable `service` arguments —
    // `overslash_call.service` wants an instance name.
    assert!(
        after.contains("not callable service names"),
        "roster is missing the template-key caveat: {after}"
    );
    assert!(
        after.starts_with("Discover Overslash service instances"),
        "roster replaced rather than extended the description: {after}"
    );
}

#[tokio::test]
async fn roster_skips_instances_that_are_not_active() {
    let fx = bootstrap().await;

    let created =
        create_user_level_service(&fx, &fx.agent_key, "gmail", "gmail_draft", "draft").await;
    assert_eq!(
        created["status"].as_str(),
        Some("draft"),
        "expected a draft instance: {created}"
    );

    let desc = search_description(&fx, &fx.agent_key).await;
    assert!(
        !roster_keys(&desc).contains(&"gmail".to_string()),
        "draft instance leaked into the roster: {desc}"
    );
}

#[tokio::test]
async fn roster_is_scoped_to_the_caller() {
    let fx = bootstrap().await;

    // A second user with its own agent, in the same org. Its user-level
    // service is owned by a different ceiling user.
    let other_user: Value = fx
        .client
        .post(format!("{}/v1/identities", fx.base))
        .header("Authorization", format!("Bearer {}", fx.fixtures.org_key))
        .json(&json!({"name": "other-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let other_user_id: Uuid = other_user["id"].as_str().unwrap().parse().unwrap();

    let other_agent: Value = fx
        .client
        .post(format!("{}/v1/identities", fx.base))
        .header("Authorization", format!("Bearer {}", fx.fixtures.org_key))
        .json(&json!({
            "name": "other-agent",
            "kind": "agent",
            "parent_id": other_user_id,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let other_agent_id: Uuid = other_agent["id"].as_str().unwrap().parse().unwrap();

    let key_resp: Value = fx
        .client
        .post(format!("{}/v1/api-keys", fx.base))
        .header("Authorization", format!("Bearer {}", fx.fixtures.org_key))
        .json(&json!({
            "org_id": fx.fixtures.org_id,
            "identity_id": other_agent_id,
            "name": "other-agent-key",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let other_key = key_resp["key"].as_str().unwrap().to_string();

    let created =
        create_user_level_service(&fx, &other_key, "gmail", "gmail_other", "active").await;
    assert_eq!(
        created["status"].as_str(),
        Some("active"),
        "expected an active instance: {created}"
    );

    // The owner sees it…
    let owner_desc = search_description(&fx, &other_key).await;
    assert!(
        roster_keys(&owner_desc).contains(&"gmail".to_string()),
        "owner's own service missing from its roster: {owner_desc}"
    );

    // …the unrelated agent does not.
    let stranger_desc = search_description(&fx, &fx.agent_key).await;
    assert!(
        !roster_keys(&stranger_desc).contains(&"gmail".to_string()),
        "another user's user-level service leaked into the roster: {stranger_desc}"
    );
}
