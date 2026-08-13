//! An agent's icon: the mark of the MCP client bound to it, plus a stripe
//! hashed from its own id. See DECISIONS.md D70.

use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use crate::common::{self, SeedOptions};

/// Register a DCR client and bind it to a fresh agent, the way consent does.
///
/// `client_info_name` is what the client announced at `initialize`; passing
/// `None` leaves the row in the state a client that registered but never
/// handshook would be in, so the resolver has to fall back to `client_name`.
async fn bind_agent(
    pool: &PgPool,
    org_id: Uuid,
    user_id: Uuid,
    agent_name: &str,
    client_name: &str,
    client_info_name: Option<&str>,
) -> Uuid {
    let client_id = format!("osc_{}", Uuid::new_v4());
    overslash_db::repos::oauth_mcp_client::create(
        pool,
        &overslash_db::repos::oauth_mcp_client::CreateOauthMcpClient {
            client_id: &client_id,
            client_name: Some(client_name),
            redirect_uris: &["http://127.0.0.1:1/cb".to_string()],
            software_id: None,
            software_version: None,
            created_ip: None,
            created_user_agent: None,
            org_id: Some(org_id),
        },
    )
    .await
    .unwrap();

    if let Some(name) = client_info_name {
        overslash_db::repos::oauth_mcp_client::update_initialize_state(
            pool,
            &client_id,
            &json!({}),
            &json!({ "name": name, "version": "1.0.0" }),
            "2025-06-18",
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    }

    let agent = overslash_db::repos::identity::create_with_parent(
        pool, org_id, agent_name, "agent", None, user_id, 1, user_id, true,
    )
    .await
    .unwrap();

    overslash_db::repos::mcp_client_agent_binding::upsert(
        pool, org_id, user_id, &client_id, agent.id,
    )
    .await
    .unwrap();

    agent.id
}

async fn list_identities(base: &str, client: &reqwest::Client, key: &str) -> Vec<Value> {
    client
        .get(format!("{base}/v1/identities"))
        .bearer_auth(key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn by_name<'a>(rows: &'a [Value], name: &str) -> &'a Value {
    rows.iter()
        .find(|r| r["name"] == name)
        .unwrap_or_else(|| panic!("no identity named {name} in {rows:#?}"))
}

#[tokio::test]
async fn an_agents_icon_is_its_mcp_clients_mark() {
    let pool = common::test_pool().await;
    let (org_id, user_id, key) = common::seed_org_user_key(
        &pool,
        SeedOptions {
            is_personal: false,
            is_admin: true,
        },
    )
    .await;

    // `clientInfo.name` wins where present.
    bind_agent(
        &pool,
        org_id,
        user_id,
        "releaser",
        "Some Registration Label",
        Some("claude-code"),
    )
    .await;
    // No handshake yet — falls back to the DCR `client_name`.
    bind_agent(&pool, org_id, user_id, "refactorer", "Cursor", None).await;
    // A client we ship no mark for lands on the generic bot, not on nothing.
    bind_agent(&pool, org_id, user_id, "in-house", "Bespoke Tool", None).await;

    let (addr, http) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let rows = list_identities(&base, &http, &key).await;

    let releaser = by_name(&rows, "releaser");
    assert!(
        releaser["icon_url"]
            .as_str()
            .unwrap()
            .ends_with("/icons/client_claude.svg"),
        "clientInfo.name should pick the Claude mark, got {:?}",
        releaser["icon_url"]
    );
    assert_eq!(releaser["mcp_client_label"], "claude-code");

    let refactorer = by_name(&rows, "refactorer");
    assert!(
        refactorer["icon_url"]
            .as_str()
            .unwrap()
            .ends_with("/icons/client_cursor.svg"),
        "a client that never handshook should still resolve from client_name, got {:?}",
        refactorer["icon_url"]
    );

    let in_house = by_name(&rows, "in-house");
    assert!(
        in_house["icon_url"]
            .as_str()
            .unwrap()
            .ends_with("/icons/client_unknown.svg"),
        "an unrecognised client falls back to the bot, got {:?}",
        in_house["icon_url"]
    );
}

#[tokio::test]
async fn every_agent_carries_a_stripe_and_no_user_does() {
    let pool = common::test_pool().await;
    let (org_id, user_id, key) = common::seed_org_user_key(
        &pool,
        SeedOptions {
            is_personal: false,
            is_admin: true,
        },
    )
    .await;

    // Two agents on the *same* client. This pair is the reason the stripe
    // exists: identical marks, and they must still be distinguishable.
    bind_agent(&pool, org_id, user_id, "twin-a", "Claude Code", None).await;
    bind_agent(&pool, org_id, user_id, "twin-b", "Claude Code", None).await;

    let (addr, http) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let rows = list_identities(&base, &http, &key).await;

    let a = by_name(&rows, "twin-a");
    let b = by_name(&rows, "twin-b");

    assert_eq!(a["icon_url"], b["icon_url"], "same client ⇒ same mark");

    for agent in [a, b] {
        let stripe = agent["icon_stripe"]
            .as_array()
            .expect("agents get a stripe");
        assert_eq!(stripe.len(), 3);
        for colour in stripe {
            let s = colour.as_str().unwrap();
            assert_eq!(s.len(), 7, "{s} is not #rrggbb");
            assert!(s.starts_with('#'));
            assert!(s[1..].chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
    assert_ne!(
        a["icon_stripe"], b["icon_stripe"],
        "two agents on one client must not be indistinguishable"
    );

    // A user identity renders its IdP picture, so it gets neither half. Both
    // keys are `skip_serializing_if = "Option::is_none"`, hence absent, not null.
    let user = by_name(&rows, "test-user");
    assert!(user.get("icon_url").is_none(), "users get no client mark");
    assert!(user.get("icon_stripe").is_none(), "users get no stripe");
}

#[tokio::test]
async fn an_agent_with_no_mcp_binding_still_gets_the_bot() {
    let pool = common::test_pool().await;
    let (org_id, user_id, key) = common::seed_org_user_key(
        &pool,
        SeedOptions {
            is_personal: false,
            is_admin: true,
        },
    )
    .await;

    // The API-key agent: created through `POST /v1/identities`, never enrolled
    // through an MCP client. It has no binding at all, and the batched lookup
    // simply returns no row for it.
    overslash_db::repos::identity::create_with_parent(
        &pool,
        org_id,
        "cron-runner",
        "agent",
        None,
        user_id,
        1,
        user_id,
        true,
    )
    .await
    .unwrap();

    let (addr, http) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let rows = list_identities(&base, &http, &key).await;

    let agent = by_name(&rows, "cron-runner");
    assert!(
        agent["icon_url"]
            .as_str()
            .unwrap()
            .ends_with("/icons/client_unknown.svg"),
        "an unbound agent still gets a mark, got {:?}",
        agent["icon_url"]
    );
    assert!(agent["icon_stripe"].is_array());
    assert!(
        agent.get("mcp_client_label").is_none(),
        "no binding ⇒ no client label to show"
    );
}
