//! A non-admin sees, and can act on, only their own user tree: themselves
//! and their agents. Org admins see the whole org. See
//! `services/visibility.rs`.
//!
//! Fixtures: `user_ids[0]` is the admin (via the Admins group's `overslash`
//! grant, not the `is_org_admin` flag), `user_ids[1]` a plain `write` member,
//! and `user_ids[2]` another plain member.

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

struct World {
    base: String,
    client: Client,
    admin_key: String,
    write_key: String,
    /// The write member.
    me: Uuid,
    my_agent: Uuid,
    /// The other member and an agent of theirs.
    other: Uuid,
    other_agent: Uuid,
    admin: Uuid,
}

async fn create_agent(w: &World, key: &str, parent: Uuid, name: &str) -> reqwest::Response {
    w.client
        .post(format!("{}/v1/identities", w.base))
        .header("Authorization", format!("Bearer {key}"))
        .json(&json!({ "kind": "agent", "name": name, "parent_id": parent }))
        .send()
        .await
        .unwrap()
}

async fn setup() -> World {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (addr, client) = common::start_api(pool).await;
    let mut w = World {
        base: format!("http://{addr}"),
        client,
        admin_key: fx.admin_key.clone(),
        write_key: fx.write_key.clone(),
        me: fx.user_ids[1],
        my_agent: Uuid::nil(),
        other: fx.user_ids[2],
        other_agent: Uuid::nil(),
        admin: fx.user_ids[0],
    };
    let r = create_agent(&w, &w.write_key, w.me, "my-agent").await;
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    w.my_agent = id_of(&r.json().await.unwrap());
    let r = create_agent(&w, &w.admin_key, w.other, "other-agent").await;
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    w.other_agent = id_of(&r.json().await.unwrap());
    w
}

fn id_of(v: &Value) -> Uuid {
    v["id"].as_str().unwrap().parse().unwrap()
}

async fn get(w: &World, key: &str, path: &str) -> reqwest::Response {
    w.client
        .get(format!("{}{path}", w.base))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
}

async fn ids(w: &World, key: &str, path: &str) -> Vec<Uuid> {
    let r = get(w, key, path).await;
    assert_eq!(r.status(), 200, "{path}");
    let rows: Vec<Value> = r.json().await.unwrap();
    rows.iter().map(id_of).collect()
}

#[tokio::test]
async fn identity_listing_is_limited_to_own_tree() {
    let w = setup().await;

    let mine = ids(&w, &w.write_key, "/v1/identities?include_archived=true").await;
    assert!(mine.contains(&w.me) && mine.contains(&w.my_agent));
    for hidden in [w.other, w.other_agent, w.admin] {
        assert!(!mine.contains(&hidden), "{hidden} leaked to a member");
    }

    let all = ids(&w, &w.admin_key, "/v1/identities").await;
    for id in [w.me, w.my_agent, w.other, w.other_agent, w.admin] {
        assert!(all.contains(&id), "admin must see {id}");
    }

    // Another user's subtree reads as missing.
    for path in [
        format!("/v1/identities/{}/children", w.other),
        format!("/v1/identities/{}/chain", w.other_agent),
        format!("/v1/identities/{}/mcp-connection", w.other_agent),
    ] {
        assert_eq!(get(&w, &w.write_key, &path).await.status(), 404, "{path}");
    }
    // Own subtree still works.
    let chain = ids(
        &w,
        &w.write_key,
        &format!("/v1/identities/{}/chain", w.my_agent),
    )
    .await;
    assert!(chain.contains(&w.me) && chain.contains(&w.my_agent));
    let kids = ids(
        &w,
        &w.write_key,
        &format!("/v1/identities/{}/children", w.me),
    )
    .await;
    assert_eq!(kids, vec![w.my_agent]);
}

#[tokio::test]
async fn members_cannot_mutate_other_users_identities() {
    let w = setup().await;

    // No agents under someone else's user.
    let r = create_agent(&w, &w.write_key, w.other, "squatter").await;
    assert_eq!(r.status(), 404);

    // Adding a member is admin-only.
    let r = w
        .client
        .post(format!("{}/v1/identities", w.base))
        .header("Authorization", format!("Bearer {}", w.write_key))
        .json(&json!({ "kind": "user", "name": "mallory" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // Archiving a colleague, or their agent, reads as missing.
    for target in [w.other, w.other_agent] {
        let r = w
            .client
            .post(format!("{}/v1/identities/{target}/archive", w.base))
            .header("Authorization", format!("Bearer {}", w.write_key))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 404, "archive {target}");
    }
    let r = w
        .client
        .patch(format!(
            "{}/v1/identities/{}/auto-call-on-approve",
            w.base, w.other_agent
        ))
        .header("Authorization", format!("Bearer {}", w.write_key))
        .json(&json!({ "enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    // Still allowed on one's own agent.
    let r = w
        .client
        .patch(format!(
            "{}/v1/identities/{}/auto-call-on-approve",
            w.base, w.my_agent
        ))
        .header("Authorization", format!("Bearer {}", w.write_key))
        .json(&json!({ "enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

#[tokio::test]
async fn audit_log_is_limited_to_own_tree() {
    let w = setup().await;
    let mine = [w.me, w.my_agent];

    let r = get(&w, &w.write_key, "/v1/audit?limit=500").await;
    assert_eq!(r.status(), 200);
    let rows: Vec<Value> = r.json().await.unwrap();
    assert!(
        !rows.is_empty(),
        "the member's own agent creation is visible"
    );
    for row in &rows {
        let actor: Uuid = row["identity_id"].as_str().unwrap().parse().unwrap();
        assert!(mine.contains(&actor), "foreign audit row leaked: {row}");
    }

    // Asking for someone else's trail finds nothing rather than erroring.
    for q in [
        format!("owner_user_id={}", w.admin),
        format!("identity_id={}", w.admin),
        format!("uuid={}", w.other_agent),
    ] {
        let r = get(&w, &w.write_key, &format!("/v1/audit?{q}")).await;
        assert_eq!(r.status(), 200);
        let rows: Vec<Value> = r.json().await.unwrap();
        assert!(rows.is_empty(), "{q} returned {rows:?}");
    }

    // The admin sees the admin's own action (creating other-agent).
    let r = get(
        &w,
        &w.admin_key,
        &format!("/v1/audit?uuid={}", w.other_agent),
    )
    .await;
    let rows: Vec<Value> = r.json().await.unwrap();
    assert!(!rows.is_empty(), "admin must see the org-wide log");

    // The export applies the same scope.
    let r = get(&w, &w.write_key, "/v1/audit/export?format=csv").await;
    assert_eq!(r.status(), 200);
    let csv = r.text().await.unwrap();
    assert!(csv.contains(&w.my_agent.to_string()));
    for hidden in [w.admin, w.other_agent] {
        assert!(!csv.contains(&hidden.to_string()), "export leaked {hidden}");
    }
}

#[tokio::test]
async fn api_key_listing_is_limited_to_own_tree() {
    let w = setup().await;
    let r = get(&w, &w.write_key, "/v1/api-keys").await;
    assert_eq!(r.status(), 200);
    let keys: Vec<Value> = r.json().await.unwrap();
    assert!(!keys.is_empty());
    for k in &keys {
        let owner: Uuid = k["identity_id"].as_str().unwrap().parse().unwrap();
        assert!(
            [w.me, w.my_agent].contains(&owner),
            "foreign key leaked: {k}"
        );
    }
    let all: Vec<Value> = get(&w, &w.admin_key, "/v1/api-keys")
        .await
        .json()
        .await
        .unwrap();
    assert!(all.len() > keys.len());
}

/// An agent's view is its owner user's tree.
#[tokio::test]
async fn agent_key_sees_its_owners_tree() {
    let w = setup().await;
    let r = w
        .client
        .post(format!("{}/v1/api-keys", w.base))
        .header("Authorization", format!("Bearer {}", w.admin_key))
        .json(&json!({ "identity_id": w.my_agent, "name": "agent-key" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let key = r.json::<Value>().await.unwrap()["key"]
        .as_str()
        .unwrap()
        .to_string();

    let seen = ids(&w, &key, "/v1/identities").await;
    assert!(seen.contains(&w.me) && seen.contains(&w.my_agent));
    assert!(!seen.contains(&w.other) && !seen.contains(&w.other_agent));
}

/// Org configuration a member could abuse against colleagues is admin-only.
#[tokio::test]
async fn org_config_reads_and_writes_are_admin_only() {
    let w = setup().await;

    // Rate limits: no throttling a colleague, no lifting the org's caps.
    let r = w
        .client
        .put(format!("{}/v1/rate-limits", w.base))
        .header("Authorization", format!("Bearer {}", w.write_key))
        .json(&json!({ "scope": "user", "identity_id": w.other,
                       "max_requests": 1, "window_seconds": 3600 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = w
        .client
        .put(format!("{}/v1/rate-limits", w.base))
        .header("Authorization", format!("Bearer {}", w.admin_key))
        .json(&json!({ "scope": "org", "max_requests": 1000, "window_seconds": 60 }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let limit_id = r.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = w
        .client
        .delete(format!("{}/v1/rate-limits/{limit_id}", w.base))
        .header("Authorization", format!("Bearer {}", w.write_key))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    for path in ["/v1/rate-limits", "/v1/webhooks", "/v1/org-idp-configs"] {
        assert_eq!(get(&w, &w.write_key, path).await.status(), 403, "{path}");
        assert_eq!(get(&w, &w.admin_key, path).await.status(), 200, "{path}");
    }
}

/// Another user's Myself group lists their personal services: hidden from
/// members, visible to admins.
#[tokio::test]
async fn other_users_myself_group_is_hidden() {
    let w = setup().await;
    let groups: Vec<Value> = get(&w, &w.admin_key, "/v1/groups?include_self=true")
        .await
        .json()
        .await
        .unwrap();
    let myself_of = |owner: Uuid| -> String {
        groups
            .iter()
            .find(|g| {
                g["system_kind"] == "self" && g["owner_identity_id"] == json!(owner.to_string())
            })
            .unwrap_or_else(|| panic!("no Myself group for {owner}"))["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let theirs = myself_of(w.other);
    let mine = myself_of(w.me);

    let listed = ids(&w, &w.write_key, "/v1/groups?include_self=true").await;
    assert!(listed.contains(&mine.parse().unwrap()));
    assert!(!listed.contains(&theirs.parse().unwrap()));

    for suffix in ["", "/grants", "/members"] {
        let path = format!("/v1/groups/{theirs}{suffix}");
        assert_eq!(get(&w, &w.write_key, &path).await.status(), 404, "{path}");
        assert_eq!(get(&w, &w.admin_key, &path).await.status(), 200, "{path}");
        let own = format!("/v1/groups/{mine}{suffix}");
        assert_eq!(get(&w, &w.write_key, &own).await.status(), 200, "{own}");
    }
}
