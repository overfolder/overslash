//! Re-authorizing an existing connection instead of duplicating it.
//!
//! An agent fixing a service's missing scopes used to call
//! `create_connection {provider}`, which always minted a second connection
//! that no service used and that was not the default — so nothing changed and
//! the agent could not even see the new row. These pin the three ways a
//! reconnect now lands on the existing row: `create_connection {service}`,
//! an explicit `upgrade_connection_id`, and the callback recognising the same
//! account on a plain connect. Plus `list_connections`, which is how an agent
//! sees the result.
#![allow(clippy::disallowed_methods)]

use crate::common;

use serde_json::{Value, json};
use uuid::Uuid;

struct Env {
    pool: sqlx::PgPool,
    client: reqwest::Client,
    base: String,
    mock: std::net::SocketAddr,
    org_id: Uuid,
    agent_key: String,
    admin_key: String,
    /// The agent's owner — where its connections live (D22).
    user_id: Uuid,
}

/// The `x` provider pointed at the fake: canned tokens for any code, and a
/// userinfo naming `testuser@example.com`.
async fn setup() -> Env {
    let pool = common::test_pool().await;
    let mock = common::start_mock().await;
    // SAFETY: test-only, ahead of API boot.
    unsafe {
        std::env::set_var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS", "1");
        std::env::set_var("OAUTH_X_CLIENT_ID", "x_test_client_id");
        std::env::set_var("OAUTH_X_CLIENT_SECRET", "x_test_client_secret");
    }
    point_userinfo(&pool, mock, "/oidc/userinfo").await;
    // The bundled registry: the `overslash` platform service and `x`.
    let (base, client) = common::start_api_with_registry(pool.clone(), None).await;
    let (org_id, agent_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;
    let user_id = sqlx::query_scalar!(
        "SELECT parent_id AS \"parent_id!\" FROM identities WHERE id = $1",
        agent_id
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    Env {
        pool,
        client,
        base,
        mock,
        org_id,
        agent_key,
        admin_key,
        user_id,
    }
}

async fn point_userinfo(pool: &sqlx::PgPool, mock: std::net::SocketAddr, path: &str) {
    sqlx::query!(
        "UPDATE oauth_providers SET token_endpoint = $1, userinfo_endpoint = $2 WHERE key = 'x'",
        format!("http://{mock}/oauth/token"),
        format!("http://{mock}{path}"),
    )
    .execute(pool)
    .await
    .unwrap();
}

impl Env {
    /// `overslash.<action>` through `/v1/actions/call`, as the MCP bridge
    /// forwards it. Returns the status and the action's own result.
    async fn call(&self, action: &str, params: Value) -> (u16, Value) {
        let r = self
            .client
            .post(format!("{}/v1/actions/call", self.base))
            .header(
                common::auth(&self.agent_key).0,
                common::auth(&self.agent_key).1,
            )
            .json(&json!({"service": "overslash", "action": action, "params": params}))
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        let body: Value = r.json().await.unwrap();
        // A platform action answers like an upstream call: its JSON rides as
        // a string in `result.body`. Errors come back bare.
        let result = match body["result"]["body"].as_str() {
            Some(raw) => serde_json::from_str(raw).unwrap(),
            None => body,
        };
        (status, result)
    }

    /// Start a flow, then complete it as the user would.
    async fn connect(&self, params: Value) -> (Value, Value) {
        let (s, flow) = self.call("create_connection", params).await;
        assert_eq!(s, 200, "{flow}");
        let callback = self.callback(flow["flow_id"].as_str().unwrap()).await;
        (flow, callback)
    }

    async fn callback(&self, flow_id: &str) -> Value {
        let callback: Value = self
            .client
            .get(format!(
                "{}/v1/oauth/callback?code=c_{}&state={flow_id}",
                self.base,
                Uuid::new_v4().simple()
            ))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(callback["status"], "connected", "{callback}");
        callback
    }

    async fn x_connections(&self) -> Vec<Value> {
        let (s, list) = self
            .call("list_connections", json!({"provider": "x"}))
            .await;
        assert_eq!(s, 200, "{list}");
        list.as_array().expect("an array").clone()
    }

    /// A user-level `x` instance with no connect flow of its own.
    async fn create_x_service(&self, name: &str, connection_id: Option<&str>) -> Uuid {
        let mut body = json!({"template_key": "x", "name": name, "skip_connect": true});
        if let Some(id) = connection_id {
            body["connection_id"] = json!(id);
        }
        let r = self
            .client
            .post(format!("{}/v1/services", self.base))
            .header(
                common::auth(&self.agent_key).0,
                common::auth(&self.agent_key).1,
            )
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        let v: Value = r.json().await.unwrap();
        assert_eq!(status, 200, "{v}");
        v["id"].as_str().unwrap().parse().unwrap()
    }

    async fn service_connection(&self, name: &str) -> Option<String> {
        let v: Value = self
            .client
            .get(format!("{}/v1/services/{name}", self.base))
            .header(
                common::auth(&self.agent_key).0,
                common::auth(&self.agent_key).1,
            )
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v["connection_id"].as_str().map(str::to_string)
    }
}

struct FlowRow {
    upgrade_connection_id: Option<Uuid>,
    scopes: Vec<String>,
    pins: Vec<Uuid>,
}

async fn flow_row(pool: &sqlx::PgPool, flow_id: &str) -> FlowRow {
    let r = sqlx::query!(
        "SELECT upgrade_connection_id, scopes, pin_service_instance_ids
         FROM oauth_connection_flows WHERE id = $1",
        flow_id
    )
    .fetch_one(pool)
    .await
    .unwrap();
    FlowRow {
        upgrade_connection_id: r.upgrade_connection_id,
        scopes: r.scopes,
        pins: r.pin_service_instance_ids,
    }
}

fn has_scope(conn: &Value, scope: &str) -> bool {
    conn["scopes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s == scope)
}

#[tokio::test]
async fn reconnecting_a_service_upgrades_its_pinned_connection_in_place() {
    let e = setup().await;
    let (_, first) = e
        .connect(json!({"provider": "x", "scopes": ["tweet.read"]}))
        .await;
    let conn_id = first["connection_id"].as_str().unwrap().to_string();
    e.create_x_service("my-x", Some(&conn_id)).await;

    let (s, flow) = e
        .call(
            "create_connection",
            json!({"service": "my-x", "scopes": ["tweet.write"]}),
        )
        .await;
    assert_eq!(s, 200, "{flow}");
    assert_eq!(flow["provider"], "x", "the service fixes the provider");
    let row = flow_row(&e.pool, flow["flow_id"].as_str().unwrap()).await;
    assert_eq!(
        row.upgrade_connection_id.map(|u| u.to_string()),
        Some(conn_id.clone())
    );
    assert!(
        row.scopes.iter().any(|s| s == "tweet.read")
            && row.scopes.iter().any(|s| s == "tweet.write"),
        "the flow asks for the union: {:?}",
        row.scopes
    );

    let callback = e.callback(flow["flow_id"].as_str().unwrap()).await;
    assert_eq!(callback["connection_id"], conn_id.as_str(), "{callback}");

    let conns = e.x_connections().await;
    assert_eq!(conns.len(), 1, "no duplicate row: {conns:?}");
    assert!(has_scope(&conns[0], "tweet.read") && has_scope(&conns[0], "tweet.write"));
    assert_eq!(e.service_connection("my-x").await, Some(conn_id));
}

#[tokio::test]
async fn reconnecting_a_service_on_the_default_connection_upgrades_the_default() {
    let e = setup().await;
    let (_, first) = e
        .connect(json!({"provider": "x", "scopes": ["tweet.read"]}))
        .await;
    let conn_id = first["connection_id"].as_str().unwrap().to_string();
    // No pin: the instance authenticates with the owner's default connection.
    e.create_x_service("my-x", None).await;

    let (s, flow) = e
        .call(
            "create_connection",
            json!({"service": "my-x", "scopes": ["tweet.write"]}),
        )
        .await;
    assert_eq!(s, 200, "{flow}");
    let row = flow_row(&e.pool, flow["flow_id"].as_str().unwrap()).await;
    assert_eq!(
        row.upgrade_connection_id.map(|u| u.to_string()),
        Some(conn_id)
    );
    assert!(
        row.pins.is_empty(),
        "a default-following service stays unpinned"
    );
}

#[tokio::test]
async fn connecting_a_service_with_no_connection_binds_the_new_one() {
    let e = setup().await;
    let instance = e.create_x_service("my-x", None).await;

    let (flow, callback) = e.connect(json!({"service": "my-x"})).await;
    let row = flow_row(&e.pool, flow["flow_id"].as_str().unwrap()).await;
    assert_eq!(row.upgrade_connection_id, None);
    assert_eq!(row.pins, vec![instance]);

    assert_eq!(
        e.service_connection("my-x").await.as_deref(),
        callback["connection_id"].as_str(),
        "{callback}"
    );
}

#[tokio::test]
async fn reconnecting_a_service_rejects_a_mismatched_provider() {
    let e = setup().await;
    e.create_x_service("my-x", None).await;
    let (s, v) = e
        .call(
            "create_connection",
            json!({"service": "my-x", "provider": "google"}),
        )
        .await;
    assert_eq!(s, 400, "{v}");
}

#[tokio::test]
async fn another_users_connection_is_refused_before_the_user_is_sent_anywhere() {
    let e = setup().await;
    // A colleague's connection, connected through their own flow.
    let colleague: Value = e
        .client
        .post(format!("{}/v1/identities", e.base))
        .header("Authorization", format!("Bearer {}", e.admin_key))
        .json(&json!({"name": "colleague", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let colleague: Uuid = colleague["id"].as_str().unwrap().parse().unwrap();
    let state = common::seed_oauth_flow(&e.pool, e.org_id, colleague, "x", None).await;
    let theirs = e.callback(&state).await;

    let flows_before = sqlx::query_scalar!("SELECT COUNT(*) FROM oauth_connection_flows")
        .fetch_one(&e.pool)
        .await
        .unwrap();
    let (s, v) = e
        .call(
            "create_connection",
            json!({"upgrade_connection_id": theirs["connection_id"]}),
        )
        .await;
    assert_eq!(s, 404, "{v}");
    assert!(v.to_string().contains("connection not found"), "{v}");
    let flows_after = sqlx::query_scalar!("SELECT COUNT(*) FROM oauth_connection_flows")
        .fetch_one(&e.pool)
        .await
        .unwrap();
    assert_eq!(
        flows_before, flows_after,
        "no flow minted for a foreign target"
    );
}

#[tokio::test]
async fn connecting_the_same_account_again_updates_the_existing_connection() {
    let e = setup().await;
    let (_, first) = e
        .connect(json!({"provider": "x", "scopes": ["tweet.read"]}))
        .await;
    let (_, second) = e
        .connect(json!({"provider": "x", "scopes": ["tweet.read", "tweet.write"]}))
        .await;
    assert_eq!(
        first["connection_id"], second["connection_id"],
        "same user, provider, account and client, and a grant covering the row ⇒ same row"
    );

    let conns = e.x_connections().await;
    assert_eq!(conns.len(), 1, "{conns:?}");
    assert!(has_scope(&conns[0], "tweet.read"), "{conns:?}");
    assert!(has_scope(&conns[0], "tweet.write"), "{conns:?}");
    assert_eq!(conns[0]["is_default"], true);
}

/// A provider that does not accumulate grants (GitHub OAuth Apps) issues a
/// token carrying only what this flow asked for. Swapping it into the row
/// would strip the broader token its services rely on, so the narrower grant
/// gets a row of its own and the original is left untouched.
#[tokio::test]
async fn a_narrower_grant_for_the_same_account_never_shrinks_the_existing_connection() {
    let e = setup().await;
    let (_, first) = e
        .connect(json!({"provider": "x", "scopes": ["tweet.read", "tweet.write"]}))
        .await;
    let (_, second) = e
        .connect(json!({"provider": "x", "scopes": ["tweet.write"]}))
        .await;
    assert_ne!(first["connection_id"], second["connection_id"]);

    let conns = e.x_connections().await;
    assert_eq!(conns.len(), 2, "{conns:?}");
    let original = conns
        .iter()
        .find(|c| c["id"] == first["connection_id"])
        .unwrap_or_else(|| panic!("original row gone: {conns:?}"));
    assert!(has_scope(original, "tweet.read"), "{original}");
    assert!(has_scope(original, "tweet.write"), "{original}");
    assert_eq!(original["is_default"], true);
}

/// Slack, Microsoft and the like: one email, several separately-granted
/// workspaces or tenants. A second connect must never overwrite the first.
#[tokio::test]
async fn a_tenant_scoped_provider_is_never_merged_by_email() {
    let e = setup().await;
    sqlx::query!("UPDATE oauth_providers SET email_identifies_account = false WHERE key = 'x'")
        .execute(&e.pool)
        .await
        .unwrap();
    let (_, first) = e.connect(json!({"provider": "x"})).await;
    let (_, second) = e.connect(json!({"provider": "x"})).await;
    assert_ne!(first["connection_id"], second["connection_id"]);
    assert_eq!(e.x_connections().await.len(), 2);
}

#[tokio::test]
async fn an_unknown_account_is_never_merged() {
    let e = setup().await;
    // No userinfo ⇒ no account email ⇒ nothing to recognise the account by.
    point_userinfo(&e.pool, e.mock, "/does-not-exist").await;
    let (_, first) = e.connect(json!({"provider": "x"})).await;
    let (_, second) = e.connect(json!({"provider": "x"})).await;
    assert_ne!(first["connection_id"], second["connection_id"]);
    assert_eq!(e.x_connections().await.len(), 2);
}

#[tokio::test]
async fn list_connections_shows_the_owners_connections() {
    let e = setup().await;
    let (_, first) = e.connect(json!({"provider": "x"})).await;

    let (s, all) = e.call("list_connections", json!({})).await;
    assert_eq!(s, 200, "{all}");
    let conn = all
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == first["connection_id"])
        .unwrap_or_else(|| panic!("connection missing from {all}"))
        .clone();
    assert_eq!(conn["owner_identity_id"], e.user_id.to_string());
    assert_eq!(conn["account_email"], "testuser@example.com");
    assert!(conn["updated_at"].is_string(), "{conn}");

    let (_, google) = e
        .call("list_connections", json!({"provider": "google"}))
        .await;
    assert_eq!(google, json!([]));
}

/// The dashboard learns a popup flow finished from the flow itself — a
/// background token refresh moves `updated_at` too, so the connections list
/// can't tell. Only the flow's actor (or the user it connects for) may read it.
#[tokio::test]
async fn a_flow_reports_its_outcome_to_its_starter_only() {
    let e = setup().await;
    let (s, flow) = e.call("create_connection", json!({"provider": "x"})).await;
    assert_eq!(s, 200, "{flow}");
    let flow_id = flow["flow_id"].as_str().unwrap();
    let status = |key: String| {
        let client = e.client.clone();
        let url = format!("{}/v1/oauth/flows/{flow_id}", e.base);
        async move {
            let r = client
                .get(url)
                .header(common::auth(&key).0, common::auth(&key).1)
                .send()
                .await
                .unwrap();
            (r.status().as_u16(), r.json::<Value>().await.unwrap())
        }
    };

    let (s, v) = status(e.agent_key.clone()).await;
    assert_eq!((s, v["status"].as_str()), (200, Some("pending")), "{v}");

    let callback = e.callback(flow_id).await;
    let (s, v) = status(e.agent_key.clone()).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["status"], "completed");
    assert_eq!(v["connection_id"], callback["connection_id"]);

    // The org's admin neither started this flow nor owns its connection.
    let (s, v) = status(e.admin_key.clone()).await;
    assert_eq!(s, 404, "{v}");
}

/// Another user's instance — here opened by id as an org admin — is not the
/// caller's to reconnect: its connection is the owner's, and a new one of the
/// caller's could not be bound to it. Refused up front instead of minting an
/// unbound connection.
#[tokio::test]
async fn reconnecting_another_users_service_is_refused() {
    let e = setup().await;
    let instance = e.create_x_service("my-x", None).await;
    let r = e
        .client
        .post(format!("{}/v1/actions/call", e.base))
        .header(common::auth(&e.admin_key).0, common::auth(&e.admin_key).1)
        .json(
            &json!({"service": "overslash", "action": "create_connection",
                      "params": {"service": instance.to_string()}}),
        )
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let body = r.text().await.unwrap();
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("only its owner can reconnect"), "{body}");
}

#[tokio::test]
async fn reconnecting_an_archived_service_is_refused() {
    let e = setup().await;
    let instance = e.create_x_service("my-x", None).await;
    let r = e
        .client
        .patch(format!("{}/v1/services/{instance}/status", e.base))
        // Archiving is an admin act.
        .header(common::auth(&e.admin_key).0, common::auth(&e.admin_key).1)
        .json(&json!({"status": "archived"}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{:?}", r.text().await);
    let (s, v) = e
        .call("create_connection", json!({"service": "my-x"}))
        .await;
    assert_eq!(s, 400, "{v}");
    assert!(v.to_string().contains("archived"), "{v}");
}
