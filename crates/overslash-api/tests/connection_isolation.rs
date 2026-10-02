//! A service instance can only authenticate with its owner's own OAuth
//! connection.
//!
//! The twin of `secret_namespaces.rs` for connections. Create already checked
//! a pinned `connection_id`; update did not, and the call-time resolvers
//! loaded a pinned connection org-wide. So julia could pin angel's Google
//! connection onto her own service and call Google as angel — and on an MCP
//! service, with `url` pointed at her own host, receive his bearer token.
#![allow(clippy::disallowed_methods)] // seeding connections and planting a pre-fix pin need raw SQL

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

use common::{auth, start_api_with_registry, start_mock};

struct Member {
    user_id: Uuid,
    user_key: String,
    agent_key: String,
    /// The user's Google connection; its access token is `<name>-token`.
    connection: Uuid,
}

struct Org {
    pool: sqlx::PgPool,
    base: String,
    client: Client,
    admin_key: String,
    mock: std::net::SocketAddr,
    angel: Member,
    julia: Member,
}

async fn post(client: &Client, url: String, key: &str, body: Value) -> Value {
    client
        .post(url)
        .header(auth(key).0, auth(key).1)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn seed_connection(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    owner: Uuid,
    token: &str,
    email: &str,
) -> Uuid {
    let enc_key = overslash_core::crypto::Keyring::test();
    let access = overslash_core::crypto::encrypt(&enc_key, token.as_bytes()).unwrap();
    sqlx::query_scalar(
        "INSERT INTO connections (org_id, identity_id, provider_key, encrypted_access_token,
                                  token_expires_at, scopes, account_email, is_default)
         VALUES ($1, $2, 'google', $3, now() + interval '1 hour', $4, $5, true) RETURNING id",
    )
    .bind(org_id)
    .bind(owner)
    .bind(&access)
    .bind(vec![
        "openid".to_string(),
        "https://www.googleapis.com/auth/calendar".to_string(),
    ])
    .bind(email)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn member(o: &OrgBase, name: &str) -> Member {
    let user = post(
        &o.client,
        format!("{}/v1/identities", o.base),
        &o.admin_key,
        json!({"name": name, "kind": "user", "email": format!("{name}@reveni.test")}),
    )
    .await;
    let user_id: Uuid = user["id"].as_str().unwrap().parse().unwrap();
    let agent = post(
        &o.client,
        format!("{}/v1/identities", o.base),
        &o.admin_key,
        json!({"name": format!("{name}-agent"), "kind": "agent", "parent_id": user_id}),
    )
    .await;
    let agent_id: Uuid = agent["id"].as_str().unwrap().parse().unwrap();
    post(
        &o.client,
        format!("{}/v1/permissions", o.base),
        &o.admin_key,
        json!({"identity_id": agent_id, "action_pattern": "google_calendar:**", "effect": "allow"}),
    )
    .await;
    let key_for = |id: Uuid| {
        post(
            &o.client,
            format!("{}/v1/api-keys", o.base),
            &o.admin_key,
            json!({"org_id": o.org_id, "identity_id": id, "name": "k"}),
        )
    };
    let key = key_for(agent_id).await;
    let user_key = key_for(user_id).await["key"].as_str().unwrap().to_string();
    let connection = seed_connection(
        &o.pool,
        o.org_id,
        user_id,
        &format!("{name}-token"),
        &format!("{name}@gmail.test"),
    )
    .await;
    Member {
        user_id,
        user_key,
        agent_key: key["key"].as_str().unwrap().to_string(),
        connection,
    }
}

struct OrgBase {
    pool: sqlx::PgPool,
    base: String,
    client: Client,
    org_id: Uuid,
    admin_key: String,
}

async fn org(pool: sqlx::PgPool, base: String, client: Client) -> OrgBase {
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "Reveni", "slug": format!("reveni-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admin_key = org["api_key"].as_str().unwrap().to_string();
    // Org client credentials, so OAuth resolution reaches the token.
    let put = client
        .put(format!("{base}/v1/org-oauth-credentials/google"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"client_id": "test_id.apps.googleusercontent.com",
                      "client_secret": "GOCSPX-test_secret"}))
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200);
    OrgBase {
        pool,
        base,
        client,
        org_id: org["id"].as_str().unwrap().parse().unwrap(),
        admin_key,
    }
}

async fn setup() -> Org {
    common::allow_loopback_ssrf();
    let pool = common::test_pool().await;
    let (base, client) = start_api_with_registry(pool.clone(), None).await;
    let o = org(pool, base, client).await;
    let angel = member(&o, "angel").await;
    let julia = member(&o, "julia").await;
    Org {
        pool: o.pool,
        base: o.base,
        client: o.client,
        admin_key: o.admin_key,
        mock: start_mock().await,
        angel,
        julia,
    }
}

impl Org {
    async fn create(&self, key: &str, body: Value) -> (u16, Value) {
        let r = self
            .client
            .post(format!("{}/v1/services", self.base))
            .header(auth(key).0, auth(key).1)
            .json(&body)
            .send()
            .await
            .unwrap();
        let s = r.status().as_u16();
        (s, r.json().await.unwrap_or(Value::Null))
    }

    async fn update(&self, key: &str, id: &str, body: Value) -> u16 {
        let r = self
            .client
            .put(format!("{}/v1/services/{id}/manage", self.base))
            .header(auth(key).0, auth(key).1)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        eprintln!(
            "update {body} -> {status}: {}",
            r.text().await.unwrap_or_default()
        );
        status
    }

    /// The agent-facing twin of `update`: the `overslash.update_service`
    /// platform action (what MCP agents call), same kernel.
    async fn update_via_agent(&self, key: &str, id: &str, mut params: Value) -> u16 {
        params["id"] = json!(id);
        let r = self
            .client
            .post(format!("{}/v1/actions/call", self.base))
            .header(auth(key).0, auth(key).1)
            .json(&json!({"service": "overslash", "action": "update_service", "params": params}))
            .send()
            .await
            .unwrap();
        let status = r.status().as_u16();
        eprintln!(
            "update_service {params} -> {status}: {}",
            r.text().await.unwrap_or_default()
        );
        status
    }

    /// A user-level `google_calendar` instance pointed at the echoing fake.
    async fn julias_calendar(&self) -> String {
        let (s, v) = self
            .create(
                &self.julia.agent_key,
                json!({"template_key": "google_calendar", "name": "calendar",
                       "url": format!("http://{}", self.mock)}),
            )
            .await;
        assert_eq!(s, 200, "{v}");
        let id = v["id"].as_str().unwrap().to_string();
        sqlx::query("UPDATE service_instances SET status = 'active' WHERE id = $1::uuid")
            .bind(&id)
            .execute(&self.pool)
            .await
            .unwrap();
        id
    }

    /// Call it through the action shape (the instance `url`, i.e. the fake,
    /// which echoes the request headers back).
    async fn call(&self) -> (u16, String) {
        let r = self
            .client
            .post(format!("{}/v1/actions/call", self.base))
            .header(auth(&self.julia.agent_key).0, auth(&self.julia.agent_key).1)
            .json(&json!({"service": "calendar", "action": "list_calendars", "params": {}}))
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.text().await.unwrap())
    }
}

#[tokio::test]
async fn create_refuses_another_users_connection() {
    let o = setup().await;
    let (s, v) = o
        .create(
            &o.julia.agent_key,
            json!({"template_key": "google_calendar", "name": "calendar",
                   "connection_id": o.angel.connection}),
        )
        .await;
    assert_eq!(s, 403, "{v}");
    let (s, v) = o
        .create(
            &o.julia.agent_key,
            json!({"template_key": "google_calendar", "name": "calendar",
                   "connection_id": o.julia.connection}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
}

#[tokio::test]
async fn update_refuses_another_users_connection() {
    let o = setup().await;
    let id = o.julias_calendar().await;
    // The bug: re-pin her own service onto angel's connection.
    assert_eq!(
        o.update(
            &o.julia.user_key,
            &id,
            json!({"connection_id": o.angel.connection})
        )
        .await,
        403
    );
    // Even an admin can't make one user's service run on another's account.
    assert_eq!(
        o.update(
            &o.admin_key,
            &id,
            json!({"connection_id": o.angel.connection})
        )
        .await,
        403
    );
    // Her own is fine, and so is unpinning.
    assert_eq!(
        o.update(
            &o.julia.user_key,
            &id,
            json!({"connection_id": o.julia.connection})
        )
        .await,
        200
    );
    assert_eq!(
        o.update(&o.julia.user_key, &id, json!({"connection_id": null}))
            .await,
        200
    );
    // The agent path (MCP `update_service`) runs the same check.
    assert_eq!(
        o.update_via_agent(
            &o.julia.agent_key,
            &id,
            json!({"connection_id": o.angel.connection})
        )
        .await,
        403
    );
    assert_eq!(
        o.update_via_agent(
            &o.julia.agent_key,
            &id,
            json!({"connection_id": o.julia.connection})
        )
        .await,
        200
    );
    assert_eq!(
        o.update(&o.julia.user_key, &id, json!({"connection_id": null}))
            .await,
        200
    );
    // Nothing foreign reached the row.
    let pinned: Option<Uuid> =
        sqlx::query_scalar("SELECT connection_id FROM service_instances WHERE id = $1::uuid")
            .bind(&id)
            .fetch_one(&o.pool)
            .await
            .unwrap();
    assert_eq!(pinned, None);
}

#[tokio::test]
async fn her_own_calls_use_her_own_token() {
    let o = setup().await;
    o.julias_calendar().await;
    let (s, body) = o.call().await;
    assert_eq!(s, 200, "{body}");
    assert!(body.contains("julia-token"), "{body}");
    assert!(!body.contains("angel-token"), "{body}");
}

/// A pin written before the fix — julia's service pointing at angel's
/// connection — is ignored at call time: the call falls back to julia's own
/// default connection and never carries angel's token.
#[tokio::test]
async fn a_planted_foreign_pin_is_never_resolved() {
    let o = setup().await;
    let id = o.julias_calendar().await;
    sqlx::query("UPDATE service_instances SET connection_id = $2 WHERE id = $1::uuid")
        .bind(&id)
        .bind(o.angel.connection)
        .execute(&o.pool)
        .await
        .unwrap();
    let (_, body) = o.call().await;
    assert!(
        !body.contains("angel-token"),
        "angel's token leaked: {body}"
    );
    assert!(
        body.contains("julia-token"),
        "expected julia's default connection: {body}"
    );

    // With her default connection gone too, it asks for authentication
    // rather than borrowing angel's.
    sqlx::query("DELETE FROM connections WHERE id = $1")
        .bind(o.julia.connection)
        .execute(&o.pool)
        .await
        .unwrap();
    let (s, body) = o.call().await;
    assert!(
        !body.contains("angel-token"),
        "angel's token leaked: {body}"
    );
    assert_ne!(s, 200, "{body}");
    assert!(body.contains("needs_authentication"), "{s} {body}");
}

#[tokio::test]
async fn a_connection_from_another_org_is_not_found() {
    let o = setup().await;
    let other = org(o.pool.clone(), o.base.clone(), o.client.clone()).await;
    let stranger = member(&other, "stranger").await;
    let (s, v) = o
        .create(
            &o.admin_key,
            json!({"template_key": "google_calendar", "name": "cal-x",
                   "connection_id": stranger.connection}),
        )
        .await;
    assert_eq!(s, 404, "{v}");
    let id = o.julias_calendar().await;
    assert_eq!(
        o.update(
            &o.admin_key,
            &id,
            json!({"connection_id": stranger.connection})
        )
        .await,
        404
    );
}

/// `create_connection` with someone else's `upgrade_connection_id` must not
/// lend that connection's account email to the authorize URL.
#[tokio::test]
async fn an_upgrade_flow_never_leaks_a_foreign_account_email() {
    let o = setup().await;
    let r = o
        .client
        .post(format!("{}/v1/actions/call", o.base))
        .header(auth(&o.julia.agent_key).0, auth(&o.julia.agent_key).1)
        .json(
            &json!({"service": "overslash", "action": "create_connection",
                      "params": {"provider": "google",
                                 "upgrade_connection_id": o.angel.connection}}),
        )
        .send()
        .await
        .unwrap();
    let body = r.text().await.unwrap();
    assert!(!body.contains("angel@gmail.test"), "leaked: {body}");
    assert!(!body.contains("angel%40gmail.test"), "leaked: {body}");
    let _ = o.angel.user_id;
}
