//! Regression tests for the binding-policy rules beyond D119/D120.
//!
//! Each one is a reference stored on (or chosen for) something user B owns,
//! resolving into something B must not reach:
//!
//! * **Instance template.** An instance resolves its *owner's* template. A
//!   caller who could reach an org-level service shadowed its template with a
//!   same-key user template of their own, and the service's credential went
//!   to that template's paths and actions.
//! * **Org-vault gate.** An org-source slot on a user-level instance reads the
//!   org vault only when the request lands on the base the org/global tier
//!   declares. Pointing one's own instance (`url`, a user-tier template) at
//!   another host used to carry the org's secret there.
//! * **BYOC pin.** A connection runs only on its owner's own OAuth app, for
//!   its provider — at create, import, and every refresh.
//! * **Connection pins in views and imports.** A foreign pin never shows a
//!   colleague's account, and import refuses a pin for the wrong provider.
//!
//! The fake upstream echoes request headers and path, so a credential that
//! reached it shows up in the response body.
#![allow(clippy::disallowed_methods)] // forcing instances active and planting pre-fix rows need raw SQL

use crate::common;

use std::sync::{Arc, Mutex};

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

use common::{auth, everyone_grant, start_api_with_registry_customized, start_mock};

/// The org's sanctioned host for its templates, and somewhere else. Both are
/// routed to the echoing fake (`service_base_overrides`) — the second under
/// `/evil`, so the echoed path tells them apart. Template hosts lose their
/// port, so a loopback `servers` URL could not reach the fake directly.
const HOME: &str = "https://home.binding.test";
const EVIL: &str = "https://evil.binding.test";

struct Member {
    user_id: Uuid,
    key: String,
}

struct World {
    pool: sqlx::PgPool,
    base: String,
    client: Client,
    org_id: Uuid,
    admin_key: String,
    mock: std::net::SocketAddr,
    angel: Member,
    julia: Member,
}

impl World {
    async fn send(&self, req: reqwest::RequestBuilder, key: &str) -> (u16, String) {
        let r = req.header(auth(key).0, auth(key).1).send().await.unwrap();
        (r.status().as_u16(), r.text().await.unwrap())
    }

    async fn post(&self, key: &str, path: &str, body: Value) -> (u16, String) {
        self.send(
            self.client.post(format!("{}{path}", self.base)).json(&body),
            key,
        )
        .await
    }

    async fn put(&self, key: &str, path: &str, body: Value) -> (u16, String) {
        self.send(
            self.client.put(format!("{}{path}", self.base)).json(&body),
            key,
        )
        .await
    }

    async fn get(&self, key: &str, path: &str) -> (u16, String) {
        self.send(self.client.get(format!("{}{path}", self.base)), key)
            .await
    }

    /// Create a service and force it active (the fake has no probe route).
    async fn service(&self, key: &str, body: Value) -> String {
        let (s, b) = self.post(key, "/v1/services", body).await;
        assert_eq!(s, 200, "{b}");
        let id = serde_json::from_str::<Value>(&b).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        sqlx::query("UPDATE service_instances SET status = 'active' WHERE id = $1::uuid")
            .bind(&id)
            .execute(&self.pool)
            .await
            .unwrap();
        id
    }

    /// Call `action` on the service named `service` through the action shape
    /// (it dials the instance's own base — the fake).
    async fn call(&self, key: &str, service: &str, action: &str) -> (u16, String) {
        self.post(
            key,
            "/v1/actions/call",
            json!({"service": service, "action": action, "params": {}}),
        )
        .await
    }

    async fn template(&self, key: &str, user_level: bool, openapi: String) {
        let (s, b) = self
            .post(
                key,
                "/v1/templates",
                json!({"openapi": openapi, "user_level": user_level}),
            )
            .await;
        assert_eq!(s, 200, "template create: {b}");
    }
}

async fn member(base: &str, client: &Client, admin_key: &str, org_id: Uuid, name: &str) -> Member {
    let post = |path: &str, body: Value| {
        client
            .post(format!("{base}{path}"))
            .header(auth(admin_key).0, auth(admin_key).1)
            .json(&body)
            .send()
    };
    let user: Value = post(
        "/v1/identities",
        json!({"name": name, "kind": "user", "email": format!("{name}@binding.test")}),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let user_id: Uuid = user["id"].as_str().unwrap().parse().unwrap();
    let key: Value = post(
        "/v1/api-keys",
        json!({"org_id": org_id, "identity_id": user_id, "name": "k"}),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    Member {
        user_id,
        key: key["key"].as_str().unwrap().to_string(),
    }
}

async fn world() -> World {
    common::allow_loopback_ssrf();
    let pool = common::test_pool().await;
    let mock = start_mock().await;
    let (base, client) = start_api_with_registry_customized(pool.clone(), None, move |cfg| {
        cfg.service_base_overrides
            .insert("home.binding.test".into(), format!("http://{mock}"));
        cfg.service_base_overrides
            .insert("evil.binding.test".into(), format!("http://{mock}/evil"));
    })
    .await;
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "Binding", "slug": format!("binding-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();
    let admin_key = org["api_key"].as_str().unwrap().to_string();
    let r = client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({"user_template_policy": "full"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let angel = member(&base, &client, &admin_key, org_id, "angel").await;
    let julia = member(&base, &client, &admin_key, org_id, "julia").await;
    World {
        pool,
        base,
        client,
        org_id,
        admin_key,
        mock,
        angel,
        julia,
    }
}

/// A template at `server` with one `GET /items` read and the given security
/// schemes (YAML, indented for `components.securitySchemes`).
fn openapi(key: &str, server: &str, schemes: &str, extra_paths: &str) -> String {
    format!(
        "openapi: 3.1.0
info:
  title: {key}
  key: {key}
servers:
  - url: {server}
components:
  securitySchemes:
{schemes}
paths:
  /items:
    get:
      operationId: list_items
      summary: List items
      risk: read
{extra_paths}"
    )
}

/// An optional org-source gateway key, as `email.yaml` declares
/// `overfwd_gateway_key`.
const GATEWAY: &str = "    gateway:
      type: apiKey
      in: header
      name: X-Gateway
      x-overslash-template:
        lang: jq
        expr: .gateway
      x-overslash-secret_source: org
      x-overslash-optional: true
      default_secret_name: gw_key";

const ORG_GATEWAY_KEY: &str = "CANARY-ORG-GATEWAY-KEY";

// ── Org-vault gate ─────────────────────────────────────────────────────

/// The org stores `gw_key` for its `gw` template at the fake's root.
async fn gateway_world() -> World {
    let w = world().await;
    w.template(&w.admin_key, false, openapi("gw", HOME, GATEWAY, ""))
        .await;
    let (s, b) = w
        .put(
            &w.admin_key,
            "/v1/secrets/gw_key?scope=org",
            json!({"value": ORG_GATEWAY_KEY}),
        )
        .await;
    assert_eq!(s, 200, "{b}");
    w
}

#[tokio::test]
async fn the_org_gateway_key_reaches_the_templates_own_host() {
    let w = gateway_world().await;
    w.service(
        &w.julia.key,
        json!({"template_key": "gw", "name": "gw-home", "user_level": true}),
    )
    .await;
    let (s, body) = w.call(&w.julia.key, "gw-home", "list_items").await;
    assert_eq!(s, 200, "{body}");
    assert!(
        body.contains(ORG_GATEWAY_KEY),
        "positive control: a user-level instance at the template's own host gets the org key: {body}"
    );
}

#[tokio::test]
async fn an_instance_url_override_does_not_carry_the_org_key() {
    let w = gateway_world().await;
    let evil = EVIL;
    // Created pointing elsewhere…
    w.service(
        &w.julia.key,
        json!({"template_key": "gw", "name": "gw-away", "user_level": true, "url": evil}),
    )
    .await;
    let (_, body) = w.call(&w.julia.key, "gw-away", "list_items").await;
    assert!(
        !body.contains(ORG_GATEWAY_KEY),
        "LEAK via create url: {body}"
    );

    // …or repointed after creation.
    let id = w
        .service(
            &w.julia.key,
            json!({"template_key": "gw", "name": "gw-moved", "user_level": true}),
        )
        .await;
    let (s, b) = w
        .put(
            &w.julia.key,
            &format!("/v1/services/{id}/manage"),
            json!({"url": evil}),
        )
        .await;
    assert_eq!(s, 200, "{b}");
    let (_, body) = w.call(&w.julia.key, "gw-moved", "list_items").await;
    assert!(
        !body.contains(ORG_GATEWAY_KEY),
        "LEAK via updated url: {body}"
    );
}

#[tokio::test]
async fn an_admin_bound_org_key_does_not_follow_a_moved_url() {
    let w = gateway_world().await;
    let id = w
        .service(
            &w.julia.key,
            json!({"template_key": "gw", "name": "gw-bound", "user_level": true}),
        )
        .await;
    // An admin may bind the org vault on an org-source slot (D119)…
    let (s, b) = w
        .put(
            &w.admin_key,
            &format!("/v1/services/{id}/manage"),
            json!({"credentials": {"gateway": "org/gw_key"}}),
        )
        .await;
    assert_eq!(s, 200, "{b}");
    let (_, body) = w.call(&w.julia.key, "gw-bound", "list_items").await;
    assert!(body.contains(ORG_GATEWAY_KEY), "positive control: {body}");
    // …but the owner then moving the instance takes the destination, not the key.
    let (s, b) = w
        .put(
            &w.julia.key,
            &format!("/v1/services/{id}/manage"),
            json!({"url": EVIL}),
        )
        .await;
    assert_eq!(s, 200, "{b}");
    let (_, body) = w.call(&w.julia.key, "gw-bound", "list_items").await;
    assert!(
        !body.contains(ORG_GATEWAY_KEY),
        "LEAK via bound slot: {body}"
    );
}

#[tokio::test]
async fn a_user_template_cannot_source_the_org_vault() {
    let w = gateway_world().await;
    let evil = EVIL;
    // A same-key shadow of the org template, served from elsewhere…
    w.template(&w.julia.key, true, openapi("gw", evil, GATEWAY, ""))
        .await;
    w.service(
        &w.julia.key,
        json!({"template_key": "gw", "name": "gw-shadow", "user_level": true}),
    )
    .await;
    let (_, body) = w.call(&w.julia.key, "gw-shadow", "list_items").await;
    assert!(
        !body.contains(ORG_GATEWAY_KEY),
        "LEAK via shadow template: {body}"
    );

    // …and a template of her own naming the org's secret as its default.
    w.template(&w.julia.key, true, openapi("mine", evil, GATEWAY, ""))
        .await;
    w.service(
        &w.julia.key,
        json!({"template_key": "mine", "name": "mine", "user_level": true}),
    )
    .await;
    let (_, body) = w.call(&w.julia.key, "mine", "list_items").await;
    assert!(
        !body.contains(ORG_GATEWAY_KEY),
        "LEAK via own template: {body}"
    );
}

// ── Instance template ──────────────────────────────────────────────────

const TOKEN_SCHEME: &str = "    token:
      type: apiKey
      in: header
      name: X-Token
      x-overslash-template:
        lang: jq
        expr: .token
      default_secret_name: ztpl_token";

const ADMIN_TOKEN: &str = "CANARY-ADMIN-ZTPL-TOKEN";

#[tokio::test]
async fn a_shared_service_resolves_its_owners_template_not_the_callers() {
    let w = world().await;
    w.template(&w.admin_key, false, openapi("ztpl", HOME, TOKEN_SCHEME, ""))
        .await;
    let (s, b) = w
        .put(
            &w.admin_key,
            "/v1/secrets/ztpl_token",
            json!({"value": ADMIN_TOKEN}),
        )
        .await;
    assert_eq!(s, 200, "{b}");
    let groups = everyone_grant(&w.base, &w.client, &w.admin_key).await;
    w.service(
        &w.admin_key,
        json!({"template_key": "ztpl", "name": "ztpl", "user_level": false,
               "credentials": {"token": "ztpl_token"}, "groups": groups}),
    )
    .await;

    // Julia shadows the key with a template of her own: the same action at
    // another path, plus one that does not exist on the real template.
    let steal = "  /steal:
    get:
      operationId: steal
      summary: Steal
      risk: read
";
    w.template(
        &w.julia.key,
        true,
        openapi("ztpl", EVIL, TOKEN_SCHEME, steal),
    )
    .await;

    let (s, body) = w.call(&w.julia.key, "ztpl", "list_items").await;
    assert_eq!(s, 200, "{body}");
    let echoed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    assert!(
        !body.contains("/evil"),
        "the shared service ran on the caller's template: {echoed}"
    );
    assert!(
        body.contains(ADMIN_TOKEN),
        "the shared service uses its configuring admin's token (the sanctioned crossing): {body}"
    );

    let (_, body) = w.call(&w.julia.key, "ztpl", "steal").await;
    assert!(
        !body.contains(ADMIN_TOKEN),
        "an action from the caller's template ran on the shared credential: {body}"
    );
}

// ── BYOC pin ───────────────────────────────────────────────────────────

const ANGEL_CLIENT_ID: &str = "CANARY-ANGEL-CLIENT-ID";
const ANGEL_SECRET: &str = "CANARY-ANGEL-CLIENT-SECRET";

async fn byoc(w: &World, m: &Member, provider: &str, id: &str, secret: &str) -> Uuid {
    let (s, b) = w
        .post(
            &m.key,
            "/v1/byoc-credentials",
            json!({"provider": provider, "client_id": id, "client_secret": secret,
                   "identity_id": m.user_id}),
        )
        .await;
    assert_eq!(s, 200, "{b}");
    serde_json::from_str::<Value>(&b).unwrap()["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn a_connection_cannot_pin_another_users_oauth_app() {
    let w = world().await;
    let angels = byoc(&w, &w.angel, "google", ANGEL_CLIENT_ID, ANGEL_SECRET).await;
    let julias = byoc(&w, &w.julia, "google", "julia-client", "julia-secret").await;
    let julias_github = byoc(&w, &w.julia, "github", "julia-gh", "julia-gh-secret").await;

    // Create: a colleague's app, or an app for another provider, is refused.
    for (pin, what) in [(angels, "angel's app"), (julias_github, "a github app")] {
        let (s, body) = w
            .post(
                &w.julia.key,
                "/v1/connections",
                json!({"provider": "google", "byoc_credential_id": pin}),
            )
            .await;
        assert_eq!(s, 400, "create pinned {what}: {body}");
        assert!(!body.contains(ANGEL_CLIENT_ID), "{body}");
    }
    let (s, body) = w
        .post(
            &w.julia.key,
            "/v1/connections",
            json!({"provider": "google", "byoc_credential_id": julias}),
        )
        .await;
    assert_eq!(s, 200, "own app: {body}");

    // Import: same rule — import pins the app permanently.
    let (s, body) = w
        .post(
            &w.julia.key,
            "/v1/connections/import",
            json!({"provider": "google", "access_token": "julia-imported",
                   "account_email": "julia@gmail.test", "byoc_credential_id": angels}),
        )
        .await;
    assert_eq!(s, 400, "import pinned angel's app: {body}");
}

/// A token endpoint that records the client credentials it is sent.
async fn recording_token_endpoint() -> (String, Arc<Mutex<Vec<String>>>) {
    use axum::{Router, routing::post};
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let s = seen.clone();
    let app = Router::new().route(
        "/token",
        post(move |headers: axum::http::HeaderMap, body: String| {
            let s = s.clone();
            async move {
                let basic = headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                s.lock().unwrap().push(format!("{basic} {body}"));
                axum::Json(
                    json!({"access_token": "refreshed-token", "token_type": "Bearer",
                                  "expires_in": 3600}),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/token"), seen)
}

#[tokio::test]
async fn a_planted_byoc_pin_is_never_used_at_refresh() {
    let w = world().await;
    let angels = byoc(&w, &w.angel, "google", ANGEL_CLIENT_ID, ANGEL_SECRET).await;
    let (s, b) = w
        .put(
            &w.admin_key,
            "/v1/org-oauth-credentials/google",
            json!({"client_id": "org-client.apps.googleusercontent.com",
                   "client_secret": "org-secret"}),
        )
        .await;
    assert_eq!(s, 200, "{b}");
    let (token_url, seen) = recording_token_endpoint().await;
    sqlx::query("UPDATE oauth_providers SET token_endpoint = $1 WHERE key = 'google'")
        .bind(&token_url)
        .execute(&w.pool)
        .await
        .unwrap();

    // Julia's expired connection, pinned (as a pre-fix row could be) to
    // angel's app.
    let enc = overslash_core::crypto::Keyring::test();
    let access = overslash_core::crypto::encrypt(&enc, b"julia-stale").unwrap();
    let refresh = overslash_core::crypto::encrypt(&enc, b"julia-refresh").unwrap();
    let conn: Uuid = sqlx::query_scalar(
        "INSERT INTO connections (org_id, identity_id, provider_key, encrypted_access_token,
                                  encrypted_refresh_token, token_expires_at, scopes,
                                  account_email, is_default, byoc_credential_id)
         VALUES ($1, $2, 'google', $3, $4, now() - interval '1 hour', $5, $6, true, $7)
         RETURNING id",
    )
    .bind(w.org_id)
    .bind(w.julia.user_id)
    .bind(&access)
    .bind(&refresh)
    .bind(vec![
        "openid".to_string(),
        "https://www.googleapis.com/auth/calendar".to_string(),
    ])
    .bind("julia@gmail.test")
    .bind(angels)
    .fetch_one(&w.pool)
    .await
    .unwrap();

    // The connection view no longer reports a BYOC source for it.
    let (s, body) = w
        .get(&w.julia.key, &format!("/v1/connections/{conn}"))
        .await;
    assert_eq!(s, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_ne!(v["credential_source"]["kind"], "byoc", "{body}");

    // A call refreshes the token: through the org app, never angel's.
    w.service(
        &w.julia.key,
        json!({"template_key": "google_calendar", "name": "calendar",
               "url": format!("http://{}", w.mock), "connection_id": conn}),
    )
    .await;
    let (_, body) = w.call(&w.julia.key, "calendar", "list_calendars").await;
    let seen = seen.lock().unwrap().join("\n");
    assert!(!seen.is_empty(), "the refresh should have run: {body}");
    assert!(
        !seen.contains(ANGEL_SECRET) && !seen.contains(ANGEL_CLIENT_ID),
        "LEAK: angel's OAuth app was presented at refresh:\n{seen}"
    );
}

// ── Connection pins: views and imports ─────────────────────────────────

async fn seed_google_connection(w: &World, owner: Uuid, email: &str) -> Uuid {
    let enc = overslash_core::crypto::Keyring::test();
    let access =
        overslash_core::crypto::encrypt(&enc, format!("{email}-token").as_bytes()).unwrap();
    sqlx::query_scalar(
        "INSERT INTO connections (org_id, identity_id, provider_key, encrypted_access_token,
                                  token_expires_at, scopes, account_email, is_default)
         VALUES ($1, $2, 'google', $3, now() + interval '1 hour', $4, $5, true) RETURNING id",
    )
    .bind(w.org_id)
    .bind(owner)
    .bind(&access)
    .bind(vec![
        "openid".to_string(),
        "https://www.googleapis.com/auth/calendar".to_string(),
    ])
    .bind(email)
    .fetch_one(&w.pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_foreign_pin_never_shows_its_account_in_views() {
    let w = world().await;
    let angels = seed_google_connection(&w, w.angel.user_id, "angel-account@gmail.test").await;
    let id = w
        .service(
            &w.julia.key,
            json!({"template_key": "google_calendar", "name": "calendar"}),
        )
        .await;
    // A pin written before the ownership rule.
    sqlx::query("UPDATE service_instances SET connection_id = $1 WHERE id = $2::uuid")
        .bind(angels)
        .bind(&id)
        .execute(&w.pool)
        .await
        .unwrap();
    for path in [
        "/v1/services".to_string(),
        format!("/v1/services/{id}"),
        "/v1/search?q=calendar".to_string(),
    ] {
        let (_, body) = w.get(&w.julia.key, &path).await;
        assert!(
            !body.contains("angel-account@gmail.test"),
            "LEAK: {path} showed the foreign pin's account:\n{body}"
        );
    }
}

#[tokio::test]
async fn import_refuses_a_pin_for_another_provider() {
    let w = world().await;
    let julias = byoc(&w, &w.julia, "google", "julia-client", "julia-secret").await;
    // A token-authenticated service: no OAuth provider at all.
    let id = w
        .service(
            &w.julia.key,
            json!({"template_key": "shortcut", "name": "shortcut",
                   "url": format!("http://{}", w.mock)}),
        )
        .await;
    let (s, body) = w
        .post(
            &w.julia.key,
            "/v1/connections/import",
            json!({"provider": "google", "access_token": "julia-imported",
                   "account_email": "julia@gmail.test", "byoc_credential_id": julias,
                   "pin_service_ids": [id]}),
        )
        .await;
    assert_eq!(s, 400, "{body}");
    assert!(body.contains("connection_provider_mismatch"), "{body}");
    let pinned: Option<Uuid> =
        sqlx::query_scalar("SELECT connection_id FROM service_instances WHERE id = $1::uuid")
            .bind(&id)
            .fetch_one(&w.pool)
            .await
            .unwrap();
    assert_eq!(pinned, None);
}
