//! Secrets are namespaced per user; bindings are qualified paths.
//!
//! The bug this pins: in one org, user julia configured her own `shortcut`
//! service with `shortcut_api_token` — a secret that belonged to user angel —
//! and her calls ran on angel's credential, because secret names were
//! org-unique and every lookup went by org + name. Now each user has a vault,
//! a binding names a vault, and nobody can bind or inline another user's.
#![allow(clippy::disallowed_methods)] // planting a pre-fix binding needs raw SQL

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

use common::{auth, start_api_with_registry, start_mock};

/// A user identity with an agent under it, and keys for both.
struct Member {
    user_id: Uuid,
    user_key: String,
    agent_key: String,
}

struct Org {
    pool: sqlx::PgPool,
    base: String,
    client: Client,
    /// The org creator: an admin user.
    admin_id: Uuid,
    admin_key: String,
    angel: Member,
    julia: Member,
}

async fn api_key(base: &str, client: &Client, admin_key: &str, org_id: Uuid, id: Uuid) -> String {
    let resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({"org_id": org_id, "identity_id": id, "name": "k"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["key"].as_str().unwrap().to_string()
}

async fn identity(base: &str, client: &Client, admin_key: &str, body: Value) -> Uuid {
    let v: Value = client
        .post(format!("{base}/v1/identities"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["id"].as_str().unwrap().parse().unwrap()
}

async fn member(base: &str, client: &Client, admin_key: &str, org_id: Uuid, name: &str) -> Member {
    let user_id = identity(
        base,
        client,
        admin_key,
        json!({"name": name, "kind": "user", "email": format!("{name}@reveni.test")}),
    )
    .await;
    let agent_id = identity(
        base,
        client,
        admin_key,
        json!({"name": format!("{name}-agent"), "kind": "agent", "parent_id": user_id}),
    )
    .await;
    // An agent may call `http` freely here; the namespace check is what's
    // under test, not the permission gate.
    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({"identity_id": agent_id, "action_pattern": "http:**", "effect": "allow"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    Member {
        user_id,
        user_key: api_key(base, client, admin_key, org_id, user_id).await,
        agent_key: api_key(base, client, admin_key, org_id, agent_id).await,
    }
}

async fn setup() -> Org {
    common::allow_loopback_ssrf();
    let pool = common::test_pool().await;
    // The shipped registry, for the `shortcut` template from the bug.
    let (base, client) = start_api_with_registry(pool.clone(), None).await;
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "Reveni", "slug": format!("reveni-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();
    let admin_key = org["api_key"].as_str().unwrap().to_string();
    let admin_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM identities WHERE org_id = $1 AND kind = 'user' AND is_org_admin",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let angel = member(&base, &client, &admin_key, org_id, "angel").await;
    let julia = member(&base, &client, &admin_key, org_id, "julia").await;
    Org {
        pool,
        base,
        client,
        admin_id,
        admin_key,
        angel,
        julia,
    }
}

async fn put_secret(o: &Org, key: &str, name: &str, value: &str, query: &str) -> reqwest::Response {
    o.client
        .put(format!("{}/v1/secrets/{name}{query}", o.base))
        .header(auth(key).0, auth(key).1)
        .json(&json!({"value": value}))
        .send()
        .await
        .unwrap()
}

async fn list_names(o: &Org, key: &str, query: &str) -> Vec<String> {
    let rows: Vec<Value> = o
        .client
        .get(format!("{}/v1/secrets{query}", o.base))
        .header(auth(key).0, auth(key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    rows.iter()
        .map(|r| r["name"].as_str().unwrap().to_string())
        .collect()
}

async fn create_service(o: &Org, key: &str, body: Value) -> reqwest::Response {
    o.client
        .post(format!("{}/v1/services", o.base))
        .header(auth(key).0, auth(key).1)
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn inline_call(
    o: &Org,
    key: &str,
    secret: &str,
    mock: std::net::SocketAddr,
) -> reqwest::Response {
    o.client
        .post(format!("{}/v1/actions/call", o.base))
        .header(auth(key).0, auth(key).1)
        .json(&json!({
            "service": "http",
            "method": "GET",
            "url": format!("http://{mock}/echo"),
            "secrets": [{"name": secret, "inject_as": "header", "header_name": "X-Token"}]
        }))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn each_user_owns_their_own_copy_of_a_name() {
    let o = setup().await;
    // Angel stores it from his agent (it lands in his user vault); julia
    // stores the same name — a separate secret, not a new version of his.
    let r = put_secret(
        &o,
        &o.angel.agent_key,
        "shortcut_api_token",
        "angel-token",
        "",
    )
    .await;
    assert_eq!(r.status(), 200);
    let r = put_secret(
        &o,
        &o.julia.user_key,
        "shortcut_api_token",
        "julia-token",
        "",
    )
    .await;
    assert_eq!(r.status(), 200);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["version"], 1, "julia's copy is v1 of her own secret");

    assert_eq!(
        list_names(&o, &o.julia.user_key, "").await,
        ["shortcut_api_token"]
    );
    assert_eq!(
        list_names(&o, &o.angel.agent_key, "").await,
        ["shortcut_api_token"]
    );
    // Julia cannot list angel's vault, nor the org vault…
    let q = format!("?owner={}", o.angel.user_id);
    assert!(list_names(&o, &o.julia.user_key, &q).await.is_empty());
    assert!(
        list_names(&o, &o.julia.user_key, "?scope=org")
            .await
            .is_empty()
    );
    // …nor write into it.
    let r = put_secret(&o, &o.julia.user_key, "shortcut_api_token", "x", &q).await;
    assert_eq!(r.status(), 403);
    // An admin sees both copies, each under its owner.
    let rows: Vec<Value> = o
        .client
        .get(format!("{}/v1/secrets", o.base))
        .header(auth(&o.admin_key).0, auth(&o.admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut paths: Vec<&str> = rows.iter().map(|r| r["path"].as_str().unwrap()).collect();
    paths.sort();
    let mut want = vec![
        format!("{}/shortcut_api_token", o.angel.user_id),
        format!("{}/shortcut_api_token", o.julia.user_id),
    ];
    want.sort();
    assert_eq!(paths, want);
}

#[tokio::test]
async fn names_that_read_as_paths_are_refused() {
    let o = setup().await;
    for name in ["user:x", "a%2Fb"] {
        let r = put_secret(&o, &o.julia.user_key, name, "v", "").await;
        assert_eq!(r.status(), 400, "{name}");
    }
}

#[tokio::test]
async fn inline_secrets_reach_only_the_callers_own_vault() {
    let o = setup().await;
    let mock = start_mock().await;
    put_secret(
        &o,
        &o.angel.user_key,
        "shortcut_api_token",
        "angel-token",
        "",
    )
    .await;
    put_secret(
        &o,
        &o.julia.user_key,
        "shortcut_api_token",
        "julia-token",
        "",
    )
    .await;
    put_secret(&o, &o.admin_key, "org_key", "org-value", "?scope=org").await;

    // A bare name is julia's own.
    let r = inline_call(&o, &o.julia.agent_key, "shortcut_api_token", mock).await;
    assert_eq!(r.status(), 200);
    let body: Value = r.json().await.unwrap();
    let echo: Value = serde_json::from_str(body["result"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(echo["headers"]["x-token"], "julia-token");

    // Angel's vault, by id or by handle: refused before anything is dialled.
    for name in [
        format!("{}/shortcut_api_token", o.angel.user_id),
        format!("user:{}/shortcut_api_token", o.angel.user_id),
        "angel/shortcut_api_token".to_string(),
        "angel@reveni.test/shortcut_api_token".to_string(),
    ] {
        let r = inline_call(&o, &o.julia.agent_key, &name, mock).await;
        assert_eq!(r.status(), 403, "{name}: {}", r.text().await.unwrap());
    }

    // The org vault is never inlined — not even by an admin's own call.
    let r = inline_call(&o, &o.julia.agent_key, "org/org_key", mock).await;
    assert_eq!(r.status(), 403);
}

#[tokio::test]
async fn a_user_service_binds_only_its_owners_vault() {
    let o = setup().await;
    put_secret(
        &o,
        &o.angel.user_key,
        "shortcut_api_token",
        "angel-token",
        "",
    )
    .await;
    put_secret(
        &o,
        &o.julia.user_key,
        "shortcut_api_token",
        "julia-token",
        "",
    )
    .await;

    // The julia → angel binding from the bug, in every spelling.
    for value in [
        format!("{}/shortcut_api_token", o.angel.user_id),
        "angel/shortcut_api_token".to_string(),
    ] {
        let r = create_service(
            &o,
            &o.julia.agent_key,
            json!({"template_key": "shortcut", "name": "shortcut", "credentials": {"token": value}}),
        )
        .await;
        assert_eq!(r.status(), 403, "{value}: {}", r.text().await.unwrap());
    }
    // Nor the org vault — only admins bind that.
    let r = create_service(
        &o,
        &o.julia.agent_key,
        json!({"template_key": "shortcut", "name": "shortcut", "credentials": {"token": "org/x"}}),
    )
    .await;
    assert_eq!(r.status(), 403);

    // A bare name binds her own copy.
    let r = create_service(
        &o,
        &o.julia.agent_key,
        json!({"template_key": "shortcut", "name": "shortcut",
               "credentials": {"token": "shortcut_api_token"}}),
    )
    .await;
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let svc: Value = r.json().await.unwrap();
    // Shown relative to the owner's vault; stored as julia's full path.
    assert_eq!(svc["credentials"]["token"], json!("shortcut_api_token"));
    assert_eq!(svc["secret_name"], json!("shortcut_api_token"));
    let id: Uuid = svc["id"].as_str().unwrap().parse().unwrap();
    let (stored_map, stored_scalar): (Value, Option<String>) =
        sqlx::query_as("SELECT credentials, secret_name FROM service_instances WHERE id = $1")
            .bind(id)
            .fetch_one(&o.pool)
            .await
            .unwrap();
    let own = format!("{}/shortcut_api_token", o.julia.user_id);
    assert_eq!(stored_map["token"], json!(own));
    assert_eq!(stored_scalar.as_deref(), Some(own.as_str()));

    // Rebinding it to angel's later is refused just the same.
    let r = o
        .client
        .put(format!(
            "{}/v1/services/{}/manage",
            o.base,
            svc["id"].as_str().unwrap()
        ))
        .header(auth(&o.julia.agent_key).0, auth(&o.julia.agent_key).1)
        .json(&json!({"credentials": {"token": format!("{}/shortcut_api_token", o.angel.user_id)}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}

/// A binding written before the fix — julia's service pointing into angel's
/// vault — stays in the row (the migration only reports it) but is never
/// resolved: the call asks for the credential instead of using angel's.
#[tokio::test]
async fn a_planted_cross_user_binding_is_never_resolved() {
    let o = setup().await;
    let mock = start_mock().await;
    put_secret(
        &o,
        &o.angel.user_key,
        "shortcut_api_token",
        "angel-token",
        "",
    )
    .await;
    put_secret(
        &o,
        &o.julia.user_key,
        "shortcut_api_token",
        "julia-token",
        "",
    )
    .await;
    let r = create_service(
        &o,
        &o.julia.agent_key,
        json!({"template_key": "shortcut", "name": "shortcut",
               "credentials": {"token": "shortcut_api_token"},
               "url": format!("http://{mock}")}),
    )
    .await;
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let svc: Value = r.json().await.unwrap();
    let id: Uuid = svc["id"].as_str().unwrap().parse().unwrap();

    let angels = format!("{}/shortcut_api_token", o.angel.user_id);
    sqlx::query(
        "UPDATE service_instances
         SET credentials = jsonb_build_object('token', $2::text), secret_name = $2, status = 'active'
         WHERE id = $1",
    )
    .bind(id)
    .bind(&angels)
    .execute(&o.pool)
    .await
    .unwrap();

    let r = o
        .client
        .post(format!("{}/v1/actions/call", o.base))
        .header(auth(&o.julia.agent_key).0, auth(&o.julia.agent_key).1)
        // The action shape dials the instance's `url` (the fake), never the
        // template's real host.
        .json(&json!({"service": "shortcut", "action": "search_stories", "params": {"query": "x"}}))
        .send()
        .await
        .unwrap();
    let status = r.status();
    let body = r.text().await.unwrap();
    assert!(
        !body.contains("angel-token"),
        "angel's secret leaked: {body}"
    );
    assert_ne!(
        status, 200,
        "a cross-user binding must not authenticate: {body}"
    );
    assert!(
        body.contains("needs_authentication") && body.contains("token"),
        "expected the credential to be reported missing: {status} {body}"
    );
}

#[tokio::test]
async fn a_shared_org_service_keeps_its_admins_binding() {
    let o = setup().await;
    put_secret(&o, &o.admin_key, "shortcut_api_token", "admin-token", "").await;
    let everyone = common::everyone_group_id(&o.base, &o.client, &o.admin_key).await;
    let r = create_service(
        &o,
        &o.admin_key,
        json!({"template_key": "shortcut", "name": "shortcut-shared", "user_level": false,
               "groups": [{"group_id": everyone, "access_level": "write"}],
               "credentials": {"token": "shortcut_api_token"}}),
    )
    .await;
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let svc: Value = r.json().await.unwrap();
    let id = svc["id"].as_str().unwrap().to_string();
    // The creating admin reads it relative to their own vault…
    assert_eq!(svc["credentials"]["token"], json!("shortcut_api_token"));
    let admins = format!("{}/shortcut_api_token", o.admin_id);

    // A second admin (angel, promoted) edits something else, or re-sends the
    // map unchanged: the binding into the first admin's vault is kept.
    sqlx::query("UPDATE identities SET is_org_admin = true WHERE id = $1")
        .bind(o.angel.user_id)
        .execute(&o.pool)
        .await
        .unwrap();
    let patch = |body: Value| {
        o.client
            .put(format!("{}/v1/services/{id}/manage", o.base))
            .header(auth(&o.angel.user_key).0, auth(&o.angel.user_key).1)
            .json(&body)
            .send()
    };
    let r = patch(json!({"name": "shortcut-team"})).await.unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    // …another admin reads the full path into the first admin's vault, and
    // echoing it back is no change.
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["credentials"]["token"], json!(admins));
    let r = patch(json!({"credentials": {"token": admins}}))
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["credentials"]["token"], json!(admins));

    // Rebinding writes into the editing admin's own vault…
    put_secret(
        &o,
        &o.angel.user_key,
        "shortcut_api_token",
        "angel-token",
        "",
    )
    .await;
    let r = patch(json!({"credentials": {"token": "shortcut_api_token"}}))
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["credentials"]["token"], json!("shortcut_api_token"));
    let (stored,): (Value,) =
        sqlx::query_as("SELECT credentials FROM service_instances WHERE id = $1::uuid")
            .bind(&id)
            .fetch_one(&o.pool)
            .await
            .unwrap();
    assert_eq!(
        stored["token"],
        json!(format!("{}/shortcut_api_token", o.angel.user_id))
    );
    // …and pointing it back at someone else's is now a change, so refused.
    let r = patch(json!({"credentials": {"token": admins}}))
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    // An admin may bind the org vault on an org service.
    let r = patch(json!({"credentials": {"token": "org/shortcut_api_token"}}))
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{}", r.text().await.unwrap());
}

#[tokio::test]
async fn a_name_in_another_vault_is_no_conflict_and_is_never_mentioned() {
    let o = setup().await;
    put_secret(
        &o,
        &o.angel.user_key,
        "shortcut_api_token",
        "angel-token",
        "",
    )
    .await;
    // Julia's unbound create mints a setup link for `shortcut_api_token` in
    // her own vault. Angel's same-named secret is not hers to conflict with —
    // the 409 used to suggest binding it.
    let r = create_service(
        &o,
        &o.julia.agent_key,
        json!({"template_key": "shortcut", "name": "shortcut"}),
    )
    .await;
    let status = r.status();
    let body = r.text().await.unwrap();
    assert_ne!(status, 409, "{body}");
    assert!(!body.contains(&o.angel.user_id.to_string()), "{body}");
}

#[tokio::test]
async fn a_secret_request_cannot_target_a_colleagues_vault() {
    let o = setup().await;
    let r = o
        .client
        .post(format!("{}/v1/secrets/requests", o.base))
        .header(auth(&o.julia.user_key).0, auth(&o.julia.user_key).1)
        .json(&json!({"secret_name": "shortcut_api_token", "identity_id": o.angel.user_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "{}", r.text().await.unwrap());
}

/// Migration 133 against the bug's own shape, on a real database: roll back
/// to before vaults existed, seed the pre-fix rows, migrate forward.
#[tokio::test]
async fn migration_133_qualifies_bindings_and_rehomes_secrets() {
    /// The migration before vaults. Renumber with 133 if it moves.
    const BEFORE: i64 = 132;
    let pool = common::test_pool().await;
    overslash_db::MIGRATOR.undo(&pool, BEFORE).await.unwrap();

    let org = Uuid::new_v4();
    let (angel, julia, bot, admin) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    sqlx::query("INSERT INTO orgs (id, name, slug) VALUES ($1, 'Reveni', $2)")
        .bind(org)
        .bind(format!("reveni-{org}"))
        .execute(&pool)
        .await
        .unwrap();
    for (id, name, admin_flag) in [
        (angel, "angel", false),
        (julia, "julia", false),
        (admin, "admin", true),
    ] {
        sqlx::query(
            "INSERT INTO identities (id, org_id, name, kind, is_org_admin) VALUES ($1, $2, $3, 'user', $4)",
        )
        .bind(id)
        .bind(org)
        .bind(name)
        .bind(admin_flag)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO identities (id, org_id, name, kind, parent_id, owner_id, depth)
         VALUES ($1, $2, 'julia-bot', 'agent', $3, $3, 1)",
    )
    .bind(bot)
    .bind(org)
    .bind(julia)
    .execute(&pool)
    .await
    .unwrap();
    for (name, owner) in [
        ("shortcut_api_token", angel), // angel's, which julia bound
        ("bot_token", bot),            // written by julia's agent
        ("OAUTH_GOOGLE_CLIENT_ID", admin),
        ("overfwd_gateway_key", admin),
        ("admin_token", admin),
    ] {
        sqlx::query("INSERT INTO secrets (org_id, name, owner_identity_id) VALUES ($1, $2, $3)")
            .bind(org)
            .bind(name)
            .bind(owner)
            .execute(&pool)
            .await
            .unwrap();
    }
    let insert = |owner: Option<Uuid>, name: &str, scalar: Option<&str>, creds: Value| {
        sqlx::query(
            "INSERT INTO service_instances
                 (org_id, owner_identity_id, name, template_source, template_key, secret_name, credentials)
             VALUES ($1, $2, $3, 'global', 'shortcut', $4, $5) RETURNING id",
        )
        .bind(org)
        .bind(owner)
        .bind(name.to_string())
        .bind(scalar.map(str::to_string))
        .bind(creds)
    };
    let julias: (Uuid,) = insert(
        Some(julia),
        "shortcut",
        Some("shortcut_api_token"),
        json!({"token": "shortcut_api_token"}),
    )
    .fetch_one(&pool)
    .await
    .map(|r: sqlx::postgres::PgRow| (sqlx::Row::get(&r, 0),))
    .unwrap();
    let mixed: (Uuid,) = insert(
        Some(julia),
        "mixed",
        None,
        json!({"a": "bot_token", "b": "never_filled", "g": "overfwd_gateway_key"}),
    )
    .fetch_one(&pool)
    .await
    .map(|r: sqlx::postgres::PgRow| (sqlx::Row::get(&r, 0),))
    .unwrap();
    let shared: (Uuid,) = insert(
        None,
        "shared",
        Some("admin_token"),
        json!({"token": "admin_token"}),
    )
    .fetch_one(&pool)
    .await
    .map(|r: sqlx::postgres::PgRow| (sqlx::Row::get(&r, 0),))
    .unwrap();

    overslash_db::MIGRATOR.run(&pool).await.unwrap();

    let owner_of = |name: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, Option<Uuid>>(
                "SELECT owner_identity_id FROM secrets WHERE org_id = $1 AND name = $2",
            )
            .bind(org)
            .bind(name)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    assert_eq!(owner_of("shortcut_api_token").await, Some(angel));
    assert_eq!(
        owner_of("bot_token").await,
        Some(julia),
        "agent secret re-homed to its user"
    );
    assert_eq!(
        owner_of("OAUTH_GOOGLE_CLIENT_ID").await,
        None,
        "OAuth app creds → org vault"
    );
    assert_eq!(
        owner_of("overfwd_gateway_key").await,
        None,
        "org-source default → org vault"
    );
    assert_eq!(owner_of("admin_token").await, Some(admin));

    let bindings = |id: Uuid| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (Option<String>, Value)>(
                "SELECT secret_name, credentials FROM service_instances WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    // Julia's binding into angel's vault is qualified as exactly that — kept
    // and reported, and refused by the read rule (see the planted test).
    let (scalar, creds) = bindings(julias.0).await;
    let angels = format!("{angel}/shortcut_api_token");
    assert_eq!(scalar.as_deref(), Some(angels.as_str()));
    assert_eq!(creds["token"], json!(angels));
    let (_, creds) = bindings(mixed.0).await;
    assert_eq!(creds["a"], json!(format!("{julia}/bot_token")));
    assert_eq!(
        creds["b"],
        json!(format!("{julia}/never_filled")),
        "unfilled → owner's vault"
    );
    assert_eq!(creds["g"], json!("org/overfwd_gateway_key"));
    let (scalar, creds) = bindings(shared.0).await;
    let admins = format!("{admin}/admin_token");
    assert_eq!(scalar.as_deref(), Some(admins.as_str()));
    assert_eq!(creds["token"], json!(admins));

    // Uniqueness is per vault now: julia can hold her own copy.
    sqlx::query("INSERT INTO secrets (org_id, name, owner_identity_id) VALUES ($1, 'shortcut_api_token', $2)")
        .bind(org)
        .bind(julia)
        .execute(&pool)
        .await
        .unwrap();
    // …but one vault still can't hold a name twice, the org vault included.
    for owner in [Some(julia), None] {
        if owner.is_none() {
            sqlx::query("INSERT INTO secrets (org_id, name) VALUES ($1, 'dup')")
                .bind(org)
                .execute(&pool)
                .await
                .unwrap();
        }
        let dup = sqlx::query(
            "INSERT INTO secrets (org_id, name, owner_identity_id) VALUES ($1, $2, $3)",
        )
        .bind(org)
        .bind(if owner.is_some() {
            "shortcut_api_token"
        } else {
            "dup"
        })
        .bind(owner)
        .execute(&pool)
        .await;
        assert!(dup.is_err(), "duplicate in vault {owner:?} must be refused");
    }
    // Deleting a user deletes their vault rather than promoting it org-wide.
    sqlx::query("DELETE FROM identities WHERE id = $1")
        .bind(angel)
        .execute(&pool)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM secrets WHERE org_id = $1 AND name = 'shortcut_api_token' AND owner_identity_id IS NULL",
    )
    .bind(org)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(left, 0);
}
