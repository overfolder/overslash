// Integration tests for the Instance Admin panel API (`/v1/instance/*`):
// org listing and creation, instance-admin grant/revoke with the last-admin
// guard, the read-only config view, and the instance audit trail.

#![allow(clippy::disallowed_methods)]

use crate::common;

use overslash_api::services::jwt;
use overslash_db::repos::user as user_repo;
use reqwest::Client;
use serde_json::{Value, json};
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

// ── Helpers ──────────────────────────────────────────────────────────

/// A dashboard session JWT carrying `user_id`. `jti: None` skips admin
/// step-up, as for every other session minted by the test suite.
fn session_cookie(org_id: Uuid, identity_id: Uuid, user_id: Uuid) -> String {
    let secret = hex::decode("cd".repeat(32)).expect("valid hex");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = jwt::Claims {
        sub: identity_id,
        org: org_id,
        email: "panel@example.com".into(),
        aud: jwt::AUD_SESSION.into(),
        iat: now,
        exp: now + 3600,
        user_id: Some(user_id),
        mcp_client_id: None,
        jti: None,
    };
    format!(
        "__Host-oss_session={}",
        jwt::mint(&secret, &claims).expect("mint jwt")
    )
}

struct Person {
    user_id: Uuid,
    org_id: Uuid,
    cookie: String,
}

/// An Overslash-backed (root IdP) user with a personal org they're admin of.
async fn person(pool: &PgPool, email: &str, instance_admin: bool) -> Person {
    let user = user_repo::create_overslash_backed(
        pool,
        Some(email),
        Some(email.split('@').next().unwrap()),
        "google",
        &format!("subj-{}", Uuid::new_v4()),
    )
    .await
    .unwrap();
    let org = overslash_db::repos::org::create(
        pool,
        "Personal",
        &format!("personal-{}", Uuid::new_v4().simple()),
        "standard",
    )
    .await
    .unwrap();
    sqlx::query("UPDATE orgs SET is_personal = true WHERE id = $1")
        .bind(org.id)
        .execute(pool)
        .await
        .unwrap();
    let ident = overslash_db::repos::identity::create_with_email(
        pool,
        org.id,
        email,
        "user",
        None,
        Some(email),
        json!({}),
    )
    .await
    .unwrap();
    overslash_db::repos::identity::set_user_id(pool, org.id, ident.id, Some(user.id))
        .await
        .unwrap();
    if instance_admin {
        user_repo::set_instance_admin(pool, user.id, true)
            .await
            .unwrap();
    }
    Person {
        user_id: user.id,
        org_id: org.id,
        cookie: session_cookie(org.id, ident.id, user.id),
    }
}

async fn get(client: &Client, url: String, cookie: &str) -> reqwest::Response {
    client
        .get(url)
        .header("cookie", cookie)
        .send()
        .await
        .unwrap()
}

async fn ok(req: reqwest::RequestBuilder, cookie: &str) {
    let r = req.header("cookie", cookie).send().await.unwrap();
    let status = r.status();
    assert!(status.is_success(), "{status}: {:?}", r.text().await);
}

// ── Access control ──────────────────────────────────────────────────

#[tokio::test]
async fn every_route_rejects_non_admins_and_api_keys() {
    let pool = common::test_pool().await;
    let member = person(&pool, "member@example.com", false).await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let (_org, _ident, agent_key, _admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let gets = [
        "/v1/instance/orgs",
        "/v1/instance/admins",
        "/v1/instance/users?q=ex",
        "/v1/instance/config",
        "/v1/instance/audit",
        "/v1/instance/audit/export",
    ];
    for path in gets {
        let r = get(&client, format!("{base}{path}"), &member.cookie).await;
        assert_eq!(r.status(), 403, "{path} as non-admin");
        let body: Value = r.json().await.unwrap();
        assert_eq!(body["error"], "instance_admin_required", "{path}");

        let r = client
            .get(format!("{base}{path}"))
            .header("authorization", format!("Bearer {agent_key}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401, "{path} with an API key");
    }

    let r = client
        .post(format!("{base}/v1/instance/admins"))
        .header("cookie", &member.cookie)
        .json(&json!({ "user_id": member.user_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}

// ── Orgs ────────────────────────────────────────────────────────────

#[tokio::test]
async fn lists_orgs_with_counts_and_hides_personal_by_default() {
    let pool = common::test_pool().await;
    let admin = person(&pool, "root@example.com", true).await;
    let team = overslash_db::repos::org::create(&pool, "Helio", "helio-test", "standard")
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO user_org_memberships (user_id, org_id, role) VALUES ($1, $2, 'member')",
    )
    .bind(admin.user_id)
    .bind(team.id)
    .execute(&pool)
    .await
    .unwrap();
    let ends = OffsetDateTime::now_utc() + time::Duration::days(5);
    overslash_db::repos::org::set_trial(&pool, team.id, ends)
        .await
        .unwrap();

    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let body: Value = get(&client, format!("{base}/v1/instance/orgs"), &admin.cookie)
        .await
        .json()
        .await
        .unwrap();
    let orgs = body["orgs"].as_array().unwrap();
    assert!(orgs.iter().all(|o| o["is_personal"] == false));
    let helio = orgs.iter().find(|o| o["slug"] == "helio-test").unwrap();
    assert_eq!(helio["plan"], "trial");
    assert_eq!(helio["trial_ends_at"], ends.unix_timestamp());
    assert_eq!(helio["member_count"], 1);
    assert!(body["trial_default_duration_days"].is_u64());

    let body: Value = get(
        &client,
        format!("{base}/v1/instance/orgs?include_personal=true"),
        &admin.cookie,
    )
    .await
    .json()
    .await
    .unwrap();
    assert!(
        body["orgs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["id"] == admin.org_id.to_string())
    );
}

#[tokio::test]
async fn creates_orgs_with_each_plan_without_switching_the_session() {
    let pool = common::test_pool().await;
    let admin = person(&pool, "root@example.com", true).await;
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    for plan in ["standard", "trial", "free_unlimited"] {
        let slug = format!(
            "{}-{}",
            plan.replace('_', "-"),
            &Uuid::new_v4().simple().to_string()[..8]
        );
        let r = client
            .post(format!("{base}/v1/instance/orgs"))
            .header("cookie", &admin.cookie)
            .json(&json!({ "name": format!("Org {plan}"), "slug": slug, "plan": plan, "trial_days": 14 }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "{plan}");
        assert!(
            r.headers().get("set-cookie").is_none(),
            "creating from the panel must not move the admin's session"
        );
        let body: Value = r.json().await.unwrap();
        let id: Uuid = body["id"].as_str().unwrap().parse().unwrap();

        let (db_plan, trial_ends_at): (String, Option<OffsetDateTime>) =
            sqlx::query_as("SELECT plan, trial_ends_at FROM orgs WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(db_plan, plan);
        assert_eq!(trial_ends_at.is_some(), plan == "trial");

        // The admin is the bootstrap admin, so the org is never orphaned.
        let role: String = sqlx::query_scalar(
            "SELECT role FROM user_org_memberships WHERE org_id = $1 AND user_id = $2",
        )
        .bind(id)
        .bind(admin.user_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(role, "admin");

        let audit: (String, Option<String>) = sqlx::query_as(
            "SELECT actor_email, org_slug FROM instance_audit_log WHERE action = 'org.created' AND org_id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audit.0, "root@example.com");
        assert_eq!(audit.1.as_deref(), Some(slug.as_str()));
    }

    let r = client
        .post(format!("{base}/v1/instance/orgs"))
        .header("cookie", &admin.cookie)
        .json(&json!({ "name": "Bad", "slug": "bad-plan-org", "plan": "enterprise" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

// ── Admins ──────────────────────────────────────────────────────────

#[tokio::test]
async fn grant_and_revoke_with_last_admin_guard() {
    let pool = common::test_pool().await;
    let root = person(&pool, "root@example.com", true).await;
    let maria = person(&pool, "maria@example.com", false).await;
    let org_only = user_repo::create_org_only(&pool, Some("lena@example.com"), Some("Lena"))
        .await
        .unwrap();

    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    // Last admin: refused.
    let r = client
        .delete(format!("{base}/v1/instance/admins/{}", root.user_id))
        .header("cookie", &root.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["error"], "last_instance_admin");

    // The search marks the org-only user ineligible.
    let found: Value = get(
        &client,
        format!("{base}/v1/instance/users?q=example.com"),
        &root.cookie,
    )
    .await
    .json()
    .await
    .unwrap();
    let lena = found
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["email"] == "lena@example.com")
        .unwrap();
    assert_eq!(lena["eligible"], false);
    assert!(lena["reason"].is_string());

    // Org-only users can't be granted.
    let r = client
        .post(format!("{base}/v1/instance/admins"))
        .header("cookie", &root.cookie)
        .json(&json!({ "user_id": org_only.id }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["error"], "not_eligible");

    // Grant María.
    let r = client
        .post(format!("{base}/v1/instance/admins"))
        .header("cookie", &root.cookie)
        .json(&json!({ "user_id": maria.user_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    let admins: Value = get(&client, format!("{base}/v1/instance/admins"), &root.cookie)
        .await
        .json()
        .await
        .unwrap();
    let admins = admins.as_array().unwrap();
    assert_eq!(admins.len(), 2);
    let root_row = admins.iter().find(|a| a["is_you"] == true).unwrap();
    assert!(
        root_row["granted_at"].is_null(),
        "psql bootstrap shows as such"
    );
    let maria_row = admins
        .iter()
        .find(|a| a["email"] == "maria@example.com")
        .unwrap();
    assert!(maria_row["granted_at"].is_i64());
    assert_eq!(maria_row["granted_by_email"], "root@example.com");

    // Now root can be revoked — by María.
    let r = client
        .delete(format!("{base}/v1/instance/admins/{}", root.user_id))
        .header("cookie", &maria.cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    assert!(
        !user_repo::is_instance_admin(&pool, root.user_id)
            .await
            .unwrap()
    );

    // Revocation is immediate.
    let r = get(&client, format!("{base}/v1/instance/orgs"), &root.cookie).await;
    assert_eq!(r.status(), 403);

    // Both landed in the instance audit, newest first.
    let audit: Value = get(&client, format!("{base}/v1/instance/audit"), &maria.cookie)
        .await
        .json()
        .await
        .unwrap();
    let actions: Vec<&str> = audit["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(
        actions,
        ["instance_admin.revoked", "instance_admin.granted"]
    );
    assert!(audit["entries"][0]["org_slug"].is_null());
}

// ── Config ──────────────────────────────────────────────────────────

#[tokio::test]
async fn config_reports_secrets_as_set_only() {
    let pool = common::test_pool().await;
    let admin = person(&pool, "root@example.com", true).await;
    let stripe = "sk_test_do_not_leak_0123456789";
    let (addr, client) = common::start_api_with(pool.clone(), |cfg| {
        cfg.stripe_secret_key = Some(stripe.into());
        cfg.trial_default_duration_days = 21;
    })
    .await;
    let base = format!("http://{addr}");

    let r = get(&client, format!("{base}/v1/instance/config"), &admin.cookie).await;
    assert_eq!(r.status(), 200);
    let text = r.text().await.unwrap();
    assert!(!text.contains(stripe), "a secret value leaked: {text}");

    let body: Value = serde_json::from_str(&text).unwrap();
    let rows: Vec<&Value> = body["groups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["rows"].as_array().unwrap())
        .collect();
    let row = |k: &str| *rows.iter().find(|r| r["key"] == k).unwrap();
    assert_eq!(row("STRIPE_SECRET_KEY")["kind"], "secret");
    assert_eq!(row("STRIPE_SECRET_KEY")["set"], true);
    assert_eq!(row("TRIAL_DEFAULT_DURATION_DAYS")["value"], "21");
    assert_eq!(row("Version")["kind"], "text");
}

// ── Audit ───────────────────────────────────────────────────────────

#[tokio::test]
async fn plan_and_trial_changes_write_instance_audit_with_filters_and_paging() {
    let pool = common::test_pool().await;
    let admin = person(&pool, "root@example.com", true).await;
    let org = overslash_db::repos::org::create(&pool, "Kestrel", "kestrel-test", "standard")
        .await
        .unwrap();
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");

    let c = &admin.cookie;
    ok(
        client
            .post(format!("{base}/v1/orgs/{}/trial", org.id))
            .json(&json!({ "duration_days": 30 })),
        c,
    )
    .await;
    ok(
        client
            .patch(format!("{base}/v1/orgs/{}/trial", org.id))
            .json(&json!({ "extend_days": 7 })),
        c,
    )
    .await;
    ok(
        client
            .patch(format!("{base}/v1/orgs/{}/plan", org.id))
            .json(&json!({ "plan": "standard" })),
        c,
    )
    .await;

    // Page through one at a time.
    let mut cursor: Option<String> = None;
    let mut actions = Vec::new();
    loop {
        let mut url = format!("{base}/v1/instance/audit?org=kestrel-test&limit=1");
        if let Some(c) = &cursor {
            url.push_str(&format!("&cursor={c}"));
        }
        let page: Value = get(&client, url, &admin.cookie).await.json().await.unwrap();
        for e in page["entries"].as_array().unwrap() {
            actions.push(e["action"].as_str().unwrap().to_string());
            assert_eq!(e["actor_email"], "root@example.com");
        }
        match page["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }
    assert_eq!(
        actions,
        [
            "org.plan.updated",
            "org.trial_extended",
            "org.trial_started"
        ]
    );

    let page: Value = get(
        &client,
        format!("{base}/v1/instance/audit?action=org.trial_extended"),
        &admin.cookie,
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(page["entries"].as_array().unwrap().len(), 1);
    assert_eq!(page["entries"][0]["detail"]["extend_days"], 7);

    // The org's own audit still carries them, for its members.
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE org_id = $1 AND action LIKE 'org.%'",
    )
    .bind(org.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(n >= 3);

    let r = get(
        &client,
        format!("{base}/v1/instance/audit/export?format=csv"),
        &admin.cookie,
    )
    .await;
    assert_eq!(r.status(), 200);
    let csv = r.text().await.unwrap();
    assert!(csv.starts_with("created_at,actor_email,action,org_slug,detail,ip_address\n"));
    assert_eq!(csv.lines().count(), 4);

    // The dashboard reuses the list's query string for the export link, so
    // paging params must be accepted (and ignored), not a 400.
    let r = get(
        &client,
        format!("{base}/v1/instance/audit/export?format=jsonl&limit=50&cursor=x"),
        &admin.cookie,
    )
    .await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap().lines().count(), 3);
}

#[tokio::test]
async fn instance_audit_list_and_export_honour_the_time_window() {
    let pool = common::test_pool().await;
    let admin = person(&pool, "root@example.com", true).await;
    let org = overslash_db::repos::org::create(&pool, "Osprey", "osprey-test", "standard")
        .await
        .unwrap();
    let (addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{addr}");
    let c = &admin.cookie;

    ok(
        client
            .post(format!("{base}/v1/orgs/{}/trial", org.id))
            .json(&json!({ "duration_days": 30 })),
        c,
    )
    .await;
    // Age the trial start out of a one-day window.
    sqlx::query(
        "UPDATE instance_audit_log SET created_at = now() - interval '10 days'
          WHERE action = 'org.trial_started'",
    )
    .execute(&pool)
    .await
    .unwrap();
    ok(
        client
            .patch(format!("{base}/v1/orgs/{}/trial", org.id))
            .json(&json!({ "extend_days": 7 })),
        c,
    )
    .await;

    let rfc = |t: OffsetDateTime| {
        t.format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let now = OffsetDateTime::now_utc();
    let since = rfc(now - time::Duration::days(1));
    let until = rfc(now + time::Duration::minutes(5));

    let actions = |page: &Value| -> Vec<String> {
        page["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["action"].as_str().unwrap().to_string())
            .collect()
    };

    let page: Value = get(
        &client,
        format!("{base}/v1/instance/audit?org=osprey-test&since={since}&until={until}"),
        c,
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(actions(&page), ["org.trial_extended"]);

    // An upper bound before the extension leaves only the aged row.
    let early = rfc(now - time::Duration::days(1));
    let page: Value = get(
        &client,
        format!("{base}/v1/instance/audit?org=osprey-test&until={early}"),
        c,
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(actions(&page), ["org.trial_started"]);

    let r = get(
        &client,
        format!("{base}/v1/instance/audit/export?format=jsonl&org=osprey-test&since={since}"),
        c,
    )
    .await;
    assert_eq!(r.status(), 200);
    let disposition = r
        .headers()
        .get("content-disposition")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        disposition.starts_with("attachment; filename=\"instance-audit-2")
            && disposition.ends_with(".jsonl\""),
        "{disposition}"
    );
    let body = r.text().await.unwrap();
    assert_eq!(body.lines().count(), 1);
    assert!(body.contains("org.trial_extended"));

    let r = get(
        &client,
        format!("{base}/v1/instance/audit?since=yesterday"),
        c,
    )
    .await;
    assert_eq!(r.status(), 400);
}
