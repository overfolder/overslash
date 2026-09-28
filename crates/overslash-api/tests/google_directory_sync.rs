// Test setup seeds identities and reads back rows the API deliberately does
// not expose, which needs dynamic SQL.
#![allow(clippy::disallowed_methods)]
//! Integration tests for Google Workspace Directory group sync.
//!
//! The API talks to the real `overslash_fakes::google_directory` fake over
//! HTTP — the token exchange verifies the RS256 assertion the API signs, and
//! every listing paginates — with Google's two hosts swapped onto it through
//! `service_base_overrides`. The sweep is driven through
//! `google_directory_worker::run_once` rather than the sleeping loop.

use crate::common;
use crate::directory_group_sync::{
    create_group, map_source, org_with_idp_customized, sign_in, synced_identity_id,
};

use overslash_fakes::google_directory::{self as fake, FakeGroup, GoogleDirectoryHandle};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use overslash_api::services::google_directory_worker;

fn point_at(fake_url: &str, config: &mut overslash_api::config::Config) {
    for host in ["oauth2.googleapis.com", "admin.googleapis.com"] {
        config
            .service_base_overrides
            .insert(host.to_string(), fake_url.to_string());
    }
}

struct Env {
    base: String,
    client: Client,
    pool: PgPool,
    org_id: Uuid,
    admin_key: String,
    fake: GoogleDirectoryHandle,
    /// What the background worker runs on, pointed at the same fake.
    state: overslash_api::AppState,
    _fake_server: overslash_fakes::Handle,
}

async fn env() -> Env {
    let pool = common::test_pool().await;
    let (fake_server, fake) = fake::start("127.0.0.1:0").await;
    let url = fake.url.clone();
    let (addr, client) = common::start_api_with(pool.clone(), |c| point_at(&url, c)).await;
    let base = format!("http://{addr}");
    let (org_id, _, _, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let mut state = common::make_app_state(pool.clone()).await;
    point_at(&fake.url, &mut state.config);
    Env {
        base,
        client,
        pool,
        org_id,
        admin_key,
        fake,
        state,
        _fake_server: fake_server,
    }
}

impl Env {
    async fn put(&self, body: Value) -> (StatusCode, Value) {
        let resp = self
            .client
            .put(format!("{}/v1/google-directory", self.base))
            .header("authorization", format!("Bearer {}", self.admin_key))
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn configure(&self) {
        let (status, body) = self
            .put(json!({
                "service_account_json": fake::service_account_json("sync@acme.iam.gserviceaccount.com"),
                "admin_subject": "admin@acme.com",
            }))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    async fn get(&self) -> (StatusCode, Value) {
        let resp = self
            .client
            .get(format!("{}/v1/google-directory", self.base))
            .header("authorization", format!("Bearer {}", self.admin_key))
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn request_sync(&self) -> (StatusCode, Value) {
        let resp = self
            .client
            .post(format!("{}/v1/google-directory/sync", self.base))
            .header("authorization", format!("Bearer {}", self.admin_key))
            .send()
            .await
            .unwrap();
        let status = resp.status();
        (status, resp.json().await.unwrap_or(Value::Null))
    }

    async fn run_worker(&self) -> usize {
        google_directory_worker::run_once(&self.state, "test-worker")
            .await
            .unwrap()
    }

    /// A user identity in this org, as sign-in would have left it.
    async fn human(&self, email: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO identities (org_id, name, kind, email) \
             VALUES ($1, $2, 'user', $2) RETURNING id",
        )
        .bind(self.org_id)
        .bind(email)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }
}

/// External ids of the Google directory groups `identity_id` is in.
async fn google_memberships(pool: &PgPool, identity_id: Uuid) -> Vec<String> {
    let mut rows = sqlx::query_scalar::<_, String>(
        "SELECT dg.external_id FROM identity_directory_groups idg \
         JOIN directory_groups dg ON dg.id = idg.directory_group_id \
         WHERE idg.identity_id = $1 AND dg.source = 'google_directory'",
    )
    .bind(identity_id)
    .fetch_all(pool)
    .await
    .unwrap();
    rows.sort();
    rows
}

async fn directory_group_id(pool: &PgPool, org_id: Uuid, external_id: &str) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM directory_groups WHERE org_id = $1 AND external_id = $2 \
         AND source = 'google_directory'",
    )
    .bind(org_id)
    .bind(external_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn three_groups() -> Vec<FakeGroup> {
    vec![
        FakeGroup::new(
            "g-eng",
            "Engineering",
            &["alice@acme.com", "bob@acme.com", "carol@acme.com"],
        ),
        FakeGroup::new("g-ops", "Operations", &["alice@acme.com"]),
        FakeGroup::new(
            "g-all",
            "Everyone at Acme",
            &["alice@acme.com", "bob@acme.com", "mallory@other.com"],
        ),
    ]
}

// ── Configuration ────────────────────────────────────────────────────

#[tokio::test]
async fn a_saved_config_never_returns_key_material() {
    let e = env().await;
    e.configure().await;
    let (status, body) = e.get().await;
    assert_eq!(status, StatusCode::OK);
    let text = body.to_string();
    assert!(!text.contains("PRIVATE KEY"), "{text}");
    assert!(body.get("service_account_json").is_none());
    assert_eq!(
        body["service_account_email"],
        "sync@acme.iam.gserviceaccount.com"
    );
    assert_eq!(
        body["domains"],
        json!(["acme.com"]),
        "defaults to the admin's domain"
    );
    assert_eq!(body["sync_interval_hours"], 8);
    assert_eq!(e.fake.with(|s| s.subjects.clone()), vec!["admin@acme.com"]);
}

/// Missing domain-wide delegation is the common setup failure. It must be a
/// 400 carrying Google's reason, and nothing must be stored.
#[tokio::test]
async fn a_credential_google_refuses_is_rejected_and_not_saved() {
    let e = env().await;
    e.fake
        .with(|s| s.token_error = Some("unauthorized_client".into()));
    let (status, body) = e
        .put(json!({
            "service_account_json": fake::service_account_json("sync@acme.iam.gserviceaccount.com"),
            "admin_subject": "admin@acme.com",
        }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.to_string().contains("delegation"), "{body}");
    assert_eq!(e.get().await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_key_that_is_not_a_service_account_is_rejected() {
    let e = env().await;
    let (status, _) = e
        .put(json!({
            "service_account_json": json!({ "type": "authorized_user" }).to_string(),
            "admin_subject": "admin@acme.com",
        }))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(e.fake.with(|s| s.token_requests), 0);
}

#[tokio::test]
async fn another_org_cannot_see_the_config() {
    let e = env().await;
    e.configure().await;
    let (_, _, _, other_key) = common::bootstrap_org_identity(&e.base, &e.client).await;
    let resp = e
        .client
        .get(format!("{}/v1/google-directory", e.base))
        .header("authorization", format!("Bearer {other_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── The sweep ────────────────────────────────────────────────────────

#[tokio::test]
async fn a_sweep_records_groups_and_direct_memberships() {
    let e = env().await;
    e.fake.set_groups(three_groups());
    let alice = e.human("Alice@Acme.com").await;
    let bob = e.human("bob@acme.com").await;
    e.configure().await;

    assert_eq!(e.run_worker().await, 1);

    assert_eq!(
        google_memberships(&e.pool, alice).await,
        ["g-all", "g-eng", "g-ops"]
    );
    assert_eq!(google_memberships(&e.pool, bob).await, ["g-all", "g-eng"]);

    let (_, body) = e.get().await;
    assert_eq!(body["last_sync_status"], "ok");
    assert_eq!(body["last_sync_stats"]["groups"], 3);
    assert_eq!(body["last_sync_stats"]["identities"], 2);
    assert_eq!(body["queued"], false);
    assert_eq!(body["running"], false);

    // Not due again until the interval passes.
    assert_eq!(e.run_worker().await, 0);
}

#[tokio::test]
async fn a_mapped_google_group_confers_membership() {
    let e = env().await;
    e.fake.set_groups(three_groups());
    let alice = e.human("alice@acme.com").await;
    e.configure().await;
    e.run_worker().await;

    let group = create_group(&e.client, &e.base, &e.admin_key, "eng-ceiling").await;
    let dg = directory_group_id(&e.pool, e.org_id, "g-eng").await;
    assert_eq!(
        map_source(&e.client, &e.base, &e.admin_key, group, dg).await,
        StatusCode::OK
    );
    let member: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM effective_identity_groups \
         WHERE identity_id = $1 AND group_id = $2)",
    )
    .bind(alice)
    .bind(group)
    .fetch_one(&e.pool)
    .await
    .unwrap();
    assert!(member);
}

#[tokio::test]
async fn a_member_removed_in_google_loses_membership_on_the_next_sweep() {
    let e = env().await;
    e.fake.set_groups(three_groups());
    let bob = e.human("bob@acme.com").await;
    e.configure().await;
    e.run_worker().await;
    assert_eq!(google_memberships(&e.pool, bob).await, ["g-all", "g-eng"]);

    e.fake.set_groups(vec![FakeGroup::new(
        "g-eng",
        "Engineering",
        &["alice@acme.com"],
    )]);
    assert_eq!(e.request_sync().await.0, StatusCode::ACCEPTED);
    e.run_worker().await;
    assert!(google_memberships(&e.pool, bob).await.is_empty());
}

/// The rule the authoritative sweep rests on: a listing that failed partway
/// is not a listing that came back short.
#[tokio::test]
async fn a_partial_listing_revokes_nothing() {
    let e = env().await;
    e.fake.set_groups(three_groups());
    let carol = e.human("carol@acme.com").await;
    e.configure().await;
    e.run_worker().await;
    assert_eq!(google_memberships(&e.pool, carol).await, ["g-eng"]);

    // Page 1 of g-eng (carol's page) now fails.
    e.fake
        .with(|s| s.fail_members_page = Some(("g-eng".into(), 1)));
    e.request_sync().await;
    e.run_worker().await;

    assert_eq!(google_memberships(&e.pool, carol).await, ["g-eng"]);
    let (_, body) = e.get().await;
    assert_eq!(body["last_sync_status"], "error");
    assert!(
        body["last_sync_error"].as_str().unwrap().contains("500"),
        "{body}"
    );
}

#[tokio::test]
async fn an_identity_outside_the_domains_is_never_touched() {
    let e = env().await;
    e.fake.set_groups(three_groups());
    let mallory = e.human("mallory@other.com").await;
    e.configure().await;
    e.run_worker().await;
    assert!(google_memberships(&e.pool, mallory).await.is_empty());
}

/// Two sources, one human: each reconciles only its own rows.
#[tokio::test]
async fn an_oidc_claim_membership_survives_a_google_sweep() {
    let e = env().await;
    e.fake.set_groups(vec![]);
    let alice = e.human("alice@acme.com").await;
    let claim_group: Uuid = sqlx::query_scalar(
        "INSERT INTO directory_groups (org_id, source, external_id, display_name) \
         VALUES ($1, 'oidc_claim', 'okta-eng', 'okta-eng') RETURNING id",
    )
    .bind(e.org_id)
    .fetch_one(&e.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO identity_directory_groups (identity_id, directory_group_id) VALUES ($1, $2)",
    )
    .bind(alice)
    .bind(claim_group)
    .execute(&e.pool)
    .await
    .unwrap();

    e.configure().await;
    e.run_worker().await;

    let still: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM identity_directory_groups \
         WHERE identity_id = $1 AND directory_group_id = $2)",
    )
    .bind(alice)
    .bind(claim_group)
    .fetch_one(&e.pool)
    .await
    .unwrap();
    assert!(still);
}

#[tokio::test]
async fn deleting_the_config_revokes_derived_access() {
    let e = env().await;
    e.fake.set_groups(three_groups());
    let alice = e.human("alice@acme.com").await;
    e.configure().await;
    e.run_worker().await;
    assert!(!google_memberships(&e.pool, alice).await.is_empty());

    let resp = e
        .client
        .delete(format!("{}/v1/google-directory", e.base))
        .header("authorization", format!("Bearer {}", e.admin_key))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(google_memberships(&e.pool, alice).await.is_empty());
    let left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM directory_groups WHERE org_id = $1 AND source = 'google_directory'",
    )
    .bind(e.org_id)
    .fetch_one(&e.pool)
    .await
    .unwrap();
    assert_eq!(left, 0);
}

// ── The manual queue ─────────────────────────────────────────────────

#[tokio::test]
async fn sync_now_queues_at_most_one_run() {
    let e = env().await;
    e.fake.set_groups(three_groups());
    e.configure().await;
    e.run_worker().await; // the initial sweep; now not due for 8h

    let (status, body) = e.request_sync().await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["queued"], true);
    for _ in 0..5 {
        let (status, body) = e.request_sync().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["already_queued"], true);
    }
    assert_eq!(e.get().await.1["queued"], true);

    let before = e.fake.with(|s| s.token_requests);
    assert_eq!(e.run_worker().await, 1);
    assert_eq!(e.run_worker().await, 0, "five extra clicks queued nothing");
    assert_eq!(e.fake.with(|s| s.token_requests), before + 1);
    assert_eq!(e.get().await.1["queued"], false);
}

/// A click during a run is not swallowed by it: it queues exactly one
/// follow-up, which a second worker may not take while the lease is live.
#[tokio::test]
async fn a_click_during_a_run_queues_one_follow_up() {
    let e = env().await;
    e.fake.set_groups(three_groups());
    e.configure().await;
    e.run_worker().await;

    // Another replica is mid-sweep.
    sqlx::query(
        "UPDATE org_google_directory_configs \
         SET lease_owner = 'other', lease_expires_at = now() + interval '1 hour' WHERE org_id = $1",
    )
    .bind(e.org_id)
    .execute(&e.pool)
    .await
    .unwrap();
    assert_eq!(e.get().await.1["running"], true);
    assert_eq!(e.request_sync().await.0, StatusCode::ACCEPTED);
    assert_eq!(e.request_sync().await.0, StatusCode::OK);

    assert_eq!(e.run_worker().await, 0, "a live lease is never taken");

    // The other replica died; its lease lapses.
    sqlx::query(
        "UPDATE org_google_directory_configs SET lease_expires_at = now() - interval '1 second' \
         WHERE org_id = $1",
    )
    .bind(e.org_id)
    .execute(&e.pool)
    .await
    .unwrap();
    assert_eq!(e.run_worker().await, 1);
    assert_eq!(e.run_worker().await, 0);
}

#[tokio::test]
async fn sync_now_on_a_disabled_config_is_refused() {
    let e = env().await;
    e.configure().await;
    let (status, _) = e.put(json!({ "enabled": false })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(e.request_sync().await.0, StatusCode::CONFLICT);
    assert_eq!(e.run_worker().await, 0, "a disabled config is never due");
}

// ── Sign-in ──────────────────────────────────────────────────────────

/// Sign-in fires a per-user pull and does not wait for it: the fake holds the
/// `userKey` lookup for two seconds, and the callback answers well inside that.
#[tokio::test]
async fn sign_in_syncs_the_user_without_waiting_on_google() {
    let (fake_server, gfake) = fake::start("127.0.0.1:0").await;
    let url = gfake.url.clone();
    let (base, client, pool, _mock, org_id, slug, admin_key) =
        org_with_idp_customized(false, None, |c| point_at(&url, c)).await;

    gfake.set_groups(vec![FakeGroup::new(
        "g-eng",
        "Engineering",
        &["testuser@example.com"],
    )]);
    let resp = client
        .put(format!("{base}/v1/google-directory"))
        .header("authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "service_account_json": fake::service_account_json("sync@example.iam.gserviceaccount.com"),
            "admin_subject": "admin@example.com",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    gfake.with(|s| s.user_groups_delay = Some(std::time::Duration::from_secs(2)));
    let started = std::time::Instant::now();
    sign_in(&client, &base, &slug, "gdir-nonce-1").await;
    assert!(
        started.elapsed() < std::time::Duration::from_millis(1500),
        "sign-in waited on Google: {:?}",
        started.elapsed()
    );

    let identity = synced_identity_id(&pool, org_id).await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if google_memberships(&pool, identity).await == ["g-eng"] {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "sign-in sync never landed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(gfake.with(|s| s.user_group_requests), 1);
    drop(fake_server);
}

// ── Regressions ──────────────────────────────────────────────────────

/// Two identities can share an email; each is owed the directory's answer.
/// Consuming the lookup on the first would have revoked the second.
#[tokio::test]
async fn identities_sharing_an_email_get_the_same_groups() {
    let e = env().await;
    e.fake.set_groups(three_groups());
    let first = e.human("bob@acme.com").await;
    let second = e.human("Bob@acme.com").await;
    e.configure().await;
    e.run_worker().await;
    assert_eq!(google_memberships(&e.pool, first).await, ["g-all", "g-eng"]);
    assert_eq!(
        google_memberships(&e.pool, second).await,
        ["g-all", "g-eng"]
    );
}

/// Disconnect is atomic against an in-flight sweep: a Google row cannot be
/// written for an org with no config, so a sweep that finishes listing after
/// the DELETE fails instead of resurrecting the groups.
#[tokio::test]
async fn a_google_group_cannot_outlive_its_config() {
    let e = env().await;
    let orphan = sqlx::query(
        "INSERT INTO directory_groups \
             (org_id, source, external_id, display_name, google_directory_org_id) \
         VALUES ($1, 'google_directory', 'g-late', 'Late', $1)",
    )
    .bind(e.org_id)
    .execute(&e.pool)
    .await;
    assert!(orphan.is_err(), "no config row, so the FK must refuse it");

    // And the pairing is enforced both ways.
    e.configure().await;
    let unpaired = sqlx::query(
        "INSERT INTO directory_groups (org_id, source, external_id, display_name) \
         VALUES ($1, 'google_directory', 'g-x', 'X')",
    )
    .bind(e.org_id)
    .execute(&e.pool)
    .await;
    assert!(unpaired.is_err(), "a Google row must name its config");
}

/// A run leased before an admin paused the config must not sweep: pausing
/// means stop, even mid-lease. Drives the sweep directly, as the worker would
/// after its claim.
#[tokio::test]
async fn a_sweep_honours_a_pause_that_lands_after_the_claim() {
    let e = env().await;
    e.fake.set_groups(three_groups());
    let alice = e.human("alice@acme.com").await;
    e.configure().await;
    let (status, _) = e.put(json!({ "enabled": false })).await;
    assert_eq!(status, StatusCode::OK);

    let stats =
        overslash_api::services::directory_sync::sync_google_directory_full(&e.state, e.org_id)
            .await
            .unwrap();
    assert_eq!(stats.groups, 0);
    assert!(google_memberships(&e.pool, alice).await.is_empty());
}
