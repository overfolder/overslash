// Test setup seeds identities and reads back rows the API deliberately does
// not expose, which needs dynamic SQL.
#![allow(clippy::disallowed_methods)]
//! Integration tests for Google Workspace Directory group sync.
//!
//! The instance has one service account (the fakes crate's test key, set on
//! `Config::google_directory`); the API talks to the real
//! `overslash_fakes::google_directory` fake over HTTP — the token exchange
//! verifies the RS256 assertion the API signs, and every listing paginates —
//! with Google's two hosts swapped onto it through `service_base_overrides`.
//! "Sign in with Google" to connect runs against the OAuth fake. The sweep is
//! driven through `google_directory_worker::run_once`, not the sleeping loop.

use crate::common;
use crate::directory_group_sync::{
    create_group, map_source, org_with_idp_customized, sign_in, synced_identity_id,
};

use overslash_fakes::google_directory::{self as fake, FakeGroup, GoogleDirectoryHandle};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

use overslash_api::services::google_directory::ServiceAccountKey;
use overslash_api::services::google_directory_worker;

const SA_EMAIL: &str = "overslash-directory@instance.iam.gserviceaccount.com";

/// Point Google's hosts at the fake and give the instance its service account.
fn instance(fake_url: &str, config: &mut overslash_api::config::Config) {
    for host in ["oauth2.googleapis.com", "admin.googleapis.com"] {
        config
            .service_base_overrides
            .insert(host.to_string(), fake_url.to_string());
    }
    config.google_directory.service_account =
        Some(ServiceAccountKey::parse(&fake::service_account_json(SA_EMAIL)).unwrap());
}

struct Env {
    base: String,
    client: Client,
    pool: PgPool,
    org_id: Uuid,
    admin_key: String,
    /// The org's bootstrapped admin, for flows that need a browser session.
    admin_identity: Uuid,
    /// The OAuth fake standing in for Google sign-in.
    mock: String,
    fake: GoogleDirectoryHandle,
    /// What the background worker runs on, pointed at the same fake.
    state: overslash_api::AppState,
    _fake_server: overslash_fakes::Handle,
}

async fn env() -> Env {
    env_with(true).await
}

async fn env_with(service_account: bool) -> Env {
    let pool = common::test_pool().await;
    let (fake_server, fake) = fake::start("127.0.0.1:0").await;
    let mock = common::start_mock().await.to_string();

    // Google sign-in goes to the OAuth fake.
    sqlx::query(
        "UPDATE oauth_providers SET authorization_endpoint = $1, token_endpoint = $2, \
         userinfo_endpoint = $3 WHERE key = 'google'",
    )
    .bind(format!("http://{mock}/oauth/authorize"))
    .bind(format!("http://{mock}/oauth/token"))
    .bind(format!("http://{mock}/oidc/userinfo"))
    .execute(&pool)
    .await
    .unwrap();

    let url = fake.url.clone();
    let (base, client) = common::start_api_with_auth_providers_customized(
        pool.clone(),
        Some(("google-client".into(), "google-secret".into())),
        None,
        "http://localhost:3000",
        |c| {
            instance(&url, c);
            if !service_account {
                c.google_directory.service_account = None;
            }
        },
    )
    .await;
    let (org_id, _, _, admin_key) = common::bootstrap_org_identity(&base, &client).await;
    let admin_identity = sqlx::query_scalar::<_, Uuid>(
        "SELECT ig.identity_id FROM identity_groups ig JOIN groups g ON g.id = ig.group_id \
         WHERE g.org_id = $1 AND g.system_kind = 'admins' LIMIT 1",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    let mut state = common::make_app_state(pool.clone()).await;
    instance(&fake.url, &mut state.config);
    Env {
        base,
        client,
        pool,
        org_id,
        admin_key,
        admin_identity,
        mock,
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

    /// A Workspace connected for `acme.com`, as a successful sign-in leaves it.
    /// The connect flow itself has its own tests below.
    async fn configure(&self) {
        sqlx::query(
            "INSERT INTO org_google_directory_configs (org_id, admin_subject, domain) \
             VALUES ($1, 'admin@acme.com', 'acme.com')",
        )
        .bind(self.org_id)
        .execute(&self.pool)
        .await
        .unwrap();
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

    /// The connected config, or `Null`.
    async fn config(&self) -> Value {
        self.get().await.1["config"].clone()
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

    /// Who Google says signed in, for the next connect.
    async fn google_user(&self, claims: Value) {
        let resp = self
            .client
            .post(format!("http://{}/control/userinfo-claims", self.mock))
            .json(&claims)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    /// `POST /connect` as the admin's browser session; returns the flow's state.
    async fn start_connect(&self) -> String {
        let resp = self
            .client
            .post(format!("{}/v1/google-directory/connect", self.base))
            .header(
                "cookie",
                common::session_cookie(self.org_id, self.admin_identity),
            )
            .send()
            .await
            .unwrap();
        let status = resp.status();
        let body: Value = resp.json().await.unwrap();
        assert_eq!(status, StatusCode::OK, "{body}");
        let auth_url = url::Url::parse(body["auth_url"].as_str().unwrap()).unwrap();
        let state = auth_url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .unwrap();
        assert!(state.starts_with("gdir:"), "{state}");
        state
    }

    /// Google's redirect back, carrying `cookie`. Returns the dashboard URL
    /// the API redirected to.
    async fn finish_connect(&self, state: &str, cookie: &str) -> String {
        let mut url = url::Url::parse(&format!("{}/auth/callback/google", self.base)).unwrap();
        url.query_pairs_mut()
            .append_pair("code", "gdir-code")
            .append_pair("state", state);
        let resp = self
            .client
            .get(url)
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_redirection(), "{}", resp.status());
        resp.headers()["location"].to_str().unwrap().to_string()
    }

    /// The whole connect as the org's admin.
    async fn connect_as(&self, claims: Value) -> String {
        self.google_user(claims).await;
        let state = self.start_connect().await;
        self.finish_connect(
            &state,
            &common::session_cookie(self.org_id, self.admin_identity),
        )
        .await
    }
}

fn workspace_admin() -> Value {
    json!({ "email": "admin@acme.com", "hd": "acme.com", "email_verified": true })
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

// ── Instance service account and connect ─────────────────────────────

/// The setup screen's first job: tell the Workspace admin exactly what to
/// add in admin.google.com. Available before anything is connected.
#[tokio::test]
async fn get_describes_the_instance_service_account() {
    let e = env().await;
    let (status, body) = e.get().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["instance"]["available"], true);
    assert_eq!(body["instance"]["client_id"], "109876543210");
    assert_eq!(body["instance"]["service_account_email"], SA_EMAIL);
    assert_eq!(
        body["instance"]["scope"],
        "https://www.googleapis.com/auth/admin.directory.group.readonly"
    );
    assert!(body["config"].is_null());
    assert!(!body.to_string().contains("PRIVATE KEY"));
}

#[tokio::test]
async fn an_instance_without_a_service_account_cannot_connect() {
    let e = env_with(false).await;
    let (_, body) = e.get().await;
    assert_eq!(body["instance"]["available"], false);
    assert!(body["instance"]["client_id"].is_null());
    let resp = e
        .client
        .post(format!("{}/v1/google-directory/connect", e.base))
        .header("cookie", common::session_cookie(e.org_id, e.admin_identity))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

/// The happy path: what Google says — `hd` and the verified email — becomes
/// the config. Nothing is typed.
#[tokio::test]
async fn signing_in_as_a_workspace_admin_connects_it() {
    let e = env().await;
    let location = e.connect_as(workspace_admin()).await;
    assert!(
        location.contains("/org/google-directory?google_directory=connected"),
        "{location}"
    );

    let cfg = e.config().await;
    assert_eq!(cfg["domain"], "acme.com");
    assert_eq!(cfg["admin_subject"], "admin@acme.com");
    // The instance service account impersonated the signed-in admin.
    assert_eq!(e.fake.with(|s| s.subjects.clone()), vec!["admin@acme.com"]);
    // Due at once.
    assert_eq!(e.run_worker().await, 1);
}

/// A personal Google account has no Workspace behind it.
#[tokio::test]
async fn a_personal_google_account_cannot_connect() {
    let e = env().await;
    let location = e
        .connect_as(json!({ "email": "someone@gmail.com", "email_verified": true }))
        .await;
    assert!(
        location.contains("google_directory_error=not_workspace"),
        "{location}"
    );
    assert!(e.config().await.is_null());
}

/// The confused-deputy guard: the auth link only works in the browser of the
/// admin who started it. Mailing it to another Workspace's admin gets nothing.
#[tokio::test]
async fn the_connect_link_only_finishes_in_the_starting_session() {
    let e = env().await;
    e.google_user(workspace_admin()).await;
    let state = e.start_connect().await;

    let stranger = e.human("stranger@acme.com").await;
    let location = e
        .finish_connect(&state, &common::session_cookie(e.org_id, stranger))
        .await;
    assert!(
        location.contains("google_directory_error=wrong_session"),
        "{location}"
    );
    let location = e.finish_connect(&state, "").await;
    // Single use: the first attempt consumed it.
    assert!(
        location.contains("google_directory_error=expired"),
        "{location}"
    );
    assert!(e.config().await.is_null());
}

#[tokio::test]
async fn a_connect_state_cannot_be_replayed() {
    let e = env().await;
    e.google_user(workspace_admin()).await;
    let state = e.start_connect().await;
    let cookie = common::session_cookie(e.org_id, e.admin_identity);
    assert!(
        e.finish_connect(&state, &cookie)
            .await
            .contains("connected")
    );
    let again = e.finish_connect(&state, &cookie).await;
    assert!(again.contains("google_directory_error=expired"), "{again}");
}

/// One org per Workspace per instance.
#[tokio::test]
async fn a_workspace_connected_by_another_org_is_refused() {
    let e = env().await;
    let (other_org, _, _, _) = common::bootstrap_org_identity(&e.base, &e.client).await;
    sqlx::query(
        "INSERT INTO org_google_directory_configs (org_id, admin_subject, domain) \
         VALUES ($1, 'it@acme.com', 'ACME.com')",
    )
    .bind(other_org)
    .execute(&e.pool)
    .await
    .unwrap();

    let location = e.connect_as(workspace_admin()).await;
    assert!(
        location.contains("google_directory_error=domain_taken"),
        "{location}"
    );
    assert!(e.config().await.is_null());
}

/// The Workspace admin has not added the instance's client ID yet.
#[tokio::test]
async fn missing_delegation_is_named() {
    let e = env().await;
    e.fake
        .with(|s| s.token_error = Some("unauthorized_client".into()));
    let location = e.connect_as(workspace_admin()).await;
    assert!(
        location.contains("google_directory_error=delegation_missing"),
        "{location}"
    );
    assert!(e.config().await.is_null());
}

/// Reconnecting as a different Workspace drops the old one's groups.
#[tokio::test]
async fn reconnecting_to_another_workspace_drops_the_old_groups() {
    let e = env().await;
    e.fake.set_groups(three_groups());
    e.human("alice@acme.com").await;
    e.connect_as(workspace_admin()).await;
    e.run_worker().await;

    e.connect_as(json!({ "email": "admin@beta.io", "hd": "beta.io", "email_verified": true }))
        .await;
    assert_eq!(e.config().await["domain"], "beta.io");
    let left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM directory_groups WHERE org_id = $1 AND source = 'google_directory'",
    )
    .bind(e.org_id)
    .fetch_one(&e.pool)
    .await
    .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn another_org_cannot_see_the_config() {
    let e = env().await;
    e.configure().await;
    let (_, _, _, other_key) = common::bootstrap_org_identity(&e.base, &e.client).await;
    let body: Value = e
        .client
        .get(format!("{}/v1/google-directory", e.base))
        .header("authorization", format!("Bearer {other_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(body["config"].is_null(), "{body}");
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

    let body = e.config().await;
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
    let body = e.config().await;
    assert_eq!(body["last_sync_status"], "error");
    assert!(
        body["last_sync_error"].as_str().unwrap().contains("500"),
        "{body}"
    );
}

#[tokio::test]
async fn an_identity_outside_the_domain_is_never_touched() {
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
    assert_eq!(e.config().await["queued"], true);

    let before = e.fake.with(|s| s.token_requests);
    assert_eq!(e.run_worker().await, 1);
    assert_eq!(e.run_worker().await, 0, "five extra clicks queued nothing");
    assert_eq!(e.fake.with(|s| s.token_requests), before + 1);
    assert_eq!(e.config().await["queued"], false);
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
    assert_eq!(e.config().await["running"], true);
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
        org_with_idp_customized(false, None, |c| instance(&url, c)).await;

    gfake.set_groups(vec![FakeGroup::new(
        "g-eng",
        "Engineering",
        &["testuser@example.com"],
    )]);
    let _ = admin_key;
    // A Workspace for `example.com`, connected as a sign-in would leave it.
    sqlx::query(
        "INSERT INTO org_google_directory_configs (org_id, admin_subject, domain) \
         VALUES ($1, 'admin@example.com', 'example.com')",
    )
    .bind(org_id)
    .execute(&pool)
    .await
    .unwrap();

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

/// Google failing mid-connect sends the admin back with a reason, never a
/// bare error page: the callback still redirects, with `google_error`.
#[tokio::test]
async fn a_google_outage_during_connect_is_reported_not_a_500() {
    let e = env().await;
    e.google_user(workspace_admin()).await;
    let state = e.start_connect().await;
    // Google's userinfo is unreachable after the code exchange succeeded.
    sqlx::query(
        "UPDATE oauth_providers SET userinfo_endpoint = 'http://127.0.0.1:1/userinfo' \
         WHERE key = 'google'",
    )
    .execute(&e.pool)
    .await
    .unwrap();
    let location = e
        .finish_connect(&state, &common::session_cookie(e.org_id, e.admin_identity))
        .await;
    assert!(
        location.contains("google_directory_error=google_error"),
        "{location}"
    );
    assert!(e.config().await.is_null());
}

/// Backing out at Google's consent screen lands back on the settings page
/// with a reason — not a 400 from a missing `code`.
#[tokio::test]
async fn refusing_consent_at_google_is_reported_as_cancelled() {
    let e = env().await;
    let state = e.start_connect().await;
    let mut url = url::Url::parse(&format!("{}/auth/callback/google", e.base)).unwrap();
    url.query_pairs_mut()
        .append_pair("error", "access_denied")
        .append_pair("state", &state);
    let resp = e
        .client
        .get(url)
        .header("cookie", common::session_cookie(e.org_id, e.admin_identity))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_redirection(), "{}", resp.status());
    let location = resp.headers()["location"].to_str().unwrap();
    assert!(
        location.contains("google_directory_error=cancelled"),
        "{location}"
    );
    assert!(e.config().await.is_null());
}

/// `hd` is the Workspace's primary domain; an admin on a secondary domain is
/// told so, not that their email is unverified.
#[tokio::test]
async fn a_secondary_domain_account_is_named_as_such() {
    let e = env().await;
    let location = e
        .connect_as(
            json!({ "email": "admin@acme-labs.com", "hd": "acme.com", "email_verified": true }),
        )
        .await;
    assert!(
        location.contains("google_directory_error=not_primary_domain"),
        "{location}"
    );
}

/// Reconnecting to a Workspace another org holds is refused as one unit: the
/// org keeps its existing connection and groups rather than losing both.
#[tokio::test]
async fn a_refused_reconnect_leaves_the_old_workspace_in_place() {
    let e = env().await;
    e.fake.set_groups(three_groups());
    e.human("alice@acme.com").await;
    e.connect_as(workspace_admin()).await;
    e.run_worker().await;

    let (other_org, _, _, _) = common::bootstrap_org_identity(&e.base, &e.client).await;
    sqlx::query(
        "INSERT INTO org_google_directory_configs (org_id, admin_subject, domain) \
         VALUES ($1, 'it@beta.io', 'beta.io')",
    )
    .bind(other_org)
    .execute(&e.pool)
    .await
    .unwrap();

    let location = e
        .connect_as(json!({ "email": "admin@beta.io", "hd": "beta.io", "email_verified": true }))
        .await;
    assert!(
        location.contains("google_directory_error=domain_taken"),
        "{location}"
    );
    assert_eq!(e.config().await["domain"], "acme.com");
    let kept: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM directory_groups WHERE org_id = $1 AND source = 'google_directory'",
    )
    .bind(e.org_id)
    .fetch_one(&e.pool)
    .await
    .unwrap();
    assert_eq!(kept, 3);
}
