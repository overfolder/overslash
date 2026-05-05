//! Shared test helpers for integration tests.
#![allow(dead_code)]
// Test setup requires dynamic SQL for updating provider endpoints, creating template DBs, etc.
#![allow(clippy::disallowed_methods)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, Once, OnceLock};

use reqwest::Client;
use serde_json::{Value, json};
use sqlx::{Connection, PgPool, Row};
use tokio::net::TcpListener;
use uuid::Uuid;

/// Shared template DB name. Created once per Postgres instance, never dropped.
/// Concurrent test processes (e.g. nextest) coordinate via a Postgres advisory
/// lock so exactly one creates+migrates it; the rest wait, then `CREATE
/// DATABASE … TEMPLATE` from it.
const TEMPLATE_DB_NAME: &str = "overslash_test_template";
/// Arbitrary key for the advisory lock used to serialize template creation.
const TEMPLATE_LOCK_KEY: i64 = 0x0_5_0_E_5_7_5_7;

/// Second-tier template: migration template + standard org/user/key/group
/// bootstrap already applied. Tests clone from this to skip the 11 HTTP
/// requests that `run_standard_bootstrap` performs.
const BOOTSTRAPPED_DB_NAME: &str = "overslash_test_bootstrapped";
const BOOTSTRAPPED_LOCK_KEY: i64 = 0x0_5_B_0_0_7;

/// Fixtures baked into the bootstrapped template.
#[derive(Clone, Debug)]
pub struct BootstrapFixtures {
    pub org_id: Uuid,
    pub org_key: String,
    pub admin_key: String,
    pub write_key: String,
    pub read_key: String,
    pub user_ids: [Uuid; 3],
}

static BOOTSTRAP_FIXTURES: OnceLock<BootstrapFixtures> = OnceLock::new();

/// Returns a fresh `PgPool` backed by a clone of the migrated template database.
/// nextest-safe: each test runs in its own process, all sharing one template.
pub async fn test_pool() -> PgPool {
    let base_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    ensure_template(&base_url).await;

    // Clone template for this test. CREATE DATABASE … TEMPLATE fails with
    // "source database is being accessed by other users" if a prior session
    // hasn't fully closed yet (the cleanup is async). Retry briefly — the
    // bootstrapped pool below uses the same pattern.
    let test_db = format!("test_{}", Uuid::new_v4().simple());
    let admin_pool = PgPool::connect(&base_url).await.unwrap();
    let mut retries = 0u32;
    loop {
        match sqlx::query(&format!(
            "CREATE DATABASE \"{test_db}\" TEMPLATE \"{TEMPLATE_DB_NAME}\""
        ))
        .execute(&admin_pool)
        .await
        {
            Ok(_) => break,
            Err(e) if retries < 20 && format!("{e}").contains("being accessed") => {
                retries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => panic!("clone template: {e}"),
        }
    }
    admin_pool.close().await;

    register_for_cleanup(base_url.clone(), test_db.clone());

    let test_url = replace_db_name(&base_url, &test_db);
    PgPool::connect(&test_url).await.unwrap()
}

/// Returns a pool cloned from the bootstrapped template + cached fixtures.
/// Each clone has an org, 3 users (admin/write/read-only), keys, and groups
/// already set up — no HTTP bootstrap needed.
pub async fn test_pool_bootstrapped() -> (PgPool, BootstrapFixtures) {
    let base_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    ensure_template(&base_url).await;
    ensure_bootstrapped(&base_url).await;

    let test_db = format!("test_{}", Uuid::new_v4().simple());
    let admin_pool = PgPool::connect(&base_url).await.unwrap();
    // pg_terminate_backend is async — the template may briefly have lingering
    // sessions right after ensure_bootstrapped returns.  Retry a few times.
    let mut retries = 0u32;
    loop {
        match sqlx::query(&format!(
            "CREATE DATABASE \"{test_db}\" TEMPLATE \"{BOOTSTRAPPED_DB_NAME}\""
        ))
        .execute(&admin_pool)
        .await
        {
            Ok(_) => break,
            Err(e) if retries < 20 && format!("{e}").contains("being accessed") => {
                retries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => panic!("clone bootstrapped template: {e}"),
        }
    }
    admin_pool.close().await;

    register_for_cleanup(base_url.clone(), test_db.clone());

    let test_url = replace_db_name(&base_url, &test_db);
    let pool = PgPool::connect(&test_url).await.unwrap();

    let fixtures = if let Some(f) = BOOTSTRAP_FIXTURES.get() {
        f.clone()
    } else {
        let f = read_fixtures(&pool).await;
        let _ = BOOTSTRAP_FIXTURES.set(f.clone());
        f
    };

    (pool, fixtures)
}

async fn read_fixtures(pool: &PgPool) -> BootstrapFixtures {
    let rows = sqlx::query("SELECT key, value FROM _test_fixtures")
        .fetch_all(pool)
        .await
        .unwrap();
    let map: HashMap<String, String> = rows
        .iter()
        .map(|r| (r.get::<String, _>("key"), r.get::<String, _>("value")))
        .collect();
    BootstrapFixtures {
        org_id: map["org_id"].parse().unwrap(),
        org_key: map["org_key"].clone(),
        admin_key: map["admin_key"].clone(),
        write_key: map["write_key"].clone(),
        read_key: map["read_key"].clone(),
        user_ids: [
            map["user_id_0"].parse().unwrap(),
            map["user_id_1"].parse().unwrap(),
            map["user_id_2"].parse().unwrap(),
        ],
    }
}

/// Per-process registry of test DBs to drop at exit.
///
/// Nextest runs each test in a fresh process, so this list typically holds one
/// entry. We register an `atexit(3)` hook on first use that builds a small
/// tokio runtime and issues `DROP DATABASE … WITH (FORCE)` for each entry.
/// Without this, every test leaks ~9 MB into the Postgres data dir, which
/// blows up disk/tmpfs across a full coverage run.
static CLEANUP: OnceLock<Mutex<Vec<(String, String)>>> = OnceLock::new();

fn register_for_cleanup(base_url: String, db_name: String) {
    let m = CLEANUP.get_or_init(|| {
        // SAFETY: atexit is async-signal-safe to register and we only ever
        // install one handler per process.
        unsafe {
            libc::atexit(run_cleanup);
        }
        Mutex::new(Vec::new())
    });
    m.lock().unwrap().push((base_url, db_name));
}

extern "C" fn run_cleanup() {
    let Some(m) = CLEANUP.get() else {
        return;
    };
    // Recover from a poisoned lock: under `cargo test` (multi-thread), a
    // panic in one test could poison the mutex. We must not panic from this
    // extern "C" function — that would cross an FFI boundary and abort the
    // process — so unwrap_or_else into the inner data instead.
    let mut guard = m.lock().unwrap_or_else(|p| p.into_inner());
    let dbs = std::mem::take(&mut *guard);
    drop(guard);
    if dbs.is_empty() {
        return;
    }
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return;
    };
    rt.block_on(async {
        // Group by base_url so we open one admin connection per Postgres.
        let mut by_url: HashMap<String, Vec<String>> = HashMap::new();
        for (url, db) in dbs {
            by_url.entry(url).or_default().push(db);
        }
        for (url, names) in by_url {
            let Ok(pool) = PgPool::connect(&url).await else {
                continue;
            };
            for db in names {
                let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{db}\" WITH (FORCE)"))
                    .execute(&pool)
                    .await;
            }
            pool.close().await;
        }
    });
}

async fn db_exists(pool: &PgPool, name: &str) -> bool {
    sqlx::query("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(name)
        .fetch_optional(pool)
        .await
        .unwrap()
        .is_some()
}

async fn db_exists_conn(conn: &mut sqlx::PgConnection, name: &str) -> bool {
    sqlx::query("SELECT 1 FROM pg_database WHERE datname = $1")
        .bind(name)
        .fetch_optional(&mut *conn)
        .await
        .unwrap()
        .is_some()
}

/// Create+migrate the shared template if it doesn't exist yet.
/// Uses a Postgres advisory lock to serialize concurrent processes.
async fn ensure_template(base_url: &str) {
    let admin_pool = PgPool::connect(base_url).await.unwrap();

    // Fast path: template already exists.
    if db_exists(&admin_pool, TEMPLATE_DB_NAME).await {
        admin_pool.close().await;
        return;
    }

    // Slow path: take a session-scoped advisory lock on a single connection
    // that we DETACH from the pool. Detaching is the panic-safety mechanism:
    // if CREATE DATABASE or MIGRATOR.run() panics, the owned PgConnection is
    // dropped, the underlying socket is closed, the Postgres session ends, and
    // session-level advisory locks held by that session are released
    // automatically. If we used a PoolConnection it would be returned to the
    // pool on unwind with the lock still held.
    //
    // CREATE DATABASE can't run inside a transaction block, so we use a
    // session lock instead of pg_advisory_xact_lock.
    let mut conn = admin_pool.acquire().await.unwrap().detach();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(TEMPLATE_LOCK_KEY)
        .execute(&mut conn)
        .await
        .unwrap();

    if !db_exists_conn(&mut conn, TEMPLATE_DB_NAME).await {
        sqlx::query(&format!("CREATE DATABASE \"{TEMPLATE_DB_NAME}\""))
            .execute(&mut conn)
            .await
            .unwrap();
        let tpl_url = replace_db_name(base_url, TEMPLATE_DB_NAME);
        let tpl_pool = PgPool::connect(&tpl_url).await.unwrap();
        overslash_db::MIGRATOR.run(&tpl_pool).await.unwrap();
        tpl_pool.close().await;
    }

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(TEMPLATE_LOCK_KEY)
        .execute(&mut conn)
        .await
        .unwrap();
    let _ = conn.close().await;
    admin_pool.close().await;
}

/// Replace the database name in a Postgres URL.
/// Handles both `postgres://user:pass@host:port/dbname` and with query params.
fn replace_db_name(url: &str, new_db: &str) -> String {
    // Find the last '/' before any '?' query string
    let (base, query) = url.split_once('?').unwrap_or((url, ""));
    let last_slash = base.rfind('/').expect("invalid DATABASE_URL: no /");
    let mut result = format!("{}/{}", &base[..last_slash], new_db);
    if !query.is_empty() {
        result.push('?');
        result.push_str(query);
    }
    result
}

/// Create the bootstrapped template if it doesn't exist yet.
/// Clones from the migration template, starts a temp API server, runs the
/// standard org/user/key/group bootstrap, stores fixtures, then terminates
/// all connections so the DB can serve as a template.
async fn ensure_bootstrapped(base_url: &str) {
    let admin_pool = PgPool::connect(base_url).await.unwrap();

    // No fast path here — unlike the migration template, the bootstrapped
    // template has a window where the DB row exists but connections are still
    // being torn down.  The advisory lock guarantees callers don't try to
    // clone until the creating process is fully done.
    let mut conn = admin_pool.acquire().await.unwrap().detach();
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(BOOTSTRAPPED_LOCK_KEY)
        .execute(&mut conn)
        .await
        .unwrap();

    if !db_exists_conn(&mut conn, BOOTSTRAPPED_DB_NAME).await {
        // Clone from migration template
        sqlx::query(&format!(
            "CREATE DATABASE \"{BOOTSTRAPPED_DB_NAME}\" TEMPLATE \"{TEMPLATE_DB_NAME}\""
        ))
        .execute(&mut conn)
        .await
        .unwrap();

        let bs_url = replace_db_name(base_url, BOOTSTRAPPED_DB_NAME);
        let bs_pool = PgPool::connect(&bs_url).await.unwrap();

        // Create fixtures table (test-only, not a migration)
        sqlx::query("CREATE TABLE _test_fixtures (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .execute(&bs_pool)
            .await
            .unwrap();

        // Start temp server and run the standard bootstrap via HTTP
        let (addr, client) = start_api(bs_pool.clone()).await;
        let base = format!("http://{addr}");
        let fixtures = run_standard_bootstrap(&base, &client).await;

        // Persist fixtures into the template DB
        for (k, v) in [
            ("org_id", fixtures.org_id.to_string()),
            ("org_key", fixtures.org_key.clone()),
            ("admin_key", fixtures.admin_key.clone()),
            ("write_key", fixtures.write_key.clone()),
            ("read_key", fixtures.read_key.clone()),
            ("user_id_0", fixtures.user_ids[0].to_string()),
            ("user_id_1", fixtures.user_ids[1].to_string()),
            ("user_id_2", fixtures.user_ids[2].to_string()),
        ] {
            sqlx::query("INSERT INTO _test_fixtures (key, value) VALUES ($1, $2)")
                .bind(k)
                .bind(&v)
                .execute(&bs_pool)
                .await
                .unwrap();
        }

        // Close our pool, then terminate the server's lingering connections
        // so Postgres allows using this DB as a template.
        bs_pool.close().await;
        sqlx::query(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = '{BOOTSTRAPPED_DB_NAME}' AND pid <> pg_backend_pid()"
        ))
        .execute(&mut conn)
        .await
        .unwrap();

        // pg_terminate_backend is asynchronous — wait until the backends
        // are actually gone before releasing the advisory lock.
        for _ in 0..50 {
            let row = sqlx::query("SELECT count(*) AS n FROM pg_stat_activity WHERE datname = $1")
                .bind(BOOTSTRAPPED_DB_NAME)
                .fetch_one(&mut conn)
                .await
                .unwrap();
            let n: i64 = row.get("n");
            if n == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(BOOTSTRAPPED_LOCK_KEY)
        .execute(&mut conn)
        .await
        .unwrap();
    let _ = conn.close().await;
    admin_pool.close().await;
}

/// Run the standard 3-user org bootstrap via HTTP.
/// Creates: org, org-level key, admin/write/read-only users with keys,
/// admin→Admins group, read-only→Viewers group with read access.
async fn run_standard_bootstrap(base: &str, client: &Client) -> BootstrapFixtures {
    // Create org
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "Tpl Test Org", "slug": format!("tpl-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    // Org-level key
    let org_key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "org-admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_key = org_key_resp["key"].as_str().unwrap().to_string();

    // Find system groups
    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admins_id = groups.iter().find(|g| g["name"] == "Admins").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let everyone_id = groups.iter().find(|g| g["name"] == "Everyone").unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Create 3 users: admin, write, read-only
    let mut user_ids = [Uuid::nil(); 3];
    let mut keys = vec![];
    for (i, name) in ["admin-user", "write-user", "readonly-user"]
        .iter()
        .enumerate()
    {
        let user: Value = client
            .post(format!("{base}/v1/identities"))
            .header("Authorization", format!("Bearer {org_key}"))
            .json(&json!({"name": name, "kind": "user"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let uid: Uuid = user["id"].as_str().unwrap().parse().unwrap();
        user_ids[i] = uid;

        let key_resp: Value = client
            .post(format!("{base}/v1/api-keys"))
            .header("Authorization", format!("Bearer {org_key}"))
            .json(&json!({"org_id": org_id, "identity_id": uid, "name": format!("{name}-key")}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        keys.push(key_resp["key"].as_str().unwrap().to_string());
    }

    // Admin user -> Admins group
    client
        .post(format!("{base}/v1/groups/{admins_id}/members"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"identity_id": user_ids[0]}))
        .send()
        .await
        .unwrap();

    // Fetch overslash service instance
    let overslash_svc: Value = client
        .get(format!("{base}/v1/services/overslash"))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let overslash_svc_id = overslash_svc["id"].as_str().unwrap().to_string();

    // Remove read-only user from Everyone
    client
        .delete(format!(
            "{base}/v1/groups/{everyone_id}/members/{}",
            user_ids[2]
        ))
        .header("Authorization", format!("Bearer {org_key}"))
        .send()
        .await
        .unwrap();

    // Create Viewers group with read access
    let viewers: Value = client
        .post(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"name": "Viewers"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let viewers_id = viewers["id"].as_str().unwrap();

    client
        .post(format!("{base}/v1/groups/{viewers_id}/grants"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"service_instance_id": overslash_svc_id, "access_level": "read"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/v1/groups/{viewers_id}/members"))
        .header("Authorization", format!("Bearer {org_key}"))
        .json(&json!({"identity_id": user_ids[2]}))
        .send()
        .await
        .unwrap();

    BootstrapFixtures {
        org_id,
        org_key,
        admin_key: keys[0].clone(),
        write_key: keys[1].clone(),
        read_key: keys[2].clone(),
        user_ids,
    }
}

/// Variant of `start_api` that lets callers tweak the `Config` before the
/// server starts — multi-org tests use this to toggle `allow_org_creation`,
/// `single_org_mode`, `app_host_suffix`, etc.
pub async fn start_api_with<F>(pool: PgPool, customize: F) -> (SocketAddr, Client)
where
    F: FnOnce(&mut overslash_api::config::Config),
{
    start_api_internal(pool, customize).await
}

/// Start the Overslash API server in-process on a random port.
pub async fn start_api(pool: PgPool) -> (SocketAddr, Client) {
    start_api_internal(pool, |_| {}).await
}

async fn start_api_internal<F>(pool: PgPool, customize: F) -> (SocketAddr, Client)
where
    F: FnOnce(&mut overslash_api::config::Config),
{
    // Surface server-side errors during tests — without this, `tracing::error!`
    // calls inside AppError are silently dropped and a 500 looks like a bare
    // "database error" string to the client.
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("error")),
        )
        .try_init();
    // Bind first so `public_url` matches the real bound address. This lets
    // server-internal loopback calls (e.g. the `/mcp` dispatcher proxying to
    // REST) reach this test's process instead of a non-existent 3000.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(), // unused, we pass pool directly
        secrets_encryption_key: "ab".repeat(32),
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        execution_pending_ttl_secs: 900,
        execution_replay_timeout_secs: 30,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: format!("http://{addr}"),
        dev_auth_enabled: false,
        max_response_body_bytes: 5_242_880,
        filter_timeout_ms: 2000,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        mcp_extra_origins: String::new(),
        redis_url: None,
        default_rate_limit: 10000,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        single_org_mode: None,
        app_host_suffix: None,
        api_host_suffix: None,
        session_cookie_domain: None,
        cloud_billing: false,
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_eur_price_id: None,
        stripe_usd_price_id: None,
        stripe_eur_lookup_key: "overslash_seat_eur".into(),
        stripe_usd_lookup_key: "overslash_seat_usd".into(),
        stripe_api_base: "https://api.stripe.com/v1".into(),
        service_base_overrides: std::collections::HashMap::new(),
        oversla_sh_base_url: None,
        oversla_sh_api_key: None,
        preview_origin_allowlist: None,
        overslash_env: None,
    };
    customize(&mut config);

    // Build the app with the test pool directly
    let state = overslash_api::AppState {
        db: pool,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(overslash_core::registry::ServiceRegistry::default()),
        rate_limiter: std::sync::Arc::new(
            overslash_api::services::rate_limit::InMemoryRateLimitStore::new(),
        ),
        rate_limit_cache: std::sync::Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        free_unlimited_cache: std::sync::Arc::new(
            overslash_api::services::billing_tier::FreeUnlimitedCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
        embedder: std::sync::Arc::new(overslash_core::embeddings::DisabledEmbedder),
        embeddings_available: false,
        platform_registry: std::sync::Arc::new(
            overslash_api::services::platform_registry::build_registry(),
        ),
    };

    let app = axum::Router::new()
        .merge(overslash_api::routes::health::router())
        .merge(overslash_api::routes::orgs::router())
        .merge(overslash_api::routes::identities::router())
        .merge(overslash_api::routes::api_keys::router())
        .merge(overslash_api::routes::secrets::router())
        .merge(overslash_api::routes::secret_requests::router())
        .merge(overslash_api::routes::permissions::router())
        .merge(overslash_api::routes::actions::router())
        .merge(overslash_api::routes::actions::validate_router())
        .merge(overslash_api::routes::approvals::router())
        .merge(overslash_api::routes::audit::router())
        .merge(overslash_api::routes::webhooks::router())
        .merge(overslash_api::routes::services::router())
        .merge(overslash_api::routes::templates::router())
        .merge(overslash_api::routes::connections::router())
        .merge(overslash_api::routes::byoc_credentials::router())
        .merge(overslash_api::routes::oauth_providers::router())
        .merge(overslash_api::routes::auth::router())
        .merge(overslash_api::routes::dev_e2e::router())
        .merge(overslash_api::routes::org_idp_configs::router())
        .merge(overslash_api::routes::org_oauth_credentials::router())
        .merge(overslash_api::routes::org_service_keys::router())
        .merge(overslash_api::routes::groups::router())
        .merge(overslash_api::routes::rate_limits::router())
        .merge(overslash_api::routes::preferences::router())
        .merge(overslash_api::routes::oauth_as::router())
        .merge(overslash_api::routes::oauth::router())
        .merge(overslash_api::routes::oauth::consent_router())
        .merge(overslash_api::routes::mcp::router())
        .merge(overslash_api::routes::oauth_mcp_clients::router());

    // Billing routes are gated on cloud_billing — test fixtures that flip the
    // flag get the routes; default-config tests don't see them.
    let app = if state.config.cloud_billing {
        app.merge(overslash_api::routes::billing::router())
            .merge(overslash_api::routes::billing::webhook_router())
    } else {
        app
    };

    let app = app
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            overslash_api::middleware::subdomain::subdomain_middleware,
        ))
        .with_state(state);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, Client::new())
}

/// Start API with dev auth enabled. Returns (base_url, client).
pub async fn start_api_with_dev_auth(pool: PgPool) -> (String, Client) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: "ab".repeat(32),
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        execution_pending_ttl_secs: 900,
        execution_replay_timeout_secs: 30,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: format!("http://{addr}"),
        dev_auth_enabled: true,
        max_response_body_bytes: 5_242_880,
        filter_timeout_ms: 2000,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        mcp_extra_origins: String::new(),
        redis_url: None,
        default_rate_limit: 10000,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        single_org_mode: None,
        app_host_suffix: None,
        api_host_suffix: None,
        session_cookie_domain: None,
        cloud_billing: false,
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_eur_price_id: None,
        stripe_usd_price_id: None,
        stripe_eur_lookup_key: "overslash_seat_eur".into(),
        stripe_usd_lookup_key: "overslash_seat_usd".into(),
        stripe_api_base: "https://api.stripe.com/v1".into(),
        service_base_overrides: std::collections::HashMap::new(),
        oversla_sh_base_url: None,
        oversla_sh_api_key: None,
        preview_origin_allowlist: None,
        overslash_env: None,
    };

    let state = overslash_api::AppState {
        db: pool,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(overslash_core::registry::ServiceRegistry::default()),
        rate_limiter: std::sync::Arc::new(
            overslash_api::services::rate_limit::InMemoryRateLimitStore::new(),
        ),
        rate_limit_cache: std::sync::Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        free_unlimited_cache: std::sync::Arc::new(
            overslash_api::services::billing_tier::FreeUnlimitedCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
        embedder: std::sync::Arc::new(overslash_core::embeddings::DisabledEmbedder),
        embeddings_available: false,
        platform_registry: std::sync::Arc::new(
            overslash_api::services::platform_registry::build_registry(),
        ),
    };

    let app = axum::Router::new()
        .merge(overslash_api::routes::health::router())
        .merge(overslash_api::routes::orgs::router())
        .merge(overslash_api::routes::identities::router())
        .merge(overslash_api::routes::api_keys::router())
        .merge(overslash_api::routes::secrets::router())
        .merge(overslash_api::routes::secret_requests::router())
        .merge(overslash_api::routes::permissions::router())
        .merge(overslash_api::routes::actions::router())
        .merge(overslash_api::routes::actions::validate_router())
        .merge(overslash_api::routes::approvals::router())
        .merge(overslash_api::routes::audit::router())
        .merge(overslash_api::routes::webhooks::router())
        .merge(overslash_api::routes::services::router())
        .merge(overslash_api::routes::templates::router())
        .merge(overslash_api::routes::connections::router())
        .merge(overslash_api::routes::byoc_credentials::router())
        .merge(overslash_api::routes::oauth_providers::router())
        .merge(overslash_api::routes::auth::router())
        .merge(overslash_api::routes::dev_e2e::router())
        .merge(overslash_api::routes::org_idp_configs::router())
        .merge(overslash_api::routes::org_oauth_credentials::router())
        .merge(overslash_api::routes::org_service_keys::router())
        .merge(overslash_api::routes::groups::router())
        .merge(overslash_api::routes::rate_limits::router())
        .merge(overslash_api::routes::preferences::router())
        .merge(overslash_api::routes::oauth_as::router())
        .merge(overslash_api::routes::oauth::router())
        .merge(overslash_api::routes::oauth::consent_router())
        .merge(overslash_api::routes::oauth_upstream::router())
        .merge(overslash_api::routes::mcp::router())
        .merge(overslash_api::routes::oauth_mcp_clients::router())
        .with_state(state);

    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (format!("http://{addr}"), Client::new())
}

/// Start API with configurable auth providers for OIDC/OAuth testing.
/// `public_url` is used as the base for callback redirect_uri construction.
pub async fn start_api_with_auth_providers(
    pool: PgPool,
    google_creds: Option<(String, String)>,
    github_creds: Option<(String, String)>,
    public_url: &str,
) -> (String, Client) {
    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: "ab".repeat(32),
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        execution_pending_ttl_secs: 900,
        execution_replay_timeout_secs: 30,
        services_dir: "services".into(),
        google_auth_client_id: google_creds.as_ref().map(|(id, _)| id.clone()),
        google_auth_client_secret: google_creds.map(|(_, s)| s),
        github_auth_client_id: github_creds.as_ref().map(|(id, _)| id.clone()),
        github_auth_client_secret: github_creds.map(|(_, s)| s),
        public_url: public_url.to_string(),
        dev_auth_enabled: true,
        max_response_body_bytes: 5_242_880,
        filter_timeout_ms: 2000,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        mcp_extra_origins: String::new(),
        redis_url: None,
        default_rate_limit: 10000,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        single_org_mode: None,
        app_host_suffix: None,
        api_host_suffix: None,
        session_cookie_domain: None,
        cloud_billing: false,
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_eur_price_id: None,
        stripe_usd_price_id: None,
        stripe_eur_lookup_key: "overslash_seat_eur".into(),
        stripe_usd_lookup_key: "overslash_seat_usd".into(),
        stripe_api_base: "https://api.stripe.com/v1".into(),
        service_base_overrides: std::collections::HashMap::new(),
        oversla_sh_base_url: None,
        oversla_sh_api_key: None,
        preview_origin_allowlist: None,
        overslash_env: None,
    };

    let state = overslash_api::AppState {
        db: pool,
        config,
        http_client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        registry: Arc::new(overslash_core::registry::ServiceRegistry::default()),
        rate_limiter: std::sync::Arc::new(
            overslash_api::services::rate_limit::InMemoryRateLimitStore::new(),
        ),
        rate_limit_cache: std::sync::Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        free_unlimited_cache: std::sync::Arc::new(
            overslash_api::services::billing_tier::FreeUnlimitedCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
        embedder: std::sync::Arc::new(overslash_core::embeddings::DisabledEmbedder),
        embeddings_available: false,
        platform_registry: std::sync::Arc::new(
            overslash_api::services::platform_registry::build_registry(),
        ),
    };

    let app = axum::Router::new()
        .merge(overslash_api::routes::health::router())
        .merge(overslash_api::routes::orgs::router())
        .merge(overslash_api::routes::identities::router())
        .merge(overslash_api::routes::api_keys::router())
        .merge(overslash_api::routes::secrets::router())
        .merge(overslash_api::routes::secret_requests::router())
        .merge(overslash_api::routes::permissions::router())
        .merge(overslash_api::routes::actions::router())
        .merge(overslash_api::routes::actions::validate_router())
        .merge(overslash_api::routes::approvals::router())
        .merge(overslash_api::routes::audit::router())
        .merge(overslash_api::routes::webhooks::router())
        .merge(overslash_api::routes::services::router())
        .merge(overslash_api::routes::templates::router())
        .merge(overslash_api::routes::connections::router())
        .merge(overslash_api::routes::byoc_credentials::router())
        .merge(overslash_api::routes::oauth_providers::router())
        .merge(overslash_api::routes::auth::router())
        .merge(overslash_api::routes::org_idp_configs::router())
        .merge(overslash_api::routes::org_oauth_credentials::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Non-redirecting client so tests can inspect 303 responses
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    (format!("http://{addr}"), client)
}

/// Start the mock target in-process on a random port.
/// Includes: echo, webhook receiver, and mock OAuth token endpoint.
/// Boot the combined OAuth/OIDC + GitHub user + echo + webhook fake on an
/// OS-assigned `127.0.0.1` port. The handle is leaked because tests treat
/// the fake as long-lived; dropping it would shut the server down.
pub async fn start_mock() -> SocketAddr {
    let handle = overslash_fakes::combined::start_in_process().await;
    let addr = handle.addr;
    // Leak so the listener stays alive for the whole test process — matches
    // the prior in-process implementation that never shut its spawn down.
    Box::leak(Box::new(handle));
    addr
}

/// Bootstrap org + identity + identity-bound API key.
/// Returns (org_id, identity_id, agent_api_key, org_admin_api_key).
pub async fn bootstrap_org_identity(base: &str, client: &Client) -> (Uuid, Uuid, String, String) {
    let org: Value = client
        .post(format!("{base}/v1/orgs"))
        .json(&json!({"name": "TestOrg", "slug": format!("test-{}", Uuid::new_v4())}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id: Uuid = org["id"].as_str().unwrap().parse().unwrap();

    // Bootstrap: first API-key call on a fresh org auto-creates an admin
    // user identity and returns its key (no auth required).
    let bootstrap_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .json(&json!({"org_id": org_id, "name": "org-admin"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_api_key = bootstrap_resp["key"].as_str().unwrap().to_string();

    // Create a "test-user" under the admin, then an agent under test-user.
    // This matches the original flow so tests can find identities by name.
    let user_ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_api_key}"))
        .json(&json!({"name": "test-user", "kind": "user"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id: Uuid = user_ident["id"].as_str().unwrap().parse().unwrap();

    let ident: Value = client
        .post(format!("{base}/v1/identities"))
        .header("Authorization", format!("Bearer {org_api_key}"))
        .json(&json!({"name": "test-agent", "kind": "agent", "parent_id": user_id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ident_id: Uuid = ident["id"].as_str().unwrap().parse().unwrap();

    // Disable auto-call-on-approve so the suite's manual `/call` flow keeps
    // winning the execution claim race. The universal default (true) would
    // spawn a background auto-call after each `/resolve`, which would beat
    // the manual call most of the time and break tests that assert
    // `triggered_by == "agent"`. Tests covering the auto-call path live in
    // `auto_call_on_approve.rs` and re-enable it explicitly.
    client
        .patch(format!(
            "{base}/v1/identities/{ident_id}/auto-call-on-approve"
        ))
        .header("Authorization", format!("Bearer {org_api_key}"))
        .json(&json!({"enabled": false}))
        .send()
        .await
        .unwrap();

    // Identity-bound key for the agent
    let key_resp: Value = client
        .post(format!("{base}/v1/api-keys"))
        .header("Authorization", format!("Bearer {org_api_key}"))
        .json(&json!({"org_id": org_id, "identity_id": ident_id, "name": "agent-key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_key = key_resp["key"].as_str().unwrap().to_string();

    (org_id, ident_id, api_key, org_api_key)
}

pub fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

/// Test helper: ensure an org-level instance for `template_key` exists, then
/// grant Everyone admin access on it so any user-identity in the org clears
/// Layer 1 for that service. Idempotent — safe to call repeatedly. Returns
/// the service instance id.
pub async fn grant_service_to_everyone(
    base: &str,
    client: &Client,
    admin_key: &str,
    template_key: &str,
) -> Uuid {
    // Create or fetch an org-level service instance for this template. The
    // create endpoint uses the template_key as the default service name, which
    // is what we want.
    let create_resp = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "template_key": template_key,
            "name": template_key,
            "user_level": false,
            "status": "active",
        }))
        .send()
        .await
        .expect("create service");

    let svc_id: Uuid = if create_resp.status() == 200 {
        let v: Value = create_resp.json().await.unwrap();
        v["id"].as_str().unwrap().parse().unwrap()
    } else {
        // 409: already exists — look it up via /v1/services
        let list: Vec<Value> = client
            .get(format!("{base}/v1/services"))
            .header("Authorization", format!("Bearer {admin_key}"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        list.iter()
            .find(|s| s["name"] == template_key)
            .expect("service should exist after conflict")["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap()
    };

    // Find the Everyone group and grant admin on it.
    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let everyone_id = groups
        .iter()
        .find(|g| g["system_kind"].as_str() == Some("everyone"))
        .and_then(|g| g["id"].as_str())
        .expect("Everyone group must exist after bootstrap");

    let grant_resp = client
        .post(format!("{base}/v1/groups/{everyone_id}/grants"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "service_instance_id": svc_id.to_string(),
            "access_level": "admin",
            "auto_approve_reads": true,
        }))
        .send()
        .await
        .unwrap();
    // 409 = already granted (idempotent), 200 = newly granted.
    assert!(
        grant_resp.status() == 200 || grant_resp.status() == 409,
        "unexpected grant status: {}",
        grant_resp.status()
    );

    svc_id
}

/// Opt the test process out of the SSRF guard so MCP/HTTP stubs bound to
/// 127.0.0.1 are reachable. The production binary never sets this env var;
/// the knob exists solely so tests can use loopback stubs without widening
/// the guard. Idempotent across calls.
pub fn allow_loopback_ssrf() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: runs exactly once, before any thread that might read the
        // env concurrently (Once provides the happens-before).
        unsafe {
            std::env::set_var("OVERSLASH_SSRF_ALLOW_PRIVATE", "1");
        }
    });
}

/// Submit the MCP OAuth consent JSON endpoint with mode=new to enroll a
/// fresh agent. Returns the `redirect_uri` (the MCP client's `redirect_uri`
/// with `?code=…`) that the dashboard would forward the browser to.
pub async fn finish_oauth_consent_new(
    base: &str,
    consent_redirect_location: &str,
    session_cookie: &str,
    agent_name: &str,
) -> String {
    // The authorize redirect now points at the dashboard
    // (`<dashboard>/oauth/consent?request_id=…`), but we only care about
    // the `request_id` parameter.
    let request_id = consent_redirect_location
        .split(&['?', '&'][..])
        .find_map(|p| p.strip_prefix("request_id="))
        .expect("consent redirect missing request_id");
    let request_id = urlencoding::decode(request_id).unwrap().into_owned();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{base}/v1/oauth/consent/{}/finish",
            urlencoding::encode(&request_id)
        ))
        .header("cookie", session_cookie)
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "mode": "new",
                "agent_name": agent_name,
                "inherit_permissions": false,
                "group_names": [],
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "consent finish must return 200 with redirect_uri"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    body["redirect_uri"]
        .as_str()
        .expect("redirect_uri missing")
        .to_string()
}

/// Start API with real service registry loaded from `services/` directory.
/// Optionally override a service's host (useful for mock-based tests).
pub async fn start_api_with_registry(
    pool: PgPool,
    host_override: Option<(&str, String)>,
) -> (String, Client) {
    let enc_key_hex = "ab".repeat(32);
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let mut registry =
        overslash_core::registry::ServiceRegistry::load_from_dir(&ws_root.join("services"))
            .unwrap_or_default();

    if let Some((service_key, new_host)) = host_override {
        if let Some(svc) = registry.get(service_key) {
            let mut svc = svc.clone();
            svc.hosts = vec![new_host];
            registry.insert(svc);
        }
    }

    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: enc_key_hex,
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        execution_pending_ttl_secs: 900,
        execution_replay_timeout_secs: 30,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: "http://localhost:3000".into(),
        dev_auth_enabled: false,
        max_response_body_bytes: 5_242_880,
        filter_timeout_ms: 2000,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        mcp_extra_origins: String::new(),
        redis_url: None,
        default_rate_limit: 10000,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        single_org_mode: None,
        app_host_suffix: None,
        api_host_suffix: None,
        session_cookie_domain: None,
        cloud_billing: false,
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_eur_price_id: None,
        stripe_usd_price_id: None,
        stripe_eur_lookup_key: "overslash_seat_eur".into(),
        stripe_usd_lookup_key: "overslash_seat_usd".into(),
        stripe_api_base: "https://api.stripe.com/v1".into(),
        service_base_overrides: std::collections::HashMap::new(),
        oversla_sh_base_url: None,
        oversla_sh_api_key: None,
        preview_origin_allowlist: None,
        overslash_env: None,
    };

    let state = overslash_api::AppState {
        db: pool,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(registry),
        rate_limiter: std::sync::Arc::new(
            overslash_api::services::rate_limit::InMemoryRateLimitStore::new(),
        ),
        rate_limit_cache: std::sync::Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        free_unlimited_cache: std::sync::Arc::new(
            overslash_api::services::billing_tier::FreeUnlimitedCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
        embedder: std::sync::Arc::new(overslash_core::embeddings::DisabledEmbedder),
        embeddings_available: false,
        platform_registry: std::sync::Arc::new(
            overslash_api::services::platform_registry::build_registry(),
        ),
    };

    let app = axum::Router::new()
        .merge(overslash_api::routes::health::router())
        .merge(overslash_api::routes::orgs::router())
        .merge(overslash_api::routes::identities::router())
        .merge(overslash_api::routes::api_keys::router())
        .merge(overslash_api::routes::secrets::router())
        .merge(overslash_api::routes::secret_requests::router())
        .merge(overslash_api::routes::permissions::router())
        .merge(overslash_api::routes::actions::router())
        .merge(overslash_api::routes::actions::validate_router())
        .merge(overslash_api::routes::approvals::router())
        .merge(overslash_api::routes::audit::router())
        .merge(overslash_api::routes::webhooks::router())
        .merge(overslash_api::routes::services::router())
        .merge(overslash_api::routes::templates::router())
        .merge(overslash_api::routes::connections::router())
        .merge(overslash_api::routes::byoc_credentials::router())
        .merge(overslash_api::routes::oauth_providers::router())
        .merge(overslash_api::routes::auth::router())
        .merge(overslash_api::routes::org_idp_configs::router())
        .merge(overslash_api::routes::org_oauth_credentials::router())
        .merge(overslash_api::routes::org_service_keys::router())
        .merge(overslash_api::routes::groups::router())
        .merge(overslash_api::routes::rate_limits::router())
        .merge(overslash_api::routes::preferences::router())
        .merge(overslash_api::routes::oauth_as::router())
        .merge(overslash_api::routes::oauth::router())
        .merge(overslash_api::routes::oauth::consent_router())
        .merge(overslash_api::routes::mcp::router())
        .merge(overslash_api::routes::oauth_mcp_clients::router())
        .merge(overslash_api::routes::search::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (format!("http://{addr}"), Client::new())
}

/// Start API wired for semantic-search integration tests. Loads the real
/// `services/` registry (so gmail/google_calendar/resend/etc. are present),
/// injects the deterministic [`StubEmbedder`] so the cosine path runs
/// without downloading model weights, and flips `embeddings_available` to
/// true so the endpoint actually issues pgvector queries.
pub async fn start_api_for_search(pool: PgPool) -> (String, Client) {
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let registry =
        overslash_core::registry::ServiceRegistry::load_from_dir(&ws_root.join("services"))
            .unwrap_or_default();

    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: "ab".repeat(32),
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        execution_pending_ttl_secs: 900,
        execution_replay_timeout_secs: 30,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: "http://localhost:3000".into(),
        dev_auth_enabled: false,
        max_response_body_bytes: 5_242_880,
        filter_timeout_ms: 2000,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        mcp_extra_origins: String::new(),
        redis_url: None,
        default_rate_limit: 10000,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        single_org_mode: None,
        app_host_suffix: None,
        api_host_suffix: None,
        session_cookie_domain: None,
        cloud_billing: false,
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_eur_price_id: None,
        stripe_usd_price_id: None,
        stripe_eur_lookup_key: "overslash_seat_eur".into(),
        stripe_usd_lookup_key: "overslash_seat_usd".into(),
        stripe_api_base: "https://api.stripe.com/v1".into(),
        service_base_overrides: std::collections::HashMap::new(),
        oversla_sh_base_url: None,
        oversla_sh_api_key: None,
        preview_origin_allowlist: None,
        overslash_env: None,
    };

    let state = overslash_api::AppState {
        db: pool,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(registry),
        rate_limiter: std::sync::Arc::new(
            overslash_api::services::rate_limit::InMemoryRateLimitStore::new(),
        ),
        rate_limit_cache: std::sync::Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        free_unlimited_cache: std::sync::Arc::new(
            overslash_api::services::billing_tier::FreeUnlimitedCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
        embedder: std::sync::Arc::new(overslash_core::embeddings::StubEmbedder),
        embeddings_available: true,
        platform_registry: std::sync::Arc::new(
            overslash_api::services::platform_registry::build_registry(),
        ),
    };

    let app = axum::Router::new()
        .merge(overslash_api::routes::health::router())
        .merge(overslash_api::routes::orgs::router())
        .merge(overslash_api::routes::identities::router())
        .merge(overslash_api::routes::api_keys::router())
        .merge(overslash_api::routes::groups::router())
        .merge(overslash_api::routes::services::router())
        .merge(overslash_api::routes::templates::router())
        .merge(overslash_api::routes::connections::router())
        .merge(overslash_api::routes::oauth_providers::router())
        .merge(overslash_api::routes::search::router())
        .merge(overslash_api::routes::actions::router())
        .merge(overslash_api::routes::actions::validate_router())
        .merge(overslash_api::routes::mcp::router())
        .merge(overslash_api::routes::auth::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (format!("http://{addr}"), Client::new())
}

/// Start API with a custom max response body size (for testing size limits).
pub async fn start_api_with_body_limit(pool: PgPool, max_bytes: usize) -> (SocketAddr, Client) {
    let config = overslash_api::config::Config {
        host: "127.0.0.1".into(),
        port: 0,
        database_url: String::new(),
        secrets_encryption_key: "ab".repeat(32),
        signing_key: "cd".repeat(32),
        approval_expiry_secs: 1800,
        execution_pending_ttl_secs: 900,
        execution_replay_timeout_secs: 30,
        services_dir: "services".into(),
        google_auth_client_id: None,
        google_auth_client_secret: None,
        github_auth_client_id: None,
        github_auth_client_secret: None,
        public_url: "http://localhost:3000".into(),
        dev_auth_enabled: false,
        max_response_body_bytes: max_bytes,
        filter_timeout_ms: 2000,
        dashboard_url: "/".into(),
        dashboard_origin: "*localhost*".into(),
        mcp_extra_origins: String::new(),
        redis_url: None,
        default_rate_limit: 10000,
        default_rate_window_secs: 60,
        allow_org_creation: true,
        single_org_mode: None,
        app_host_suffix: None,
        api_host_suffix: None,
        session_cookie_domain: None,
        cloud_billing: false,
        stripe_secret_key: None,
        stripe_webhook_secret: None,
        stripe_eur_price_id: None,
        stripe_usd_price_id: None,
        stripe_eur_lookup_key: "overslash_seat_eur".into(),
        stripe_usd_lookup_key: "overslash_seat_usd".into(),
        stripe_api_base: "https://api.stripe.com/v1".into(),
        service_base_overrides: std::collections::HashMap::new(),
        oversla_sh_base_url: None,
        oversla_sh_api_key: None,
        preview_origin_allowlist: None,
        overslash_env: None,
    };

    let state = overslash_api::AppState {
        db: pool,
        config,
        http_client: reqwest::Client::new(),
        registry: Arc::new(overslash_core::registry::ServiceRegistry::default()),
        rate_limiter: std::sync::Arc::new(
            overslash_api::services::rate_limit::InMemoryRateLimitStore::new(),
        ),
        rate_limit_cache: std::sync::Arc::new(
            overslash_api::services::rate_limit::RateLimitConfigCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        free_unlimited_cache: std::sync::Arc::new(
            overslash_api::services::billing_tier::FreeUnlimitedCache::new(
                std::time::Duration::from_secs(30),
            ),
        ),
        auth_code_store: overslash_api::services::oauth_as::AuthCodeStore::new(),
        pending_authorize_store: overslash_api::services::oauth_as::PendingAuthorizeStore::new(),
        embedder: std::sync::Arc::new(overslash_core::embeddings::DisabledEmbedder),
        embeddings_available: false,
        platform_registry: std::sync::Arc::new(
            overslash_api::services::platform_registry::build_registry(),
        ),
    };

    let app = axum::Router::new()
        .merge(overslash_api::routes::health::router())
        .merge(overslash_api::routes::orgs::router())
        .merge(overslash_api::routes::identities::router())
        .merge(overslash_api::routes::api_keys::router())
        .merge(overslash_api::routes::secrets::router())
        .merge(overslash_api::routes::secret_requests::router())
        .merge(overslash_api::routes::permissions::router())
        .merge(overslash_api::routes::actions::router())
        .merge(overslash_api::routes::actions::validate_router())
        .merge(overslash_api::routes::approvals::router())
        .merge(overslash_api::routes::audit::router())
        .merge(overslash_api::routes::webhooks::router())
        .merge(overslash_api::routes::services::router())
        .merge(overslash_api::routes::templates::router())
        .merge(overslash_api::routes::connections::router())
        .merge(overslash_api::routes::byoc_credentials::router())
        .merge(overslash_api::routes::oauth_providers::router())
        .merge(overslash_api::routes::auth::router())
        .merge(overslash_api::routes::org_idp_configs::router())
        .merge(overslash_api::routes::org_oauth_credentials::router())
        .merge(overslash_api::routes::org_service_keys::router())
        .merge(overslash_api::routes::groups::router())
        .merge(overslash_api::routes::rate_limits::router())
        .merge(overslash_api::routes::preferences::router())
        .merge(overslash_api::routes::oauth_as::router())
        .merge(overslash_api::routes::oauth::router())
        .merge(overslash_api::routes::oauth::consent_router())
        .merge(overslash_api::routes::mcp::router())
        .merge(overslash_api::routes::oauth_mcp_clients::router())
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (addr, Client::new())
}

// ─── openapi fixtures ──────────────────────────────────────────────────────

/// Render an OpenAPI Jinja template loaded via `include_str!` with the given
/// context values. Templates live under `tests/fixtures/openapi/`. We use
/// minijinja rather than hand-rolled string substitution so fixtures can grow
/// into conditionals/loops later without churn on the helper.
pub fn render_openapi(template: &str, ctx: &[(&str, &str)]) -> String {
    use minijinja::{Environment, Value};
    use std::collections::BTreeMap;
    let mut env = Environment::new();
    env.add_template("t", template).expect("template parses");
    let bag: BTreeMap<String, Value> = ctx
        .iter()
        .map(|(k, v)| ((*k).to_string(), Value::from(*v)))
        .collect();
    env.get_template("t")
        .unwrap()
        .render(Value::from(bag))
        .expect("template renders")
}

/// Render the shared minimal OpenAPI fixture for the given template key.
/// Display name defaults to the key — pass both separately via `render_openapi`
/// when you need a different display name.
pub fn minimal_openapi(key: &str) -> String {
    render_openapi(
        include_str!("../fixtures/openapi/minimal.yaml.tmpl"),
        &[("key", key), ("display_name", key)],
    )
}

/// Options for `seed_org_user_key`.
#[derive(Default, Clone, Copy)]
pub struct SeedOptions {
    /// Mark the new org as a personal (1-member) tenant.
    pub is_personal: bool,
    /// Flip `identities.is_org_admin` so the resulting API key passes
    /// `AdminAcl` extraction.
    pub is_admin: bool,
}

/// Insert org + user identity + user-bound API key directly via SQL,
/// bypassing the HTTP bootstrap path. Returns `(org_id, user_id, raw_api_key)`.
///
/// The raw key is the literal `osk_<32-char-suffix>` string the caller would
/// send in `Authorization: Bearer …`; the row stored in `api_keys` carries
/// the argon2 hash (matches the production flow). Used by tests that need
/// fine control over org/identity setup without going through the public
/// `POST /v1/orgs` route — useful for testing rate-limit middleware,
/// per-org plan flags, etc.
pub async fn seed_org_user_key(pool: &PgPool, opts: SeedOptions) -> (Uuid, Uuid, String) {
    use rand::RngExt;

    let org_id = Uuid::new_v4();
    sqlx::query("INSERT INTO orgs (id, name, slug, is_personal) VALUES ($1, $2, $3, $4)")
        .bind(org_id)
        .bind("test-org")
        .bind(format!("test-{}", Uuid::new_v4()))
        .bind(opts.is_personal)
        .execute(pool)
        .await
        .unwrap();

    let user_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO identities (id, org_id, name, kind, is_org_admin)
         VALUES ($1, $2, $3, 'user', $4)",
    )
    .bind(user_id)
    .bind(org_id)
    .bind("test-user")
    .bind(opts.is_admin)
    .execute(pool)
    .await
    .unwrap();

    let suffix: String = (0..32)
        .map(|_| {
            let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            chars[rand::rng().random_range(0..chars.len())] as char
        })
        .collect();
    let raw_key = format!("osk_{suffix}");
    let prefix = raw_key[..12].to_string();

    use argon2::{
        Argon2,
        password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
    };
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(raw_key.as_bytes(), &salt)
        .unwrap()
        .to_string();

    sqlx::query(
        "INSERT INTO api_keys (org_id, identity_id, name, key_hash, key_prefix, scopes)
         VALUES ($1, $2, $3, $4, $5, ARRAY[]::text[])",
    )
    .bind(org_id)
    .bind(user_id)
    .bind("test-key")
    .bind(&hash)
    .bind(&prefix)
    .execute(pool)
    .await
    .unwrap();

    (org_id, user_id, raw_key)
}
