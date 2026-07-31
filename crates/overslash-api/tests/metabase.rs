//! Metabase service template + D42 SQL content policy, end-to-end through
//! the gateway against an in-test mock Metabase.
//!
//! Two tiers:
//!   * default-build tests — template compiles, `x-api-key` injects, the
//!     flat `query` param nests into `native.query`, and (without the
//!     `sql_policy` feature) every `risk: dynamic` call fails closed to
//!     write on the all-tables sentinel key;
//!   * `#[cfg(feature = "sql_policy")]` tests — SELECTs classify read and
//!     execute against per-table grants, writes elevate and bubble
//!     approvals carrying `table=…` keys, `require_risk` and the column
//!     deny screen behave, and `/validate` agrees with `/call`.
//!
//! The real-Metabase (+ Pagila) suite lives at the bottom behind
//! `#[ignore]` + env guards — see docker/metabase/README.md.
// The tag assertions read `approvals.tags` / `audit_log.tags` back out with
// runtime-checked queries; the columns aren't part of any API response, so
// there is nothing typed to assert against. Same allow as tests/audit.rs.
#![allow(clippy::disallowed_methods)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{Router, extract::State, response::IntoResponse, routing::any};
use serde_json::{Value, json};

use crate::common::{self, auth, bootstrap_org_identity, start_api_with_registry};

/// One request the mock Metabase saw: method, path, `x-api-key` header, body.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    api_key: Option<String>,
    body: Value,
}

type SeenLog = Arc<Mutex<Vec<Seen>>>;

/// Minimal mock Metabase: records every request and answers the endpoints
/// the template declares with plausible shapes.
async fn start_mock_metabase() -> (SocketAddr, SeenLog) {
    let seen: SeenLog = Arc::new(Mutex::new(Vec::new()));

    async fn handler(
        State(seen): State<SeenLog>,
        req: axum::extract::Request,
    ) -> impl IntoResponse {
        let (parts, body) = req.into_parts();
        let bytes = axum::body::to_bytes(body, 1 << 20)
            .await
            .unwrap_or_default();
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let path = parts.uri.path().to_string();
        seen.lock().unwrap().push(Seen {
            method: parts.method.to_string(),
            path: path.clone(),
            api_key: parts
                .headers
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            body,
        });
        let payload = if path == "/api/database" {
            json!({ "data": [ { "id": 1, "name": "pagila", "engine": "postgres" } ] })
        } else if path == "/api/dataset" {
            json!({ "status": "completed", "data": { "rows": [[1]], "cols": [{"name": "n"}] } })
        } else {
            json!({ "ok": true })
        };
        axum::Json(payload)
    }

    let app = Router::new()
        .route("/{*path}", any(handler))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, seen)
}

/// Boot the API on the shipped registry, seed the `metabase_api_key` org
/// secret, create an org-level `metabase` instance pointed at the mock with
/// the given `sql_databases` config, and grant it to Everyone at
/// `access_level`. `auto_approve_reads` controls the Layer-2 read bypass —
/// pass `false` to force read-classified calls through the chain walk
/// (table grants), `true` to exercise the bypass semantics.
/// Returns `(base, client, agent_key, admin_key, agent_ident_id)`.
async fn setup(
    pool: sqlx::PgPool,
    mock: SocketAddr,
    access_level: &str,
    auto_approve_reads: bool,
    sql_databases: Option<&str>,
) -> (String, reqwest::Client, String, String, String) {
    setup_against(
        pool,
        format!("http://{mock}"),
        "mb_test_key_123",
        access_level,
        auto_approve_reads,
        sql_databases,
    )
    .await
}

/// [`setup`] against an arbitrary upstream URL + API key — shared with the
/// gated real-Metabase suite, which points at the docker/metabase stack.
async fn setup_against(
    pool: sqlx::PgPool,
    upstream_url: String,
    api_key_value: &str,
    access_level: &str,
    auto_approve_reads: bool,
    sql_databases: Option<&str>,
) -> (String, reqwest::Client, String, String, String) {
    common::allow_loopback_ssrf();
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    let put = client
        .put(format!("{base}/v1/secrets/metabase_api_key"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "value": api_key_value }))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "secret put: {}", put.status());

    let mut body = json!({
        "template_key": "metabase",
        "name": "metabase",
        "url": upstream_url,
        "user_level": false,
        "status": "active",
        "credentials": { "token": "metabase_api_key" },
    });
    if let Some(dbs) = sql_databases {
        body["config"] = json!({ "sql_databases": dbs });
    }
    let svc: Value = client
        .post(format!("{base}/v1/services"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let svc_id = svc["id"]
        .as_str()
        .expect("service create failed")
        .to_string();

    let groups: Vec<Value> = client
        .get(format!("{base}/v1/groups"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
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
        .expect("Everyone group exists");
    let grant = client
        .post(format!("{base}/v1/groups/{everyone_id}/grants"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "service_instance_id": svc_id,
            "access_level": access_level,
            "auto_approve_reads": auto_approve_reads,
        }))
        .send()
        .await
        .unwrap();
    assert!(grant.status().is_success(), "grant: {}", grant.status());

    (base, client, agent_key, admin_key, ident_id.to_string())
}

async fn add_rule(
    base: &str,
    client: &reqwest::Client,
    admin_key: &str,
    ident_id: &str,
    pattern: &str,
    effect: &str,
) {
    let resp = client
        .post(format!("{base}/v1/permissions"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({
            "identity_id": ident_id,
            "action_pattern": pattern,
            "effect": effect,
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "rule {pattern}: {}",
        resp.status()
    );
}

async fn run_query(
    base: &str,
    client: &reqwest::Client,
    agent_key: &str,
    sql: &str,
    extra: Value,
) -> Value {
    let mut body = json!({
        "service": "metabase",
        "action": "run_query",
        "params": { "database": 1, "query": sql },
    });
    if let Some(map) = extra.as_object() {
        for (k, v) in map {
            body[k] = v.clone();
        }
    }
    client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(agent_key).0, auth(agent_key).1)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

// ─── Default-build tier (runs in normal CI, parser compiled out) ───────────

/// The shipped template compiles into the registry with the expected action
/// surface and risk classes.
#[tokio::test]
async fn metabase_template_ships() {
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("services");
    let reg = overslash_core::registry::ServiceRegistry::load_from_dir(
        &ws_root,
        overslash_core::template_vars::Vars::for_tests(),
    )
    .unwrap();
    let svc = reg.get("metabase").expect("metabase template registered");

    use overslash_core::types::DeclaredRisk;
    for (action, want) in [
        ("list_databases", DeclaredRisk::Read),
        ("get_database_schema", DeclaredRisk::Read),
        ("list_cards", DeclaredRisk::Read),
        ("run_card", DeclaredRisk::Read),
        ("search", DeclaredRisk::Read),
        ("run_query", DeclaredRisk::Dynamic),
        ("export_query", DeclaredRisk::Dynamic),
    ] {
        assert_eq!(svc.actions[action].risk, want, "{action}");
    }

    let query = &svc.actions["run_query"].params["query"];
    assert_eq!(query.sql_field.as_deref(), Some("native.query"));
    assert_eq!(
        svc.actions["run_query"].params["database"]
            .sql_database
            .as_deref(),
        Some(".database | tostring")
    );
    // The MBQL escape hatch stays pinned shut.
    assert_eq!(
        svc.actions["run_query"].params["type"].enum_values,
        Some(vec!["native".to_string()])
    );

    // export_query uses extraction mode: the object param carries the SQL
    // at a nested path (Metabase's export endpoint wants the dataset query
    // as one `query` object).
    let export_q = &svc.actions["export_query"].params["query"];
    assert_eq!(export_q.param_type, "object");
    assert_eq!(export_q.sql_field.as_deref(), Some("query.native.query"));
    assert_eq!(
        export_q.sql_database.as_deref(),
        Some(".query.database | tostring")
    );
}

/// A read action executes with the API key injected as `x-api-key` — never a
/// bearer header, never in the body.
#[tokio::test]
async fn api_key_injects_on_read_action() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_metabase().await;
    let (base, client, agent_key, _admin, _ident) = setup(pool, mock, "admin", true, None).await;

    let resp: Value = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "metabase",
            "action": "list_databases",
            "params": {},
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["status"].as_str(), Some("called"), "{resp:?}");

    let seen = seen.lock().unwrap();
    let req = seen.last().expect("mock saw the request");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/api/database");
    assert_eq!(req.api_key.as_deref(), Some("mb_test_key_123"));
}

/// Without the `sql_policy` feature, a `risk: dynamic` action fails closed:
/// the effective risk is write and the uncovered key set carries the
/// all-tables sentinel — even for a SELECT.
#[cfg(not(feature = "sql_policy"))]
#[tokio::test]
async fn dynamic_fails_closed_without_the_parser() {
    let pool = common::test_pool().await;
    let (mock, _seen) = start_mock_metabase().await;
    let (base, client, agent_key, _admin, _ident) = setup(pool, mock, "admin", false, None).await;

    let resp = run_query(&base, &client, &agent_key, "SELECT 1", json!({})).await;
    assert_eq!(
        resp["status"].as_str(),
        Some("pending_approval"),
        "{resp:?}"
    );
    let keys: Vec<&str> = resp["permission_keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    // No sql_databases config → the db-key ("1") is the label. The
    // sentinel is mutation-shaped (nothing was proven read).
    assert_eq!(keys, vec!["metabase:run_query:table_mut=1/*"]);
    // Classified write → "med" severity card.
    assert_eq!(resp["risk"].as_str(), Some("med"));
}

/// …and covering the sentinel with an explicit db-wide grant lets the call
/// through even without the parser: the operator consciously granted the
/// whole database.
#[cfg(not(feature = "sql_policy"))]
#[tokio::test]
async fn dynamic_without_parser_executes_under_sentinel_grant() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_metabase().await;
    let (base, client, agent_key, admin_key, ident) = setup(pool, mock, "admin", false, None).await;
    add_rule(
        &base,
        &client,
        &admin_key,
        &ident,
        "metabase:run_query:table_mut=1/*",
        "allow",
    )
    .await;

    let resp = run_query(&base, &client, &agent_key, "SELECT 1", json!({})).await;
    assert_eq!(resp["status"].as_str(), Some("called"), "{resp:?}");

    // The flat `query` param was nested into Metabase's native shape and
    // the pinned `type: native` default rode along.
    let seen = seen.lock().unwrap();
    let req = seen.last().unwrap();
    assert_eq!(req.path, "/api/dataset");
    assert_eq!(
        req.body,
        json!({ "database": 1, "type": "native", "native": { "query": "SELECT 1" } })
    );
    assert_eq!(req.api_key.as_deref(), Some("mb_test_key_123"));
}

// ─── sql_policy tier (cargo test -p overslash-api --features sql_policy) ───

#[cfg(feature = "sql_policy")]
mod classified {
    use super::*;

    const DBS: &str = r#"{"1": {"dialect": "postgres", "label": "pagila"}}"#;

    /// A SELECT classifies read: it clears a read-level ceiling, needs only
    /// its table keys covered, and executes — the frictionless path that
    /// motivates the parser.
    #[tokio::test]
    async fn select_executes_under_table_grant() {
        let pool = common::test_pool().await;
        let (mock, seen) = start_mock_metabase().await;
        let (base, client, agent_key, admin_key, ident) =
            setup(pool, mock, "read", false, Some(DBS)).await;
        add_rule(
            &base,
            &client,
            &admin_key,
            &ident,
            "metabase:run_query:table=pagila/public.*",
            "allow",
        )
        .await;

        let resp = run_query(
            &base,
            &client,
            &agent_key,
            "SELECT title FROM public.film",
            json!({}),
        )
        .await;
        assert_eq!(resp["status"].as_str(), Some("called"), "{resp:?}");

        let seen = seen.lock().unwrap();
        let req = seen.last().unwrap();
        assert_eq!(
            req.body["native"]["query"].as_str(),
            Some("SELECT title FROM public.film")
        );
    }

    /// An ungranted table bubbles an approval naming exactly that table.
    #[tokio::test]
    async fn ungranted_table_bubbles_approval() {
        let pool = common::test_pool().await;
        let (mock, _seen) = start_mock_metabase().await;
        let (base, client, agent_key, admin_key, ident) =
            setup(pool, mock, "admin", false, Some(DBS)).await;
        add_rule(
            &base,
            &client,
            &admin_key,
            &ident,
            "metabase:run_query:table=pagila/public.film",
            "allow",
        )
        .await;

        let resp = run_query(
            &base,
            &client,
            &agent_key,
            "SELECT * FROM public.film JOIN public.payment USING (customer_id)",
            json!({}),
        )
        .await;
        assert_eq!(
            resp["status"].as_str(),
            Some("pending_approval"),
            "{resp:?}"
        );
        let keys: Vec<&str> = resp["permission_keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        // film is covered; only payment is uncovered.
        assert_eq!(keys, vec!["metabase:run_query:table=pagila/public.payment"]);
        // Read-classified → the approval card says low.
        assert_eq!(resp["risk"].as_str(), Some("low"));
    }

    /// DML elevates to write: it exceeds a read ceiling outright (403, not
    /// approvable), and under a write ceiling it bubbles an approval.
    #[tokio::test]
    async fn insert_elevates_to_write() {
        let pool = common::test_pool().await;
        let (mock, _seen) = start_mock_metabase().await;
        let (base, client, agent_key, admin_key, ident) =
            setup(pool, mock, "read", false, Some(DBS)).await;
        add_rule(&base, &client, &admin_key, &ident, "metabase:**", "allow").await;

        // Read-level ceiling: the write never reaches Layer 2.
        let resp = run_query(
            &base,
            &client,
            &agent_key,
            "INSERT INTO public.film (title) VALUES ('x')",
            json!({}),
        )
        .await;
        assert_eq!(resp["status"].as_str(), Some("denied"), "{resp:?}");
    }

    /// The D43 fix demonstrated end-to-end: a remembered *read* grant on a
    /// table does not authorize mutating it — the INSERT still bubbles, on
    /// the `table_mut=` key.
    #[tokio::test]
    async fn insert_bubbles_under_write_ceiling() {
        let pool = common::test_pool().await;
        let (mock, _seen) = start_mock_metabase().await;
        let (base, client, agent_key, admin_key, ident) =
            setup(pool, mock, "write", false, Some(DBS)).await;
        add_rule(
            &base,
            &client,
            &admin_key,
            &ident,
            "metabase:run_query:table=pagila/*",
            "allow",
        )
        .await;

        let resp = run_query(
            &base,
            &client,
            &agent_key,
            "INSERT INTO public.film (title) VALUES ('x')",
            json!({}),
        )
        .await;
        assert_eq!(
            resp["status"].as_str(),
            Some("pending_approval"),
            "{resp:?}"
        );
        let keys: Vec<&str> = resp["permission_keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            keys,
            vec!["metabase:run_query:table_mut=pagila/public.film"]
        );
        assert_eq!(resp["risk"].as_str(), Some("med"));
    }

    /// `require_risk: read` (the MCP `overslash_read` gate) admits a
    /// SELECT-only query and rejects a write-classified one up front.
    #[tokio::test]
    async fn require_risk_read_admits_selects_only() {
        let pool = common::test_pool().await;
        let (mock, _seen) = start_mock_metabase().await;
        let (base, client, agent_key, admin_key, ident) =
            setup(pool, mock, "admin", true, Some(DBS)).await;
        add_rule(&base, &client, &admin_key, &ident, "metabase:**", "allow").await;

        let resp = run_query(
            &base,
            &client,
            &agent_key,
            "SELECT 1",
            json!({ "require_risk": "read" }),
        )
        .await;
        assert_eq!(resp["status"].as_str(), Some("called"), "{resp:?}");

        let resp = client
            .post(format!("{base}/v1/actions/call"))
            .header(auth(&agent_key).0, auth(&agent_key).1)
            .json(&json!({
                "service": "metabase",
                "action": "run_query",
                "params": { "database": 1, "query": "DROP TABLE public.film" },
                "require_risk": "read",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "write SQL must be rejected by the gate");
        let body: Value = resp.json().await.unwrap();
        let msg = serde_json::to_string(&body).unwrap();
        assert!(msg.contains("risk=write"), "{msg}");
    }

    /// The column deny screen: `column_star` forces enumeration, and a
    /// named-column deny bites even when every table is granted.
    #[tokio::test]
    async fn column_denies_screen_without_needing_allows() {
        let pool = common::test_pool().await;
        let (mock, _seen) = start_mock_metabase().await;
        let (base, client, agent_key, admin_key, ident) =
            setup(pool, mock, "admin", true, Some(DBS)).await;
        add_rule(&base, &client, &admin_key, &ident, "metabase:**", "allow").await;
        add_rule(
            &base,
            &client,
            &admin_key,
            &ident,
            "metabase:*:column_star=*",
            "deny",
        )
        .await;
        add_rule(
            &base,
            &client,
            &admin_key,
            &ident,
            "metabase:*:column=*/ssn",
            "deny",
        )
        .await;

        // SELECT * → denied by the star screen.
        let resp = run_query(
            &base,
            &client,
            &agent_key,
            "SELECT * FROM public.customer",
            json!({}),
        )
        .await;
        assert_eq!(resp["status"].as_str(), Some("denied"), "{resp:?}");

        // Enumerated benign columns pass (no allow rule names any column).
        let resp = run_query(
            &base,
            &client,
            &agent_key,
            "SELECT first_name, last_name FROM public.customer",
            json!({}),
        )
        .await;
        assert_eq!(resp["status"].as_str(), Some("called"), "{resp:?}");

        // A denied identifier is a hard 403 wherever it is referenced.
        let resp = run_query(
            &base,
            &client,
            &agent_key,
            "SELECT ssn FROM public.customer",
            json!({}),
        )
        .await;
        assert_eq!(resp["status"].as_str(), Some("denied"), "{resp:?}");
    }

    /// `/v1/actions/validate` reports the same verdict and the same table
    /// keys `/call` acts on — the dry-run contract.
    #[tokio::test]
    async fn validate_agrees_with_call() {
        let pool = common::test_pool().await;
        let (mock, _seen) = start_mock_metabase().await;
        let (base, client, agent_key, _admin, _ident) =
            setup(pool, mock, "write", false, Some(DBS)).await;

        let sql = "WITH d AS (DELETE FROM public.rental RETURNING *) SELECT * FROM d";
        let validate: Value = client
            .post(format!("{base}/v1/actions/validate"))
            .header(auth(&agent_key).0, auth(&agent_key).1)
            .json(&json!({
                "service": "metabase",
                "action": "run_query",
                "params": { "database": 1, "query": sql },
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            validate["permission"]["status"].as_str(),
            Some("would_require_approval"),
            "{validate:?}"
        );
        let validate_keys = validate["permission"]["uncovered_keys"].clone();

        let call = run_query(&base, &client, &agent_key, sql, json!({})).await;
        assert_eq!(call["status"].as_str(), Some("pending_approval"));
        assert_eq!(
            call["permission_keys"], validate_keys,
            "validate and call must derive identical keys"
        );
    }

    /// The classifier's facts survive as metadata tags on the approval row.
    ///
    /// Before tagging, the analysis was reduced to a risk floor plus a set of
    /// permission keys and then dropped — the columns a statement touched were
    /// never persisted anywhere, and the tables only survived by accident,
    /// string-encoded inside the *uncovered* key subset.
    #[tokio::test]
    async fn approval_tags_carry_the_sql_facts() {
        let pool = common::test_pool().await;
        let (mock, _seen) = start_mock_metabase().await;
        let (base, client, agent_key, admin_key, ident) =
            setup(pool.clone(), mock, "write", false, Some(DBS)).await;
        add_rule(
            &base,
            &client,
            &admin_key,
            &ident,
            "metabase:run_query:table=pagila/*",
            "allow",
        )
        .await;

        let resp = run_query(
            &base,
            &client,
            &agent_key,
            "INSERT INTO public.film (title) VALUES ('x')",
            json!({}),
        )
        .await;
        assert_eq!(
            resp["status"].as_str(),
            Some("pending_approval"),
            "{resp:?}"
        );

        let tags: Vec<String> =
            sqlx::query_scalar("SELECT tags FROM approvals ORDER BY created_at DESC LIMIT 1")
                .fetch_one(&pool)
                .await
                .unwrap();

        // SQL-derived facts.
        assert!(tags.contains(&"sql:write".to_string()), "{tags:?}");
        assert!(
            tags.contains(&"sql_reason:statement".to_string()),
            "{tags:?}"
        );
        assert!(
            tags.contains(&"sql_stmt:insertstmt".to_string()),
            "{tags:?}"
        );
        assert!(tags.contains(&"db:pagila".to_string()), "{tags:?}");
        assert!(
            tags.contains(&"table_mut:pagila/public.film".to_string()),
            "{tags:?}"
        );
        // A mutation target is not exhaustive-flagged; the parser enumerated it.
        assert!(
            !tags.contains(&"sql_exhaustive:false".to_string()),
            "{tags:?}"
        );

        // Call-context facts.
        assert!(tags.contains(&"service:metabase".to_string()), "{tags:?}");
        assert!(tags.contains(&"action:run_query".to_string()), "{tags:?}");
        assert!(tags.contains(&"mode:c".to_string()), "{tags:?}");
        assert!(tags.contains(&"transport:http".to_string()), "{tags:?}");
        // Effective risk — the classifier elevated a `dynamic` action.
        assert!(tags.contains(&"risk:write".to_string()), "{tags:?}");

        // The approval.created audit row carries the identical set.
        let audit: Vec<String> = sqlx::query_scalar(
            "SELECT tags FROM audit_log WHERE action = 'approval.created' ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audit, tags, "approval and its audit row must not drift");
    }

    /// An executed read tags the audit row, including the outcome the
    /// approval could not know.
    #[tokio::test]
    async fn executed_read_tags_the_audit_row() {
        let pool = common::test_pool().await;
        let (mock, _seen) = start_mock_metabase().await;
        let (base, client, agent_key, admin_key, ident) =
            setup(pool.clone(), mock, "read", false, Some(DBS)).await;
        add_rule(
            &base,
            &client,
            &admin_key,
            &ident,
            "metabase:run_query:table=pagila/public.*",
            "allow",
        )
        .await;

        let resp = run_query(
            &base,
            &client,
            &agent_key,
            "SELECT title FROM public.film",
            json!({}),
        )
        .await;
        assert_eq!(resp["status"].as_str(), Some("called"), "{resp:?}");

        let tags: Vec<String> = sqlx::query_scalar(
            "SELECT tags FROM audit_log WHERE action = 'action.executed' ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(tags.contains(&"sql:read".to_string()), "{tags:?}");
        assert!(
            tags.contains(&"table:pagila/public.film".to_string()),
            "{tags:?}"
        );
        assert!(
            tags.contains(&"column:pagila/title".to_string()),
            "{tags:?}"
        );
        assert!(tags.contains(&"outcome:ok".to_string()), "{tags:?}");
        // A read carries no write reason.
        assert!(
            tags.iter().all(|t| !t.starts_with("sql_reason:")),
            "{tags:?}"
        );
    }
}

// ─── Gated real-Metabase suite (docker/metabase + Pagila) ──────────────────
//
// Runs only with `--ignored` AND the env the harness writes to
// docker/metabase/.env.metabase (`make metabase-up` / `make metabase-e2e`):
// METABASE_URL, METABASE_API_KEY, METABASE_PAGILA_DB_ID. Compiled only with
// the sql_policy feature — the whole point is exercising the classifier
// against a real Postgres-backed Metabase and the Pagila dataset's views
// and partitioned tables.
#[cfg(feature = "sql_policy")]
mod real_e2e {
    use super::*;

    /// `(url, api_key, pagila_db_id)` from the harness env, or `None` → the
    /// caller prints a SKIP and returns (repo idiom: `#[ignore]` + guard).
    fn harness_env() -> Option<(String, String, i64)> {
        let url = std::env::var("METABASE_URL")
            .ok()
            .filter(|s| !s.is_empty())?;
        let key = std::env::var("METABASE_API_KEY")
            .ok()
            .filter(|s| !s.is_empty())?;
        let db: i64 = std::env::var("METABASE_PAGILA_DB_ID").ok()?.parse().ok()?;
        Some((url, key, db))
    }

    macro_rules! require_harness {
        () => {
            match harness_env() {
                Some(env) => env,
                None => {
                    eprintln!("SKIP: METABASE_URL / METABASE_API_KEY / METABASE_PAGILA_DB_ID not set (run `make metabase-up`)");
                    return;
                }
            }
        };
    }

    fn dbs_config(db_id: i64) -> String {
        format!(r#"{{"{db_id}": {{"dialect": "postgres", "label": "pagila"}}}}"#)
    }

    async fn real_query(
        base: &str,
        client: &reqwest::Client,
        agent_key: &str,
        db_id: i64,
        action: &str,
        params: Value,
    ) -> Value {
        let mut p = params;
        p["database"] = json!(db_id);
        client
            .post(format!("{base}/v1/actions/call"))
            .header(auth(agent_key).0, auth(agent_key).1)
            .json(&json!({ "service": "metabase", "action": action, "params": p }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }

    #[ignore] // real-Metabase e2e: run with --ignored after `make metabase-up`
    #[tokio::test]
    async fn discovery_and_schema() {
        let (url, key, db_id) = require_harness!();
        let pool = common::test_pool().await;
        let (base, client, agent_key, _admin, _ident) =
            setup_against(pool, url, &key, "admin", true, Some(&dbs_config(db_id))).await;

        let resp: Value = client
            .post(format!("{base}/v1/actions/call"))
            .header(auth(&agent_key).0, auth(&agent_key).1)
            .json(&json!({ "service": "metabase", "action": "list_databases", "params": {} }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp["status"].as_str(), Some("called"), "{resp:?}");
        let body = resp["result"]["body"].as_str().unwrap();
        assert!(body.contains("pagila"), "pagila not listed: {body}");

        let resp: Value = client
            .post(format!("{base}/v1/actions/call"))
            .header(auth(&agent_key).0, auth(&agent_key).1)
            .json(&json!({
                "service": "metabase",
                "action": "get_database_schema",
                "params": { "database_id": db_id },
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp["status"].as_str(), Some("called"), "{resp:?}");
        let body = resp["result"]["body"].as_str().unwrap();
        assert!(body.contains("film"), "schema missing film table: {body}");
    }

    #[ignore] // real-Metabase e2e: run with --ignored after `make metabase-up`
    #[tokio::test]
    async fn select_reads_rows_under_table_grant() {
        let (url, key, db_id) = require_harness!();
        let pool = common::test_pool().await;
        let (base, client, agent_key, admin_key, ident) =
            setup_against(pool, url, &key, "read", false, Some(&dbs_config(db_id))).await;
        add_rule(
            &base,
            &client,
            &admin_key,
            &ident,
            "metabase:run_query:table=pagila/*",
            "allow",
        )
        .await;

        let resp = real_query(
            &base,
            &client,
            &agent_key,
            db_id,
            "run_query",
            json!({ "query": "SELECT title, rating FROM public.film ORDER BY film_id LIMIT 5" }),
        )
        .await;
        assert_eq!(resp["status"].as_str(), Some("called"), "{resp:?}");
        let body = resp["result"]["body"].as_str().unwrap();
        assert!(
            body.contains("ACADEMY DINOSAUR"),
            "expected pagila rows, got: {body}"
        );
    }

    /// A view is gated as its own name (D42): granting only the view lets a
    /// query over it run even though the base tables carry no grant.
    #[ignore] // real-Metabase e2e: run with --ignored after `make metabase-up`
    #[tokio::test]
    async fn view_gates_as_its_own_name() {
        let (url, key, db_id) = require_harness!();
        let pool = common::test_pool().await;
        let (base, client, agent_key, admin_key, ident) =
            setup_against(pool, url, &key, "read", false, Some(&dbs_config(db_id))).await;
        add_rule(
            &base,
            &client,
            &admin_key,
            &ident,
            "metabase:run_query:table=pagila/public.film_list",
            "allow",
        )
        .await;

        let resp = real_query(
            &base,
            &client,
            &agent_key,
            db_id,
            "run_query",
            json!({ "query": "SELECT title FROM public.film_list LIMIT 3" }),
        )
        .await;
        assert_eq!(resp["status"].as_str(), Some("called"), "{resp:?}");

        // …and the partitioned payment table behaves as one relation.
        add_rule(
            &base,
            &client,
            &admin_key,
            &ident,
            "metabase:run_query:table=pagila/public.payment",
            "allow",
        )
        .await;
        let resp = real_query(
            &base,
            &client,
            &agent_key,
            db_id,
            "run_query",
            json!({ "query": "SELECT count(*) FROM public.payment" }),
        )
        .await;
        assert_eq!(resp["status"].as_str(), Some("called"), "{resp:?}");
    }

    #[ignore] // real-Metabase e2e: run with --ignored after `make metabase-up`
    #[tokio::test]
    async fn write_bubbles_and_never_reaches_metabase() {
        let (url, key, db_id) = require_harness!();
        let pool = common::test_pool().await;
        let (base, client, agent_key, _admin, _ident) =
            setup_against(pool, url, &key, "write", false, Some(&dbs_config(db_id))).await;

        let resp = real_query(
            &base,
            &client,
            &agent_key,
            db_id,
            "run_query",
            json!({ "query": "INSERT INTO public.actor (first_name, last_name) VALUES ('E2E', 'PROBE')" }),
        )
        .await;
        assert_eq!(
            resp["status"].as_str(),
            Some("pending_approval"),
            "{resp:?}"
        );
        let keys: Vec<&str> = resp["permission_keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(
            keys,
            vec!["metabase:run_query:table_mut=pagila/public.actor"]
        );
    }

    #[ignore] // real-Metabase e2e: run with --ignored after `make metabase-up`
    #[tokio::test]
    async fn column_star_deny_forces_enumeration() {
        let (url, key, db_id) = require_harness!();
        let pool = common::test_pool().await;
        let (base, client, agent_key, admin_key, ident) =
            setup_against(pool, url, &key, "admin", true, Some(&dbs_config(db_id))).await;
        add_rule(&base, &client, &admin_key, &ident, "metabase:**", "allow").await;
        add_rule(
            &base,
            &client,
            &admin_key,
            &ident,
            "metabase:*:column_star=*",
            "deny",
        )
        .await;

        let resp = real_query(
            &base,
            &client,
            &agent_key,
            db_id,
            "run_query",
            json!({ "query": "SELECT * FROM public.customer LIMIT 1" }),
        )
        .await;
        assert_eq!(resp["status"].as_str(), Some("denied"), "{resp:?}");

        let resp = real_query(
            &base,
            &client,
            &agent_key,
            db_id,
            "run_query",
            json!({ "query": "SELECT first_name, last_name FROM public.customer LIMIT 1" }),
        )
        .await;
        assert_eq!(resp["status"].as_str(), Some("called"), "{resp:?}");
    }

    #[ignore] // real-Metabase e2e: run with --ignored after `make metabase-up`
    #[tokio::test]
    async fn export_returns_csv_payload() {
        let (url, key, db_id) = require_harness!();
        let pool = common::test_pool().await;
        let (base, client, agent_key, admin_key, ident) =
            setup_against(pool, url, &key, "admin", true, Some(&dbs_config(db_id))).await;
        add_rule(&base, &client, &admin_key, &ident, "metabase:**", "allow").await;

        let resp: Value = client
            .post(format!("{base}/v1/actions/call"))
            .header(auth(&agent_key).0, auth(&agent_key).1)
            .json(&json!({
                "service": "metabase",
                "action": "export_query",
                "params": {
                    "export_format": "csv",
                    "query": {
                        "database": db_id,
                        "type": "native",
                        "native": {
                            "query": "SELECT title FROM public.film ORDER BY film_id LIMIT 3"
                        },
                    },
                },
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp["status"].as_str(), Some("called"), "{resp:?}");
        let body = resp["result"]["body"].as_str().unwrap();
        assert!(
            body.to_lowercase().contains("title") && body.contains("ACADEMY DINOSAUR"),
            "expected CSV payload, got: {body}"
        );
    }

    #[ignore] // real-Metabase e2e: run with --ignored after `make metabase-up`
    #[tokio::test]
    async fn search_finds_pagila_tables() {
        let (url, key, db_id) = require_harness!();
        let pool = common::test_pool().await;
        let (base, client, agent_key, _admin, _ident) =
            setup_against(pool, url, &key, "admin", true, Some(&dbs_config(db_id))).await;

        let resp: Value = client
            .post(format!("{base}/v1/actions/call"))
            .header(auth(&agent_key).0, auth(&agent_key).1)
            .json(&json!({
                "service": "metabase",
                "action": "search",
                "params": { "q": "film" },
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(resp["status"].as_str(), Some("called"), "{resp:?}");
        let body = resp["result"]["body"].as_str().unwrap();
        assert!(body.contains("film"), "search found nothing: {body}");
    }
}

// ─── D44: no shipped host, so the endpoint is asked for at instantiation ────

/// With `OVERSLASH_TEMPLATE_VAR_METABASE_URL` unset, `${METABASE_URL?}`
/// resolves to null and the template ships **host-less** — still offered, but
/// with nowhere to send a request until an instance names one.
///
/// The contrast with `email.yaml` is the whole point of having both spellings:
/// email's `${MAILBOX_HOST}` has no fallback, so an unset deployment loses the
/// template entirely (there is no gateway to talk to). Metabase is self-hosted,
/// so losing the template would be wrong — the deployment simply doesn't know
/// the URL yet, and the operator does.
#[tokio::test]
async fn metabase_without_a_url_variable_requires_one_per_instance() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry_vars(
        pool,
        None,
        // Deliberately no METABASE_URL. MAILBOX_HOST is present only so the
        // rest of the shipped catalog loads normally.
        overslash_core::template_vars::Vars::from_pairs([(
            "MAILBOX_HOST",
            "mailbox.overslash.com",
        )]),
        |_| {},
    )
    .await;
    let (_org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    // Still in the catalog, and the dashboard is told to ask for a URL.
    let detail: Value = client
        .get(format!("{base}/v1/templates/metabase"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["hosts"], json!([]), "no host without the variable");
    assert_eq!(
        detail["configurable_url"],
        json!(true),
        "a host-less template must reveal the URL field"
    );

    // Creating an instance without one is rejected here, where the operator is
    // looking — not at send time with an opaque failure.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "template_key": "metabase",
            "name": "mb-no-url",
            "user_level": false,
            "status": "active",
            "credentials": { "token": "metabase_api_key" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("declares no endpoint"),
        "error should say what to supply, got: {body}"
    );

    // Supplying one is all it takes.
    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "template_key": "metabase",
            "name": "mb-with-url",
            "url": "https://mb.example.com",
            "user_level": false,
            "status": "active",
            "credentials": { "token": "metabase_api_key" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "instance with an explicit url should create: {:?}",
        resp.text().await
    );
}

/// The other half: when the deployment *does* set the variable, the template
/// carries that host and an instance needs no `url` at all.
#[tokio::test]
async fn metabase_with_a_url_variable_needs_no_per_instance_url() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry_vars(
        pool,
        None,
        overslash_core::template_vars::Vars::from_pairs([
            ("MAILBOX_HOST", "mailbox.overslash.com"),
            ("METABASE_URL", "https://mb.example.com"),
        ]),
        |_| {},
    )
    .await;
    let (_org_id, _ident_id, _agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let detail: Value = client
        .get(format!("{base}/v1/templates/metabase"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["hosts"], json!(["mb.example.com"]));

    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "template_key": "metabase",
            "name": "mb-default",
            "user_level": false,
            "status": "active",
            "credentials": { "token": "metabase_api_key" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "the deployment's host is the default: {:?}",
        resp.text().await
    );
}

/// A host-less template must **not** become a raw-HTTP escape hatch.
///
/// `resolve_verb_host_and_path` reads `hosts: []` as "unbound — the caller
/// names the target", which was safe while `http` was the only host-less HTTP
/// template. `${METABASE_URL?}` makes a *named* service compile host-less, and
/// without the pseudo-service guard an agent holding `metabase` permissions
/// could point the HTTP-verb shape at any host in the world — the host-binding
/// gap D14 closed by removing Mode B, reopened through the back door.
#[tokio::test]
async fn host_less_metabase_is_not_a_raw_http_escape_hatch() {
    let pool = common::test_pool().await;
    let (base, client) = common::start_api_with_registry_vars(
        pool,
        None,
        overslash_core::template_vars::Vars::from_pairs([(
            "MAILBOX_HOST",
            "mailbox.overslash.com",
        )]),
        |_| {},
    )
    .await;
    let (_org_id, _ident_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "template_key": "metabase",
            "name": "metabase",
            "url": "https://mb.example.com",
            "user_level": false,
            "status": "active",
            "credentials": { "token": "metabase_api_key" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    // The template still has no host (the *instance* has a url), so the verb
    // shape must refuse rather than forward to an arbitrary target.
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(&agent_key).0, auth(&agent_key).1)
        .json(&json!({
            "service": "metabase",
            "method": "GET",
            "url": "https://evil.example.com/steal",
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap();
    assert_ne!(
        status, 200,
        "a host-less template must not forward an arbitrary url: {body}"
    );
    assert!(
        body.contains("declares no host"),
        "expected the host-binding refusal specifically (so this test can't pass \
         for an unrelated reason), got {status}: {body}"
    );
}
