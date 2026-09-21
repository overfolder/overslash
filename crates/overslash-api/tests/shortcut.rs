//! Shortcut service template, end-to-end through the gateway against an
//! in-test mock Shortcut.
//!
//! Three things are worth proving here that a unit test cannot:
//!
//!   1. the shipped YAML compiles into the actions and risk classes it claims;
//!   2. the workspace API token reaches the upstream as a bare `Shortcut-Token`
//!      header — no `Bearer`, no query string, no body;
//!   3. `search_stories` pages. Shortcut answers with the next *URL* in the
//!      response body (`/api/v3/search/stories?query=…&next=<token>`) while its
//!      `next` parameter takes only the token, which is the whole reason
//!      `link` pagination learned to read a body path. This file is where that
//!      capability meets the template that motivated it.
//!
//! The real-workspace test at the bottom is `#[ignore]`d and needs
//! `SHORTCUT_TEST_API_TOKEN` (Settings → API Tokens). It only reads.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{Router, extract::State, response::IntoResponse, routing::any};
use serde_json::{Value, json};

use crate::common::{self, auth, bootstrap_org_identity, start_api_with_registry};

// ============================================================================
// Parse smoke test
// ============================================================================

#[test]
fn shortcut_yaml_parses() {
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let reg = overslash_core::registry::ServiceRegistry::load_from_dir(
        &ws_root.join("services"),
        overslash_core::template_vars::Vars::for_tests(),
    )
    .expect("services/ should load cleanly");
    let svc = reg.get("shortcut").expect("shortcut should be registered");

    assert_eq!(svc.display_name, "Shortcut");
    assert_eq!(svc.hosts, vec!["api.app.shortcut.com".to_string()]);

    // The curated surface, spelled out so that dropping one is a test failure
    // rather than a silently smaller service.
    for action in [
        "search_stories",
        "search_epics",
        "query_stories",
        "get_story",
        "create_story",
        "update_story",
        "delete_story",
        "list_story_comments",
        "create_story_comment",
        "update_story_comment",
        "create_task",
        "update_task",
        "create_story_link",
        "list_epics",
        "get_epic",
        "create_epic",
        "update_epic",
        "list_epic_stories",
        "create_epic_comment",
        "list_iterations",
        "get_iteration",
        "create_iteration",
        "list_iteration_stories",
        "get_epic_workflow",
        "list_workflows",
        "list_members",
        "get_current_member",
        "list_groups",
        "list_labels",
        "list_projects",
        "get_project",
        "create_project",
        "update_project",
        "delete_project",
        "list_project_stories",
    ] {
        assert!(
            svc.actions.contains_key(action),
            "missing action '{action}'"
        );
    }
    assert_eq!(svc.actions.len(), 35, "curated surface changed size");

    // Risk classes are what the approval chain gates on, so the destructive
    // one is asserted by name rather than left to the method default.
    use overslash_core::types::DeclaredRisk;
    assert_eq!(svc.actions["delete_story"].risk, DeclaredRisk::Delete);
    assert_eq!(svc.actions["get_story"].risk, DeclaredRisk::Read);
    assert_eq!(svc.actions["update_story"].risk, DeclaredRisk::Write);
    // A POST that only reads — the search twin — must not default to write.
    assert_eq!(svc.actions["query_stories"].risk, DeclaredRisk::Read);
    assert_eq!(svc.actions["delete_project"].risk, DeclaredRisk::Delete);
    assert_eq!(svc.actions["list_projects"].risk, DeclaredRisk::Read);

    // The two story writes have to be able to *say* which project a story
    // belongs to — the whole reason the project surface exists. A body
    // property the template does not declare is rejected as an unknown
    // argument, which is how this went missing in the first place.
    for action in ["create_story", "update_story"] {
        assert!(
            svc.actions[action].params.contains_key("project_id"),
            "{action} must accept project_id"
        );
    }
    assert!(
        svc.actions["query_stories"]
            .params
            .contains_key("project_ids"),
        "query_stories must filter on project_ids"
    );
}

/// The pagination declaration that motivated the body-borne `link` form.
#[test]
fn shortcut_search_declares_a_body_borne_next_url() {
    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let reg = overslash_core::registry::ServiceRegistry::load_from_dir(
        &ws_root.join("services"),
        overslash_core::template_vars::Vars::for_tests(),
    )
    .unwrap();
    let svc = reg.get("shortcut").unwrap();

    let spec = svc.actions["search_stories"]
        .pagination
        .as_ref()
        .expect("search_stories pages");
    assert_eq!(spec.next.style, overslash_core::types::NextStyle::Link);
    assert_eq!(spec.next.from.as_deref(), Some("next"));
    assert_eq!(spec.next.param.as_deref(), Some("next"));
    // The bound that keeps a page inside the response cap reaches the wire as
    // the parameter's own default.
    assert_eq!(
        svc.actions["search_stories"].params["page_size"].default,
        Some(json!(25))
    );
    // And `detail` is pinned to the small projection, not left to Shortcut's.
    assert_eq!(
        svc.actions["search_stories"].params["detail"].default,
        Some(json!("slim"))
    );

    // Epics page by ordinal instead — the paginated endpoint's own shape.
    let epics = svc.actions["list_epics"]
        .pagination
        .as_ref()
        .expect("list_epics pages");
    assert_eq!(epics.next.style, overslash_core::types::NextStyle::Page);
    assert_eq!(
        svc.actions["list_epics"].params["page"].default,
        Some(json!(1)),
        "the `page` style needs the origin the parameter declares"
    );
}

// ============================================================================
// Mock Shortcut
// ============================================================================

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    query: String,
    token: Option<String>,
    authorization: Option<String>,
    body: Value,
}

type SeenLog = Arc<Mutex<Vec<Seen>>>;

/// Answers the handful of endpoints these tests touch, and records every
/// request so the auth header can be asserted on rather than assumed.
async fn start_mock_shortcut() -> (SocketAddr, SeenLog) {
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
        let query = parts.uri.query().unwrap_or_default().to_string();
        let header = |name: &str| {
            parts
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        seen.lock().unwrap().push(Seen {
            method: parts.method.to_string(),
            path: path.clone(),
            query: query.clone(),
            token: header("shortcut-token"),
            authorization: header("authorization"),
            body,
        });

        let payload = if path == "/api/v3/search/stories" {
            // Page two is whatever carries `next=`; page one hands back the
            // URL shape Shortcut really sends — a path plus a query string,
            // not the bare token its `next` parameter takes.
            if query.contains("next=") {
                json!({
                    "total": 2,
                    "data": [{"id": 2, "name": "Second"}],
                    "next": null,
                })
            } else {
                json!({
                    "total": 2,
                    "data": [{"id": 1, "name": "First"}],
                    "next": "/api/v3/search/stories?query=state%3Astarted&page_size=25&detail=slim&next=a8acc65~24",
                })
            }
        } else if path == "/api/v3/stories" {
            json!({"id": 99, "name": "Fix login redirect", "app_url": "https://app.shortcut.com/x/story/99"})
        } else if path.starts_with("/api/v3/stories/") {
            json!({"id": 12345, "name": "Fix login redirect", "story_type": "bug"})
        } else if path == "/api/v3/projects" {
            json!([
                {"id": 77, "name": "Billing", "abbreviation": "BIL", "team_id": 500},
                // The one the story endpoints never mention, which is the
                // whole reason this action exists.
                {"id": 78, "name": "Empty", "abbreviation": "EMP", "team_id": 500},
            ])
        } else if path.starts_with("/api/v3/projects/") && path.ends_with("/stories") {
            json!([{"id": 12345, "name": "Fix login redirect"}])
        } else if path.starts_with("/api/v3/projects/") {
            json!({"id": 77, "name": "Billing", "abbreviation": "BIL"})
        } else if path == "/api/v3/workflows" {
            json!([{"id": 500, "name": "Engineering", "states": [{"id": 5001, "name": "Ready"}]}])
        } else {
            json!({"ok": true})
        };
        axum::Json(payload).into_response()
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

/// Boot the API on the shipped registry, seed the `shortcut_api_token` org
/// secret, and create an org-level `shortcut` instance pointed at the mock.
/// Returns `(base, client, agent_key, admin_key)`.
async fn setup(
    pool: sqlx::PgPool,
    mock: SocketAddr,
    access_level: &str,
) -> (String, reqwest::Client, String, String) {
    setup_auto_approving(pool, mock, access_level, "read").await
}

/// `setup`, with the auto-approve level spelled out. At `"write"` a story
/// write runs instead of bubbling, which is the only way to see the body the
/// gateway actually puts on the wire — an approval stops the call before the
/// upstream is touched.
async fn setup_auto_approving(
    pool: sqlx::PgPool,
    mock: SocketAddr,
    access_level: &str,
    auto_approve_level: &str,
) -> (String, reqwest::Client, String, String) {
    common::allow_loopback_ssrf();
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    let put = client
        .put(format!("{base}/v1/secrets/shortcut_api_token"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "value": "sc_test_token_123" }))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "secret put: {}", put.status());

    let everyone_id = common::everyone_group_id(&base, &client, &admin_key).await;
    let svc: Value = client
        .post(format!("{base}/v1/services"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "template_key": "shortcut",
            "name": "shortcut",
            "url": format!("http://{mock}"),
            "user_level": false,
            "groups": [{
                "group_id": everyone_id.to_string(),
                "access_level": access_level,
                "auto_approve_level": auto_approve_level,
            }],
            "status": "active",
            "credentials": { "token": "shortcut_api_token" },
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    svc["id"].as_str().expect("service create failed");

    (base, client, agent_key, admin_key)
}

async fn call(
    base: &str,
    client: &reqwest::Client,
    agent_key: &str,
    action: &str,
    params: Value,
) -> Value {
    client
        .post(format!("{base}/v1/actions/call"))
        .header(auth(agent_key).0, auth(agent_key).1)
        .json(&json!({ "service": "shortcut", "action": action, "params": params }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

// ============================================================================
// Auth
// ============================================================================

/// The workspace token goes out verbatim in `Shortcut-Token`. Not `Bearer`,
/// not a query parameter: Shortcut rejects both, and a template that got this
/// wrong would fail only against the real API.
#[tokio::test]
async fn the_api_token_is_injected_as_a_bare_shortcut_token_header() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_shortcut().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "read").await;

    let body = call(&base, &client, &agent_key, "list_workflows", json!({})).await;
    assert_eq!(body["status"], json!("called"), "{body}");

    let req = seen.lock().unwrap().last().cloned().expect("mock saw none");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/api/v3/workflows");
    assert_eq!(req.token.as_deref(), Some("sc_test_token_123"));
    assert!(
        req.authorization.is_none(),
        "the token must not also be sent as Authorization: {:?}",
        req.authorization
    );
    assert!(
        !req.query.contains("sc_test_token_123"),
        "the token must never reach the query string: {}",
        req.query
    );
}

// ============================================================================
// Pagination — the body-borne next URL, end to end
// ============================================================================

/// Shortcut's `next` is a URL path and query string; its `next` *parameter* is
/// a bare token. The marker has to carry the token, and carrying the URL would
/// send the upstream a page token that is really a URL.
#[tokio::test]
async fn search_stories_turns_the_body_next_url_into_a_ready_to_call_token() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_shortcut().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "read").await;

    let page_one = call(
        &base,
        &client,
        &agent_key,
        "search_stories",
        json!({ "query": "state:started" }),
    )
    .await;
    assert_eq!(page_one["status"], json!("called"), "{page_one}");

    let pagination = &page_one["result"]["_pagination"];
    assert_eq!(pagination["has_more"], json!(true), "{page_one}");
    assert_eq!(
        pagination["next"]["params"],
        json!({ "next": "a8acc65~24" }),
        "the marker carries the token lifted out of the URL, not the URL"
    );
    assert_eq!(pagination["next"]["service"], json!("shortcut"));
    assert_eq!(pagination["next"]["action"], json!("search_stories"));

    // The declared page size reached the wire without the caller naming it.
    let first = seen.lock().unwrap().last().cloned().unwrap();
    assert!(
        first.query.contains("page_size=25"),
        "page size not bounded: {}",
        first.query
    );
    assert!(
        first.query.contains("detail=slim"),
        "detail not pinned: {}",
        first.query
    );

    // Following the marker is one ordinary call, and it reaches the last page.
    let page_two = call(
        &base,
        &client,
        &agent_key,
        "search_stories",
        json!({ "query": "state:started", "next": "a8acc65~24" }),
    )
    .await;
    assert_eq!(
        page_two["result"]["_pagination"],
        json!({ "has_more": false }),
        "a null `next` is the last page: {page_two}"
    );
    let second = seen.lock().unwrap().last().cloned().unwrap();
    assert!(
        second.query.contains("next=a8acc65"),
        "the continuation did not reach the wire: {}",
        second.query
    );
}

// ============================================================================
// Writes and disclosure
// ============================================================================

/// A write with no grant raises an approval, and the approval has to say what
/// it is about: the story's own name, not only the numeric id, plus the text
/// the call would write.
#[tokio::test]
async fn updating_a_story_discloses_its_id_name_and_the_text_it_would_write() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_shortcut().await;
    // `admin` is the group ceiling, not a grant: Layer 1 admits the write so
    // that Layer 2 can raise the approval this test is about. At `read` the
    // call is denied outright and no disclosure is ever computed.
    let (base, client, agent_key, _admin_key) = setup(pool, mock, "admin").await;

    let body = call(
        &base,
        &client,
        &agent_key,
        "update_story",
        json!({
            "story_id": 12345,
            "description": "Users hit a redirect loop after SSO.",
        }),
    )
    .await;
    assert_eq!(
        body["status"],
        json!("pending_approval"),
        "an ungranted write must bubble: {body}"
    );

    let rendered = serde_json::to_string(&body["disclosed_fields"]).unwrap();
    assert!(
        rendered.contains("#12345"),
        "the disclosure must name the story id: {rendered}"
    );
    assert!(
        rendered.contains("Fix login redirect"),
        "the disclosure must resolve the id to the story's name: {rendered}"
    );
    assert!(
        rendered.contains("Users hit a redirect loop after SSO."),
        "the disclosure must carry the description being written: {rendered}"
    );

    // Nothing was written: the only request the mock saw is the resolver's
    // read of the story's name, and it carries no body.
    let requests = seen.lock().unwrap().clone();
    assert!(
        requests
            .iter()
            .all(|r| r.method == "GET" && r.body.is_null()),
        "a pending approval must not have reached the upstream: {requests:?}"
    );
}

/// jq's `//` yields its right-hand side for `false` as well as `null`, and a
/// filter that yields nothing drops the row — so `.body.archived // empty`
/// disclosed *nothing* for the one write a reviewer most needs to see. The
/// mirror image: `[]` is truthy, so clearing the owner set rendered an empty
/// row instead of no row.
#[tokio::test]
async fn a_disclosure_survives_the_falsy_half_of_every_field() {
    let pool = common::test_pool().await;
    let (mock, _seen) = start_mock_shortcut().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "admin").await;

    let body = call(
        &base,
        &client,
        &agent_key,
        "update_story",
        json!({
            "story_id": 12345,
            "archived": false,
            "epic_id": Value::Null,
            "owner_ids": [],
        }),
    )
    .await;
    assert_eq!(body["status"], json!("pending_approval"), "{body}");

    let fields = body["disclosed_fields"]
        .as_array()
        .cloned()
        .expect("inline disclosed_fields present");
    let labelled = |label: &str| -> Option<Value> {
        fields.iter().find(|f| f["label"] == json!(label)).cloned()
    };

    let archived = labelled("Archived").expect("un-archiving must be disclosed, not swallowed");
    assert!(
        serde_json::to_string(&archived).unwrap().contains("false"),
        "the Archived row must carry `false`: {archived}"
    );
    let epic = labelled("Epic").expect("unfiling from an epic must be disclosed");
    assert!(
        serde_json::to_string(&epic).unwrap().contains("none"),
        "a null epic_id must read as an unfile, not vanish: {epic}"
    );
    assert!(
        labelled("Owners").is_none(),
        "an empty owner set must omit the row, not render an empty one: {fields:?}"
    );
}

/// The bug this surface exists to fix: `update_story` could not say which
/// project a story belongs to, because the template never declared the field
/// — so the gateway rejected it as an unknown argument. Filing a story into a
/// project has to reach the wire, and has to be disclosed.
#[tokio::test]
async fn a_story_can_be_filed_into_a_project_and_the_move_is_disclosed() {
    let pool = common::test_pool().await;
    let (mock, _seen) = start_mock_shortcut().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "admin").await;

    let filed = call(
        &base,
        &client,
        &agent_key,
        "update_story",
        json!({ "story_id": 12345, "project_id": 77 }),
    )
    .await;
    assert_eq!(filed["status"], json!("pending_approval"), "{filed}");
    let rendered = serde_json::to_string(&filed["disclosed_fields"]).unwrap();
    assert!(
        rendered.contains("Project"),
        "filing a story into a project must be disclosed: {rendered}"
    );
    assert!(
        rendered.contains("77"),
        "the disclosure must name the project: {rendered}"
    );

    // And the unfile — `project_id: null` is a real change, which the `//`
    // form of the filter would have swallowed. Same reasoning as `epic_id`.
    let unfiled = call(
        &base,
        &client,
        &agent_key,
        "update_story",
        json!({ "story_id": 12345, "project_id": Value::Null }),
    )
    .await;
    let fields = unfiled["disclosed_fields"]
        .as_array()
        .cloned()
        .expect("inline disclosed_fields present");
    let project = fields
        .iter()
        .find(|f| f["label"] == json!("Project"))
        .expect("unfiling from a project must be disclosed");
    assert!(
        serde_json::to_string(project).unwrap().contains("none"),
        "a null project_id must read as an unfile, not vanish: {project}"
    );
}

/// The wire half of the same bug. A disclosure proves the gateway *parsed*
/// `project_id`; only the request the upstream receives proves it forwarded
/// it. Auto-approve the write so the call is not stopped at the approval.
#[tokio::test]
async fn project_id_reaches_the_upstream_on_both_story_writes() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_shortcut().await;
    let (base, client, agent_key, _admin) =
        setup_auto_approving(pool, mock, "admin", "write").await;

    let created = call(
        &base,
        &client,
        &agent_key,
        "create_story",
        json!({ "name": "Fix login redirect", "project_id": 77 }),
    )
    .await;
    assert_eq!(created["status"], json!("called"), "{created}");
    let post = seen
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|r| r.method == "POST" && r.path == "/api/v3/stories")
        .cloned()
        .expect("create_story must have reached the upstream");
    assert_eq!(
        post.body["project_id"],
        json!(77),
        "create_story dropped project_id: {}",
        post.body
    );

    let moved = call(
        &base,
        &client,
        &agent_key,
        "update_story",
        json!({ "story_id": 12345, "project_id": 77 }),
    )
    .await;
    assert_eq!(moved["status"], json!("called"), "{moved}");
    let put = seen
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|r| r.method == "PUT")
        .cloned()
        .expect("update_story must have reached the upstream");
    assert_eq!(
        put.body["project_id"],
        json!(77),
        "update_story dropped project_id: {}",
        put.body
    );

    // The unfile has to survive as a literal `null`, not be pruned out of the
    // body on its way through — `null` is what Shortcut reads as "unfile".
    call(
        &base,
        &client,
        &agent_key,
        "update_story",
        json!({ "story_id": 12345, "project_id": Value::Null }),
    )
    .await;
    let unfile = seen
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|r| r.method == "PUT")
        .cloned()
        .unwrap();
    assert!(
        unfile.body.get("project_id") == Some(&Value::Null),
        "a null project_id must reach the wire as null, not vanish: {}",
        unfile.body
    );
}

/// A project write is scoped to the project it names, exactly as a story
/// write is scoped to its story.
#[tokio::test]
async fn a_project_write_is_scoped_to_the_project_it_names() {
    let pool = common::test_pool().await;
    let (mock, _seen) = start_mock_shortcut().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "admin").await;

    let body = call(
        &base,
        &client,
        &agent_key,
        "delete_project",
        json!({ "project_id": 77 }),
    )
    .await;
    let rendered = serde_json::to_string(&body).unwrap();
    assert!(
        rendered.contains("shortcut:delete_project:project_id=77"),
        "expected a project-scoped permission key, got: {rendered}"
    );
    assert!(
        rendered.contains("Billing"),
        "the disclosure must resolve the project to its name: {rendered}"
    );
}

/// The permission key a story write mints is bound to that story, so approving
/// one is not approving every story.
#[tokio::test]
async fn a_story_write_is_scoped_to_the_story_it_names() {
    let pool = common::test_pool().await;
    let (mock, _seen) = start_mock_shortcut().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "admin").await;

    let body = call(
        &base,
        &client,
        &agent_key,
        "delete_story",
        json!({ "story_id": 12345 }),
    )
    .await;
    let rendered = serde_json::to_string(&body).unwrap();
    assert!(
        rendered.contains("shortcut:delete_story:story_id=12345"),
        "expected a story-scoped permission key, got: {rendered}"
    );
}

// ============================================================================
// Real workspace — `cargo test --test api -- shortcut::real --ignored`
// ============================================================================

/// Reads only: whoami, the workflow list, and one page of search. Needs
/// `SHORTCUT_TEST_API_TOKEN` from Settings → API Tokens.
#[tokio::test]
#[ignore = "needs SHORTCUT_TEST_API_TOKEN and a real Shortcut workspace"]
async fn real_shortcut_reads() {
    let Ok(token) = std::env::var("SHORTCUT_TEST_API_TOKEN") else {
        eprintln!("SHORTCUT_TEST_API_TOKEN unset — skipping");
        return;
    };
    let http = reqwest::Client::new();
    for path in [
        "/api/v3/member",
        "/api/v3/workflows",
        "/api/v3/search/stories?query=%21archived&page_size=2&detail=slim",
    ] {
        let resp = http
            .get(format!("https://api.app.shortcut.com{path}"))
            .header("Shortcut-Token", &token)
            .send()
            .await
            .expect("request");
        assert!(
            resp.status().is_success(),
            "{path}: {} — the template's host, path and auth header must match the live API",
            resp.status()
        );
    }
}
