//! #537 — compact mode must not eat the means to fetch the next page.
//!
//! Compact is the *default* on MCP, so this is the response shape agents
//! actually see, and it used to lose a cursor two different ways: it dropped
//! every response header (killing RFC 8288 `Link: rel="next"`), and its
//! object-key cap kept the *alphabetically* first 20 keys, because
//! `serde_json` is built without `preserve_order` and `Value::Object` is
//! therefore a `BTreeMap`. `nextPageToken` lost to anything spelled `a`–`m`.
//!
//! The mechanics are unit-tested next to the code, in
//! `services::compact_response::tests`. What this file proves is that the fix
//! survives the whole pipeline — a real `POST /v1/actions/call`, and the real
//! MCP `tools/call` frame with no `verbose` argument at all, which is the path
//! the field reports came in on.
//!
//! Prerequisite for #536: a uniform `next` sitting on top of a pipeline that
//! eats the cursor would be worse than no `next`, because the agent would
//! trust it.

use crate::common;

use std::net::SocketAddr;

use axum::{Router, response::IntoResponse, routing::get};
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// The cursor the paged mock hands back. Distinctive enough that a partial
/// match in an assertion means what it says.
const CURSOR: &str = "CURSOR-page-2";

/// A mock that paginates the way real APIs do: a `Link` header carrying
/// `rel="next"`, a `nextPageToken` in the body, and enough sibling metadata
/// to blow the 8 KB compact budget — all of it spelled so it sorts *before*
/// both `nextPageToken` and `rows`, which is precisely how the old cap lost
/// them.
async fn start_paged_mock() -> SocketAddr {
    fn paged_body() -> String {
        let mut obj = serde_json::Map::new();
        for i in 0..30 {
            obj.insert(format!("field_{i:02}"), json!("v".repeat(400)));
        }
        obj.insert("nextPageToken".into(), json!(CURSOR));
        obj.insert(
            "rows".into(),
            json!((0..5).map(|i| json!({"id": i})).collect::<Vec<_>>()),
        );
        serde_json::to_string(&Value::Object(obj)).unwrap()
    }

    async fn paged() -> impl IntoResponse {
        (
            [
                ("content-type", "application/json"),
                (
                    "link",
                    "<https://api.example.com/paged?page=2>; rel=\"next\", \
                     <https://api.example.com/paged?page=9>; rel=\"last\"",
                ),
                // Not pagination, and must still be dropped: the fix is an
                // allow-list, not a surrender of the compact shape.
                ("x-request-id", "req-abc123"),
            ],
            paged_body(),
        )
    }

    /// Two *separate* `Link` field lines, which RFC 8288 allows. Collecting
    /// them into a `HashMap` used to keep only the last, so `rel="next"` could
    /// be lost one layer before the compact render ever saw it.
    async fn paged_twice() -> axum::response::Response {
        let mut resp = axum::response::Response::new(axum::body::Body::from(r#"{"ok":true}"#));
        let h = resp.headers_mut();
        h.insert("content-type", "application/json".parse().unwrap());
        h.append("link", "<https://x.test/1>; rel=\"prev\"".parse().unwrap());
        h.append("link", "<https://x.test/2>; rel=\"next\"".parse().unwrap());
        resp
    }

    let app = Router::new()
        .route("/paged", get(paged))
        .route("/paged-twice", get(paged_twice));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Raw-HTTP (Mode A) call against the mock — no template, no instance.
async fn call(
    base: &str,
    client: &reqwest::Client,
    key: &str,
    mock: SocketAddr,
    path: &str,
    extra: Value,
) -> Value {
    let mut body = json!({
        "service": "http",
        "method": "GET",
        "url": format!("http://{mock}{path}"),
    });
    let obj = body.as_object_mut().unwrap();
    for (k, v) in extra.as_object().unwrap() {
        obj.insert(k.clone(), v.clone());
    }
    let resp = client
        .post(format!("{base}/v1/actions/call"))
        .header("Authorization", format!("Bearer {key}"))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let text = resp.text().await.unwrap();
    assert_eq!(status, 200, "call failed: {text}");
    serde_json::from_str(&text).unwrap()
}

async fn setup(
    pool: sqlx::PgPool,
    fx: &common::BootstrapFixtures,
) -> (String, String, reqwest::Client, SocketAddr) {
    common::allow_loopback_ssrf();
    let mock = start_paged_mock().await;
    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");
    let (_u, _i, key) = common::bootstrap_agent_on_fixtures(&base, &client, fx).await;
    (base, key, client, mock)
}

/// The headline. An agent on the compact shape can now see where page two is.
#[tokio::test]
async fn link_header_reaches_a_compact_caller() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, client, mock) = setup(pool, &fx).await;

    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/paged",
        json!({"verbose": false}),
    )
    .await;
    let result = &body["result"];

    let link = result["headers"]["link"]
        .as_str()
        .unwrap_or_else(|| panic!("no link header in the compact render: {result}"));
    assert!(link.contains("rel=\"next\""), "{link}");
    assert!(link.contains("page=2"), "{link}");
}

/// The allow-list is an allow-list: everything that isn't pagination still
/// goes, because the whole point of the compact shape is to be small.
#[tokio::test]
async fn non_pagination_headers_are_still_dropped() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, client, mock) = setup(pool, &fx).await;

    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/paged",
        json!({"verbose": false}),
    )
    .await;
    let headers = &body["result"]["headers"];

    assert!(headers.get("x-request-id").is_none(), "{headers}");
    assert!(headers.get("content-type").is_none(), "{headers}");
}

/// Bug 2 over the wire: thirty `field_NN` keys all sort before
/// `nextPageToken`, and the old cap kept the alphabetically first twenty.
#[tokio::test]
async fn next_page_token_survives_the_compact_crop() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, client, mock) = setup(pool, &fx).await;

    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/paged",
        json!({"verbose": false}),
    )
    .await;
    let result = &body["result"];

    assert!(
        result["_truncated"].is_object(),
        "the payload must actually have been cropped, or this proves nothing: {result}"
    );
    assert_eq!(
        result["body"]["nextPageToken"], CURSOR,
        "the cursor did not survive the crop: {}",
        result["body"]
    );
}

/// The other half: `field_*` sorts before `rows`, which is the same mechanism
/// behind "the truncator spends its budget on metadata before it reaches the
/// rows". Ranking by shape puts the collection ahead of the scalars.
#[tokio::test]
async fn rows_survive_alphabetically_earlier_metadata() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, client, mock) = setup(pool, &fx).await;

    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/paged",
        json!({"verbose": false}),
    )
    .await;

    let rows = body["result"]["body"]["rows"]
        .as_array()
        .unwrap_or_else(|| panic!("rows lost to metadata: {}", body["result"]["body"]));
    assert_eq!(rows.len(), 5);
}

/// Verbose mode is untouched: every header, raw body string, no marker.
#[tokio::test]
async fn verbose_true_still_returns_every_header() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, client, mock) = setup(pool, &fx).await;

    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/paged",
        json!({"verbose": true}),
    )
    .await;
    let result = &body["result"];

    assert!(result["headers"]["x-request-id"].is_string(), "{result}");
    assert!(result["headers"]["link"].is_string(), "{result}");
    assert!(
        result["body"].is_string(),
        "verbose keeps the raw body string"
    );
    assert!(result.get("_truncated").is_none(), "{result}");
}

/// `Link` legally repeats. Collecting the header map used to keep only the
/// last field line, so an upstream that split `prev` and `next` across two
/// lines lost one of them before compact was ever reached.
#[tokio::test]
async fn repeated_link_headers_are_combined_not_lost() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, client, mock) = setup(pool, &fx).await;

    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/paged-twice",
        json!({"verbose": false}),
    )
    .await;

    let link = body["result"]["headers"]["link"]
        .as_str()
        .unwrap_or_else(|| panic!("no link header: {}", body["result"]));
    assert!(link.contains("rel=\"prev\""), "{link}");
    assert!(link.contains("rel=\"next\""), "{link}");
}

/// The real default path. MCP has no Mode A — both call tools require
/// `service` + `action` — so this needs a template, and it deliberately passes
/// **no** `verbose` argument: `dispatch.rs` defaults it to `false`, which is
/// exactly the render the field reports arrived on.
#[tokio::test]
async fn the_mcp_default_render_carries_the_cursor() {
    common::allow_loopback_ssrf();
    let pool = common::test_pool().await;
    let mock = start_paged_mock().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let openapi = format!(
        "openapi: 3.1.0\n\
         info:\n  title: Paged\n  key: pagedsvc\n\
         servers:\n  - url: http://{mock}\n\
         paths:\n  /paged:\n    get:\n      operationId: list\n      \
         summary: List a page\n      risk: read\n"
    );
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "openapi": openapi, "user_level": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "template: {:?}", resp.text().await);

    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "identity_id": ident_id,
            "action_pattern": "pagedsvc:**",
            "effect": "allow",
        }))
        .send()
        .await
        .unwrap();

    // The group ceiling gates services independently of permission rules, and
    // attaches to the owner user rather than the calling agent.
    let owner_id = common::owner_user_id(&pool, org_id).await;
    let groups: Value = client
        .get(format!("{base}/v1/groups"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let admins = groups
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["name"] == "Admins")
        .expect("Admins group")["id"]
        .as_str()
        .unwrap()
        .to_string();
    client
        .post(format!("{base}/v1/groups/{admins}/members"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "identity_id": owner_id }))
        .send()
        .await
        .unwrap();

    let inst: Value = client
        .post(format!("{base}/v1/services"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "name": "pagedsvc",
            "template_key": "pagedsvc",
            "url": format!("http://{mock}"),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let inst_id = inst["id"]
        .as_str()
        .unwrap_or_else(|| panic!("instance create failed: {inst}"))
        .to_string();
    client
        .post(format!("{base}/v1/groups/{admins}/grants"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "service_instance_id": inst_id, "access_level": "write" }))
        .send()
        .await
        .unwrap();

    let frame: Value = client
        .post(format!("{base}/mcp"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "overslash_read",
                "arguments": { "service": "pagedsvc", "action": "list", "params": {} }
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let rendered = frame.to_string();
    assert!(
        rendered.contains(CURSOR),
        "the MCP default render lost the cursor: {rendered}"
    );
    assert!(
        rendered.contains("rel="),
        "the MCP default render lost the Link header: {rendered}"
    );
}
