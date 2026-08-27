//! #536 — one vocabulary for paging, over the many an upstream picks.
//!
//! `x-overslash-pagination` does two things, and this file proves both survive
//! the real pipeline rather than only the unit tests next to the code
//! (`services::pagination::tests` for the extraction, `openapi::compile::tests`
//! for the seeding):
//!
//!   1. A page size the upstream never bounded gets bounded, because the
//!      declaration seeds the parameter's own `default:` and
//!      `validate_input::apply_defaults` — which already existed — puts it on
//!      the wire.
//!   2. Every paged response carries the *same* `_pagination.next`, whether the
//!      upstream spells continuation `pageToken`, `offset` or a `Link` header.
//!
//! Built on D74. A uniform `next` over a render that eats cursors would be
//! worse than none, so `compact_pagination.rs` is the file underneath this one.

use crate::common;

use serde_json::{Value, json};

/// Stand up an org, a template with one paged action pointed at the fake, an
/// instance, and the grants a call needs. Returns `(base, agent_key, client)`.
///
/// The `pagination:` block is authored in its **unprefixed** form, which is how
/// a template author writes it and therefore the spelling worth exercising
/// end-to-end — the prefixed one is covered by a compile round-trip.
async fn setup(
    pool: sqlx::PgPool,
    key: &str,
    path: &str,
    pagination: &str,
) -> (String, String, reqwest::Client) {
    common::allow_loopback_ssrf();
    let mock = common::start_mock().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (org_id, ident_id, agent_key, admin_key) =
        common::bootstrap_org_identity(&base, &client).await;

    let openapi = format!(
        "openapi: 3.1.0\n\
         info:\n  title: Paged\n  key: {key}\n\
         servers:\n  - url: http://{mock}\n\
         paths:\n  {path}:\n    get:\n      operationId: list\n      \
         summary: List a page\n      risk: read\n{pagination}"
    );
    let resp = client
        .post(format!("{base}/v1/templates"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({ "openapi": openapi, "user_level": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "template rejected: {:?}",
        resp.text().await
    );

    client
        .post(format!("{base}/v1/permissions"))
        .header("Authorization", format!("Bearer {admin_key}"))
        .json(&json!({
            "identity_id": ident_id,
            "action_pattern": format!("{key}:**"),
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
            "name": key,
            "template_key": key,
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

    (base, agent_key, client)
}

async fn call(
    base: &str,
    client: &reqwest::Client,
    key: &str,
    service: &str,
    extra: Value,
) -> Value {
    let mut body = json!({"service": service, "action": "list", "verbose": false});
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

const CURSOR_YAML: &str = r#"      pagination:
        page_size:
          param: maxResults
          default: 10
          max: 25
        next:
          style: cursor
          param: pageToken
          from: nextPageToken
        items: items
      parameters:
        - name: maxResults
          in: query
          schema:
            type: integer
        - name: pageToken
          in: query
          schema:
            type: string
"#;

const OFFSET_YAML: &str = r#"      pagination:
        page_size:
          param: limit
          default: 10
        next:
          style: offset
          param: offset
        items: data
        has_more: has_more
      parameters:
        - name: limit
          in: query
          schema:
            type: integer
        - name: offset
          in: query
          schema:
            type: integer
"#;

const LINK_YAML: &str = r#"      pagination:
        page_size:
          param: per_page
          default: 10
          max: 25
        next:
          style: link
      parameters:
        - name: per_page
          in: query
          schema:
            type: integer
        - name: page
          in: query
          schema:
            type: integer
"#;

const PLAIN_YAML: &str = r#"      parameters:
        - name: maxResults
          in: query
          schema:
            type: integer
"#;

/// The headline case. The caller named no page size and no cursor; it gets a
/// bounded page and the exact arguments for the next one, spelled in the
/// action's own parameter names.
#[tokio::test]
async fn a_cursor_upstream_yields_a_ready_to_call_arg_map() {
    let pool = common::test_pool().await;
    let (base, key, client) = setup(pool, "pagecursor", "/paged/cursor", CURSOR_YAML).await;

    let body = call(&base, &client, &key, "pagecursor", json!({"params": {}})).await;
    let result = &body["result"];

    // The declared default reached the wire: the fake serves 25 rows total and
    // returned exactly one page of 10.
    assert_eq!(
        result["body"]["items"].as_array().map(Vec::len),
        Some(10),
        "an omitted page size should be injected from the declaration: {result}"
    );

    let next = &result["_pagination"]["next"];
    assert_eq!(result["_pagination"]["has_more"], json!(true), "{result}");
    assert_eq!(next["service"], json!("pagecursor"));
    assert_eq!(next["action"], json!("list"));
    assert_eq!(
        next["params"],
        json!({"pageToken": "tok-10", "maxResults": 10}),
        "the continuation is the upstream's spelling, ready to send back"
    );
}

/// Following `next` has to actually work, and the last page has to say it is
/// the last — otherwise an agent either stops early or loops forever.
#[tokio::test]
async fn following_next_walks_the_collection_and_stops() {
    let pool = common::test_pool().await;
    let (base, key, client) = setup(pool, "pagewalk", "/paged/cursor", CURSOR_YAML).await;

    let mut params = json!({});
    let mut seen = Vec::new();
    let mut pages = 0;
    loop {
        let body = call(&base, &client, &key, "pagewalk", json!({"params": params})).await;
        let result = &body["result"];
        for row in result["body"]["items"].as_array().unwrap() {
            seen.push(row["id"].as_str().unwrap().to_string());
        }
        pages += 1;
        assert!(pages < 10, "walk did not terminate: {result}");

        let pagination = &result["_pagination"];
        if pagination["has_more"] != json!(true) {
            assert!(pagination.get("next").is_none(), "{pagination}");
            break;
        }
        // Exactly what an agent does: merge the delta into what it sent.
        for (k, v) in pagination["next"]["params"].as_object().unwrap() {
            params[k] = v.clone();
        }
    }

    assert_eq!(pages, 3, "25 rows at 10 a page is three pages");
    assert_eq!(seen.len(), 25);
    let unique: std::collections::BTreeSet<_> = seen.iter().collect();
    assert_eq!(unique.len(), 25, "a page was repeated: {seen:?}");
}

/// The upstream sends no cursor at all — the caller advances a number, and an
/// explicit `has_more` says when to stop.
#[tokio::test]
async fn an_offset_upstream_advances_by_the_page_size() {
    let pool = common::test_pool().await;
    let (base, key, client) = setup(pool, "pageoffset", "/paged/offset", OFFSET_YAML).await;

    let body = call(
        &base,
        &client,
        &key,
        "pageoffset",
        json!({"params": {"limit": 20}}),
    )
    .await;
    let result = &body["result"];
    assert_eq!(result["body"]["data"].as_array().map(Vec::len), Some(20));
    assert_eq!(
        result["_pagination"]["next"]["params"],
        json!({"offset": 20, "limit": 20}),
        "{result}"
    );

    // Page two is underfull and the upstream says so.
    let body = call(
        &base,
        &client,
        &key,
        "pageoffset",
        json!({"params": {"limit": 20, "offset": 20}}),
    )
    .await;
    assert_eq!(
        body["result"]["_pagination"],
        json!({"has_more": false}),
        "{}",
        body["result"]
    );
}

/// The way forward is in a header, not the body — the case that was
/// unreachable over MCP at all until D74 stopped dropping `Link`.
#[tokio::test]
async fn a_link_upstream_is_read_from_the_header() {
    let pool = common::test_pool().await;
    let (base, key, client) = setup(pool, "pagelink", "/paged/link", LINK_YAML).await;

    let body = call(
        &base,
        &client,
        &key,
        "pagelink",
        json!({"params": {"page": 1}}),
    )
    .await;
    let result = &body["result"];
    assert_eq!(result["body"].as_array().map(Vec::len), Some(10));
    assert_eq!(
        result["_pagination"]["next"]["params"],
        json!({"page": 2}),
        "only the parameter that changed, and only one the action declares: {result}"
    );

    // Page three is the last: 25 rows at 10 a page, so no `rel="next"`.
    let body = call(
        &base,
        &client,
        &key,
        "pagelink",
        json!({"params": {"page": 3}}),
    )
    .await;
    assert_eq!(body["result"]["_pagination"], json!({"has_more": false}));
}

/// A jq filter narrows what the caller *receives*. It must not narrow what the
/// caller can *reach* — the continuation is read from the raw body, upstream of
/// both the filter and the compact render.
#[tokio::test]
async fn a_filter_that_projects_the_cursor_away_keeps_the_next_page() {
    let pool = common::test_pool().await;
    let (base, key, client) = setup(pool, "pagefilter", "/paged/cursor", CURSOR_YAML).await;

    let body = call(
        &base,
        &client,
        &key,
        "pagefilter",
        json!({"params": {}, "filter": {"lang": "jq", "expr": "[.items[] | .id]"}}),
    )
    .await;
    let result = &body["result"];
    assert_eq!(
        result["body"].as_array().map(Vec::len),
        Some(10),
        "the filter shaped the body: {result}"
    );
    assert_eq!(
        result["_pagination"]["next"]["params"]["pageToken"],
        json!("tok-10"),
        "the filter must not cost the caller the page: {result}"
    );
}

/// The marker is a property of the call, not of the render. A dashboard on the
/// REST API and an agent on MCP are looking at the same next page.
#[tokio::test]
async fn the_verbose_render_carries_the_same_marker() {
    let pool = common::test_pool().await;
    let (base, key, client) = setup(pool, "pageverbose", "/paged/cursor", CURSOR_YAML).await;

    let body = call(
        &base,
        &client,
        &key,
        "pageverbose",
        json!({"params": {}, "verbose": true}),
    )
    .await;
    assert_eq!(
        body["result"]["_pagination"]["next"]["params"]["pageToken"],
        json!("tok-10"),
        "{}",
        body["result"]
    );
}

/// D57 put an action's declared parameters on search rows. This adds the fact
/// a parameter name cannot carry: that following pages is possible at all.
#[tokio::test]
async fn search_rows_advertise_that_an_action_pages() {
    let pool = common::test_pool().await;
    let (base, key, client) = setup(pool, "pagesearch", "/paged/cursor", CURSOR_YAML).await;

    let rows: Value = client
        .get(format!("{base}/v1/search?q=list%20a%20page"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let row = rows["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["action"] == json!("list") && r["template"] == json!("pagesearch"))
        .unwrap_or_else(|| panic!("action row missing: {rows}"));

    assert_eq!(row["paginated"], json!(true), "{row}");
    // And the seeded bound is already visible beside it, because the extension
    // seeds the parameter's own default rather than inventing a second channel.
    let page_size = row["params"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == json!("maxResults"))
        .unwrap_or_else(|| panic!("maxResults missing: {row}"));
    assert_eq!(page_size["default"], json!(10), "{row}");
}

/// An action nobody has annotated must look exactly as it did before, on every
/// surface. The extension is opt-in, and most of the corpus has not opted in.
#[tokio::test]
async fn an_unannotated_action_gains_nothing() {
    let pool = common::test_pool().await;
    let (base, key, client) = setup(pool, "pageplain", "/paged/cursor", PLAIN_YAML).await;

    let body = call(&base, &client, &key, "pageplain", json!({"params": {}})).await;
    assert!(
        body["result"].get("_pagination").is_none(),
        "{}",
        body["result"]
    );

    let rows: Value = client
        .get(format!("{base}/v1/search?q=list%20a%20page"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = rows["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["action"] == json!("list") && r["template"] == json!("pageplain"))
        .unwrap_or_else(|| panic!("action row missing: {rows}"));
    assert!(row.get("paginated").is_none(), "{row}");
}
