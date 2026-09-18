//! Holded service template, end to end through the gateway against an in-test
//! mock Holded.
//!
//! Four things are worth proving here that a unit test cannot:
//!
//!   1. the shipped YAML compiles into the actions and risk classes it claims;
//!   2. the API token reaches the upstream as `Authorization: Bearer <token>`
//!      and nowhere else — Holded's deprecated v1 API took a bare `key:`
//!      header, so a template that confused the two would fail only against
//!      the live API;
//!   3. the uniform `{items, cursor, has_more}` envelope pages, and stops when
//!      `has_more` goes false;
//!   4. the writes that move money or leave the building disclose what they
//!      are about, including the fields whose *absence* is the dangerous case.
//!
//! The real-account test at the bottom is `#[ignore]`d and needs
//! `HOLDED_TEST_API_KEY` (Settings → Developers → Credentials). It only reads:
//! the account behind that key is somebody's books.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::{Router, extract::State, response::IntoResponse, routing::any};
use serde_json::{Value, json};

use crate::common::{self, auth, bootstrap_org_identity, start_api_with_registry};

// ============================================================================
// Parse smoke test
// ============================================================================

#[test]
fn holded_yaml_parses() {
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
    let svc = reg.get("holded").expect("holded should be registered");

    assert_eq!(svc.display_name, "Holded");
    assert_eq!(svc.hosts, vec!["api.holded.com".to_string()]);

    // The curated surface, spelled out so that dropping one is a test failure
    // rather than a silently smaller service.
    for action in [
        "get_usage",
        "list_contacts",
        "get_contact",
        "search_contacts",
        "create_contact",
        "update_contact",
        "list_funnels",
        "list_leads",
        "create_lead",
        "update_lead_stage",
        "list_invoices",
        "get_invoice",
        "find_invoices_by_number",
        "get_invoice_pdf",
        "create_invoice",
        "approve_invoice",
        "send_invoice",
        "create_invoice_payment",
        "cancel_invoice",
        "list_credit_notes",
        "create_credit_note",
        "list_estimates",
        "create_estimate",
        "convert_document",
        "list_products",
        "list_purchases",
        "get_purchase",
        "create_purchase",
        "list_payments",
        "list_banking_accounts",
        "list_bank_movements",
        "list_ledger_entries",
        "list_payment_methods",
        "list_taxes",
        "list_expenses_accounts",
        "list_accounting_accounts",
    ] {
        assert!(
            svc.actions.contains_key(action),
            "holded.yaml should declare {action}"
        );
    }
    assert_eq!(svc.actions.len(), 36, "the curated set is 36 actions");

    // Nothing here deletes. A fiscal document is cancelled or corrected with a
    // credit note; Holded's delete and bulk-delete endpoints are deliberately
    // not modelled, and this is the assertion that keeps them out.
    let deleting: Vec<&String> = svc
        .actions
        .iter()
        .filter(|(_, a)| matches!(a.risk.display_risk(), overslash_core::types::Risk::Delete))
        .map(|(k, _)| k)
        .collect();
    assert!(
        deleting.is_empty(),
        "no Holded action should be delete-class: {deleting:?}"
    );

    // `get_usage` is the credential probe, and validation already holds it to
    // being read-class. Assert it is *this* action, since which endpoint the
    // "Check it works" button hits is a product decision, not an accident.
    let probe = svc
        .test_action()
        .expect("holded declares a credential probe");
    assert_eq!(probe.0, "get_usage");
}

/// Every pageable list shares one block, because Holded answers every one of
/// them with the same `{items, cursor, has_more}` envelope. Three settings
/// lists take no cursor at all and are in the allow-list of
/// `shipped_list_actions_declare_pagination` instead.
#[test]
fn every_pageable_list_declares_the_same_cursor_block() {
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
    let svc = reg.get("holded").unwrap();

    let unpaged = [
        "list_taxes",
        "list_expenses_accounts",
        "list_accounting_accounts",
    ];
    let mut paged = 0;
    for (key, action) in &svc.actions {
        if unpaged.contains(&key.as_str()) {
            assert!(
                action.pagination.is_none(),
                "{key} has no upstream cursor, so it must declare no pagination"
            );
            continue;
        }
        let Some(p) = action.pagination.as_ref() else {
            continue;
        };
        paged += 1;
        let size = p.page_size.as_ref().expect("a page size");
        assert_eq!(size.param, "limit", "{key}");
        assert_eq!(size.max, Some(200), "{key}: Holded's documented ceiling");
        assert_eq!(p.items.as_deref(), Some("items"), "{key}");
        assert_eq!(p.has_more.as_deref(), Some("has_more"), "{key}");
    }
    assert_eq!(paged, 15, "fifteen lists page");
}

// ============================================================================
// Mock Holded
// ============================================================================

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    query: String,
    authorization: Option<String>,
    key_header: Option<String>,
    body: Value,
}

type SeenLog = Arc<Mutex<Vec<Seen>>>;

/// Answers the handful of endpoints these tests touch, in Holded's own
/// envelope, and records every request so the auth header can be asserted on
/// rather than assumed.
async fn start_mock_holded() -> (SocketAddr, SeenLog) {
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
            authorization: header("authorization"),
            // Holded's deprecated v1 API took the key in a bare `key` header.
            // Recorded so the test can prove we send the v2 bearer and not it.
            key_header: header("key"),
            body,
        });

        let payload = if path == "/api/v2/usage" {
            json!({ "period": "2026-09", "count": 412, "limit": 100000 })
        } else if path == "/api/v2/contacts" {
            // Two pages, so a traversal has somewhere to go and somewhere to
            // stop. `cursor` is null on the last page, exactly as Holded types
            // it.
            if query.contains("cursor=") {
                json!({
                    "items": [{ "id": "c2", "name": "Beta S.L." }],
                    "cursor": null,
                    "has_more": false,
                })
            } else {
                json!({
                    "items": [{ "id": "c1", "name": "Acme S.L." }],
                    "cursor": "eyJvIjoyNX0",
                    "has_more": true,
                })
            }
        } else if path.starts_with("/api/v2/contacts/") {
            json!({ "id": "6410a1b2c3d4e5f600000001", "name": "Acme S.L.", "code": "B12345678" })
        } else if path.starts_with("/api/v2/invoices/") && path.ends_with("/pdf") {
            json!({ "ok": true })
        } else if path.starts_with("/api/v2/invoices/") && parts.method == "GET" {
            json!({ "id": "6410a1b2c3d4e5f600000002", "document_number": "F-2026-0042" })
        } else if path == "/api/v2/taxes" {
            json!({ "items": [{ "id": "t1", "name": "IVA 21%" }] })
        } else {
            json!({ "ok": true })
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

/// Boot the API on the shipped registry, seed the `holded_api_key` org secret,
/// and create an org-level `holded` instance pointed at the mock.
async fn setup(
    pool: sqlx::PgPool,
    mock: SocketAddr,
    access_level: &str,
) -> (String, reqwest::Client, String, String) {
    common::allow_loopback_ssrf();
    let (base, client) = start_api_with_registry(pool, None).await;
    let (_org_id, _ident_id, agent_key, admin_key) = bootstrap_org_identity(&base, &client).await;

    let put = client
        .put(format!("{base}/v1/secrets/holded_api_key"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "value": "hld_test_token_123" }))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "secret put: {}", put.status());

    let everyone_id = common::everyone_group_id(&base, &client, &admin_key).await;
    let svc: Value = client
        .post(format!("{base}/v1/services"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "template_key": "holded",
            "name": "holded",
            "url": format!("http://{mock}"),
            "user_level": false,
            "groups": [{
                "group_id": everyone_id.to_string(),
                "access_level": access_level,
                "auto_approve_reads": true,
            }],
            "status": "active",
            "credentials": { "token": "holded_api_key" },
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
        .json(&json!({ "service": "holded", "action": action, "params": params }))
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

/// The token goes out as `Authorization: Bearer <token>`. Holded's v1 API took
/// a bare `key:` header instead, and it is still reachable — so a template that
/// carried the old shape would authenticate against a deprecated surface, or
/// against nothing at all.
#[tokio::test]
async fn the_api_token_is_injected_as_a_bearer_and_nowhere_else() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_holded().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "read").await;

    let body = call(&base, &client, &agent_key, "get_usage", json!({})).await;
    assert_eq!(body["status"], json!("called"), "{body}");

    let req = seen.lock().unwrap().last().cloned().expect("mock saw none");
    assert_eq!(req.method, "GET");
    assert_eq!(req.path, "/api/v2/usage");
    assert_eq!(
        req.authorization.as_deref(),
        Some("Bearer hld_test_token_123")
    );
    assert!(
        req.key_header.is_none(),
        "the v1 `key` header must not be sent: {:?}",
        req.key_header
    );
    assert!(
        !req.query.contains("hld_test_token_123"),
        "the token must never reach the query string: {}",
        req.query
    );
}

// ============================================================================
// Pagination
// ============================================================================

/// Every Holded list answers `{items, cursor, has_more}`, so one block covers
/// the lot. This walks it: page one offers a marker, page two is the last.
#[tokio::test]
async fn a_contact_list_walks_the_cursor_and_stops_when_has_more_goes_false() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_holded().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "read").await;

    let page_one = call(&base, &client, &agent_key, "list_contacts", json!({})).await;
    assert_eq!(page_one["status"], json!("called"), "{page_one}");

    let pagination = &page_one["result"]["_pagination"];
    assert_eq!(pagination["has_more"], json!(true), "{page_one}");
    // The marker carries the opaque cursor Holded handed back, and the page
    // size the call was actually made with — so following it keeps the same
    // bound rather than silently reverting to the upstream's own default.
    assert_eq!(
        pagination["next"]["params"],
        json!({ "cursor": "eyJvIjoyNX0", "limit": 50 }),
    );
    assert_eq!(pagination["next"]["service"], json!("holded"));
    assert_eq!(pagination["next"]["action"], json!("list_contacts"));

    // The declared page size reached the wire without the caller naming it.
    let first = seen.lock().unwrap().last().cloned().unwrap();
    assert!(
        first.query.contains("limit=50"),
        "page size not bounded: {}",
        first.query
    );

    let page_two = call(
        &base,
        &client,
        &agent_key,
        "list_contacts",
        json!({ "cursor": "eyJvIjoyNX0" }),
    )
    .await;
    assert_eq!(
        page_two["result"]["_pagination"],
        json!({ "has_more": false }),
        "`has_more: false` is the last page: {page_two}"
    );
    let second = seen.lock().unwrap().last().cloned().unwrap();
    assert!(
        second.query.contains("cursor=eyJvIjoyNX0"),
        "the continuation did not reach the wire: {}",
        second.query
    );
}

/// A settings list has no cursor upstream, so the gateway must offer no
/// continuation for it rather than inventing one.
#[tokio::test]
async fn a_settings_list_offers_no_continuation() {
    let pool = common::test_pool().await;
    let (mock, _seen) = start_mock_holded().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "read").await;

    let body = call(&base, &client, &agent_key, "list_taxes", json!({})).await;
    assert_eq!(body["status"], json!("called"), "{body}");
    assert!(
        body["result"]["_pagination"].is_null(),
        "list_taxes cannot page and must not pretend to: {body}"
    );
}

// ============================================================================
// Writes and disclosure
// ============================================================================

/// Sending an invoice leaves the account and reaches a third party, so the
/// approval has to carry every address that gets it — and the invoice's own
/// document number, not just an opaque id.
#[tokio::test]
async fn sending_an_invoice_discloses_the_document_and_every_recipient() {
    let pool = common::test_pool().await;
    let (mock, seen) = start_mock_holded().await;
    // `admin` is the group ceiling, not a grant: Layer 1 admits the write so
    // that Layer 2 can raise the approval this test is about.
    let (base, client, agent_key, _admin) = setup(pool, mock, "admin").await;

    let body = call(
        &base,
        &client,
        &agent_key,
        "send_invoice",
        json!({
            "invoiceId": "6410a1b2c3d4e5f600000002",
            "emails": ["finance@acme.example"],
            "bcc": ["archive@ours.example"],
            "subject": "Invoice F-2026-0042",
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
        rendered.contains("F-2026-0042"),
        "the disclosure must resolve the id to the document number: {rendered}"
    );
    assert!(
        rendered.contains("finance@acme.example"),
        "the disclosure must name the recipient: {rendered}"
    );
    assert!(
        rendered.contains("archive@ours.example"),
        "a bcc is still someone receiving the invoice: {rendered}"
    );

    // Nothing was sent: the only request the mock saw is the resolver's read.
    let requests = seen.lock().unwrap().clone();
    assert!(
        requests
            .iter()
            .all(|r| r.method == "GET" && r.body.is_null()),
        "a pending approval must not have reached the upstream: {requests:?}"
    );
}

/// `create_invoice_payment` has no required body fields at all, and an omitted
/// amount or treasury account is the most consequential thing a reviewer could
/// be shown. `// empty` would have rendered both as nothing.
#[tokio::test]
async fn recording_a_payment_discloses_the_fields_that_were_left_out() {
    let pool = common::test_pool().await;
    let (mock, _seen) = start_mock_holded().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "admin").await;

    let body = call(
        &base,
        &client,
        &agent_key,
        "create_invoice_payment",
        json!({ "invoiceId": "6410a1b2c3d4e5f600000002" }),
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

    let amount = labelled("Amount").expect("an unspecified amount must still be disclosed");
    assert!(
        serde_json::to_string(&amount)
            .unwrap()
            .contains("not specified"),
        "an omitted amount must say so, not vanish: {amount}"
    );
    let treasury =
        labelled("Treasury account").expect("an unspecified treasury account must be disclosed");
    assert!(
        serde_json::to_string(&treasury)
            .unwrap()
            .contains("default"),
        "an omitted treasury account books to the account default, and must say so: {treasury}"
    );
}

/// Approving an invoice has no body at all — the resolved document number and
/// a statement of what approval does are the whole review.
#[tokio::test]
async fn approving_an_invoice_discloses_what_approval_does() {
    let pool = common::test_pool().await;
    let (mock, _seen) = start_mock_holded().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "admin").await;

    let body = call(
        &base,
        &client,
        &agent_key,
        "approve_invoice",
        json!({ "invoiceId": "6410a1b2c3d4e5f600000002" }),
    )
    .await;
    assert_eq!(body["status"], json!("pending_approval"), "{body}");

    let rendered = serde_json::to_string(&body["disclosed_fields"]).unwrap();
    assert!(
        rendered.contains("F-2026-0042"),
        "the disclosure must resolve the invoice: {rendered}"
    );
    assert!(
        rendered.contains("credit note"),
        "a reviewer must be told approval is only correctable by credit note: {rendered}"
    );
}

/// The permission key an invoice write mints is bound to that invoice, so
/// approving one is not approving every invoice on the account.
#[tokio::test]
async fn an_invoice_write_is_scoped_to_the_invoice_it_names() {
    let pool = common::test_pool().await;
    let (mock, _seen) = start_mock_holded().await;
    let (base, client, agent_key, _admin) = setup(pool, mock, "admin").await;

    let body = call(
        &base,
        &client,
        &agent_key,
        "cancel_invoice",
        json!({ "invoiceId": "6410a1b2c3d4e5f600000002" }),
    )
    .await;
    let rendered = serde_json::to_string(&body).unwrap();
    assert!(
        rendered.contains("holded:cancel_invoice:invoiceId=6410a1b2c3d4e5f600000002"),
        "expected an invoice-scoped permission key, got: {rendered}"
    );
}

// ============================================================================
// Real account — `cargo test --test api -- holded::real --ignored`
// ============================================================================

/// Reads only, and deliberately so: the account behind a real key is somebody's
/// books. Proves the host, the paths and the auth header match the live API.
/// Needs `HOLDED_TEST_API_KEY` from Settings → Developers → Credentials.
#[tokio::test]
#[ignore = "needs HOLDED_TEST_API_KEY and a real Holded account"]
async fn real_holded_reads() {
    let Ok(token) = std::env::var("HOLDED_TEST_API_KEY") else {
        eprintln!("HOLDED_TEST_API_KEY unset — skipping");
        return;
    };
    let http = reqwest::Client::new();
    for path in [
        "/api/v2/usage",
        "/api/v2/contacts?limit=1",
        "/api/v2/invoices?limit=1",
        "/api/v2/taxes",
    ] {
        let resp = http
            .get(format!("https://api.holded.com{path}"))
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .await
            .expect("request");
        assert!(
            resp.status().is_success(),
            "{path}: {} — the template's host, path and auth header must match \
             the live API. A 403 here means the token lacks the module scope \
             that action's description names.",
            resp.status()
        );
    }
}
