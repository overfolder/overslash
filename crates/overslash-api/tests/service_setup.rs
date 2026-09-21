//! Integration tests for service setup links and the credential probe.
//!
//! Three surfaces, one story: `POST /v1/services` mints a setup link for a
//! secret-backed template, the public setup page renders it, submitting the
//! value binds the instance's credential slot, and
//! `POST /v1/services/{id}/test` then proves the credential works.

#![allow(clippy::disallowed_methods)]

use crate::common;

use reqwest::Client;
use serde_json::{Value, json};
use uuid::Uuid;

/// Boot the API against the shipped registry with `resend`'s host pointed at
/// a fake, so the probe reaches something that answers.
///
/// The override carries its scheme (`http://…`): `effective_base` uses a host
/// containing `://` verbatim and otherwise prefixes `https://`, which a
/// loopback fake does not speak.
async fn setup_with_upstream(upstream: String) -> (String, Client, common::BootstrapFixtures) {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api_with_registry(pool, Some(("resend", upstream))).await;
    (base, client, fx)
}

async fn create_service(base: &str, client: &Client, key: &str, body: Value) -> Value {
    client
        .post(format!("{base}/v1/services"))
        .header(common::auth(key).0, common::auth(key).1)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn parse_setup_url(url: &str) -> (String, String) {
    let parsed = url::Url::parse(url).expect("setup_url parses");
    let token = parsed
        .query_pairs()
        .find(|(k, _)| k == "token")
        .map(|(_, v)| v.to_string())
        .expect("setup_url carries a token");
    let req_id = parsed
        .path_segments()
        .and_then(|mut s| s.next_back())
        .expect("setup_url has a path")
        .to_string();
    assert!(
        parsed.path().contains("/services/setup/"),
        "a service-bound request must point at the setup page, got {}",
        parsed.path()
    );
    (req_id, token)
}

/// Boot with the `oversla.sh` shortener configured, so `short_url` is the
/// difference between "this path shortens" and "nobody configured a shortener".
async fn setup_with_shortener(upstream: String) -> (String, Client, common::BootstrapFixtures) {
    let shortener = common::start_shortener_stub().await;
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, client) =
        common::start_api_with_registry_customized(pool, Some(("resend", upstream)), move |cfg| {
            cfg.oversla_sh_base_url = Some(shortener);
            cfg.oversla_sh_api_key = Some("stub-key".into());
        })
        .await;
    (base, client, fx)
}

// ── Auto-mint ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn creating_a_secret_service_mints_a_setup_link() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-auto", "user_level": true}),
    )
    .await;
    assert_eq!(svc["name"], "resend-auto", "create failed: {svc}");

    let setup = &svc["setup"];
    assert!(!setup.is_null(), "no setup bundle on {svc}");
    let requests = setup["requests"].as_array().unwrap();
    assert_eq!(requests.len(), 1, "resend declares one instance slot");
    assert_eq!(requests[0]["credential_key"], "token");
    assert_eq!(requests[0]["secret_name"], "resend_key");
    assert_eq!(setup["setup_url"], requests[0]["setup_url"]);
    parse_setup_url(setup["setup_url"].as_str().unwrap());

    // The probe is advertised on the instance so the dashboard knows to offer
    // a Test button without fetching the template.
    assert_eq!(svc["test_action"]["action"], "list_domains");
}

/// The link is handed to a person, usually through a chat message, so the
/// shortened form is the one that matters — and it has to be on the entry as
/// well as on the bundle, because a multi-slot template hands over one link
/// per entry and the bundle's scalar only covers the first.
#[tokio::test]
async fn a_setup_link_is_shortened() {
    let mock = common::start_mock().await;
    let (base, client, fx) =
        setup_with_shortener(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": format!("resend-short-{}", Uuid::new_v4().simple()),
               "user_level": true}),
    )
    .await;
    let setup = &svc["setup"];
    assert!(!setup.is_null(), "no setup bundle on {svc}");
    assert_eq!(setup["short_url"], common::STUB_SHORT_URL, "{setup}");
    assert_eq!(
        setup["requests"][0]["short_url"],
        common::STUB_SHORT_URL,
        "every entry carries its own short form, not just the bundle: {setup}"
    );
    // The long form is always there to fall back on.
    assert!(
        setup["requests"][0]["setup_url"]
            .as_str()
            .is_some_and(|u| u.contains("/services/setup/")),
        "{setup}"
    );
}

/// Over MCP the bundle carries one URL per link, already shortened.
///
/// `create_service` reaches an agent through `routes::mcp::forward`, which
/// collapses every canonical/short pair (#627) so the agent is never handed
/// two URLs and made to pick. The setup bundle is a pair at two depths — the
/// bundle scalar and each `requests[]` entry — so this drives the real
/// `/mcp` endpoint rather than asserting over `collapse_link_pairs` alone:
/// the unit test proves the walk, this proves the bundle actually reaches it.
#[tokio::test]
async fn the_setup_bundle_is_collapsed_for_mcp_callers() {
    let mock = common::start_mock().await;
    let (base, client, fx) =
        setup_with_shortener(format!("http://127.0.0.1:{}", mock.port())).await;
    let (_user, _ident, agent_key) = common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    // `manage_services_own` is seeded for a first-level agent (D79), but grant
    // it explicitly so this asserts the collapse rather than the org default.
    let grant = client
        .post(format!("{base}/v1/permissions"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({
            "identity_id": _ident,
            "action_pattern": "overslash:manage_services_own:*",
            "effect": "allow"
        }))
        .send()
        .await
        .unwrap();
    assert!(grant.status().is_success(), "grant: {}", grant.status());

    let frame: Value = client
        .post(format!("{base}/mcp"))
        .header("Authorization", format!("Bearer {agent_key}"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "overslash_call",
                "arguments": {
                    "service": "overslash",
                    "action": "create_service",
                    "params": {
                        "template_key": "resend",
                        "name": format!("resend-mcp-short-{}", Uuid::new_v4().simple()),
                        "user_level": true
                    }
                }
            }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let text = frame["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no tool text: {frame}"));
    let call: Value = serde_json::from_str(text).unwrap();
    assert_eq!(call["status"], "called", "{call}");
    // Compact (the MCP default), deliberately: it parses `body` into an
    // object, which is what lets the collapse walk reach inside it. Under
    // `verbose: true` the body is a raw JSON *string* and opaque to the walk
    // — true of every pair, not just this one, and the shape a caller asking
    // for verbose has asked for.
    let inner = &call["result"]["body"];

    let setup = &inner["setup"];
    assert!(!setup.is_null(), "no setup bundle: {inner}");
    assert_eq!(setup["setup_url"], common::STUB_SHORT_URL, "{setup}");
    assert!(
        setup.get("short_url").is_none(),
        "the pair is collapsed, not duplicated: {setup}"
    );
    assert_eq!(
        setup["requests"][0]["setup_url"],
        common::STUB_SHORT_URL,
        "each entry collapses too, not just the bundle scalar: {setup}"
    );
    assert!(setup["requests"][0].get("short_url").is_none(), "{setup}");
}

/// Binding the slot at create time is the caller saying "I have this covered".
#[tokio::test]
async fn a_bound_slot_mints_no_setup_link() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-bound",
               "secret_name": "resend_key", "user_level": true}),
    )
    .await;
    assert_eq!(svc["name"], "resend-bound", "create failed: {svc}");
    assert!(svc["setup"].is_null(), "unexpected setup bundle on {svc}");
}

#[tokio::test]
async fn skip_credentials_suppresses_the_setup_link() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-skip",
               "skip_credentials": true, "user_level": true}),
    )
    .await;
    assert_eq!(svc["name"], "resend-skip", "create failed: {svc}");
    assert!(svc["setup"].is_null(), "unexpected setup bundle on {svc}");
}

/// An org-level instance is owned by nobody, so the mint has no identity to
/// store the secret under and the bundle is suppressed. This is why the search
/// setup hint names a `request_secret` fallback rather than promising a
/// `setup_url` unconditionally.
#[tokio::test]
async fn an_org_level_service_gets_no_setup_link() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let groups: Value = client
        .get(format!("{base}/v1/groups"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let everyone = groups
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["name"] == "Everyone")
        .expect("Everyone group");

    // Note: no `skip_credentials`. That flag would suppress the bundle on its
    // own and confound what this asserts.
    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend",
               "name": format!("resend-orglevel-{}", Uuid::new_v4().simple()),
               "user_level": false,
               "groups": [{"group_id": everyone["id"], "access_level": "write"}]}),
    )
    .await;
    assert!(svc["id"].is_string(), "org-level create failed: {svc}");
    assert!(
        svc["owner_identity_id"].is_null(),
        "an org-level instance is owned by nobody: {svc}"
    );
    assert!(svc["setup"].is_null(), "unexpected setup bundle on {svc}");
}

/// An OAuth template gets the `connect` bundle it always got, and no `setup`
/// one — the two paths are twins, not alternatives that can both fire.
#[tokio::test]
async fn an_oauth_template_gets_connect_not_setup() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "google_calendar", "name": "gcal-auto", "user_level": true}),
    )
    .await;
    assert_eq!(svc["name"], "gcal-auto", "create failed: {svc}");
    assert!(
        svc["setup"].is_null(),
        "an OAuth template has no per-instance secret slot to ask for: {svc}"
    );
}

// ── The public setup page ─────────────────────────────────────────────────

#[tokio::test]
async fn the_setup_page_renders_the_service_and_binds_on_submit() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-flow", "user_level": true}),
    )
    .await;
    let service_id = svc["id"].as_str().unwrap().to_string();
    let (req_id, token) = parse_setup_url(svc["setup"]["setup_url"].as_str().unwrap());

    // GET is public — no API key.
    let resp = client
        .get(format!(
            "{base}/public/services/setup/{req_id}?token={}",
            urlencoding::encode(&token)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let meta: Value = resp.json().await.unwrap();
    assert_eq!(meta["secret_name"], "resend_key", "flattened provide half");
    assert!(
        meta["org_name"].as_str().is_some_and(|n| !n.is_empty()),
        "the page names the org it is asking on behalf of: {meta}"
    );
    assert_eq!(meta["service"]["id"], service_id);
    assert_eq!(meta["service"]["display_name"], "Resend");
    assert_eq!(meta["service"]["slot"]["key"], "token");
    assert_eq!(meta["service"]["slot"]["bound"], false);
    assert_eq!(meta["service"]["test_action"]["action"], "list_domains");

    // A setup request always requires a session, whatever the org's
    // `allow_unsigned_secret_provide` says: fulfilment is what triggers the
    // probe, and the probe needs an identity to evaluate a chain against.
    assert_eq!(
        meta["require_user_session"], true,
        "the page must know before the visitor types a secret: {meta}"
    );

    // Submit through the provide endpoint — the setup page has no write path
    // of its own, deliberately.
    let resp = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .header("cookie", common::session_cookie(fx.org_id, fx.user_ids[0]))
        .json(&json!({"token": token, "value": "re_test_key"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let submit: Value = resp.json().await.unwrap();
    assert_eq!(submit["name"], "resend_key");
    assert_eq!(submit["service"]["id"], service_id);
    assert_eq!(submit["service"]["credential_key"], "token");
    assert_eq!(
        submit["service"]["remaining_slots"]
            .as_array()
            .unwrap()
            .len(),
        0,
        "the only slot was just filled"
    );

    // Every credential is present — and that is a different claim from
    // callable. The probe runs from the page, after this response, so the
    // instance is still gated here. A page reading `remaining_slots: []` alone
    // would announce it live one round trip early.
    assert_eq!(submit["service"]["status"], "pending_setup");

    // Bound, and reporting itself credentialled — but `?include_inactive`,
    // because a gated instance does not resolve by name.
    let detail: Value = client
        .get(format!(
            "{base}/v1/services/resend-flow?include_inactive=true"
        ))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["credentials"]["token"], "resend_key");
    assert_eq!(detail["credentials_status"], "ok");
    assert_eq!(
        detail["status"], "pending_setup",
        "`credentials_status: ok` says a credential is bound, not that it works: {detail}"
    );
}

/// An anonymous submit is refused, and refused *before* the single-use row is
/// burned — otherwise a visitor who signs in and retries would meet a `410`
/// over a link that was never spent.
#[tokio::test]
async fn an_anonymous_setup_submit_is_refused() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-anon", "user_level": true}),
    )
    .await;
    let (req_id, token) = parse_setup_url(svc["setup"]["setup_url"].as_str().unwrap());

    let resp = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .json(&json!({"token": token, "value": "re_anon"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body.to_string().contains("user_session_required"),
        "the page branches on this code to render its sign-in banner: {body}"
    );

    // The capability survives the refusal: signing in and retrying works.
    let resp = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .header("cookie", common::session_cookie(fx.org_id, fx.user_ids[0]))
        .json(&json!({"token": token, "value": "re_anon"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "the refused submit must not burn the row"
    );
}

/// The other half of the pair: a *bare* secret request still honours the org's
/// policy. The floor is on setup requests specifically, not on the endpoint.
#[tokio::test]
async fn a_bare_secret_request_still_allows_an_anonymous_submit() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let req: Value = client
        .post(format!("{base}/v1/secrets/requests"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"secret_name": "loose_key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Not `parse_setup_url`: a request that names no service correctly lands
    // on the older, service-less page, which that helper asserts against.
    let parsed = url::Url::parse(req["url"].as_str().unwrap()).unwrap();
    assert!(parsed.path().contains("/secrets/provide/"), "{parsed}");
    let token = parsed
        .query_pairs()
        .find(|(k, _)| k == "token")
        .map(|(_, v)| v.to_string())
        .unwrap();
    let req_id = parsed.path_segments().unwrap().next_back().unwrap();

    let resp = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .json(&json!({"token": token, "value": "loose"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "no service to gate on, so the org's `allow_unsigned` setting still rules"
    );
}

#[tokio::test]
async fn a_second_submit_is_gone() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-once", "user_level": true}),
    )
    .await;
    let (req_id, token) = parse_setup_url(svc["setup"]["setup_url"].as_str().unwrap());

    let cookie = common::session_cookie(fx.org_id, fx.user_ids[0]);
    for (n, expected) in [(1, 200), (2, 410)] {
        let resp = client
            .post(format!("{base}/public/secrets/provide/{req_id}"))
            .header("cookie", cookie.clone())
            .json(&json!({"token": token, "value": format!("re_{n}")}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), expected, "submit #{n}");
    }
}

/// The setup page is for setup requests. A bare secret request rendered there
/// would be a service-shaped page around no service.
#[tokio::test]
async fn a_bare_secret_request_is_not_a_setup_page() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let req: Value = client
        .post(format!("{base}/v1/secrets/requests"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"secret_name": "loose_key"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let req_id = req["id"].as_str().unwrap();
    let token = req["token"].as_str().unwrap();
    assert!(
        req["url"].as_str().unwrap().contains("/secrets/provide/"),
        "a service-less request keeps the bare provide page: {req}"
    );

    let resp = client
        .get(format!(
            "{base}/public/services/setup/{req_id}?token={}",
            urlencoding::encode(token)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// `credential_key` naming something the template does not declare must fail
/// at mint — fulfilment trusts the row and re-derives nothing.
#[tokio::test]
async fn an_unknown_credential_key_is_rejected_at_mint() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-badkey",
               "skip_credentials": true, "user_level": true}),
    )
    .await;

    let resp = client
        .post(format!("{base}/v1/secrets/requests"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({
            "secret_name": "resend_key",
            "service_id": svc["id"],
            "credential_key": "not_a_slot"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body.to_string().contains("not_a_slot"),
        "the error must name the bad key: {body}"
    );
}

/// A user-tier template resolves through the *instance owner*, not whoever is
/// minting. An agent minting for its owner-user's instance is the flow this
/// surface exists for, and resolving as the caller would miss the owner's
/// user-tier template entirely — "template not found" on the happy path.
#[tokio::test]
async fn a_user_tier_template_resolves_through_the_instance_owner() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    // User-tier templates are off by default at the org level.
    let policy = client
        .patch(format!("{base}/v1/orgs/{}/template-settings", fx.org_id))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"user_template_policy": "full"}))
        .send()
        .await
        .unwrap();
    assert_eq!(policy.status(), 200, "enable user templates");

    // A user-tier template owned by write-user, with one instance slot.
    let key = format!("acme_private_{}", Uuid::new_v4().simple());
    let openapi = format!(
        "openapi: 3.1.0\n\
         info:\n\
        \x20 title: Acme Private\n\
        \x20 key: {key}\n\
         servers:\n\
        \x20 - url: https://api.acme.test\n\
         components:\n\
        \x20 securitySchemes:\n\
        \x20   token:\n\
        \x20     type: apiKey\n\
        \x20     in: header\n\
        \x20     name: Authorization\n\
        \x20     default_secret_name: acme_private_key\n\
         paths:\n\
        \x20 /ping:\n\
        \x20   get:\n\
        \x20     operationId: ping\n\
        \x20     summary: Ping the service\n\
        \x20     risk: read\n"
    );
    let tpl = client
        .post(format!("{base}/v1/templates"))
        .header(common::auth(&fx.write_key).0, common::auth(&fx.write_key).1)
        .json(&json!({"openapi": openapi, "user_level": true}))
        .send()
        .await
        .unwrap();
    let tpl_status = tpl.status();
    assert!(
        tpl_status.is_success(),
        "user-tier template create: {tpl_status} {}",
        tpl.text().await.unwrap_or_default()
    );

    let svc = create_service(
        &base,
        &client,
        &fx.write_key,
        json!({"template_key": key,
               "name": format!("acme-private-{}", Uuid::new_v4().simple()),
               "skip_credentials": true, "user_level": true}),
    )
    .await;
    assert!(svc["id"].is_string(), "create failed: {svc}");

    // An admin minting for someone else's instance must resolve the *owner's*
    // user tier, not their own — resolving as the caller 404s here.
    let resp = client
        .post(format!("{base}/v1/secrets/requests"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"secret_name": "acme_private_key", "service_id": svc["id"]}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        status, 200,
        "admin mint over an owner's user-tier template: {body}"
    );
    assert_eq!(body["credential_key"], "token", "{body}");
}

/// A minted setup link is a live capability to *write* an instance's
/// credential binding, so minting one has to be gated on managing that
/// instance — not merely on being in its org. `get_service_instance` filters
/// by tenant alone, which is what makes this the security boundary rather
/// than a formality.
///
/// `NotFound`, not `Forbidden`: a caller with no reach on the row should not
/// be able to probe which instance ids exist in the org.
#[tokio::test]
async fn a_stranger_cannot_mint_a_setup_link_for_someone_elses_service() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    // Owned by admin-user.
    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-private",
               "skip_credentials": true, "user_level": true}),
    )
    .await;

    // write-user is in the same org, holds write access, and owns nothing here.
    let resp = client
        .post(format!("{base}/v1/secrets/requests"))
        .header(common::auth(&fx.write_key).0, common::auth(&fx.write_key).1)
        .json(&json!({"secret_name": "resend_key", "service_id": svc["id"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "a stranger must not mint a binding link"
    );
}

/// An org-level instance is owned by nobody, so it matches no ceiling and
/// always requires admin — the same conclusion the update kernel reaches.
#[tokio::test]
async fn a_non_admin_cannot_mint_a_setup_link_for_an_org_level_service() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let groups: Value = client
        .get(format!("{base}/v1/groups"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let everyone = groups
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["name"] == "Everyone")
        .expect("Everyone group");

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": format!("resend-org-{}", Uuid::new_v4().simple()),
               "skip_credentials": true, "user_level": false,
               "groups": [{"group_id": everyone["id"], "access_level": "write"}]}),
    )
    .await;
    assert!(svc["id"].is_string(), "org-level create failed: {svc}");

    let resp = client
        .post(format!("{base}/v1/secrets/requests"))
        .header(common::auth(&fx.write_key).0, common::auth(&fx.write_key).1)
        .json(&json!({"secret_name": "resend_key", "service_id": svc["id"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// An OAuth template has no per-instance secret slot, so there is nothing to
/// name — refuse rather than invent a binding.
#[tokio::test]
async fn a_template_with_no_instance_slot_is_rejected_at_mint() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "google_calendar", "name": "gcal-noslot", "user_level": true}),
    )
    .await;

    let resp = client
        .post(format!("{base}/v1/secrets/requests"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"secret_name": "anything", "service_id": svc["id"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.unwrap();
    assert!(
        body.to_string().contains("no per-instance credential slot"),
        "the error must say why: {body}"
    );
}

/// An instance id from another tenant reads as absent, never as a slot
/// inventory.
#[tokio::test]
async fn a_cross_tenant_service_id_is_not_found() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let resp = client
        .post(format!("{base}/v1/secrets/requests"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"secret_name": "resend_key", "service_id": Uuid::new_v4()}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ── The credential probe ──────────────────────────────────────────────────

async fn run_probe(base: &str, client: &Client, key: &str, service_id: &str) -> (u16, Value) {
    let resp = client
        .post(format!("{base}/v1/services/{service_id}/test"))
        .header(common::auth(key).0, common::auth(key).1)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap())
}

#[tokio::test]
async fn the_probe_runs_the_templates_declared_action() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-probe",
               "secret_name": "resend_key", "user_level": true}),
    )
    .await;
    let service_id = svc["id"].as_str().unwrap();

    // The slot needs a value before the call can resolve one.
    let put = client
        .put(format!("{base}/v1/secrets/resend_key"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"value": "re_live_key"}))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "seed secret: {}", put.status());

    let (status, verdict) = run_probe(&base, &client, &fx.admin_key, service_id).await;
    assert_eq!(status, 200, "probe: {verdict}");
    assert_eq!(verdict["status"], "ok", "{verdict}");
    assert_eq!(verdict["action"], "list_domains");
    assert!(verdict["latency_ms"].is_number());
    // The verdict answers "do these credentials work", nothing more — the
    // upstream body is deliberately not echoed back.
    assert!(verdict.get("body").is_none(), "{verdict}");
    assert!(verdict.get("result").is_none(), "{verdict}");
}

/// No credential at all is a verdict, not a 500.
#[tokio::test]
async fn the_probe_reports_a_missing_credential() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-nocred",
               "skip_credentials": true, "user_level": true}),
    )
    .await;
    let (status, verdict) =
        run_probe(&base, &client, &fx.admin_key, svc["id"].as_str().unwrap()).await;
    assert_eq!(status, 200, "probe: {verdict}");
    assert_ne!(verdict["status"], "ok", "{verdict}");
}

/// A template with no `x-overslash-test` says so rather than 404ing, so the
/// dashboard can render the same page either way.
#[tokio::test]
async fn a_template_without_a_probe_is_not_supported() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "deepwiki", "name": "deepwiki-probe", "user_level": true}),
    )
    .await;
    assert_eq!(svc["name"], "deepwiki-probe", "create failed: {svc}");
    assert!(
        svc["test_action"].is_null(),
        "deepwiki declares no probe: {svc}"
    );

    let (status, verdict) =
        run_probe(&base, &client, &fx.admin_key, svc["id"].as_str().unwrap()).await;
    assert_eq!(status, 200, "probe: {verdict}");
    assert_eq!(verdict["status"], "not_supported");
}

/// The arm that keeps a gateway error from masquerading as one: an upstream
/// that cannot be reached is the service being broken, not Overslash, so the
/// probe answers `failed` rather than propagating a 502.
#[tokio::test]
async fn an_unreachable_upstream_is_a_verdict_not_a_gateway_error() {
    // A port nothing is listening on. Bound and dropped so the OS has handed
    // it out at least once and is unlikely to reissue it mid-test.
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{dead}")).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-dead",
               "secret_name": "resend_key", "user_level": true}),
    )
    .await;
    let put = client
        .put(format!("{base}/v1/secrets/resend_key"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"value": "re_live_key"}))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "seed secret: {}", put.status());

    let (status, verdict) =
        run_probe(&base, &client, &fx.admin_key, svc["id"].as_str().unwrap()).await;
    assert_eq!(status, 200, "a 502 here would blame the gateway: {verdict}");
    assert_eq!(verdict["status"], "failed", "{verdict}");
    assert!(
        verdict["error"]
            .as_str()
            .unwrap_or_default()
            .contains("service"),
        "the error must name the service, not the gateway: {verdict}"
    );
}

#[tokio::test]
async fn probing_an_unknown_instance_is_not_found() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let (status, _) = run_probe(&base, &client, &fx.admin_key, &Uuid::new_v4().to_string()).await;
    assert_eq!(status, 404);
}

// ── Secret-name collisions ────────────────────────────────────────────────
//
// A slot's vault name comes from the template's `default_secret_name` and
// mixes in nothing per-instance, so two instances of one template point at one
// secret. Before these tests the second setup link silently stored a new
// version over the first instance's credential, and the first anybody heard of
// it was a 401 on a real call.

/// Stand up `resend` and fulfil its link, leaving `resend_key` occupied.
///
/// The submit carries a session because a *setup* request is always minted
/// `require_user_session` (D-NEXT): fulfilling one triggers the instance's
/// credential probe, and the probe runs as somebody.
async fn seed_bound_resend(
    base: &str,
    client: &Client,
    fx: &common::BootstrapFixtures,
    name: &str,
) -> Value {
    let svc = create_service(
        base,
        client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": name, "user_level": true}),
    )
    .await;
    let (req_id, token) = parse_setup_url(svc["setup"]["setup_url"].as_str().unwrap());
    let resp = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .header("cookie", common::session_cookie(fx.org_id, fx.user_ids[0]))
        .json(&json!({"token": token, "value": "re_first_key"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "seed fulfilment failed");
    svc
}

#[tokio::test]
async fn a_second_instance_refuses_to_claim_the_first_ones_secret() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;
    seed_bound_resend(&base, &client, &fx, "resend-one").await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"template_key": "resend", "name": "resend-two", "user_level": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "a taken vault name must refuse");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "secret_name_conflict", "{body}");
    assert_eq!(body["conflicts"][0]["secret_name"], "resend_key", "{body}");
    assert_eq!(body["conflicts"][0]["credential_key"], "token", "{body}");
    assert_eq!(body["conflicts"][0]["current_version"], 1, "{body}");
    // The hint has to carry its own instructions: an agent hitting this is not
    // holding the docs, and the bind escape is the one usually meant.
    let hint = body["hint"].as_str().unwrap_or_default();
    assert!(hint.contains("credentials"), "{body}");
    assert!(hint.contains("force"), "{body}");

    // Nothing was written: the refusal happens before the instance row.
    let listed: Value = client
        .get(format!("{base}/v1/services"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let names: Vec<&str> = listed
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["name"].as_str())
        .collect();
    assert!(
        !names.contains(&"resend-two"),
        "a refused create must leave no orphan instance: {names:?}"
    );
}

/// The escape that overwrites nothing, and the one people usually want.
#[tokio::test]
async fn binding_the_existing_secret_is_allowed_and_mints_no_link() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;
    seed_bound_resend(&base, &client, &fx, "resend-one").await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({
            "template_key": "resend",
            "name": "resend-shared",
            "user_level": true,
            "credentials": {"token": "resend_key"}
        }),
    )
    .await;
    assert_eq!(svc["name"], "resend-shared", "create failed: {svc}");
    assert_eq!(svc["credentials"]["token"], "resend_key");
    assert!(
        svc["setup"].is_null(),
        "a bound slot needs no link, and minting one would reintroduce the \
         overwrite this whole check exists to stop: {svc}"
    );
    // Sharing means sharing: the instance is callable immediately.
    assert_eq!(svc["credentials_status"], "ok", "{svc}");
}

#[tokio::test]
async fn force_mints_the_link_and_says_what_it_will_replace() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;
    seed_bound_resend(&base, &client, &fx, "resend-one").await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({
            "template_key": "resend",
            "name": "resend-rotate",
            "user_level": true,
            "force": true
        }),
    )
    .await;
    assert_eq!(svc["name"], "resend-rotate", "create failed: {svc}");
    let setup = &svc["setup"];
    assert!(!setup.is_null(), "force must still mint: {svc}");
    let warnings = setup["warnings"].as_array().expect("warnings present");
    assert_eq!(warnings.len(), 1, "{setup}");
    assert_eq!(warnings[0]["code"], "overwrites_existing_secret");
    assert_eq!(warnings[0]["secret_name"], "resend_key");
    assert_eq!(
        warnings[0]["current_version"], 1,
        "the warning names the version being superseded: {setup}"
    );
}

/// The ordinary path must stay quiet. A `warnings` key on every create would
/// train callers to ignore it.
#[tokio::test]
async fn an_uncontested_create_carries_no_warnings() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-clean", "user_level": true}),
    )
    .await;
    assert!(
        svc["setup"]["warnings"].is_null(),
        "empty warnings must not serialize: {svc}"
    );
}

/// `force` is about the *vault name*, not the instance name — the two failures
/// are different and must stay different.
#[tokio::test]
async fn force_does_not_override_a_taken_instance_name() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;
    seed_bound_resend(&base, &client, &fx, "resend-one").await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({
            "template_key": "resend",
            "name": "resend-one",
            "user_level": true,
            "force": true
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    assert_ne!(
        body["error"], "secret_name_conflict",
        "an instance-name clash is a plain conflict, not a secret one: {body}"
    );
}

/// The public page is the last place the truth is available before the write,
/// and it is reached long after the mint-time check ran.
#[tokio::test]
async fn the_setup_page_warns_when_the_name_is_already_taken() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    // Mint first, while the name is still free — so the page, not the mint, is
    // what catches it.
    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-race", "user_level": true}),
    )
    .await;
    let (req_id, token) = parse_setup_url(svc["setup"]["setup_url"].as_str().unwrap());

    let meta: Value = client
        .get(format!(
            "{base}/public/services/setup/{req_id}?token={}",
            urlencoding::encode(&token)
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        meta["overwrites_version"].is_null(),
        "nothing to overwrite yet: {meta}"
    );

    // Someone fills the name in the meantime.
    let put = client
        .put(format!("{base}/v1/secrets/resend_key"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"value": "re_someone_elses_key"}))
        .send()
        .await
        .unwrap();
    assert!(put.status().is_success(), "seed put: {}", put.status());

    let meta: Value = client
        .get(format!(
            "{base}/public/services/setup/{req_id}?token={}",
            urlencoding::encode(&token)
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        meta["overwrites_version"], 1,
        "the page must name the version it is about to replace: {meta}"
    );
}

// ── Instance-name collisions ──────────────────────────────────────────────

/// Renaming onto a taken name used to fall through to `AppError::Database`
/// and reach the caller as a 500 "database error".
#[tokio::test]
async fn renaming_onto_a_taken_name_is_a_conflict_not_a_server_error() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;
    seed_bound_resend(&base, &client, &fx, "resend-one").await;

    let second = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({
            "template_key": "resend",
            "name": "resend-two",
            "user_level": true,
            "credentials": {"token": "resend_key"}
        }),
    )
    .await;
    let id = second["id"].as_str().unwrap();

    let resp = client
        .put(format!("{base}/v1/services/{id}/manage"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"name": "resend-one"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "not a 500");
    let body: Value = resp.json().await.unwrap();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("resend-one"),
        "the message names the contested name: {body}"
    );
}

/// Neither unique index has a status predicate, so an archived instance keeps
/// its name — while the default service list hides it. Being told a name is
/// taken by something invisible is the papercut; the message has to say so.
#[tokio::test]
async fn an_archived_instance_still_holding_a_name_says_so() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;
    let first = seed_bound_resend(&base, &client, &fx, "resend-one").await;
    let id = first["id"].as_str().unwrap();

    let arch = client
        .patch(format!("{base}/v1/services/{id}/status"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"status": "archived"}))
        .send()
        .await
        .unwrap();
    assert!(arch.status().is_success(), "archive: {}", arch.status());

    let resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({
            "template_key": "resend",
            "name": "resend-one",
            "user_level": true,
            "credentials": {"token": "resend_key"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    let msg = body["error"].as_str().unwrap_or_default();
    assert!(msg.contains("archived"), "must name the real cause: {body}");
    assert!(msg.contains(id), "must name the row holding it: {body}");
}

/// The hint has to name a fix the caller can actually apply.
///
/// `request_secret` and `POST /v1/secrets/requests` take no `credentials` map,
/// so pointing a bound request at `credentials: {slot: name}` would describe a
/// field its own body does not have. Keyed on the surface, not on whether a
/// slot happens to be named — a bound request has both.
#[tokio::test]
async fn a_bound_request_is_pointed_at_update_service_not_credentials() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;
    let first = seed_bound_resend(&base, &client, &fx, "resend-one").await;
    let service_id = first["id"].as_str().unwrap();

    let resp = client
        .post(format!("{base}/v1/secrets/requests"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({
            "secret_name": "resend_key",
            "service_id": service_id,
            "ttl_seconds": 3600
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "secret_name_conflict", "{body}");
    let hint = body["hint"].as_str().unwrap_or_default();
    assert!(
        hint.contains("update_service") && hint.contains(service_id),
        "the bind escape must name the call and the instance: {body}"
    );
    assert!(
        hint.contains("force"),
        "and still offer the replace path: {body}"
    );
    // No stray whitespace runs: these hints are prose assembled from
    // `\`-continued literals, and a lost escape is invisible to `contains`.
    assert!(!hint.contains("  "), "hint has a run of spaces: {hint:?}");
}

/// The create surface keeps the `credentials` wording, because there it is a
/// real field on the request body.
#[tokio::test]
async fn the_create_hint_names_the_credentials_map() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;
    seed_bound_resend(&base, &client, &fx, "resend-one").await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"template_key": "resend", "name": "resend-two", "user_level": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let body: Value = resp.json().await.unwrap();
    let hint = body["hint"].as_str().unwrap_or_default();
    assert!(
        hint.contains(r#"credentials: {"token": "resend_key"}"#),
        "{body}"
    );
    assert!(!hint.contains("update_service"), "{body}");
    assert!(!hint.contains("  "), "hint has a run of spaces: {hint:?}");
}

// ── Draft until verified ──────────────────────────────────────────────────

async fn activate(
    base: &str,
    client: &Client,
    key: &str,
    service_id: &str,
    force: bool,
) -> (u16, Value) {
    let q = if force { "?force=true" } else { "" };
    let resp = client
        .post(format!("{base}/v1/services/{service_id}/activate{q}"))
        .header(common::auth(key).0, common::auth(key).1)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap())
}

async fn get_service(base: &str, client: &Client, key: &str, name: &str) -> (u16, Value) {
    let resp = client
        .get(format!("{base}/v1/services/{name}?include_inactive=true"))
        .header(common::auth(key).0, common::auth(key).1)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap())
}

/// The gate's default rule: a probe to run, and a credential nobody has
/// supplied — so a link is about to be minted and a human will run it.
#[tokio::test]
async fn an_unbound_secret_service_is_created_pending_setup() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-gated", "user_level": true}),
    )
    .await;
    assert_eq!(svc["status"], "pending_setup", "{svc}");
    assert!(
        svc["setup"]["setup_url"].as_str().is_some(),
        "gated exactly because a link was minted: {svc}"
    );
}

/// The escape hatch an agent needs. Nothing in this flow can produce a
/// verdict — no link, no page — and the agent could not lift the gate itself,
/// so gating would strand the instance until the sweeper ate it.
#[tokio::test]
async fn a_bound_credential_and_skip_credentials_both_create_live() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let bound = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-bound",
               "secret_name": "resend_key", "user_level": true}),
    )
    .await;
    assert_eq!(bound["status"], "active", "{bound}");

    let skipped = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-skipped",
               "skip_credentials": true, "user_level": true}),
    )
    .await;
    assert_eq!(skipped["status"], "active", "{skipped}");
}

/// `verify` asks for a guarantee. On a template with no probe there is none to
/// give, and answering "fine, it's live" is how a dashboard ends up reporting
/// a service checked that nothing ever checked.
#[tokio::test]
async fn verify_true_on_a_probeless_template_is_rejected() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let resp = client
        .post(format!("{base}/v1/services"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(
            &json!({"template_key": "deepwiki", "name": "dw", "user_level": true,
                      "verify": true}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "{:?}", resp.text().await);
}

/// The whole point of the status: a gated instance is not reachable by the
/// name an agent would call it by, and does not appear in the search results
/// an agent discovers it through.
#[tokio::test]
async fn a_pending_setup_service_is_neither_callable_nor_discoverable() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-hidden", "user_level": true}),
    )
    .await;

    // `include_inactive` still finds it — the reopen surfaces depend on that.
    let (status, detail) = get_service(&base, &client, &fx.admin_key, "resend-hidden").await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(detail["status"], "pending_setup", "{detail}");

    // By name, without `include_inactive`: not found.
    let resp = client
        .get(format!("{base}/v1/services/resend-hidden"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "a gated instance does not resolve by name"
    );

    // And search does not offer it, because it is not callable.
    let results: Value = client
        .get(format!("{base}/v1/search?q=resend&include_catalog=true"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let body = results.to_string();
    assert!(
        !body.contains("resend-hidden"),
        "a gated instance is not a search result: {results}"
    );
    // …but the catalog row must not tell the agent to create *another* one.
    // The second `create_service` collides on the name index, which knows
    // nothing about lifecycle status.
    assert!(
        body.contains("awaiting setup") || body.contains("do not create"),
        "the row has to say an instance already exists: {results}"
    );
}

/// The happy path, end to end: gated on create, green on probe, live after.
#[tokio::test]
async fn a_green_probe_activates_the_instance() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-green", "user_level": true}),
    )
    .await;
    let service_id = svc["id"].as_str().unwrap().to_string();
    assert_eq!(svc["status"], "pending_setup");

    let (req_id, token) = parse_setup_url(svc["setup"]["setup_url"].as_str().unwrap());
    let resp = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .header("cookie", common::session_cookie(fx.org_id, fx.user_ids[0]))
        .json(&json!({"token": token, "value": "re_live_key"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let (status, body) = activate(&base, &client, &fx.admin_key, &service_id, false).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["verdict"]["status"], "ok", "{body}");
    assert_eq!(body["status"], "active", "{body}");

    // Now it resolves by the name an agent calls it by.
    let resp = client
        .get(format!("{base}/v1/services/resend-green"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

/// A red verdict is an answer, not an error: `200`, the verdict rendered, and
/// the instance left exactly where it was.
#[tokio::test]
async fn a_red_probe_leaves_the_instance_gated() {
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{dead}")).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-red", "user_level": true}),
    )
    .await;
    let service_id = svc["id"].as_str().unwrap().to_string();
    let (req_id, token) = parse_setup_url(svc["setup"]["setup_url"].as_str().unwrap());
    client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .header("cookie", common::session_cookie(fx.org_id, fx.user_ids[0]))
        .json(&json!({"token": token, "value": "re_bad_key"}))
        .send()
        .await
        .unwrap();

    let (status, body) = activate(&base, &client, &fx.admin_key, &service_id, false).await;
    assert_eq!(
        status, 200,
        "a 4xx would make the dashboard render an error where a verdict belongs: {body}"
    );
    assert_eq!(body["verdict"]["status"], "failed", "{body}");
    assert_eq!(body["status"], "pending_setup", "{body}");
}

/// "Activate anyway". Deliberately runs no probe at all: burning an upstream
/// call whose answer is discarded would misreport what was checked.
#[tokio::test]
async fn force_activates_without_a_probe() {
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{dead}")).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-forced", "user_level": true}),
    )
    .await;
    let service_id = svc["id"].as_str().unwrap().to_string();

    let (status, body) = activate(&base, &client, &fx.admin_key, &service_id, true).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "active", "{body}");
    assert!(
        body.get("verdict").is_none_or(Value::is_null),
        "no probe ran, so there is no verdict to report: {body}"
    );
}

/// Reopen. The primitive is that `validate_binding` never required the slot to
/// be *un*bound — so a wrong key is corrected by minting a second link at the
/// same slot, and the new value lands as a new secret version.
#[tokio::test]
async fn a_reopened_draft_takes_a_new_credential_and_goes_green() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-reopen", "user_level": true}),
    )
    .await;
    let service_id = svc["id"].as_str().unwrap().to_string();
    let cookie = common::session_cookie(fx.org_id, fx.user_ids[0]);

    // First value, through the auto-minted link.
    let (req_id, token) = parse_setup_url(svc["setup"]["setup_url"].as_str().unwrap());
    client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .header("cookie", cookie.clone())
        .json(&json!({"token": token, "value": "re_first"}))
        .send()
        .await
        .unwrap();

    // Re-minting against the now-*bound* slot is refused unforced, and that is
    // D85 working rather than a collision between the two features: the name
    // is occupied, and a link aimed at an occupied name replaces whatever is
    // there. Reopening a credential to fix it *is* a rotation, which is the
    // case D85 reserves `force` for.
    let unforced = client
        .post(format!("{base}/v1/secrets/requests"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(
            &json!({"secret_name": "resend_key", "service_id": service_id,
                      "credential_key": "token"}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(unforced.status(), 409, "a bound slot is occupied, not free");
    let body: Value = unforced.json().await.unwrap();
    assert_eq!(body["error"], "secret_name_conflict", "{body}");

    // Forced: the reopen path proper. It needs no new endpoint, only the
    // acknowledgement that it is replacing a value.
    let req: Value = client
        .post(format!("{base}/v1/secrets/requests"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(
            &json!({"secret_name": "resend_key", "service_id": service_id,
                      "credential_key": "token", "force": true}),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        req["warning"].as_str().is_some(),
        "a forced re-mint says what it supersedes: {req}"
    );
    let (req_id2, token2) = parse_setup_url(req["url"].as_str().unwrap());
    let resp = client
        .post(format!("{base}/public/secrets/provide/{req_id2}"))
        .header("cookie", cookie)
        .json(&json!({"token": token2, "value": "re_second"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "a bound slot can be rebound");
    let submit: Value = resp.json().await.unwrap();
    assert_eq!(
        submit["version"], 2,
        "the correction is a new version, not an overwrite: {submit}"
    );

    let (status, body) = activate(&base, &client, &fx.admin_key, &service_id, false).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "active", "{body}");
}

/// Instance config is editable while gated — `kernel_update_service` has no
/// status predicate, and reopening must cover "or other", not just the key.
#[tokio::test]
async fn a_gated_instance_accepts_a_config_change() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-edit", "user_level": true}),
    )
    .await;
    let service_id = svc["id"].as_str().unwrap();

    let resp = client
        .put(format!("{base}/v1/services/{service_id}/manage"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"name": "resend-edited"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
}

/// The override path. It is not `activate` — it is the blunt status PATCH —
/// and since it now bypasses verification it has to leave a trail.
#[tokio::test]
async fn the_status_override_is_audited_as_a_bypass() {
    let mock = common::start_mock().await;
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api_with_registry(
        pool.clone(),
        Some(("resend", format!("http://127.0.0.1:{}", mock.port()))),
    )
    .await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-override", "user_level": true}),
    )
    .await;
    let service_id = Uuid::parse_str(svc["id"].as_str().unwrap()).unwrap();

    let resp = client
        .patch(format!("{base}/v1/services/{service_id}/status"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"status": "active"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let detail: Value = sqlx::query_scalar!(
        "SELECT detail FROM audit_log WHERE action = 'service.status_changed' \
         AND resource_id = $1 ORDER BY created_at DESC LIMIT 1",
        service_id,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(detail["from"], "pending_setup", "{detail}");
    assert_eq!(detail["to"], "active", "{detail}");
    assert_eq!(
        detail["bypassed_verification"], true,
        "the one transition worth finding later: live without a verdict: {detail}"
    );
}

/// The sweeper takes unverified setup drafts and nothing else — in particular
/// not a `draft` somebody parked on purpose, which is the whole reason the two
/// are separate statuses.
#[tokio::test]
async fn the_sweeper_purges_only_unverified_setup_drafts() {
    let mock = common::start_mock().await;
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api_with_registry(
        pool.clone(),
        Some(("resend", format!("http://127.0.0.1:{}", mock.port()))),
    )
    .await;

    let gated = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-stale", "user_level": true}),
    )
    .await;
    let gated_id = Uuid::parse_str(gated["id"].as_str().unwrap()).unwrap();

    let parked = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-parked", "user_level": true,
               "skip_credentials": true, "status": "draft"}),
    )
    .await;
    let parked_id = Uuid::parse_str(parked["id"].as_str().unwrap()).unwrap();
    assert_eq!(parked["status"], "draft", "{parked}");

    // Age both past any plausible window.
    sqlx::query!(
        "UPDATE service_instances SET created_at = now() - interval '30 days' \
         WHERE id = ANY($1)",
        &[gated_id, parked_id][..],
    )
    .execute(&pool)
    .await
    .unwrap();

    // The setup link is outstanding, and must go with the instance.
    let links_before: i64 = sqlx::query_scalar!(
        "SELECT count(*) FROM secret_requests WHERE service_instance_id = $1",
        gated_id,
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .unwrap_or(0);
    assert_eq!(links_before, 1);

    let purged = overslash_db::repos::service_instance::purge_expired_setup_drafts(&pool, 60)
        .await
        .unwrap();
    assert_eq!(purged, 1, "exactly the gated one");

    let survivors: Vec<Uuid> = sqlx::query_scalar!(
        "SELECT id FROM service_instances WHERE id = ANY($1)",
        &[gated_id, parked_id][..],
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        survivors,
        vec![parked_id],
        "a deliberately parked draft is not this sweeper's business"
    );

    let links_after: i64 = sqlx::query_scalar!(
        "SELECT count(*) FROM secret_requests WHERE service_instance_id = $1",
        gated_id,
    )
    .fetch_one(&pool)
    .await
    .unwrap()
    .unwrap_or(0);
    assert_eq!(links_after, 0, "the outstanding link cascades with it");
}

/// The vault keeps what a human typed. `mint_bundle` stores under the
/// *template's* default name, so two instances of one template share it —
/// deleting it with an instance could pull the credential out from under a
/// different, live service.
#[tokio::test]
async fn the_sweeper_leaves_the_vault_secret_standing() {
    let mock = common::start_mock().await;
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api_with_registry(
        pool.clone(),
        Some(("resend", format!("http://127.0.0.1:{}", mock.port()))),
    )
    .await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-abandoned", "user_level": true}),
    )
    .await;
    let service_id = Uuid::parse_str(svc["id"].as_str().unwrap()).unwrap();
    let (req_id, token) = parse_setup_url(svc["setup"]["setup_url"].as_str().unwrap());
    client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .header("cookie", common::session_cookie(fx.org_id, fx.user_ids[0]))
        .json(&json!({"token": token, "value": "re_typed_by_a_human"}))
        .send()
        .await
        .unwrap();

    sqlx::query!(
        "UPDATE service_instances SET created_at = now() - interval '30 days' WHERE id = $1",
        service_id,
    )
    .execute(&pool)
    .await
    .unwrap();
    overslash_db::repos::service_instance::purge_expired_setup_drafts(&pool, 60)
        .await
        .unwrap();

    let secret: Option<Uuid> = sqlx::query_scalar!(
        "SELECT id FROM secrets WHERE org_id = $1 AND name = 'resend_key' \
         AND deleted_at IS NULL",
        fx.org_id,
    )
    .fetch_optional(&pool)
    .await
    .unwrap();
    assert!(
        secret.is_some(),
        "an orphan row is recoverable; a destroyed credential is not"
    );
}

/// `/activate` refuses an archived instance, so a green credential cannot
/// silently resurrect a service somebody retired. `/test` still answers, which
/// is why the dashboard keeps both.
#[tokio::test]
async fn an_archived_service_is_diagnosable_but_not_activatable() {
    let mock = common::start_mock().await;
    let (base, client, fx) = setup_with_upstream(format!("http://127.0.0.1:{}", mock.port())).await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-archived",
               "secret_name": "resend_key", "user_level": true}),
    )
    .await;
    let service_id = svc["id"].as_str().unwrap().to_string();
    assert_eq!(svc["status"], "active", "a bound credential is not gated");

    let resp = client
        .patch(format!("{base}/v1/services/{service_id}/status"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"status": "archived"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let (status, body) = activate(&base, &client, &fx.admin_key, &service_id, false).await;
    assert_eq!(status, 400, "restoring is a deliberate act: {body}");

    // …but the diagnostic still works, which is what the detail page's Test
    // button needs on an archived row.
    let (status, verdict) = run_probe(&base, &client, &fx.admin_key, &service_id).await;
    assert_eq!(status, 200, "{verdict}");
    assert!(verdict["action"].is_string(), "{verdict}");
}

/// A forced activation still announces itself.
///
/// This is why "Activate anyway" is `activate?force=true` rather than the
/// blunt `PATCH /status`: the PATCH promotes just as well and emits nothing,
/// so an agent blocked on its service going live would wait forever. The
/// audience is the other half — `chain` walks *upwards*, so the agent that
/// minted the setup link is a descendant the owner's chain does not contain,
/// and it has to come from the `secret_requests` rows instead.
#[tokio::test]
async fn a_forced_activation_still_emits_service_activated() {
    let mock = common::start_mock().await;
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api_with_registry(
        pool.clone(),
        Some(("resend", format!("http://127.0.0.1:{}", mock.port()))),
    )
    .await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-announced", "user_level": true}),
    )
    .await;
    let service_id = svc["id"].as_str().unwrap().to_string();

    let (status, body) = activate(&base, &client, &fx.admin_key, &service_id, true).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "active");

    // `emit` spawns, so give it a moment rather than racing it.
    let mut payload = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let row = sqlx::query!(
            "SELECT payload FROM events WHERE org_id = $1 AND type = 'service.activated' \
             ORDER BY id DESC LIMIT 1",
            fx.org_id,
        )
        .fetch_optional(&pool)
        .await
        .unwrap();
        if let Some(r) = row {
            payload = Some(r.payload);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let payload = payload.expect("a forced activation emits service.activated");
    assert_eq!(payload["service_name"], "resend-announced", "{payload}");
    assert_eq!(payload["status"], "active", "{payload}");
    assert_eq!(
        payload["forced"], true,
        "the event says the probe was skipped: {payload}"
    );
    assert!(
        payload["verdict"].is_null(),
        "no probe ran, so there is no verdict to carry: {payload}"
    );
}

/// Parking a gated instance as `draft` takes it off the sweeper's clock, and
/// `/activate` is how it comes back — with the probe, not around it.
///
/// `/activate` deliberately accepts any non-archived status for this reason.
/// Refusing `draft` would leave `PATCH /status` as the only way out of a park,
/// and that is the path that runs no probe: it would push someone toward
/// unverified activation to escape a deadline extension. The audit records
/// `from: "draft"` either way, and `bypassed_verification` under the same name
/// `PATCH /status` uses, so "which services went live without a verdict?" is
/// one query rather than two.
#[tokio::test]
async fn a_parked_draft_comes_back_through_the_probe() {
    let mock = common::start_mock().await;
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api_with_registry(
        pool.clone(),
        Some(("resend", format!("http://127.0.0.1:{}", mock.port()))),
    )
    .await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-parked-resume", "user_level": true}),
    )
    .await;
    let service_id = svc["id"].as_str().unwrap().to_string();
    assert_eq!(svc["status"], "pending_setup");

    let (req_id, token) = parse_setup_url(svc["setup"]["setup_url"].as_str().unwrap());
    client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
        .header("cookie", common::session_cookie(fx.org_id, fx.user_ids[0]))
        .json(&json!({"token": token, "value": "re_live_key"}))
        .send()
        .await
        .unwrap();

    // Park it: off the clock, and out of `pending_setup`.
    let resp = client
        .patch(format!("{base}/v1/services/{service_id}/status"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .json(&json!({"status": "draft"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // …and back, through the probe.
    let (status, body) = activate(&base, &client, &fx.admin_key, &service_id, false).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["verdict"]["status"], "ok", "{body}");
    assert_eq!(body["status"], "active", "{body}");

    let detail: Value = sqlx::query_scalar!(
        "SELECT detail FROM audit_log WHERE action = 'service.activated' \
         AND resource_id = $1 ORDER BY created_at DESC LIMIT 1",
        Uuid::parse_str(&service_id).unwrap(),
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(detail["from"], "draft", "{detail}");
    assert_eq!(
        detail["bypassed_verification"], false,
        "a green verdict is not a bypass: {detail}"
    );
}

/// The forced twin, and the reason `bypassed_verification` lives on this
/// action too: an operator asking "what went live unchecked?" gets one answer
/// from one key, whichever endpoint did it.
#[tokio::test]
async fn a_forced_activation_is_audited_as_a_bypass() {
    let mock = common::start_mock().await;
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api_with_registry(
        pool.clone(),
        Some(("resend", format!("http://127.0.0.1:{}", mock.port()))),
    )
    .await;

    let svc = create_service(
        &base,
        &client,
        &fx.admin_key,
        json!({"template_key": "resend", "name": "resend-bypass", "user_level": true}),
    )
    .await;
    let service_id = svc["id"].as_str().unwrap().to_string();

    let (status, body) = activate(&base, &client, &fx.admin_key, &service_id, true).await;
    assert_eq!(status, 200, "{body}");

    let detail: Value = sqlx::query_scalar!(
        "SELECT detail FROM audit_log WHERE action = 'service.activated' \
         AND resource_id = $1 ORDER BY created_at DESC LIMIT 1",
        Uuid::parse_str(&service_id).unwrap(),
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(detail["forced"], true, "{detail}");
    assert_eq!(detail["bypassed_verification"], true, "{detail}");
    assert_eq!(detail["from"], "pending_setup", "{detail}");
}
