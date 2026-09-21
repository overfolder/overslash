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

    // Submit through the provide endpoint — the setup page has no write path
    // of its own, deliberately.
    let resp = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
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

    // The instance is now bound and reports itself healthy.
    let detail: Value = client
        .get(format!("{base}/v1/services/resend-flow"))
        .header(common::auth(&fx.admin_key).0, common::auth(&fx.admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["credentials"]["token"], "resend_key");
    assert_eq!(detail["credentials_status"], "ok");
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

    for (n, expected) in [(1, 200), (2, 410)] {
        let resp = client
            .post(format!("{base}/public/secrets/provide/{req_id}"))
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
async fn seed_bound_resend(base: &str, client: &Client, admin_key: &str, name: &str) -> Value {
    let svc = create_service(
        base,
        client,
        admin_key,
        json!({"template_key": "resend", "name": name, "user_level": true}),
    )
    .await;
    let (req_id, token) = parse_setup_url(svc["setup"]["setup_url"].as_str().unwrap());
    let resp = client
        .post(format!("{base}/public/secrets/provide/{req_id}"))
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
    seed_bound_resend(&base, &client, &fx.admin_key, "resend-one").await;

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
    seed_bound_resend(&base, &client, &fx.admin_key, "resend-one").await;

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
    seed_bound_resend(&base, &client, &fx.admin_key, "resend-one").await;

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
    seed_bound_resend(&base, &client, &fx.admin_key, "resend-one").await;

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
    seed_bound_resend(&base, &client, &fx.admin_key, "resend-one").await;

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
    let first = seed_bound_resend(&base, &client, &fx.admin_key, "resend-one").await;
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
    let first = seed_bound_resend(&base, &client, &fx.admin_key, "resend-one").await;
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
    seed_bound_resend(&base, &client, &fx.admin_key, "resend-one").await;

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
