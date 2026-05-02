//! Integration tests for `GET /v1/search` (SPEC.md §10).
//!
//! Uses `common::start_api_for_search`, which loads the real
//! `services/*.yaml` registry (so gmail/google_calendar/resend/slack/etc.
//! are visible candidates) and injects the deterministic `StubEmbedder`.
//! The stub produces 384-dim vectors just like the real fastembed backend,
//! so the pgvector path is exercised end-to-end without dragging the model
//! weights into CI.

mod common;

use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

fn auth(key: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {key}"))
}

async fn bootstrap() -> (String, Client, Uuid, String, String) {
    let (pool, fixtures) = common::test_pool_bootstrapped().await;
    let (base, client) = common::start_api_for_search(pool).await;
    (
        base,
        client,
        fixtures.org_id,
        fixtures.admin_key,
        fixtures.write_key,
    )
}

/// Variant that also returns the BootstrapFixtures and a clone of the test
/// `PgPool` so individual tests can seed OAuth `connections` rows directly
/// (the OAuth flow has no test-friendly REST shortcut).
async fn bootstrap_full() -> (String, Client, common::BootstrapFixtures, PgPool) {
    let (pool, fixtures) = common::test_pool_bootstrapped().await;
    let pool_clone = pool.clone();
    let (base, client) = common::start_api_for_search(pool).await;
    (base, client, fixtures, pool_clone)
}

/// Insert a `connections` row directly so tests can seed OAuth instances
/// without going through the live OAuth flow. The encrypted token is dummy
/// bytes — the search endpoint never decrypts it.
#[allow(clippy::disallowed_methods)] // runtime sqlx::query is the only practical option for one-off test seeds
async fn seed_oauth_connection(
    pool: &PgPool,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
    account_email: &str,
) -> Uuid {
    let connection_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO connections \
         (id, org_id, identity_id, provider_key, encrypted_access_token, \
          scopes, account_email, is_default) \
         VALUES ($1, $2, $3, $4, $5, ARRAY[]::TEXT[], $6, false)",
    )
    .bind(connection_id)
    .bind(org_id)
    .bind(identity_id)
    .bind(provider_key)
    .bind(b"fake_token".as_ref())
    .bind(account_email)
    .execute(pool)
    .await
    .expect("seed connection");
    connection_id
}

/// Create a user-level OAuth-backed service instance via the REST API,
/// pinned to the supplied `connection_id`.
async fn create_oauth_service(
    base: &str,
    client: &Client,
    admin_key: &str,
    template_key: &str,
    name: &str,
    connection_id: Uuid,
) -> Value {
    let resp: Value = client
        .post(format!("{base}/v1/services"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({
            "template_key": template_key,
            "name": name,
            "connection_id": connection_id.to_string(),
            "user_level": true,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        resp["name"], name,
        "create OAuth service '{name}' failed: {resp}"
    );
    resp
}

/// Create a user-level api-key-backed service instance via the REST API
/// (no real `secrets` row required — the search endpoint surfaces the
/// label only).
async fn create_api_key_service(
    base: &str,
    client: &Client,
    admin_key: &str,
    template_key: &str,
    name: &str,
    secret_name: &str,
) -> Value {
    let resp: Value = client
        .post(format!("{base}/v1/services"))
        .header(auth(admin_key).0, auth(admin_key).1)
        .json(&json!({
            "template_key": template_key,
            "name": name,
            "secret_name": secret_name,
            "user_level": true,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        resp["name"], name,
        "create api-key service '{name}' failed: {resp}"
    );
    resp
}

/// Find the first result with the matching `(service, action)` pair.
fn find(results: &[Value], service: &str, action: &str) -> Option<Value> {
    results
        .iter()
        .find(|r| r["service"].as_str() == Some(service) && r["action"].as_str() == Some(action))
        .cloned()
}

fn rank_of(results: &[Value], service: &str, action: &str) -> Option<usize> {
    results.iter().position(|r| {
        r["service"].as_str() == Some(service) && r["action"].as_str() == Some(action)
    })
}

#[tokio::test]
async fn empty_query_with_include_catalog_lists_all_services() {
    // Browse mode with `include_catalog=true`: returns every visible service
    // template (connected and not), with no action data attached. The
    // default empty-query mode is connected-only; this opt-in mode is what
    // lets agents survey the full catalog.
    let (base, client, _, admin_key, _) = bootstrap().await;
    let resp = client
        .get(format!("{base}/v1/search?q=&include_catalog=true"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    let results = body["results"].as_array().expect("results array");
    assert!(!results.is_empty(), "browse mode should surface services");

    // Service-level entries: identifiers and auth must be present;
    // action/description/risk/score must be absent (skip_serializing_if).
    for r in results {
        assert!(
            r.get("service").and_then(|v| v.as_str()).is_some(),
            "missing service: {r}"
        );
        assert!(
            r.get("service_display_name")
                .and_then(|v| v.as_str())
                .is_some(),
            "missing service_display_name: {r}"
        );
        assert!(
            r.get("tier").and_then(|v| v.as_str()).is_some(),
            "missing tier: {r}"
        );
        assert!(r.get("auth").is_some(), "missing auth: {r}");
        assert!(r.get("action").is_none(), "browse leaked action: {r}");
        assert!(
            r.get("description").is_none(),
            "browse leaked description: {r}"
        );
        assert!(r.get("risk").is_none(), "browse leaked risk: {r}");
        assert!(r.get("score").is_none(), "browse leaked score: {r}");
    }

    // Sanity-check that the bootstrapped global registry is being walked.
    assert!(
        results.iter().any(|r| r["service"] == "gmail"),
        "gmail missing from browse output: {results:?}"
    );
}

#[tokio::test]
async fn empty_query_respects_global_template_visibility() {
    // Browse mode must apply the same global-tier visibility filter as
    // scored search — disabling globals and enabling only gmail must hide
    // every other global from the catalog.
    let (base, client, org_id, admin_key, _) = bootstrap().await;

    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "global_templates_enabled": false }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "toggle failed: {}",
        resp.status()
    );

    let _ = client
        .post(format!("{base}/v1/templates/enabled-globals"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "template_key": "gmail" }))
        .send()
        .await
        .unwrap();

    let body: Value = client
        .get(format!("{base}/v1/search?q=&include_catalog=true"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();

    assert!(
        results.iter().any(|r| r["service"] == "gmail"),
        "gmail (explicitly enabled) missing from browse: {results:?}"
    );
    assert!(
        !results.iter().any(|r| r["service"] == "stripe"),
        "stripe should be hidden in browse: {results:?}"
    );
}

#[tokio::test]
async fn empty_query_floats_connected_services_first() {
    // Connected services lead alphabetical order in browse mode — mirrors
    // the CONNECTED_BONUS intent in scored mode. Without this rule gmail
    // (display name "Gmail") would precede resend ("Resend") alphabetically.
    let (base, client, _, admin_key, _) = bootstrap().await;

    let create: Value = client
        .post(format!("{base}/v1/services"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "template_key": "resend",
            "name": "resend-work",
            "secret_name": "resend_api_key",
            "user_level": true,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        create["name"], "resend-work",
        "service creation failed: {create}"
    );

    let body: Value = client
        .get(format!("{base}/v1/search?q=&include_catalog=true"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();

    let resend_rank = results
        .iter()
        .position(|r| r["service"] == "resend")
        .expect("resend missing from browse");
    let gmail_rank = results
        .iter()
        .position(|r| r["service"] == "gmail")
        .expect("gmail missing from browse");

    assert!(
        resend_rank < gmail_rank,
        "expected connected resend (#{resend_rank}) ahead of non-connected gmail (#{gmail_rank}): {results:?}"
    );
    assert_eq!(
        results[resend_rank]["auth"]["connected"], true,
        "resend not marked connected: {}",
        results[resend_rank]
    );
}

#[tokio::test]
async fn limit_parameter_is_honored_and_clamped() {
    let (base, client, _, admin_key, _) = bootstrap().await;

    // limit=1 proves the parameter is honored on the low end — without
    // enforcement we'd see the full result set. "send email" plus
    // include_catalog ensures the scorer produces more than one hit.
    let one: Value = client
        .get(format!(
            "{base}/v1/search?q={}&limit=1&include_catalog=true",
            urlencoding::encode("send email")
        ))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let one_results = one["results"].as_array().expect("results array");
    assert_eq!(
        one_results.len(),
        1,
        "limit=1 should return exactly one result, got {}",
        one_results.len()
    );

    // limit=1000 must clamp to MAX_LIMIT (100). A lax inequality is
    // vacuous for a small corpus, so we also compare to limit=9999 — both
    // should yield the same length (whatever the corpus produces).
    let large_a: Value = client
        .get(format!(
            "{base}/v1/search?q={}&limit=1000&include_catalog=true",
            urlencoding::encode("send email")
        ))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let large_b: Value = client
        .get(format!(
            "{base}/v1/search?q={}&limit=9999&include_catalog=true",
            urlencoding::encode("send email")
        ))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let a_len = large_a["results"].as_array().unwrap().len();
    let b_len = large_b["results"].as_array().unwrap().len();
    assert!(a_len <= 100, "clamp not enforced: {a_len}");
    assert_eq!(
        a_len, b_len,
        "two above-ceiling limits returned different lengths ({a_len} vs {b_len})"
    );
}

#[tokio::test]
async fn find_send_email_across_gmail_and_resend() {
    let (base, client, _, admin_key, _) = bootstrap().await;
    let body: Value = client
        .get(format!(
            "{base}/v1/search?q={}&include_catalog=true",
            urlencoding::encode("send an email")
        ))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();
    // Both gmail's send_message (or equivalent) and resend's send_email
    // should appear. We don't hardcode the exact action keys since
    // template authors can rename them — instead we check that at least
    // one hit for each service is present in the ranked list.
    assert!(
        results.iter().any(|r| r["service"] == "gmail"),
        "expected a gmail hit; got {results:?}"
    );
    assert!(
        results.iter().any(|r| r["service"] == "resend"),
        "expected a resend hit; got {results:?}"
    );
    // Top result for a mail query should come from one of the two
    // email-centric services.
    let top = &results[0];
    let top_service = top["service"].as_str().unwrap();
    assert!(
        matches!(top_service, "gmail" | "resend"),
        "top hit was {top_service}, expected gmail or resend"
    );
}

#[tokio::test]
async fn find_create_calendar_event() {
    let (base, client, _, admin_key, _) = bootstrap().await;
    let body: Value = client
        .get(format!(
            "{base}/v1/search?q={}&include_catalog=true",
            urlencoding::encode("create a calendar event")
        ))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();
    let rank = results
        .iter()
        .position(|r| r["service"] == "google_calendar");
    assert!(
        rank.is_some(),
        "google_calendar missing from results: {results:?}"
    );
    // Should be within the top handful — the query is a near-paraphrase
    // of the action's own description.
    assert!(
        rank.unwrap() < 5,
        "google_calendar ranked too low at {}: {results:?}",
        rank.unwrap()
    );
}

#[tokio::test]
async fn unrelated_query_returns_empty_or_low_score() {
    let (base, client, _, admin_key, _) = bootstrap().await;
    let body: Value = client
        .get(format!(
            "{base}/v1/search?q={}&include_catalog=true",
            urlencoding::encode("xyzzy quantum zephyr")
        ))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();
    // We don't demand zero hits (the stub embedder can coincidentally
    // align with a template), but nothing should score high.
    for r in results {
        let score = r["score"].as_f64().unwrap();
        assert!(score < 0.5, "unexpected high score on noise query: {r}");
    }
}

#[tokio::test]
async fn connected_instance_surfaces_in_auth_instances() {
    let (base, client, _, admin_key, _) = bootstrap().await;

    // Create a resend service instance (api_key auth) so the search
    // endpoint has a connected instance to surface. We use resend because
    // it's api_key-based, so no OAuth dance is required.
    let create: Value = client
        .post(format!("{base}/v1/services"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({
            "template_key": "resend",
            "name": "resend-work",
            "secret_name": "resend_api_key",
            "user_level": true,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        create["name"], "resend-work",
        "service creation failed: {create}"
    );

    let body: Value = client
        .get(format!(
            "{base}/v1/search?q={}",
            urlencoding::encode("send an email")
        ))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();
    let resend_hit = results
        .iter()
        .find(|r| r["service"] == "resend")
        .expect("resend result missing");
    let auth = &resend_hit["auth"];
    assert_eq!(auth["connected"], true, "expected connected=true: {auth}");
    let instances = auth["instances"].as_array().expect("instances array");
    assert!(!instances.is_empty(), "instances empty: {auth}");
    // Exactly one instance we just created; name + secret_name surface
    // verbatim. owner_email is a deprecated field and must NOT appear in
    // the new payload — instance disambiguation is by account_email
    // (OAuth) or secret_name (api-key) only.
    assert_eq!(instances[0]["name"], "resend-work");
    assert_eq!(instances[0]["secret_name"], "resend_api_key");
    assert!(
        instances[0].get("owner_email").is_none(),
        "owner_email leaked into payload: {}",
        instances[0]
    );
    assert!(
        instances[0].get("account_email").is_none(),
        "api-key instance must not surface account_email: {}",
        instances[0]
    );
    // No raw UUID anywhere — the search response should never expose
    // internal identifiers like connection_id or service_instance_id.
    let serialized = serde_json::to_string(&instances[0]).unwrap();
    let has_uuid = serialized.as_bytes().windows(36).any(|w| {
        std::str::from_utf8(w)
            .ok()
            .and_then(|s| Uuid::parse_str(s).ok())
            .is_some()
    });
    assert!(!has_uuid, "raw UUID leaked into instance ref: {serialized}");

    // Connected bonus should push gmail/resend above non-connected
    // mail-adjacent options that don't have a wired instance. With
    // include_catalog=false (default), only resend appears, so it's
    // guaranteed to be at index 0.
    let resend_rank = rank_of(results, "resend", resend_hit["action"].as_str().unwrap());
    assert!(resend_rank.unwrap() < 3, "connected resend rank too low");
}

#[tokio::test]
async fn hidden_global_template_is_filtered() {
    let (base, client, org_id, admin_key, _) = bootstrap().await;

    // Flip the org to restrict globals: now only explicitly enabled
    // templates are visible.
    let resp = client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "global_templates_enabled": false }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "toggle failed: {}",
        resp.status()
    );

    // Enable only gmail. Stripe should now be invisible.
    let _ = client
        .post(format!("{base}/v1/templates/enabled-globals"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "template_key": "gmail" }))
        .send()
        .await
        .unwrap();

    let body: Value = client
        .get(format!(
            "{base}/v1/search?q={}&include_catalog=true",
            urlencoding::encode("charge")
        ))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();
    assert!(
        !results.iter().any(|r| r["service"] == "stripe"),
        "stripe should be hidden but appeared in results: {results:?}"
    );
}

#[tokio::test]
async fn template_update_refreshes_embeddings() {
    // Landing scenario: create a user-level template, confirm it appears in
    // search for its action description, then update it and confirm the
    // search surface reflects the new description. Verifies the
    // write-path embedding hook.
    let (base, client, org_id, admin_key, _) = bootstrap().await;

    // Enable user-level templates
    let _ = client
        .patch(format!("{base}/v1/orgs/{org_id}/template-settings"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "allow_user_templates": true }))
        .send()
        .await
        .unwrap();

    let initial_yaml = r#"
openapi: 3.1.0
info:
  title: Widgets Tracker
  x-overslash-key: widget_tracker
servers:
  - url: https://api.widgets.test
components:
  securitySchemes:
    bearer:
      type: http
      scheme: bearer
      x-overslash-default_secret_name: widget_token
paths:
  /widgets:
    post:
      operationId: do_thing
      summary: Dispatch a package to the warehouse floor
      x-overslash-risk: write
"#;

    let create_resp = client
        .post(format!("{base}/v1/templates"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": initial_yaml, "user_level": true }))
        .send()
        .await
        .unwrap();
    assert!(
        create_resp.status().is_success(),
        "create_template failed: {}",
        create_resp.status()
    );
    let created: Value = create_resp.json().await.unwrap();
    let tmpl_id = created["id"].as_str().unwrap().to_string();

    // First query: "dispatch package" — keyword and embedding both match
    // the initial description, so widget_tracker must appear.
    let body: Value = client
        .get(format!(
            "{base}/v1/search?q={}&include_catalog=true",
            urlencoding::encode("dispatch package")
        ))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();
    assert!(
        find(results, "widget_tracker", "do_thing").is_some(),
        "widget_tracker missing right after create: {results:?}"
    );

    // Update: replace the description with one that has no lexical
    // overlap with the original. If the embedding refresh hook runs, the
    // stored vector now matches "rocket launch" (not "dispatch package").
    // If the hook doesn't run, the stale vector still matches
    // "dispatch package" and widget_tracker would still appear below —
    // the assertion that it DOESN'T appear is the actual regression
    // catcher. The keyword scorer alone can't save the test either way
    // because it reads the live (new) description and sees zero lexical
    // match for "dispatch package" against "Schedule an interstellar
    // rocket launch".
    let updated_yaml = r#"
openapi: 3.1.0
info:
  title: Widgets Tracker
  x-overslash-key: widget_tracker
servers:
  - url: https://api.widgets.test
components:
  securitySchemes:
    bearer:
      type: http
      scheme: bearer
      x-overslash-default_secret_name: widget_token
paths:
  /widgets:
    post:
      operationId: do_thing
      summary: Schedule an interstellar rocket launch
      x-overslash-risk: write
"#;
    let upd_resp = client
        .put(format!("{base}/v1/templates/{tmpl_id}/manage"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .json(&json!({ "openapi": updated_yaml }))
        .send()
        .await
        .unwrap();
    assert!(
        upd_resp.status().is_success(),
        "update_template failed: {}",
        upd_resp.status()
    );

    // Querying the OLD description must no longer surface widget_tracker.
    // A stale embedding (missing refresh hook) would still match on
    // cosine similarity; refreshed embeddings would not.
    let body: Value = client
        .get(format!(
            "{base}/v1/search?q={}&include_catalog=true",
            urlencoding::encode("dispatch package")
        ))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();
    assert!(
        find(results, "widget_tracker", "do_thing").is_none(),
        "widget_tracker still matches the OLD description — embedding was not refreshed: {results:?}"
    );

    // And the new description should match.
    let body: Value = client
        .get(format!(
            "{base}/v1/search?q={}&include_catalog=true",
            urlencoding::encode("rocket launch")
        ))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();
    assert!(
        find(results, "widget_tracker", "do_thing").is_some(),
        "widget_tracker not found via the NEW description: {results:?}"
    );
}

// ─── connected-only-by-default + instance disambiguation ─────────────────
//
// These tests exercise the `include_catalog` flag and the new instance
// fields (`account_email`, `secret_name`) introduced so agents can tell
// two Gmail or two Resend connections apart. Defaults match the agent's
// most common need: a directory of what the caller can actually call
// right now.

#[tokio::test]
async fn empty_query_returns_only_connected_services_by_default() {
    // No `include_catalog` → empty query lists only services with at
    // least one active instance bound to the caller. A bare resend
    // instance is connected; gmail is left untouched and must NOT appear.
    let (base, client, _, admin_key, _) = bootstrap().await;
    create_api_key_service(&base, &client, &admin_key, "resend", "resend-work", "rk").await;

    let body: Value = client
        .get(format!("{base}/v1/search?q="))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();

    assert!(
        results.iter().any(|r| r["service"] == "resend"),
        "connected resend missing from default browse: {results:?}"
    );
    assert!(
        !results.iter().any(|r| r["service"] == "gmail"),
        "unconnected gmail leaked into default browse: {results:?}"
    );
    assert!(
        !results.iter().any(|r| r["service"] == "stripe"),
        "unconnected stripe leaked into default browse: {results:?}"
    );
}

#[tokio::test]
async fn empty_query_with_include_catalog_returns_full_catalog() {
    // Same seed as above; `include_catalog=true` brings the un-bound
    // catalog back. Connected resend still ranks first thanks to the
    // connected bonus.
    let (base, client, _, admin_key, _) = bootstrap().await;
    create_api_key_service(&base, &client, &admin_key, "resend", "resend-work", "rk").await;

    let body: Value = client
        .get(format!("{base}/v1/search?q=&include_catalog=true"))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();

    let resend_rank = rank_of_service(results, "resend").expect("resend missing");
    let gmail_rank = rank_of_service(results, "gmail").expect("gmail missing with catalog");
    assert!(
        resend_rank < gmail_rank,
        "connected resend (#{resend_rank}) should beat gmail (#{gmail_rank}): {results:?}"
    );
}

#[tokio::test]
async fn keyword_query_filters_to_connected_by_default() {
    // A keyword query without `include_catalog` only matches actions on
    // services the caller has connected. Resend is connected (api_key);
    // gmail is not. "send email" must resolve to resend only.
    let (base, client, _, admin_key, _) = bootstrap().await;
    create_api_key_service(&base, &client, &admin_key, "resend", "resend-work", "rk").await;

    let body: Value = client
        .get(format!(
            "{base}/v1/search?q={}",
            urlencoding::encode("send email")
        ))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();

    assert!(
        results.iter().any(|r| r["service"] == "resend"),
        "connected resend missing from default keyword search: {results:?}"
    );
    assert!(
        !results.iter().any(|r| r["service"] == "gmail"),
        "unconnected gmail leaked into default keyword search: {results:?}"
    );
}

#[tokio::test]
async fn keyword_query_with_include_catalog_searches_full_catalog() {
    let (base, client, _, admin_key, _) = bootstrap().await;
    create_api_key_service(&base, &client, &admin_key, "resend", "resend-work", "rk").await;

    let body: Value = client
        .get(format!(
            "{base}/v1/search?q={}&include_catalog=true",
            urlencoding::encode("send email")
        ))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();

    assert!(
        results.iter().any(|r| r["service"] == "resend"),
        "resend missing with include_catalog: {results:?}"
    );
    assert!(
        results.iter().any(|r| r["service"] == "gmail"),
        "gmail missing with include_catalog: {results:?}"
    );
}

#[tokio::test]
async fn oauth_instance_exposes_account_email() {
    // OAuth-backed instances surface the connection's `account_email`,
    // not the Overslash user's email. The Overslash user's identity
    // email is no longer leaked into the search payload.
    let (base, client, fixtures, pool) = bootstrap_full().await;
    let conn = seed_oauth_connection(
        &pool,
        fixtures.org_id,
        fixtures.user_ids[0],
        "google",
        "alice@gmail.com",
    )
    .await;
    create_oauth_service(
        &base,
        &client,
        &fixtures.admin_key,
        "gmail",
        "gmail-alice",
        conn,
    )
    .await;

    let body: Value = client
        .get(format!("{base}/v1/search?q="))
        .header(auth(&fixtures.admin_key).0, auth(&fixtures.admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();
    let gmail = results
        .iter()
        .find(|r| r["service"] == "gmail")
        .expect("connected gmail missing");
    let instances = gmail["auth"]["instances"].as_array().unwrap();
    assert_eq!(instances.len(), 1, "expected one instance: {instances:?}");
    assert_eq!(instances[0]["name"], "gmail-alice");
    assert_eq!(instances[0]["account_email"], "alice@gmail.com");
    assert!(
        instances[0].get("owner_email").is_none(),
        "owner_email leaked: {}",
        instances[0]
    );
    assert!(
        instances[0].get("secret_name").is_none(),
        "OAuth instance must not expose secret_name: {}",
        instances[0]
    );
}

#[tokio::test]
async fn api_key_instance_exposes_secret_name() {
    // API-key instances surface the `secret_name` label only — never the
    // value, never a version, never the encryption envelope.
    let (base, client, _, admin_key, _) = bootstrap().await;
    create_api_key_service(
        &base,
        &client,
        &admin_key,
        "resend",
        "resend-work",
        "resend_work",
    )
    .await;

    let body: Value = client
        .get(format!("{base}/v1/search?q="))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let serialized = serde_json::to_string(&body).unwrap();
    let results = body["results"].as_array().unwrap();
    let resend = results
        .iter()
        .find(|r| r["service"] == "resend")
        .expect("resend missing");
    let instances = resend["auth"]["instances"].as_array().unwrap();
    assert_eq!(instances[0]["secret_name"], "resend_work");
    assert!(
        instances[0].get("account_email").is_none(),
        "api-key instance leaked account_email: {}",
        instances[0]
    );
    // Defense-in-depth: nothing in the response body should look like an
    // encrypted-blob field, an envelope, or a version pointer.
    for forbidden in [
        "encrypted_value",
        "encrypted_access_token",
        "secret_value",
        "version",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "search response leaked '{forbidden}': {serialized}"
        );
    }
}

#[tokio::test]
async fn multiple_instances_of_same_service_disambiguate_by_account_email() {
    // Two Google Calendar accounts (a@ + b@) should each surface as a
    // distinct entry in `auth.instances`, with their respective OAuth
    // account emails. Action data is NOT duplicated — there's still one
    // gmail row, with two instances under it.
    let (base, client, fixtures, pool) = bootstrap_full().await;
    let conn_a = seed_oauth_connection(
        &pool,
        fixtures.org_id,
        fixtures.user_ids[0],
        "google",
        "a@gmail.com",
    )
    .await;
    let conn_b = seed_oauth_connection(
        &pool,
        fixtures.org_id,
        fixtures.user_ids[0],
        "google",
        "b@gmail.com",
    )
    .await;
    create_oauth_service(
        &base,
        &client,
        &fixtures.admin_key,
        "gmail",
        "gmail-a",
        conn_a,
    )
    .await;
    create_oauth_service(
        &base,
        &client,
        &fixtures.admin_key,
        "gmail",
        "gmail-b",
        conn_b,
    )
    .await;

    let body: Value = client
        .get(format!("{base}/v1/search?q="))
        .header(auth(&fixtures.admin_key).0, auth(&fixtures.admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();
    let gmail_rows: Vec<&Value> = results.iter().filter(|r| r["service"] == "gmail").collect();
    assert_eq!(
        gmail_rows.len(),
        1,
        "actions must stay DRY across instances; got {} gmail rows",
        gmail_rows.len()
    );
    let instances = gmail_rows[0]["auth"]["instances"].as_array().unwrap();
    assert_eq!(
        instances.len(),
        2,
        "expected two gmail instances: {instances:?}"
    );
    let mut emails: Vec<String> = instances
        .iter()
        .map(|i| i["account_email"].as_str().unwrap().to_string())
        .collect();
    emails.sort();
    assert_eq!(emails, vec!["a@gmail.com", "b@gmail.com"]);
}

#[tokio::test]
async fn multiple_instances_of_same_service_disambiguate_by_secret_name() {
    // Two Resend instances bound to different secret names should each
    // surface with their distinct `secret_name`.
    let (base, client, _, admin_key, _) = bootstrap().await;
    create_api_key_service(&base, &client, &admin_key, "resend", "resend-a", "secret_a").await;
    create_api_key_service(&base, &client, &admin_key, "resend", "resend-b", "secret_b").await;

    let body: Value = client
        .get(format!("{base}/v1/search?q="))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();
    let resend_rows: Vec<&Value> = results
        .iter()
        .filter(|r| r["service"] == "resend")
        .collect();
    assert_eq!(
        resend_rows.len(),
        1,
        "actions must stay DRY across instances; got {} resend rows",
        resend_rows.len()
    );
    let instances = resend_rows[0]["auth"]["instances"].as_array().unwrap();
    assert_eq!(
        instances.len(),
        2,
        "expected two resend instances: {instances:?}"
    );
    let mut secrets: Vec<String> = instances
        .iter()
        .map(|i| i["secret_name"].as_str().unwrap().to_string())
        .collect();
    secrets.sort();
    assert_eq!(secrets, vec!["secret_a", "secret_b"]);
}

#[tokio::test]
async fn instances_with_same_account_email_disambiguate_by_name() {
    // Two service instances pinned to the SAME OAuth connection (so
    // they share `account_email`) must still surface as two distinct
    // entries with their unique `name`s. Name is the canonical
    // identifier — `account_email` and `secret_name` are convenience
    // hints, not primary keys.
    let (base, client, fixtures, pool) = bootstrap_full().await;
    let conn = seed_oauth_connection(
        &pool,
        fixtures.org_id,
        fixtures.user_ids[0],
        "google",
        "alice@gmail.com",
    )
    .await;
    create_oauth_service(
        &base,
        &client,
        &fixtures.admin_key,
        "gmail",
        "gmail-priority",
        conn,
    )
    .await;
    create_oauth_service(
        &base,
        &client,
        &fixtures.admin_key,
        "gmail",
        "gmail-archive",
        conn,
    )
    .await;

    let body: Value = client
        .get(format!("{base}/v1/search?q="))
        .header(auth(&fixtures.admin_key).0, auth(&fixtures.admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();
    let gmail = results
        .iter()
        .find(|r| r["service"] == "gmail")
        .expect("gmail missing");
    let instances = gmail["auth"]["instances"].as_array().unwrap();
    assert_eq!(
        instances.len(),
        2,
        "expected two distinct gmail instances despite shared connection: {instances:?}"
    );
    let mut names: Vec<String> = instances
        .iter()
        .map(|i| i["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(names, vec!["gmail-archive", "gmail-priority"]);
    for inst in instances {
        assert_eq!(
            inst["account_email"], "alice@gmail.com",
            "shared connection should yield same account_email: {inst}"
        );
    }
}

#[tokio::test]
async fn instances_with_same_secret_name_disambiguate_by_name() {
    // Two API-key instances bound to the SAME secret label must still
    // surface as two distinct `instances[]` entries identifiable by
    // their unique `name`.
    let (base, client, _, admin_key, _) = bootstrap().await;
    create_api_key_service(
        &base,
        &client,
        &admin_key,
        "resend",
        "resend-prod",
        "shared_resend_key",
    )
    .await;
    create_api_key_service(
        &base,
        &client,
        &admin_key,
        "resend",
        "resend-staging",
        "shared_resend_key",
    )
    .await;

    let body: Value = client
        .get(format!("{base}/v1/search?q="))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let results = body["results"].as_array().unwrap();
    let resend = results
        .iter()
        .find(|r| r["service"] == "resend")
        .expect("resend missing");
    let instances = resend["auth"]["instances"].as_array().unwrap();
    assert_eq!(
        instances.len(),
        2,
        "expected two distinct resend instances despite shared secret_name: {instances:?}"
    );
    let mut names: Vec<String> = instances
        .iter()
        .map(|i| i["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(names, vec!["resend-prod", "resend-staging"]);
    for inst in instances {
        assert_eq!(inst["secret_name"], "shared_resend_key");
    }
}

fn rank_of_service(results: &[Value], service: &str) -> Option<usize> {
    results.iter().position(|r| r["service"] == service)
}
