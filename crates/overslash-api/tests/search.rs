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
async fn empty_query_returns_400() {
    let (base, client, _, admin_key, _) = bootstrap().await;
    let resp = client
        .get(format!("{base}/v1/search?q="))
        .header(auth(&admin_key).0, auth(&admin_key).1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn limit_parameter_is_honored_and_clamped() {
    let (base, client, _, admin_key, _) = bootstrap().await;

    // limit=1 proves the parameter is honored on the low end — without
    // enforcement we'd see the full result set. "a" is a permissive query
    // chosen so the scorer produces more than one hit.
    let one: Value = client
        .get(format!(
            "{base}/v1/search?q={}&limit=1",
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
            "{base}/v1/search?q={}&limit=1000",
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
            "{base}/v1/search?q={}&limit=9999",
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
            "{base}/v1/search?q={}",
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
            "{base}/v1/search?q={}",
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
    // Exactly one instance we just created; name surfaces verbatim and
    // UUID never appears in the response.
    assert_eq!(instances[0]["name"], "resend-work");
    // owner_email may or may not be present depending on whether the
    // bootstrapped admin has an email set; what matters is that *no*
    // field contains a raw UUID. Scan the raw serialization for any
    // substring matching the 8-4-4-4-12 hex layout — that's what a leak
    // would look like.
    let serialized = serde_json::to_string(&instances[0]).unwrap();
    let has_uuid = serialized.as_bytes().windows(36).any(|w| {
        std::str::from_utf8(w)
            .ok()
            .and_then(|s| Uuid::parse_str(s).ok())
            .is_some()
    });
    assert!(!has_uuid, "raw UUID leaked into instance ref: {serialized}");

    // Connected bonus should push gmail/resend above non-connected
    // mail-adjacent options that don't have a wired instance.
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
            "{base}/v1/search?q={}",
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
            "{base}/v1/search?q={}",
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
            "{base}/v1/search?q={}",
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
            "{base}/v1/search?q={}",
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
