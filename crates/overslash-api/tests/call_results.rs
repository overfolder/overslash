//! D57 — a truncated compact result is stored and re-fetchable behind a URL.
//!
//! The motivating report: an agent driving Metabase got a 254-row result
//! rendered as 10 rows plus `…+244 more items`, then re-ran a 30-second query
//! purely to change the delivery mode of bytes the gateway already had. The
//! `_hint` it was handed — "pass verbose=true" — recommended the *expensive*
//! option, since `verbose` is a field on a new `CallRequest`.
//!
//! What every test here is really guarding is the upstream hit count. A stored
//! result that quietly re-dials upstream would pass a byte-comparison and fail
//! the entire point, so the mock counts requests and the assertions are on that
//! counter as much as on the payload.
//!
//! Pairs with the unit tests at `services::compact_response::tests`.

use crate::common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::{Router, extract::State, response::IntoResponse, routing::get};
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// A mock that returns `rows` JSON records and counts how many times it was
/// asked. The count is the load-bearing assertion in this file.
async fn start_counting_mock() -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));

    fn rows_payload() -> String {
        // ~250 records of ~80 bytes: comfortably over the 8 KB compact budget,
        // comfortably under the buffering cap, so it truncates without 502ing.
        let items: Vec<Value> = (0..250)
            .map(|i| {
                json!({
                    "id": i,
                    "name": format!("record-{i:04}"),
                    "note": "the quick brown fox jumps over the lazy dog",
                })
            })
            .collect();
        serde_json::to_string(&json!({ "rows": items })).unwrap()
    }

    async fn rows(State(hits): State<Arc<AtomicUsize>>) -> impl IntoResponse {
        hits.fetch_add(1, Ordering::SeqCst);
        ([("content-type", "application/json")], rows_payload())
    }

    /// Small enough that the compact render never truncates.
    async fn tiny(State(hits): State<Arc<AtomicUsize>>) -> impl IntoResponse {
        hits.fetch_add(1, Ordering::SeqCst);
        (
            [("content-type", "application/json")],
            r#"{"ok":true}"#.to_string(),
        )
    }

    /// Same oversized payload, but the upstream reports a failure. Used to
    /// prove the redemption audit describes the fetch, not the stored call.
    async fn rows_404(State(hits): State<Arc<AtomicUsize>>) -> impl IntoResponse {
        hits.fetch_add(1, Ordering::SeqCst);
        (
            axum::http::StatusCode::NOT_FOUND,
            [("content-type", "application/json")],
            rows_payload(),
        )
    }

    let app = Router::new()
        .route("/rows", get(rows))
        .route("/rows-404", get(rows_404))
        .route("/tiny", get(tiny))
        .with_state(hits.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, hits)
}

/// Raw-HTTP (Mode A) call against the mock. Mode A is the shape the field
/// report actually came in on, and it needs no template or instance.
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
) -> (
    String,
    String,
    reqwest::Client,
    SocketAddr,
    Arc<AtomicUsize>,
) {
    common::allow_loopback_ssrf();
    let (mock, hits) = start_counting_mock().await;
    let (api_addr, client) = common::start_api(pool).await;
    let base = format!("http://{api_addr}");
    let (_u, _i, key) = common::bootstrap_agent_on_fixtures(&base, &client, fx).await;
    (base, key, client, mock, hits)
}

/// The headline: a cropped result carries a URL to its own full bytes, and the
/// hint no longer sends the agent back through the upstream call.
#[tokio::test]
async fn truncated_compact_result_carries_a_download_url() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, client, mock, _hits) = setup(pool, &fx).await;

    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/rows",
        json!({ "verbose": false }),
    )
    .await;
    let result = &body["result"];

    assert_eq!(result["_truncated"], true, "expected a crop: {result}");
    let url = result["_full_result"]["download_url"]
        .as_str()
        .unwrap_or_else(|| panic!("_full_result.download_url missing: {result}"));
    assert!(
        url.starts_with(&base),
        "descriptor url should be ours: {url}"
    );
    assert!(
        result["_full_result"]["expires_at"].as_str().is_some(),
        "expiry must be stated: {result}"
    );

    // The hint's whole job is to stop recommending the expensive recovery.
    let hint = result["_hint"].as_str().expect("hint");
    assert!(
        hint.contains("_full_result.download_url"),
        "hint must name the free path: {hint}"
    );
    assert!(
        hint.contains("re-runs"),
        "hint must say verbose costs an upstream call: {hint}"
    );
}

/// The load-bearing test. Redeeming the URL must serve stored bytes — if it
/// replayed the request instead, this feature would be an alias for the thing
/// it exists to replace.
#[tokio::test]
async fn refetch_serves_stored_bytes_without_a_second_upstream_hit() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, client, mock, hits) = setup(pool, &fx).await;

    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/rows",
        json!({ "verbose": false }),
    )
    .await;
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the call itself");

    let url = body["result"]["_full_result"]["download_url"]
        .as_str()
        .expect("download_url")
        .to_string();

    // Redeemed unauthenticated, deliberately — the fetcher is curl in a
    // sandbox, holding none of the caller's credentials.
    let fetched = client.get(&url).send().await.unwrap();
    assert_eq!(fetched.status(), 200);
    let raw = fetched.text().await.unwrap();

    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "redemption must not re-dial upstream — that is the entire feature"
    );

    // All 250 records, not the ~10 the compact view kept.
    let full: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        full["rows"].as_array().expect("rows array").len(),
        250,
        "stored body must be the untruncated payload"
    );
    assert!(
        body["result"]["body"]["rows"]
            .as_array()
            .expect("cropped rows")
            .len()
            < 250,
        "precondition: the inline view really was cropped"
    );
}

/// The descriptor must describe what a redemption actually writes. It is easy
/// to report the encrypted envelope's length here instead — that is the number
/// the size cap is measured on — and an agent sizing a disk write off it would
/// be wrong by the ciphertext overhead plus the rest of the ActionResult.
#[tokio::test]
async fn descriptor_size_matches_the_bytes_served() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, client, mock, _hits) = setup(pool.clone(), &fx).await;

    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/rows",
        json!({ "verbose": false }),
    )
    .await;
    let url = body["result"]["_full_result"]["download_url"]
        .as_str()
        .expect("download_url")
        .to_string();

    let stored: i64 = sqlx::query_scalar!("SELECT body_bytes FROM call_results LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    let served = client
        .get(&url)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(
        stored as usize,
        served.len(),
        "advertised size must equal the bytes a redemption writes"
    );
}

/// The dashboard and direct REST callers lose nothing to the crop, so they must
/// not pay for a stored row on every call.
#[tokio::test]
async fn verbose_call_stores_nothing() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, client, mock, _hits) = setup(pool.clone(), &fx).await;

    let body = call(&base, &client, &key, mock, "/rows", json!({})).await;
    assert!(
        body["result"].get("_full_result").is_none(),
        "verbose render must carry no descriptor: {}",
        body["result"]
    );

    let rows: i64 = sqlx::query_scalar!("SELECT count(*) FROM call_results")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(rows, 0, "verbose calls must not write call_results rows");
}

/// A compact render that fit has nothing to re-fetch.
#[tokio::test]
async fn untruncated_compact_call_carries_no_download_url() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, client, mock, _hits) = setup(pool.clone(), &fx).await;

    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/tiny",
        json!({ "verbose": false }),
    )
    .await;
    assert!(body["result"].get("_truncated").is_none());
    assert!(body["result"].get("_full_result").is_none());

    let rows: i64 = sqlx::query_scalar!("SELECT count(*) FROM call_results")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(rows, 0);
}

/// Over the cap we store nothing and say so, rather than storing a shortened
/// copy the agent would fetch and believe complete.
#[tokio::test]
async fn oversized_response_stores_nothing_and_says_so() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    common::allow_loopback_ssrf();
    let (mock, _hits) = start_counting_mock().await;
    // Small enough that the ~24 KB payload is over the storage cap while still
    // being well under the buffering cap.
    let (api_addr, client) =
        common::start_api_with(pool.clone(), |cfg| cfg.call_result_max_bytes = 4096).await;
    let base = format!("http://{api_addr}");
    let (_u, _i, key) = common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/rows",
        json!({ "verbose": false }),
    )
    .await;
    let result = &body["result"];
    assert_eq!(result["_truncated"], true);
    assert!(
        result.get("_full_result").is_none(),
        "nothing should be stored over the cap: {result}"
    );

    // Falls back to the plain cropped-response hint: narrowing still works, and
    // there is no stored copy to point at. Naming `_full_result` here would send
    // the agent after a URL that was never minted.
    let hint = result["_hint"].as_str().expect("hint");
    assert!(
        !hint.contains("_full_result"),
        "must not advertise a URL that was never minted: {hint}"
    );
    assert!(
        hint.starts_with("narrow with"),
        "the unstored hint must still name a recovery that works: {hint}"
    );

    let rows: i64 = sqlx::query_scalar!("SELECT count(*) FROM call_results")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(rows, 0);
}

/// `call_result_max_bytes = 0` turns the feature off entirely, for deployments
/// that do not want response bodies at rest at all.
#[tokio::test]
async fn zero_cap_disables_storage() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    common::allow_loopback_ssrf();
    let (mock, _hits) = start_counting_mock().await;
    let (api_addr, client) =
        common::start_api_with(pool.clone(), |cfg| cfg.call_result_max_bytes = 0).await;
    let base = format!("http://{api_addr}");
    let (_u, _i, key) = common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/rows",
        json!({ "verbose": false }),
    )
    .await;
    assert_eq!(body["result"]["_truncated"], true);
    assert!(body["result"].get("_full_result").is_none());

    let rows: i64 = sqlx::query_scalar!("SELECT count(*) FROM call_results")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(rows, 0);
}

/// The result and its token die together. Pruning the row must take the token
/// with it — otherwise a live capability outlives the bytes it names.
#[tokio::test]
async fn expired_call_result_is_gone_and_its_token_dies_with_it() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, client, mock, _hits) = setup(pool.clone(), &fx).await;

    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/rows",
        json!({ "verbose": false }),
    )
    .await;
    let url = body["result"]["_full_result"]["download_url"]
        .as_str()
        .expect("download_url")
        .to_string();
    assert_eq!(client.get(&url).send().await.unwrap().status(), 200);

    sqlx::query!("UPDATE call_results SET expires_at = now() - interval '1 hour'")
        .execute(&pool)
        .await
        .unwrap();
    let pruned = overslash_db::repos::call_result::prune_expired(&pool)
        .await
        .unwrap();
    assert_eq!(pruned, 1);

    let tokens: i64 = sqlx::query_scalar!("SELECT count(*) FROM download_tokens")
        .fetch_one(&pool)
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(tokens, 0, "the FK cascade must reap the token too");

    // Unknown and expired are deliberately indistinguishable.
    assert_eq!(client.get(&url).send().await.unwrap().status(), 404);
}

/// The `action.downloaded` row must describe *this fetch*, not the call the
/// bytes came from. Logging the stored call's status as `status_code` produced
/// rows reading `status_code: 404, is_error: false` — contradictory on their
/// face. The two facts now get two fields, and this pins that they stay apart.
#[tokio::test]
async fn a_stored_redemption_audits_the_fetch_not_the_original_call() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    common::allow_loopback_ssrf();
    let (mock, _hits) = start_counting_mock().await;
    let (api_addr, client) = common::start_api(pool.clone()).await;
    let base = format!("http://{api_addr}");
    let (_u, _i, key) = common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    // The upstream answers 404 with a body big enough to crop, so the stored
    // result records a failure while the redemption itself succeeds.
    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/rows-404",
        json!({ "verbose": false }),
    )
    .await;
    let url = body["result"]["_full_result"]["download_url"]
        .as_str()
        .expect("download_url")
        .to_string();
    assert_eq!(client.get(&url).send().await.unwrap().status(), 200);

    let detail: serde_json::Value = sqlx::query_scalar!(
        "SELECT detail FROM audit_log WHERE action = 'action.downloaded' LIMIT 1"
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(detail["status_code"], 200, "the fetch succeeded: {detail}");
    assert_eq!(detail["is_error"], false, "the fetch succeeded: {detail}");
    assert_eq!(
        detail["stored_status_code"], 404,
        "the stored call's own status must survive under its own key: {detail}"
    );
}

/// A capability must not outlive the bytes it names, and the clamp that
/// guarantees it must not depend on the API and the database agreeing about
/// the time. `expires_at` is written from the database clock, so differencing
/// it against the API's `now()` compares two clocks — under skew that yields a
/// negative remaining lifetime and mints a token that is dead on arrival while
/// reporting a healthy `expires_at`. The clamp is a SQL `LEAST` instead, so
/// both bounds are evaluated against the one clock that wrote them.
#[tokio::test]
async fn a_token_never_outlives_the_result_it_points_at() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    common::allow_loopback_ssrf();
    let (mock, _hits) = start_counting_mock().await;
    // A token TTL far longer than the result's, so the ceiling is what binds.
    let (api_addr, client) =
        common::start_api_with(pool.clone(), |cfg| cfg.download_token_ttl_secs = 86_400).await;
    let base = format!("http://{api_addr}");
    let (_u, _i, key) = common::bootstrap_agent_on_fixtures(&base, &client, &fx).await;

    call(
        &base,
        &client,
        &key,
        mock,
        "/rows",
        json!({ "verbose": false }),
    )
    .await;

    let (token_exp, result_exp): (time::OffsetDateTime, time::OffsetDateTime) = sqlx::query_as!(
        TokenAndResultExpiry,
        "SELECT t.expires_at AS token_expires_at, r.expires_at AS result_expires_at
         FROM download_tokens t JOIN call_results r ON r.id = t.call_result_id
         LIMIT 1"
    )
    .fetch_one(&pool)
    .await
    .map(|r| (r.token_expires_at, r.result_expires_at))
    .unwrap();

    assert!(
        token_exp <= result_exp,
        "token outlives its result: token={token_exp} result={result_exp}"
    );
    // And the clamp actually bound: the configured TTL was a day, so an
    // unclamped token would sit far past the result's 15-minute horizon.
    assert!(
        token_exp > time::OffsetDateTime::now_utc(),
        "clamp must not mint an already-expired token: {token_exp}"
    );
}

struct TokenAndResultExpiry {
    token_expires_at: time::OffsetDateTime,
    result_expires_at: time::OffsetDateTime,
}

/// The claim that makes the encryption real. Cheap, and without it "encrypted
/// at rest" is a comment rather than a property.
#[tokio::test]
async fn a_stored_body_is_ciphertext_at_rest() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, client, mock, _hits) = setup(pool.clone(), &fx).await;

    call(
        &base,
        &client,
        &key,
        mock,
        "/rows",
        json!({ "verbose": false }),
    )
    .await;

    let blob: Vec<u8> = sqlx::query_scalar!("SELECT body_ciphertext FROM call_results LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();

    let as_text = String::from_utf8_lossy(&blob);
    assert!(
        !as_text.contains("the quick brown fox"),
        "plaintext leaked into the stored blob"
    );
    assert!(
        !as_text.contains("record-0000"),
        "plaintext leaked into the stored blob"
    );
    // Byte 0 is the keyring version, which is what makes the row rotatable.
    assert_eq!(blob[0], 1, "expected the active key version tag");
    assert!(blob.len() > overslash_core::crypto::MIN_BLOB_LEN);
}

/// The gap this closes for free. `deliver: "url"` refuses OAuth-authenticated
/// services because a deferred fetch cannot re-mint a bearer; a result-backed
/// token dials nothing, so there is no bearer to re-mint.
///
/// Asserted at the level that matters — the stored path never calls
/// `open_upstream`, so it has no credential requirement at all. The companion
/// half (a fresh `deliver: "url"` on an OAuth service still 400s) is already
/// covered by `tests/downloads.rs`.
#[tokio::test]
async fn stored_refetch_needs_no_credential_at_fetch_time() {
    let (pool, fx) = common::test_pool_bootstrapped().await;
    let (base, key, client, mock, hits) = setup(pool.clone(), &fx).await;

    let body = call(
        &base,
        &client,
        &key,
        mock,
        "/rows",
        json!({ "verbose": false }),
    )
    .await;
    let url = body["result"]["_full_result"]["download_url"]
        .as_str()
        .expect("download_url")
        .to_string();

    // A result-backed token stores no request at all — nothing to re-resolve,
    // which is precisely why the OAuth refusal cannot apply to it.
    let request: Option<Value> = sqlx::query_scalar!("SELECT request FROM download_tokens LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        request.is_none(),
        "a result-backed token must name no replayable request"
    );

    assert_eq!(client.get(&url).send().await.unwrap().status(), 200);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}
