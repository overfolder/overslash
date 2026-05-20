//! Load-bearing correctness check for the shared-router test harness.
//!
//! Two tests run against the same Axum router (since `start_api_shared`
//! is a per-binary singleton) but register distinct per-test
//! `TestResources` bundles. The contract is that every request
//! dispatches through the resolver to its own `TestPoolId`'s bundle —
//! so test A's DB, OAuth stores, and rate-limit caches can't leak into
//! test B (and vice versa).
//!
//! These tests fail if:
//! - The accessor methods on `AppState` aren't actually used by the
//!   route handlers (i.e. they still touch the static field).
//! - The `TestPoolId` extension isn't stamped or read correctly.
//! - The resolver returns the wrong bundle.

#![allow(clippy::disallowed_methods)]

mod common;

use serde_json::Value;

/// Two tests, each with its own bootstrapped pool. Each test verifies
/// that the org it created is visible in its OWN pool and absent from
/// the other (the routes go through `state.db(&ext)` which the test-
/// pool middleware steers to the right per-test pool).
#[tokio::test]
async fn db_pool_isolated_per_test() {
    let (pool_a, fx_a) = common::test_pool_bootstrapped().await;
    let (addr_a, client_a, _guard_a) = common::start_api_shared(pool_a.clone()).await;
    let base_a = format!("http://{addr_a}");

    let (pool_b, fx_b) = common::test_pool_bootstrapped().await;
    let (addr_b, client_b, _guard_b) = common::start_api_shared(pool_b.clone()).await;
    let base_b = format!("http://{addr_b}");

    // Both tests in one binary hit the SAME router/addr. The
    // `X-Test-Pool-Id` header (stamped into each client's
    // default_headers by `start_api_shared`) is what disambiguates.
    assert_eq!(addr_a, addr_b, "shared-router harness binds a single addr");

    // Each client reads its OWN org.
    let me_a: Value = client_a
        .get(format!("{base_a}/v1/whoami"))
        .header("Authorization", format!("Bearer {}", fx_a.org_key))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        me_a["org_id"].as_str().unwrap(),
        fx_a.org_id.to_string(),
        "client A must see its own org"
    );

    let me_b: Value = client_b
        .get(format!("{base_b}/v1/whoami"))
        .header("Authorization", format!("Bearer {}", fx_b.org_key))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        me_b["org_id"].as_str().unwrap(),
        fx_b.org_id.to_string(),
        "client B must see its own org"
    );

    // Cross-key check: A's key against B's pool must NOT authenticate
    // (the key row lives in A's DB, not B's, so the bearer should be
    // rejected). If the resolver leaked, this would 200 unexpectedly.
    let cross_resp = client_b
        .get(format!("{base_b}/v1/whoami"))
        .header("Authorization", format!("Bearer {}", fx_a.org_key))
        .send()
        .await
        .unwrap();
    assert_eq!(
        cross_resp.status().as_u16(),
        401,
        "A's API key must not authenticate against B's pool"
    );
}

/// Requests missing the `X-Test-Pool-Id` header must 400 with a clear
/// error — better signal than a silent fallthrough that would hit the
/// shared-router's unreachable fallback pool.
#[tokio::test]
async fn missing_header_rejected() {
    let (pool, _fx) = common::test_pool_bootstrapped().await;
    let (addr, _client, _guard) = common::start_api_shared(pool).await;
    let raw = reqwest::Client::new();
    let resp = raw
        .get(format!("http://{addr}/v1/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "shared router must reject requests missing X-Test-Pool-Id"
    );
}
