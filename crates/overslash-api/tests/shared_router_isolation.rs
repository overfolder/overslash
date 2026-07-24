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

use crate::common;

use serde_json::{Value, json};

/// Two tests, each with its own pool. Each registers an org via the
/// shared router (going through `state.db(&ext)`); a `SystemScope`
/// read against the *other* pool must not see the freshly-created
/// org row. If the resolver leaked, the second probe would find the
/// first test's org in the wrong DB.
#[tokio::test]
async fn db_pool_isolated_per_test() {
    let pool_a = common::test_pool().await;
    let (addr_a, client_a, _guard_a) = common::start_api_shared(pool_a.clone()).await;
    let base_a = format!("http://{addr_a}");

    let pool_b = common::test_pool().await;
    let (addr_b, client_b, _guard_b) = common::start_api_shared(pool_b.clone()).await;
    let base_b = format!("http://{addr_b}");

    // Both tests in one binary hit the SAME router/addr. The
    // `X-Test-Pool-Id` header (stamped into each client's
    // default_headers by `start_api_shared`) is what disambiguates.
    assert_eq!(addr_a, addr_b, "shared-router harness binds a single addr");

    // Create a unique slug per pool via the shared router (so the
    // write actually flows through `state.db(&ext)` → the per-test
    // resolver). Each pool starts empty (plain `test_pool()`), so the
    // slug only exists in the pool that created it.
    let slug_a = format!("iso-a-{}", uuid::Uuid::new_v4().simple());
    let create_a: Value = client_a
        .post(format!("{base_a}/v1/orgs"))
        .json(&json!({"name": "A", "slug": slug_a}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id_a = create_a["id"]
        .as_str()
        .expect("org create returned id")
        .to_string();

    let slug_b = format!("iso-b-{}", uuid::Uuid::new_v4().simple());
    let create_b: Value = client_b
        .post(format!("{base_b}/v1/orgs"))
        .json(&json!({"name": "B", "slug": slug_b}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let org_id_b = create_b["id"]
        .as_str()
        .expect("org create returned id")
        .to_string();
    assert_ne!(
        org_id_a, org_id_b,
        "distinct pools must produce distinct ids"
    );

    // Direct DB probes against each pool: A's org row must NOT exist
    // in B's pool, and B's org row must NOT exist in A's pool.
    let count_a_in_b: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM orgs WHERE id = $1::uuid")
            .bind(&org_id_a)
            .fetch_one(&pool_b)
            .await
            .unwrap();
    assert_eq!(
        count_a_in_b, 0,
        "A's org must NOT appear in B's DB (resolver leak)"
    );

    let count_b_in_a: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM orgs WHERE id = $1::uuid")
            .bind(&org_id_b)
            .fetch_one(&pool_a)
            .await
            .unwrap();
    assert_eq!(
        count_b_in_a, 0,
        "B's org must NOT appear in A's DB (resolver leak)"
    );

    // And the writes did land in the right place:
    let count_a_in_a: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM orgs WHERE id = $1::uuid")
            .bind(&org_id_a)
            .fetch_one(&pool_a)
            .await
            .unwrap();
    assert_eq!(count_a_in_a, 1, "A's org must exist in A's DB");

    let count_b_in_b: i64 =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM orgs WHERE id = $1::uuid")
            .bind(&org_id_b)
            .fetch_one(&pool_b)
            .await
            .unwrap();
    assert_eq!(count_b_in_b, 1, "B's org must exist in B's DB");
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
