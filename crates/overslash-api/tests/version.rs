//! Integration tests for `GET /v1/version`.
//!
//! The dashboard renders this in the sidebar footer, so the field names are a
//! contract with `dashboard/src/lib/types.ts`'s `BuildInfo`. The values
//! themselves come from `overslash-core`'s build script and are asserted
//! structurally here — a test binary and a released container are built from
//! different inputs, so the only invariant that holds everywhere is
//! "non-empty, and `commit_short` is a prefix of `commit`".

use crate::common;

use serde_json::Value;

#[tokio::test]
async fn version_reports_build_identity() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;

    let res = client
        .get(format!("http://{addr}/v1/version"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();

    let version = body["version"].as_str().expect("version is a string");
    let commit = body["commit"].as_str().expect("commit is a string");
    let short = body["commit_short"].as_str().expect("short is a string");

    assert!(!version.is_empty());
    assert!(!commit.is_empty());
    assert!(
        commit.starts_with(short),
        "commit_short ({short}) must abbreviate commit ({commit})"
    );
}

/// The `sql_policy` bit exists so a deploy check can tell whether the build
/// carries the D42 parser without reading a Dockerfile — the container image
/// once shipped without it, which silently fail-closed every SQL-annotated
/// action. It must track the feature this binary was compiled with, not a
/// constant.
#[tokio::test]
async fn version_reports_sql_policy_feature() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;

    let body: Value = client
        .get(format!("http://{addr}/v1/version"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(
        body["sql_policy"].as_bool(),
        Some(cfg!(feature = "sql_policy")),
        "sql_policy must report the feature this binary was built with"
    );
}

/// The route is deliberately unauthenticated: it publishes exactly the same
/// values `/health` already exposes to the public internet, and the dashboard
/// reads it before it has done anything else. It must agree with `/health`, or
/// a deploy check and the UI could name different builds.
#[tokio::test]
async fn version_agrees_with_health() {
    let pool = common::test_pool().await;
    let (addr, client) = common::start_api(pool).await;

    let version: Value = client
        .get(format!("http://{addr}/v1/version"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let health: Value = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(version["version"], health["version"]);
    assert_eq!(version["commit"], health["commit"]);
    assert_eq!(version["sql_policy"], health["sql_policy"]);
}
