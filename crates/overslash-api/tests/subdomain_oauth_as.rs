//! Integration tests for the per-subdomain OAuth-AS metadata + MCP
//! `WWW-Authenticate` challenge introduced by the org-slug-subdomain PR.
//!
//! The issuer URL on `<slug>.<api-apex>` and `<slug>.<app-apex>` must be
//! the host the client connected to — otherwise an MCP client doing
//! discovery on `acme.api.overslash.com` would receive `api.overslash.com`
//! as issuer and fail RFC 8414's issuer-URL invariant.

#![allow(clippy::disallowed_methods)] // seeding needs raw SQL

mod common;

use reqwest::StatusCode;
use serde_json::Value;
use uuid::Uuid;

#[tokio::test]
async fn well_known_issuer_reflects_api_subdomain() {
    let pool = common::test_pool().await;
    let slug = format!("acme-{}", Uuid::new_v4().simple());

    // Seed an org so the subdomain middleware can resolve it. Personal orgs
    // are rejected on subdomains, so flag this one as a corp org.
    let _org_id: Uuid = sqlx::query_scalar(
        "INSERT INTO orgs (name, slug, is_personal) VALUES ('Acme', $1, false) RETURNING id",
    )
    .bind(&slug)
    .fetch_one(&pool)
    .await
    .unwrap();

    let suffix = "api.test";
    let suffix_owned = suffix.to_string();
    let (addr, client) = common::start_api_with(pool.clone(), move |cfg| {
        cfg.api_host_suffix = Some(suffix_owned.clone());
        // public_url stays at the loopback addr — it's the apex fallback.
    })
    .await;
    let base = format!("http://{addr}");

    // X-Forwarded-Host carries the original. The Host header in the test
    // client points at 127.0.0.1:<port>, but production traffic always
    // arrives with the real host — match the production shape so we cover
    // the path that GCLB/Vercel exercises.
    let resp = client
        .get(format!("{base}/.well-known/oauth-authorization-server"))
        .header("x-forwarded-host", format!("{slug}.{suffix}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    let issuer = body["issuer"].as_str().unwrap();
    assert_eq!(issuer, format!("http://{slug}.{suffix}"));
    assert_eq!(
        body["authorization_endpoint"].as_str().unwrap(),
        format!("http://{slug}.{suffix}/oauth/authorize")
    );
    assert_eq!(
        body["token_endpoint"].as_str().unwrap(),
        format!("http://{slug}.{suffix}/oauth/token")
    );
}

#[tokio::test]
async fn well_known_issuer_falls_back_to_apex_on_root() {
    let pool = common::test_pool().await;
    let suffix_owned = "api.test".to_string();
    let (addr, client) = common::start_api_with(pool.clone(), move |cfg| {
        cfg.api_host_suffix = Some(suffix_owned.clone());
    })
    .await;
    let base = format!("http://{addr}");

    // No subdomain → Root context → issuer is state.config.public_url.
    let resp = client
        .get(format!("{base}/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    let issuer = body["issuer"].as_str().unwrap();
    assert_eq!(issuer, format!("http://{addr}"));
}

#[tokio::test]
async fn mcp_challenge_resource_metadata_is_subdomain_scoped() {
    let pool = common::test_pool().await;
    let slug = format!("acme-{}", Uuid::new_v4().simple());
    let _org_id: Uuid = sqlx::query_scalar(
        "INSERT INTO orgs (name, slug, is_personal) VALUES ('Acme', $1, false) RETURNING id",
    )
    .bind(&slug)
    .fetch_one(&pool)
    .await
    .unwrap();

    let suffix_owned = "api.test".to_string();
    let (addr, client) = common::start_api_with(pool.clone(), move |cfg| {
        cfg.api_host_suffix = Some(suffix_owned.clone());
    })
    .await;
    let base = format!("http://{addr}");

    // No Authorization header → the MCP handler emits the challenge.
    let resp = client
        .post(format!("{base}/mcp"))
        .header("x-forwarded-host", format!("{slug}.api.test"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        www_auth.contains(&format!(
            "http://{slug}.api.test/.well-known/oauth-protected-resource"
        )),
        "expected challenge to point at <slug>.api.test discovery, got: {www_auth}"
    );
}
