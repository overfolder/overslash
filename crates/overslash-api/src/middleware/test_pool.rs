//! Stamps a `TestPoolId` request-extension marker from the
//! `X-Test-Pool-Id` header. Mounted by every test helper (and by
//! `create_app` in production for symmetry, where it no-ops because
//! `AppState.test_resources` is `None`). The downstream accessor
//! methods on [`crate::AppState`] (`state.db(&ext)`,
//! `state.rate_limit_cache(&ext)`, etc.) read the marker out of
//! `parts.extensions` / `request.extensions()` and dispatch to the
//! per-test `TestResources` bundle when both the resolver and the
//! marker are present.
//!
//! In production: middleware is mounted but the header is never set
//! on genuine traffic and the resolver is always `None`, so the
//! dispatch short-circuits to the static AppState fields with one
//! extension-map probe per request — negligible cost.
//!
//! Layer this **before** `subdomain_middleware` so the subdomain
//! resolver itself (which calls `state.db(...)`) picks the right
//! pool.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;
use uuid::Uuid;

use crate::{AppState, TestPoolId};

/// Header used by test clients to stamp a per-test pool id onto every
/// request. Matched verbatim; HTTP header parsing is case-insensitive
/// but we standardize on lowercase to match the rest of the codebase.
pub const TEST_POOL_HEADER: &str = "x-test-pool-id";

pub async fn test_pool_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    // Fast path: production builds have `test_resources: None` and
    // skip header parsing entirely. The pool-id marker is only
    // meaningful when a resolver is wired.
    if state.test_resources.is_none() {
        return next.run(request).await;
    }

    match request.headers().get(TEST_POOL_HEADER) {
        Some(value) => {
            let parsed: Option<TestPoolId> = value
                .to_str()
                .ok()
                .and_then(|s| Uuid::parse_str(s).ok())
                .map(TestPoolId);
            match parsed {
                Some(id) => {
                    request.extensions_mut().insert(id);
                }
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        axum::Json(json!({
                            "error": "test_pool_id_invalid",
                            "message": "X-Test-Pool-Id header must be a UUID",
                        })),
                    )
                        .into_response();
                }
            }
        }
        None => {
            // Test build, resolver wired, but the request didn't
            // carry the header. Surface a clear error so this fails
            // fast in the test (better signal than a downstream sqlx
            // error about a closed fallback pool).
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({
                    "error": "test_pool_id_missing",
                    "message": "shared-router test harness requires X-Test-Pool-Id header on every request",
                })),
            )
                .into_response();
        }
    }
    next.run(request).await
}
