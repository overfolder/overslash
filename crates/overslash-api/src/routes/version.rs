use axum::{Json, Router, routing::get};
use overslash_core::build_info::build_info;
use serde::Serialize;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/version", get(version))
}

/// Build identity of the API the caller is talking to.
///
/// Unauthenticated, and mounted next to `/health` rather than in the
/// rate-limited `/v1` group, because it carries exactly the same two values
/// `/health` already publishes to the public internet — gating it would be
/// theatre. It exists as its own route so the dashboard can ask "which build
/// is this?" without triggering `/health`'s per-request database probe, and so
/// `commit_short` is computed in one place instead of once per client.
///
/// The field names are a contract with `dashboard/src/lib/types.ts`'s
/// `BuildInfo`.
#[derive(Serialize)]
struct VersionResponse {
    version: &'static str,
    commit: &'static str,
    commit_short: &'static str,
}

async fn version() -> Json<VersionResponse> {
    let info = build_info();
    Json(VersionResponse {
        version: info.version,
        commit: info.commit,
        commit_short: info.commit_short(),
    })
}
