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
/// rate-limited `/v1` group, because it carries exactly the same values
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
    /// Whether this build carries the D42 SQL parser (the default-off
    /// `sql_policy` Cargo feature). `false` means every SQL-annotated action
    /// fails closed — `sql_policy::analyze` classifies write on unknown tables
    /// and routes to approval without ever parsing the statement. That is a
    /// correct-but-degraded mode which is otherwise indistinguishable from a
    /// genuinely write-shaped query, so it is reported here rather than left
    /// to be inferred from a Dockerfile.
    sql_policy: bool,
}

async fn version() -> Json<VersionResponse> {
    let info = build_info();
    Json(VersionResponse {
        version: info.version,
        commit: info.commit,
        commit_short: info.commit_short(),
        sql_policy: overslash_core::sql_policy::available(),
    })
}
