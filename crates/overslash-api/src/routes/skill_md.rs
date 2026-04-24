//! Serve the repo-root `SKILL.md` at `/SKILL.md`.
//!
//! The file is baked into the binary so cloud and self-hosted deployments
//! both reach it without any static-asset plumbing.

use axum::{Router, http::header::CONTENT_TYPE, response::IntoResponse, routing::get};

use crate::AppState;

const SKILL_MD: &str = include_str!("../../../../SKILL.md");

pub fn router() -> Router<AppState> {
    Router::new().route("/SKILL.md", get(skill_md))
}

async fn skill_md() -> impl IntoResponse {
    ([(CONTENT_TYPE, "text/markdown; charset=utf-8")], SKILL_MD)
}
