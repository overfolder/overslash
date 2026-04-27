//! Serve the repo-root `SKILL.md` at `/SKILL.md`.
//!
//! The file is baked into the binary so cloud and self-hosted deployments
//! both reach it without any static-asset plumbing.

use axum::{Router, http::header::CONTENT_TYPE, response::IntoResponse, routing::get};

use crate::AppState;

// `CARGO_MANIFEST_DIR` is `crates/overslash-api`, so two levels up reaches
// the workspace root regardless of which file in the crate references it.
const SKILL_MD: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../SKILL.md"));

pub fn router() -> Router<AppState> {
    Router::new().route("/SKILL.md", get(skill_md))
}

async fn skill_md() -> impl IntoResponse {
    ([(CONTENT_TYPE, "text/markdown; charset=utf-8")], SKILL_MD)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, response::IntoResponse};

    #[tokio::test]
    async fn skill_md_is_non_empty_and_mentions_enrollment() {
        // The baked file must exist and cover the advertised enrollment flow —
        // if someone blanks SKILL.md the contract is broken.
        assert!(!SKILL_MD.is_empty(), "SKILL.md must not be empty");
        assert!(
            SKILL_MD.contains("MCP OAuth"),
            "SKILL.md must describe MCP OAuth enrollment"
        );
    }

    #[tokio::test]
    async fn skill_md_handler_returns_markdown() {
        let resp = skill_md().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .expect("content-type present")
            .to_str()
            .unwrap();
        assert!(
            ct.starts_with("text/markdown"),
            "expected markdown content-type, got {ct}"
        );
    }
}
