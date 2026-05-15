//! Shared session-gate primitives for OAuth-flow proxied URLs.
//!
//! Both `oauth_upstream` (nested OAuth, MCP-client role) and `connections`
//! (first-party HTTP OAuth) hand out URLs of the form
//! `https://app.overslash.com/<gate>?id=<flow>`. Each gate handler reads
//! the dashboard session cookie, looks up its own flow row, and
//! fail-fasts on a mismatch. The session-reading and HTML-rendering
//! parts are identical across the two; live here once.
//!
//! Caller-owned: each gate handler reads its own flow table and decides
//! whether the parsed session is authorized for that specific flow. We
//! only provide the generic `(org_id, identity_id)` permit check —
//! flow-specific shape stays in the call site.

use axum::{
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use uuid::Uuid;

use overslash_db::repos::identity;

use crate::AppState;
use crate::error::AppError;
use crate::extractors::extract_cookie;
use crate::routes::auth::signing_key_bytes;
use crate::services::jwt;

#[derive(Debug)]
pub struct ParsedSession {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub user_id: Option<Uuid>,
}

pub enum SessionError {
    Missing,
    Invalid,
}

pub fn read_session(state: &AppState, headers: &HeaderMap) -> Result<ParsedSession, SessionError> {
    let token = extract_cookie(headers, "oss_session").ok_or(SessionError::Missing)?;
    let signing_key = signing_key_bytes(&state.config.signing_key);
    let claims =
        jwt::verify(&signing_key, &token, jwt::AUD_SESSION).map_err(|_| SessionError::Invalid)?;
    Ok(ParsedSession {
        org_id: claims.org,
        identity_id: claims.sub,
        user_id: claims.user_id,
    })
}

/// Generic permit check: `true` iff the session is in the same org as
/// the flow target and either *is* that target or sits above it in the
/// identity owner chain (so the parent user authorizing on behalf of
/// their owned agent is fine).
pub async fn session_authorized_for_org_identity(
    state: &AppState,
    session: &ParsedSession,
    flow_org_id: Uuid,
    flow_identity_id: Uuid,
) -> Result<bool, AppError> {
    if session.org_id != flow_org_id {
        return Ok(false);
    }
    if session.identity_id == flow_identity_id {
        return Ok(true);
    }
    let chain = identity::get_ancestor_chain(&state.db, flow_org_id, flow_identity_id).await?;
    Ok(chain.iter().any(|row| row.id == session.identity_id))
}

// ── HTML helpers ──────────────────────────────────────────────────────────
// Minimal, server-rendered. The dashboard owns rich UX; these pages are
// only reached when the session check fails or the URL is gone. Any
// caller-controlled data MUST go through `html_escape` before
// interpolation.

pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

pub fn gone_html(msg: &str) -> Response {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>OAuth link unavailable</title>\
         <body style='font-family:system-ui;max-width:480px;margin:4rem auto;padding:0 1rem'>\
         <h1>Link unavailable</h1><p>{}</p></body>",
        html_escape(msg)
    );
    (StatusCode::GONE, Html(body)).into_response()
}

pub fn mismatch_html() -> Response {
    let body = "<!doctype html><meta charset=utf-8><title>Wrong account</title>\
                <body style='font-family:system-ui;max-width:480px;margin:4rem auto;padding:0 1rem'>\
                <h1>Wrong account</h1>\
                <p>This OAuth link was created for a different Overslash account. \
                If you believe this is an error, sign out and sign in as the correct user, \
                then click the link again.</p></body>";
    (StatusCode::FORBIDDEN, Html(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::html_escape;

    #[test]
    fn html_escape_handles_xss_payloads() {
        assert_eq!(
            html_escape("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;"
        );
        assert_eq!(html_escape("a&b\"c"), "a&amp;b&quot;c");
    }
}
