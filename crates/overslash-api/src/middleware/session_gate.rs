//! Refuses session cookies whose server-side session is over
//! ([`crate::services::user_sessions`]).
//!
//! Runs before every router, so the dozen places that read the session cookie
//! — extractors, the rate limiter, the opportunistic "is anyone signed in?"
//! checks on public pages — never see a dead one and need no change: a dead
//! cookie is removed from the request, and the request continues as if it had
//! never been sent. A route that requires a session then answers 401, and the
//! response clears the cookie so the browser stops presenting it.
//!
//! A JWT that fails its signature or expiry check is left alone — every reader
//! already rejects those.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::AppState;
use crate::cookies;
use crate::services::jwt;
use crate::services::user_sessions::{self, Verdict};

pub async fn session_gate(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let key = jwt::signing_key_bytes(&state.config.signing_key);
    // Wire names of the cookies whose session is dead. Only those are
    // cleared: with a cookie Domain configured a request can carry both the
    // `__Secure-` cookie and the preview handoff's host-only `__Host-` one,
    // and a dead one must not take a live one down with it.
    let mut dead_names: Vec<String> = Vec::new();
    // `read_session` falls back from the configured name to the host-only
    // one, so a dead first cookie can uncover a second. Two names, two turns.
    for _ in 0..2 {
        let Some(token) = cookies::read_session(request.headers(), &state) else {
            break;
        };
        let Ok(claims) = jwt::verify(&key, &token, jwt::AUD_SESSION) else {
            break;
        };
        let dead = match user_sessions::check(&state, request.extensions(), &claims).await {
            Ok(Verdict::Live) => break,
            Ok(Verdict::Dead) => true,
            Ok(Verdict::Superseded) => false,
            Err(e) => {
                // Fail closed, but not as a 401: the dashboard reads 401 as
                // "sign in again", and a database blip is not that.
                tracing::error!("session check failed: {e}");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    axum::Json(json!({ "error": "session store unavailable" })),
                )
                    .into_response();
            }
        };
        let names = strip_cookie_value(request.headers_mut(), &token);
        if dead {
            dead_names.extend(names);
        }
    }

    let mut response = next.run(request).await;
    let host_only = cookies::name(cookies::SESSION, None);
    let mut clears: Vec<String> = Vec::new();
    for name in dead_names {
        let clear = if name == host_only {
            cookies::clear(cookies::SESSION, None, "/")
        } else {
            cookies::clear_for(&state, cookies::SESSION, "/")
        };
        if !clears.contains(&clear) {
            clears.push(clear);
        }
    }
    cookies::append_all(response.headers_mut(), clears);
    response
}

/// Drop every cookie pair whose value is `value` from the request's `Cookie`
/// headers, folding them into one header as `cookies::extract` reads only the
/// first. Matching on the value (a signed JWT) rather than the name removes
/// exactly the cookie that was judged, whichever name carried it. Returns the
/// names it removed.
fn strip_cookie_value(headers: &mut HeaderMap, value: &str) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    let mut removed: Vec<String> = Vec::new();
    for pair in headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .filter(|pair| !pair.is_empty())
    {
        match pair.split_once('=') {
            Some((name, v)) if v == value => removed.push(name.to_string()),
            _ => kept.push(pair.to_string()),
        }
    }
    headers.remove(header::COOKIE);
    if !kept.is_empty()
        && let Ok(v) = HeaderValue::from_str(&kept.join("; "))
    {
        headers.insert(header::COOKIE, v);
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_only_the_judged_cookie() {
        let mut h = HeaderMap::new();
        h.append(
            header::COOKIE,
            "a=1; __Host-oss_session=tok".parse().unwrap(),
        );
        h.append(header::COOKIE, "b=2".parse().unwrap());
        let removed = strip_cookie_value(&mut h, "tok");
        assert_eq!(removed, ["__Host-oss_session"]);
        let all: Vec<_> = h.get_all(header::COOKIE).iter().collect();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], "a=1; b=2");
    }

    #[test]
    fn removes_the_header_when_nothing_is_left() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "__Host-oss_session=tok".parse().unwrap());
        strip_cookie_value(&mut h, "tok");
        assert!(h.get(header::COOKIE).is_none());
    }
}
