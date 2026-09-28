//! Every cookie Overslash sets or reads goes through here (CASA 2.3.1).
//!
//! Callers name a cookie by its *base* (`oss_session`, `oss_auth_nonce`, …);
//! the wire name carries a prefix the browser enforces:
//!
//! - `SESSION_COOKIE_DOMAIN` set → `__Secure-<base>`, `Domain=<d>`, the
//!   caller's Path. `__Secure-` is the strongest prefix a Domain cookie can
//!   carry.
//! - unset → `__Host-<base>`, no Domain, and `Path=/` regardless of what the
//!   caller asked for — `__Host-` requires both.
//!
//! Every cookie is `HttpOnly; SameSite=Lax; Secure`. Browsers accept `Secure`
//! (and both prefixes) on `http://localhost` / `http://127.0.0.1`, so local
//! dev and e2e keep working; any other plain-http origin loses its session,
//! which is the point.
//!
//! The unprefixed names are never read. Browsers still holding a pre-rename
//! `oss_session` get it cleared by [`legacy_session_clears`] on login and
//! logout.

use axum::http::{HeaderMap, HeaderValue, header};

use crate::AppState;

/// Dashboard session JWT.
pub const SESSION: &str = "oss_session";
/// IdP login state, set at `/auth/login/{provider}` and read at the callback.
pub const AUTH_NONCE: &str = "oss_auth_nonce";
pub const AUTH_VERIFIER: &str = "oss_auth_verifier";
pub const AUTH_ORG: &str = "oss_auth_org";
pub const AUTH_NEXT: &str = "oss_auth_next";

/// Session lifetime; matches the JWT `exp` the minting sites stamp.
pub const SESSION_MAX_AGE: i64 = 7 * 24 * 3600;
/// Auth-state cookies only need to survive one IdP round-trip.
pub const AUTH_STATE_MAX_AGE: i64 = 600;
/// Path the auth-state cookies are scoped to when a Domain allows it.
pub const AUTH_STATE_PATH: &str = "/auth";

/// The wire name of `base` for a deployment whose cookie Domain is `domain`.
pub fn name(base: &str, domain: Option<&str>) -> String {
    match domain {
        Some(_) => format!("__Secure-{base}"),
        None => format!("__Host-{base}"),
    }
}

/// Build a `Set-Cookie` value. `path` is honoured only for `__Secure-`
/// cookies; `__Host-` ones are always `Path=/`.
pub fn build(base: &str, value: &str, domain: Option<&str>, path: &str, max_age: i64) -> String {
    let name = name(base, domain);
    let path = if domain.is_some() { path } else { "/" };
    let mut out =
        format!("{name}={value}; HttpOnly; SameSite=Lax; Secure; Path={path}; Max-Age={max_age}");
    if let Some(domain) = domain {
        out.push_str(&format!("; Domain={domain}"));
    }
    out
}

/// The matching clear for [`build`]: same name, Path and Domain, or the
/// browser keeps its copy.
pub fn clear(base: &str, domain: Option<&str>, path: &str) -> String {
    build(base, "", domain, path, 0)
}

/// Clears for the pre-prefix `oss_session`. It may have been set with or
/// without a Domain, and a clear only matches its own Domain, so send both.
pub fn legacy_session_clears(domain: Option<&str>) -> Vec<String> {
    let bare = format!("{SESSION}=; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age=0");
    let mut out = vec![bare.clone()];
    if let Some(domain) = domain {
        out.push(format!("{bare}; Domain={domain}"));
    }
    out
}

fn domain(state: &AppState) -> Option<&str> {
    state.config.session_cookie_domain.as_deref()
}

/// Wire name of `base` under this deployment's config.
pub fn name_for(state: &AppState, base: &str) -> String {
    name(base, domain(state))
}

/// `Set-Cookie` for `base` under this deployment's config.
pub fn set_for(state: &AppState, base: &str, value: &str, path: &str, max_age: i64) -> String {
    build(base, value, domain(state), path, max_age)
}

/// Clear for `base` under this deployment's config.
pub fn clear_for(state: &AppState, base: &str, path: &str) -> String {
    clear(base, domain(state), path)
}

/// The session `Set-Cookie`, host-only — the Vercel preview handoff, where
/// the browser's origin is a `*.vercel.app` host no Domain could cover.
pub fn host_only_session(value: &str) -> String {
    build(SESSION, value, None, "/", SESSION_MAX_AGE)
}

/// Legacy `oss_session` clears under this deployment's config.
pub fn legacy_session_clears_for(state: &AppState) -> Vec<String> {
    legacy_session_clears(domain(state))
}

/// Append every clear in `values` to `headers` as a `Set-Cookie`.
pub fn append_all(headers: &mut HeaderMap, values: impl IntoIterator<Item = String>) {
    for v in values {
        // Built from constants and config the operator controls; a value
        // that won't parse is a config error, not a request error.
        if let Ok(hv) = HeaderValue::from_str(&v) {
            headers.append(header::SET_COOKIE, hv);
        }
    }
}

/// Raw value of the cookie literally named `name`.
pub fn extract(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie_header.split(';').find_map(|pair| {
        pair.trim()
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
            .map(str::to_string)
    })
}

/// Value of `base` under this deployment's wire name.
pub fn read(headers: &HeaderMap, state: &AppState, base: &str) -> Option<String> {
    extract(headers, &name_for(state, base))
}

/// The session JWT, if the request carries one. Tries the configured name,
/// then the host-only `__Host-oss_session` the preview handoff sets on a
/// deployment that otherwise uses a Domain. Never the unprefixed name.
pub fn read_session(headers: &HeaderMap, state: &AppState) -> Option<String> {
    read_session_with(headers, domain(state))
}

fn read_session_with(headers: &HeaderMap, domain: Option<&str>) -> Option<String> {
    extract(headers, &name(SESSION, domain)).or_else(|| extract(headers, &name(SESSION, None)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_only_cookie_is_host_prefixed_with_root_path() {
        let c = build(AUTH_NONCE, "n", None, AUTH_STATE_PATH, 600);
        assert_eq!(
            c,
            "__Host-oss_auth_nonce=n; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age=600"
        );
        assert!(!c.contains("Domain"));
    }

    #[test]
    fn domain_cookie_is_secure_prefixed_and_keeps_path() {
        let c = build(
            AUTH_NONCE,
            "n",
            Some(".app.example.com"),
            AUTH_STATE_PATH,
            600,
        );
        assert_eq!(
            c,
            "__Secure-oss_auth_nonce=n; HttpOnly; SameSite=Lax; Secure; Path=/auth; Max-Age=600; Domain=.app.example.com"
        );
    }

    #[test]
    fn clear_matches_build_attributes() {
        assert_eq!(
            clear(SESSION, Some(".d"), "/"),
            "__Secure-oss_session=; HttpOnly; SameSite=Lax; Secure; Path=/; Max-Age=0; Domain=.d"
        );
    }

    #[test]
    fn legacy_clears_cover_both_domain_forms() {
        assert_eq!(legacy_session_clears(None).len(), 1);
        let both = legacy_session_clears(Some(".d"));
        assert_eq!(both.len(), 2);
        assert!(both.iter().all(|c| c.starts_with("oss_session=;")));
        assert!(both[1].ends_with("Domain=.d"));
    }

    fn cookie_headers(cookie: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, cookie.parse().unwrap());
        h
    }

    #[test]
    fn session_reader_never_accepts_the_unprefixed_name() {
        let h = cookie_headers("oss_session=legacy");
        assert_eq!(read_session_with(&h, None), None);
        assert_eq!(read_session_with(&h, Some(".d")), None);
    }

    #[test]
    fn session_reader_prefers_configured_name_then_host_only() {
        let both = cookie_headers("__Host-oss_session=preview; __Secure-oss_session=main");
        assert_eq!(
            read_session_with(&both, Some(".d")).as_deref(),
            Some("main")
        );
        let preview = cookie_headers("__Host-oss_session=preview");
        assert_eq!(
            read_session_with(&preview, Some(".d")).as_deref(),
            Some("preview")
        );
        // A host-only deployment has no reason to honour `__Secure-`: a
        // sibling subdomain could plant one.
        let secure = cookie_headers("__Secure-oss_session=main");
        assert_eq!(read_session_with(&secure, None), None);
    }

    #[test]
    fn extract_matches_whole_names_only() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            "oss_session=old; __Host-oss_session_x=nope; __Host-oss_session=new"
                .parse()
                .unwrap(),
        );
        assert_eq!(extract(&h, "__Host-oss_session").as_deref(), Some("new"));
        assert_eq!(extract(&h, "oss_session").as_deref(), Some("old"));
    }
}
