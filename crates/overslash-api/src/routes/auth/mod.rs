//! Authentication routes: provider OAuth login/callback, passwordless
//! magic-link, session + multi-org account endpoints, dev token, and user
//! provisioning.

use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::{
    AppState, cookies,
    error::AppError,
    extractors::{ClientIp, ReqExt},
    services::{jwt, oauth, org_signin, user_sessions},
};
use base64::Engine as _;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::{magic_link_token, membership, oauth_provider, org, user as user_repo};
use overslash_db::{OrgScope, SystemScope};
use rand::RngExt as _;
use sha2::{Digest as _, Sha256};

/// How long a `oauth_preview_origins` row lives — must comfortably exceed
/// the slowest realistic IdP round-trip (Google login can take 30 s if MFA
/// is involved, plus an unhurried human picking an account).
const PREVIEW_ORIGIN_TTL_SECS: i64 = 600;
/// One-time handoff codes are exchanged for a session cookie within seconds
/// of the OAuth callback. A short TTL keeps the redemption window tight if
/// the redirect URL is ever logged or intercepted.
const PREVIEW_HANDOFF_CODE_TTL_SECS: i64 = 60;

mod account_sessions;
mod dev_token;
pub(crate) mod google_directory_connect;
mod magic_link;
mod providers;
mod provisioning;
mod session;
mod userinfo;

use account_sessions::{list_sessions, revoke_other_sessions, revoke_session};
use dev_token::dev_token;
use magic_link::{request_magic_link, verify_magic_link};
use providers::{
    google_callback_compat, google_login_compat, handoff_consume, list_auth_providers,
    provider_callback, provider_login,
};
use session::{
    drop_account_membership, get_email_preferences, list_account_memberships, logout, me,
    me_identity, put_email_preferences, switch_org,
};

pub fn router() -> Router<AppState> {
    Router::new()
        // Generic provider auth
        .route("/auth/login/{provider_key}", get(provider_login))
        .route("/auth/callback/{provider_key}", get(provider_callback))
        .route("/auth/providers", get(list_auth_providers))
        // Passwordless email magic-link login (root apex only). Request mints
        // a hashed, short-TTL, single-use token and emails the link; verify
        // claims it and provisions/loads the Overslash-backed `email` user.
        .route("/auth/magic-link/request", post(request_magic_link))
        .route("/auth/magic-link/verify", get(verify_magic_link))
        // Vercel preview-deployment handoff. 404s unless the feature is
        // explicitly enabled (OVERSLASH_ENV=dev + PREVIEW_ORIGIN_ALLOWLIST).
        // Production must never serve this — the response sets a session
        // cookie keyed to a one-time code minted in the OAuth callback.
        .route("/auth/handoff", get(handoff_consume))
        // Backward compat — Google callback must remain a real handler (not redirect)
        // because existing Google OAuth apps have this URL registered as redirect_uri
        .route("/auth/google/login", get(google_login_compat))
        .route("/auth/google/callback", get(google_callback_compat))
        // Session endpoints
        .route("/auth/me", get(me))
        .route("/auth/me/identity", get(me_identity))
        .route("/auth/dev/token", get(dev_token))
        .route("/auth/logout", post(logout))
        // Multi-org switching + account surface. See docs/design/multi_org_auth.md.
        .route("/auth/switch-org", post(switch_org))
        .route("/v1/account/memberships", get(list_account_memberships))
        .route(
            "/v1/account/memberships/{org_id}",
            axum::routing::delete(drop_account_membership),
        )
        .route(
            "/v1/account/email-preferences",
            get(get_email_preferences).put(put_email_preferences),
        )
        // Server-side sessions: list, end one, end all others (CASA 2.2.2).
        .route("/v1/account/sessions", get(list_sessions))
        .route(
            "/v1/account/sessions/revoke-others",
            post(revoke_other_sessions),
        )
        .route(
            "/v1/account/sessions/{id}",
            axum::routing::delete(revoke_session),
        )
}

// ---------------------------------------------------------------------------
// Normalized user info (provider-agnostic)
// ---------------------------------------------------------------------------

struct NormalizedUserInfo {
    provider_key: String,
    external_id: String,
    email: String,
    name: Option<String>,
    picture: Option<String>,
    /// Every other claim the IdP returned, merged from `/userinfo` and the ID
    /// token. The four fields above are what Overslash has always understood;
    /// this is what an org's *own* IdP additionally asserts, and the only
    /// consumer today is directory group sync, which reads one admin-named key
    /// out of it. Empty for providers that assert nothing extra (GitHub, magic
    /// link) — and an empty bag means "no claim", which is why sync treats it
    /// as "change nothing" rather than "member of nothing".
    claims: serde_json::Map<String, serde_json::Value>,
}

/// Absolute URL for `path` on a corp org's dashboard host,
/// `<scheme>://<slug>.<app-apex><path>`. `None` when the deployment has no
/// `APP_HOST_SUFFIX` (self-hosted single-host), which is the caller's cue to
/// keep whatever host-relative path it already had.
///
/// The **app** apex specifically, not the API one: the auth-state cookies
/// (`oss_auth_*`) and the session cookie carry `Domain=SESSION_COOKIE_DOMAIN`
/// (typically `.app.<apex>`), so a login kicked off from `<slug>.api.<apex>`
/// has its `Set-Cookie`s rejected outright by the browser and dies at the
/// callback with "missing auth nonce cookie". Anything that starts a login
/// must therefore send the user to the app host first.
///
/// Mirrors `public_url`'s port suffix when present so the e2e harness
/// (which boots the API on a random loopback port) lands on the right
/// listener. In prod `public_url` has no port (default 443/80) so this is
/// a no-op.
pub(crate) fn org_app_url(state: &AppState, slug: &str, path: &str) -> Option<String> {
    let apex = state.config.app_host_suffix.as_deref()?;
    Some(slug_host_url(state, slug, apex, path))
}

/// The MCP endpoint an agent of `org` should be pointed at — what the
/// dashboard's "Connect an agent" tip renders (`ownMcpUrlFor`), built
/// server-side for surfaces with no browser origin to go on (the invite
/// email).
///
/// On a subdomain deployment a corp org gets `<slug>.<api apex>/mcp`: per
/// D26 the subdomain is an enforced enrollment lock, so the agent lands in
/// this org. Personal orgs aren't reachable by subdomain
/// (`personal_org_unreachable`), and a single-host deployment has no
/// subdomains at all — both fall back to the dashboard origin's `/mcp`,
/// which serves (or rewrites to) the API.
pub(crate) fn org_mcp_url(state: &AppState, org: &overslash_db::repos::org::OrgRow) -> String {
    match state.config.api_host_suffix.as_deref() {
        Some(apex) if !org.is_personal => slug_host_url(state, &org.slug, apex, "/mcp"),
        _ => state.config.dashboard_url_for("/mcp"),
    }
}

/// `<scheme>://<slug>.<apex><port><path>`, with scheme and port taken from
/// `public_url` (see [`org_app_url`]).
fn slug_host_url(state: &AppState, slug: &str, apex: &str, path: &str) -> String {
    let scheme = if state.config.public_url.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    let port_suffix = state
        .config
        .public_url
        .rsplit_once('/')
        .map(|(_, host)| host)
        .unwrap_or(state.config.public_url.as_str())
        .rsplit_once(':')
        .map(|(_, port)| format!(":{port}"))
        .unwrap_or_default();
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    format!("{scheme}://{slug}.{apex}{port_suffix}{path}")
}

/// If login originated on a corp subdomain, build an absolute redirect to
/// the org's app host so the user lands back where they started. Without a
/// subdomain context, see [`landing_url`].
fn absolute_redirect_for_org(state: &AppState, headers: &HeaderMap, path: &str) -> String {
    let Some(slug) = cookies::read(headers, state, cookies::AUTH_ORG).filter(|s| s != "none")
    else {
        return landing_url(&state.config, path);
    };
    org_app_url(state, &slug, path).unwrap_or_else(|| path.to_string())
}

/// Build the absolute URL the dashboard should hard-reload to after a
/// successful switch. Personal orgs live at the apex; corp orgs live at
/// `<slug>.<apex>`. When no apex is configured (self-hosted single-host),
/// fall back to `dashboard_url` so the caller stays on the current origin.
pub(crate) fn build_org_redirect(
    state: &AppState,
    org: &overslash_db::repos::org::OrgRow,
) -> String {
    let scheme = if state.config.public_url.starts_with("https://") {
        "https"
    } else {
        "http"
    };
    if let Some(apex) = state.config.app_host_suffix.as_deref() {
        if org.is_personal {
            format!("{scheme}://{apex}/")
        } else {
            format!("{scheme}://{}.{apex}/", org.slug)
        }
    } else {
        // No subdomain deployment — keep the caller on the configured
        // dashboard URL, same as logout/redirect elsewhere.
        state.config.dashboard_url_for("/")
    }
}

/// Construct the `Set-Cookie` value for the session token, honoring the
/// configured cookie Domain for cross-subdomain sessions.
pub(crate) fn session_cookie(
    state: &AppState,
    token: &str,
) -> Result<header::HeaderValue, AppError> {
    cookies::set_for(
        state,
        cookies::SESSION,
        token,
        "/",
        cookies::SESSION_MAX_AGE,
    )
    .parse()
    .map_err(|e| AppError::Internal(format!("build session cookie: {e}")))
}

/// Post-login targets the API itself serves: the MCP authorization server
/// resuming (`/oauth/authorize`) and the OAuth-connect gates. Everything else
/// a `next` carries is a dashboard page — including `/oauth/consent`.
const API_LANDINGS: &[&str] = &[
    "/oauth/authorize",
    "/connect-authorize",
    "/gated-authorize",
    "/auth/",
];

/// Where a post-login `next` path lands when there's no org subdomain to
/// return to. A dashboard page (e.g. an approval deep link the login page
/// carried over from `return_to`) must resolve against `dashboard_url`: on a
/// split-host deployment that's a different origin from the API host the
/// callback landed on, and a bare path would 404 there. API routes stay
/// relative to the API. A relative `dashboard_url` means one host serves
/// both, so the path is already right; absolute URLs (the `dashboard_url`
/// fallback itself) pass through too.
fn landing_url(config: &crate::config::Config, path: &str) -> String {
    let dash = &config.dashboard_url;
    let split_host = dash.starts_with("http://") || dash.starts_with("https://");
    let api_route = API_LANDINGS.iter().any(|p| path.starts_with(p));
    if split_host && path.starts_with('/') && !api_route {
        config.dashboard_url_for(path)
    } else {
        path.to_string()
    }
}

/// Only allow same-origin path redirects to prevent open-redirect abuse
/// via the `?next=` parameter on IdP login. Browsers read a backslash in a
/// `Location` as a slash, so `/\evil.com` would leave the site like
/// `//evil.com` — reject backslashes and control characters outright.
fn sanitize_next(raw: &str) -> Option<String> {
    if raw.starts_with('/')
        && !raw.starts_with("//")
        && !raw.contains('\\')
        && !raw.chars().any(char::is_control)
    {
        Some(raw.to_string())
    } else {
        None
    }
}

pub(crate) fn signing_key_bytes(signing_key: &str) -> Vec<u8> {
    crate::services::jwt::signing_key_bytes(signing_key)
}

#[cfg(test)]
mod tests {
    use super::{landing_url, sanitize_next};
    use crate::config::tests::empty_test_config;

    fn split_host() -> crate::config::Config {
        let mut c = empty_test_config();
        c.public_url = "http://api.test".into();
        c.dashboard_url = "http://app.test".into();
        c
    }

    #[test]
    fn dashboard_pages_land_on_the_dashboard_host() {
        let c = split_host();
        assert_eq!(
            landing_url(&c, "/approvals/abc?org=x"),
            "http://app.test/approvals/abc?org=x"
        );
        assert_eq!(
            landing_url(&c, "/oauth/consent?request_id=r"),
            "http://app.test/oauth/consent?request_id=r"
        );
    }

    #[test]
    fn api_routes_stay_on_the_api_host() {
        let c = split_host();
        for path in ["/oauth/authorize?client_id=c", "/connect-authorize?id=1"] {
            assert_eq!(landing_url(&c, path), path);
        }
    }

    #[test]
    fn single_host_and_absolute_targets_are_untouched() {
        let mut c = empty_test_config();
        c.dashboard_url = "/".into();
        assert_eq!(landing_url(&c, "/approvals/abc"), "/approvals/abc");
        let c = split_host();
        assert_eq!(landing_url(&c, "http://app.test"), "http://app.test");
    }

    #[test]
    fn next_accepts_same_origin_paths() {
        assert_eq!(
            sanitize_next("/approvals/abc?org=x").as_deref(),
            Some("/approvals/abc?org=x")
        );
    }

    #[test]
    fn next_rejects_off_site_targets() {
        for raw in [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "/\\/evil.com",
            "/a\r\nSet-Cookie: x=1",
            "/a\tb",
            "evil.com",
        ] {
            assert_eq!(sanitize_next(raw), None, "{raw:?}");
        }
    }
}
