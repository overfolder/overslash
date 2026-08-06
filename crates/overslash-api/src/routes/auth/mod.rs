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
    AppState,
    error::AppError,
    extractors::{ClientIp, ReqExt},
    services::{jwt, oauth, org_signin},
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

mod dev_token;
mod magic_link;
mod providers;
mod provisioning;
mod session;
mod userinfo;

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
    Some(format!("{scheme}://{slug}.{apex}{port_suffix}{path}"))
}

/// If login originated on a corp subdomain, build an absolute redirect to
/// the org's app host so the user lands back where they started. Returns
/// `path` unchanged when there's no subdomain context.
fn absolute_redirect_for_org(state: &AppState, headers: &HeaderMap, path: &str) -> String {
    let Some(slug) = extract_cookie(headers, "oss_auth_org").filter(|s| s != "none") else {
        return path.to_string();
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
    let mut value = format!("oss_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800");
    if let Some(domain) = state.config.session_cookie_domain.as_deref() {
        value.push_str(&format!("; Domain={domain}"));
    }
    value
        .parse()
        .map_err(|e| AppError::Internal(format!("build session cookie: {e}")))
}

/// Only allow same-origin path redirects to prevent open-redirect abuse
/// via the `?next=` parameter on IdP login.
fn sanitize_next(raw: &str) -> Option<String> {
    if raw.starts_with('/') && !raw.starts_with("//") && !raw.contains('\r') && !raw.contains('\n')
    {
        Some(raw.to_string())
    } else {
        None
    }
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(&format!("{name}=")) {
            return Some(value.to_string());
        }
    }
    None
}

pub(crate) fn signing_key_bytes(signing_key: &str) -> Vec<u8> {
    crate::services::jwt::signing_key_bytes(signing_key)
}
