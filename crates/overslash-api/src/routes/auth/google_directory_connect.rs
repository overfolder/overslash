//! "Sign in with Google" to connect an org's Google Workspace Directory.
//!
//! Every org syncs through the instance's one service account, so every
//! connected Workspace has delegated to the same client ID and Google no
//! longer tells tenants apart. This flow is how Overslash does: an org admin
//! signs in with Google as an admin of the Workspace, and what Google returns
//! — the `hd` (hosted domain) and the verified email — becomes the config.
//! Nothing about the Workspace is typed.
//!
//! It rides the login's registered redirect URI (`/auth/callback/google`) with
//! a `gdir:<flow id>` state, so operators register nothing new. The flow row
//! is single-use and bound to the admin who started it; the callback refuses
//! any browser whose live session is someone else's. Without that binding an
//! org admin could mail the auth link to a victim Workspace's admin and attach
//! the victim's directory to their own org.

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use uuid::Uuid;

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::{google_directory_config, oauth_provider, org};

use super::userinfo::{fetch_userinfo, resolve_auth_credentials};
use crate::services::directory_sync::email_domain;
use crate::services::google_directory::{DirectoryClient, DirectoryError};
use crate::services::{oauth, session, user_sessions};
use crate::{AppState, error::AppError};

/// OAuth `state` prefix the login callback hands off on.
pub(crate) const STATE_PREFIX: &str = "gdir:";
/// How long an admin has to finish signing in.
const FLOW_TTL_SECS: i64 = 600;
/// Where the dashboard shows the result.
const SETTINGS_PATH: &str = "/org/google-directory";

/// Why a connect was refused. The code rides the redirect back to the
/// dashboard, which owns the wording; it is an allow-list, never upstream
/// text, so nothing from Google or the browser is reflected into a URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectError {
    /// Unknown, used or expired flow.
    Expired,
    /// The admin backed out at Google's consent screen.
    Cancelled,
    /// The browser finishing the flow is not the admin who started it.
    WrongSession,
    /// A personal Google account: no `hd`, so no Workspace to sync.
    NotWorkspace,
    EmailUnverified,
    /// Signed in with an account on a secondary domain. `hd` is always the
    /// Workspace's primary domain, which is what the sync matches on.
    NotPrimaryDomain,
    /// Another org on this instance already connected this Workspace.
    DomainTaken,
    /// Google refused the instance service account for this Workspace.
    DelegationMissing,
    /// The signed-in account is not an admin who can read groups.
    NotAdmin,
    /// Anything else Google said.
    Google,
}

impl ConnectError {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::WrongSession => "wrong_session",
            Self::NotWorkspace => "not_workspace",
            Self::EmailUnverified => "email_unverified",
            Self::NotPrimaryDomain => "not_primary_domain",
            Self::DomainTaken => "domain_taken",
            Self::DelegationMissing => "delegation_missing",
            Self::NotAdmin => "not_admin",
            Self::Google => "google_error",
        }
    }
}

/// Mint the Google authorization URL for `identity_id` to connect `org_id`.
///
/// Refuses (409) when the instance has no service account, or no Google
/// sign-in client to prove the Workspace with.
pub(crate) async fn start(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    identity_id: Uuid,
) -> Result<String, AppError> {
    if state.config.google_directory.service_account.is_none() {
        return Err(AppError::Conflict(
            "this Overslash instance has no Google Directory service account configured".into(),
        ));
    }
    let provider = oauth_provider::get_by_key(state.db(ext), "google")
        .await?
        .ok_or_else(|| AppError::Conflict("Google sign-in is not available".into()))?;
    // Instance-level Google client (no org slug): the one the operator
    // registered `/auth/callback/google` on. An org's own Google IdP config
    // is not used — this proves a Workspace to the instance, not a login.
    let (client_id, _) = resolve_auth_credentials(state, ext, "google", None)
        .await
        .map_err(|_| {
            AppError::Conflict(
                "Google sign-in is not configured on this Overslash instance \
                 (GOOGLE_AUTH_CLIENT_ID / GOOGLE_AUTH_CLIENT_SECRET)"
                    .into(),
            )
        })?;

    let pkce = oauth::generate_pkce();
    let flow_id = scope
        .create_google_directory_connect_flow(identity_id, &pkce.verifier, FLOW_TTL_SECS)
        .await?;

    let redirect_uri = format!("{}/auth/callback/google", state.config.public_url);
    Ok(oauth::build_auth_url(
        &provider,
        &client_id,
        &redirect_uri,
        &["openid".to_string(), "email".to_string()],
        &format!("{STATE_PREFIX}{flow_id}"),
        Some(&pkce.challenge),
        None,
    ))
}

/// Finish a connect from the Google callback. Always answers with a redirect
/// to the dashboard's Google Workspace settings page, carrying either
/// `google_directory=connected` or `google_directory_error=<code>`.
pub(crate) async fn finish(
    state: &AppState,
    ext: &axum::http::Extensions,
    headers: &HeaderMap,
    flow_id: &str,
    code: Option<&str>,
) -> Result<Response, AppError> {
    let Ok(flow_id) = Uuid::parse_str(flow_id) else {
        return Ok(back(state, None, Err(ConnectError::Expired)));
    };
    let Some(flow) = google_directory_config::take_connect_flow(state.db(ext), flow_id).await?
    else {
        return Ok(back(state, None, Err(ConnectError::Expired)));
    };
    let org_row = org::get_by_id(state.db(ext), flow.org_id).await?;
    let slug = org_row.as_ref().map(|o| o.slug.as_str());
    // Consent refused: the flow is spent either way (taken above).
    let Some(code) = code else {
        return Ok(back(state, slug, Err(ConnectError::Cancelled)));
    };

    // The browser must be the admin who started this, with a live session.
    let session_ok = match session::extract_session(state, headers) {
        Some(claims) if claims.sub == flow.identity_id && claims.org == flow.org_id => {
            matches!(
                user_sessions::check(state, ext, &claims).await?,
                user_sessions::Verdict::Live
            )
        }
        _ => false,
    };
    if !session_ok {
        return Ok(back(state, slug, Err(ConnectError::WrongSession)));
    }

    match prove_and_connect(state, ext, &flow, code).await? {
        Ok((domain, admin)) => {
            let scope = OrgScope::new(flow.org_id, state.db_pool(ext));
            let _ = scope
                .log_audit(AuditEntry {
                    org_id: flow.org_id,
                    identity_id: Some(flow.identity_id),
                    action: "google_directory.connected",
                    resource_type: Some("google_directory"),
                    resource_id: None,
                    detail: serde_json::json!({ "domain": domain, "admin_subject": admin }),
                    description: None,
                    ip_address: None,
                })
                .await;
            Ok(back(state, slug, Ok(())))
        }
        Err(e) => Ok(back(state, slug, Err(e))),
    }
}

/// Exchange the code, read who signed in, check they are an admin of a
/// Workspace this instance can read, and record it. `Ok(Err(_))` is a refusal
/// the admin can act on; `Err(_)` is a fault.
async fn prove_and_connect(
    state: &AppState,
    ext: &axum::http::Extensions,
    flow: &google_directory_config::ConnectFlow,
    code: &str,
) -> Result<Result<(String, String), ConnectError>, AppError> {
    let provider = oauth_provider::get_by_key(state.db(ext), "google")
        .await?
        .ok_or_else(|| AppError::Internal("google provider missing".into()))?;
    let (client_id, client_secret) = resolve_auth_credentials(state, ext, "google", None).await?;
    let redirect_uri = format!("{}/auth/callback/google", state.config.public_url);
    let tokens = match oauth::exchange_code(
        &state.http_client,
        &provider,
        &client_id,
        &client_secret,
        code,
        &redirect_uri,
        Some(&flow.pkce_verifier),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "google directory connect: code exchange failed");
            return Ok(Err(ConnectError::Google));
        }
    };
    // `/userinfo`, fetched directly with the access token we were just
    // issued — the source of `hd` and `email_verified`.
    let info = match fetch_userinfo(
        &state.http_client,
        &provider,
        "google",
        &tokens.access_token,
        None,
        None,
    )
    .await
    {
        Ok(info) => info,
        // Google-side trouble, like a failed exchange: the admin gets sent
        // back with a reason to retry, not a bare error page.
        Err(e) => {
            tracing::warn!(error = %e, "google directory connect: userinfo failed");
            return Ok(Err(ConnectError::Google));
        }
    };

    let Some(hd) = info
        .claims
        .get("hd")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
    else {
        return Ok(Err(ConnectError::NotWorkspace));
    };
    let verified = info
        .claims
        .get("email_verified")
        .is_some_and(|v| v.as_bool() == Some(true) || v.as_str() == Some("true"));
    let email = info.email.trim().to_lowercase();
    if !verified {
        return Ok(Err(ConnectError::EmailUnverified));
    }
    if email_domain(&email).as_deref() != Some(hd.as_str()) {
        return Ok(Err(ConnectError::NotPrimaryDomain));
    }

    // Can the instance service account read this Workspace as this admin?
    // That is both the delegation check and the admin check.
    let key = state
        .config
        .google_directory
        .service_account
        .as_ref()
        .ok_or_else(|| AppError::Conflict("no Google Directory service account".into()))?;
    let probe = match DirectoryClient::connect(state, key, &email).await {
        Ok(client) => client.probe("my_customer").await,
        Err(e) => Err(e),
    };
    if let Err(e) = probe {
        tracing::info!(error = %e, %hd, "google directory connect: probe refused");
        return Ok(Err(match e {
            DirectoryError::TokenRejected { ref code, .. } if code == "unauthorized_client" => {
                ConnectError::DelegationMissing
            }
            DirectoryError::Api { status: 403, .. } => ConnectError::NotAdmin,
            DirectoryError::TokenRejected { .. } => ConnectError::NotAdmin,
            _ => ConnectError::Google,
        }));
    }

    // Reconnecting as a different Workspace replaces the old one atomically
    // inside `connect` — its groups are not this one's.
    let scope = OrgScope::new(flow.org_id, state.db_pool(ext));
    match scope
        .connect_google_directory(&email, &hd, flow.identity_id)
        .await
    {
        Ok(_) => Ok(Ok((hd, email))),
        Err(sqlx::Error::Database(db)) if db.is_unique_violation() => {
            Ok(Err(ConnectError::DomainTaken))
        }
        Err(e) => Err(e.into()),
    }
}

/// The dashboard's Google Workspace settings page, on the org's own host when
/// the deployment has one.
fn back(state: &AppState, slug: Option<&str>, outcome: Result<(), ConnectError>) -> Response {
    let query = match outcome {
        Ok(()) => "google_directory=connected".to_string(),
        Err(e) => format!("google_directory_error={}", e.code()),
    };
    let path = format!("{SETTINGS_PATH}?{query}");
    let url = slug
        .and_then(|s| super::org_app_url(state, s, &path))
        .unwrap_or_else(|| {
            let base = state.config.dashboard_url.trim_end_matches('/');
            format!("{base}{path}")
        });
    Redirect::to(&url).into_response()
}
