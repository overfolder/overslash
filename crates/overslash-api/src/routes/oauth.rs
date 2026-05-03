//! OAuth 2.1 Authorization Server endpoints backing the MCP transport.
//!
//! Wired from `docs/design/mcp-oauth-transport.md`.
//!
//! - `POST /oauth/register` — RFC 7591 Dynamic Client Registration.
//!   Open by default; clients are public (PKCE), no `client_secret` issued.
//! - `GET  /oauth/authorize` — OAuth 2.1 §4.1 + PKCE (S256). Bounces through
//!   the existing IdP login if no `oss_session` cookie is present, then
//!   returns a one-shot authorization code bound to the client_id + challenge.
//! - `POST /oauth/token` — `authorization_code` and `refresh_token` grants.
//!   Refresh rotation is single-use per OAuth 2.1 BCP; reuse of a revoked
//!   refresh token revokes the entire chain (replay detection).
//! - `POST /oauth/revoke` — RFC 7009. Revokes a refresh token. Access
//!   tokens are JWT-based (stateless) so revocation there is best-effort.

use std::time::Instant;

use axum::{
    Form, Json, Router,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    AppState,
    error::AppError,
    middleware::subdomain::RequestOrgContext,
    services::{jwt, oauth_as, session},
};
use overslash_db::repos::{
    identity, mcp_client_agent_binding, mcp_refresh_token, oauth_mcp_client, org_idp_config,
};
use overslash_db::scopes::OrgScope;

/// Public OAuth Authorization Server endpoints (RFC 7591 / OAuth 2.1).
///
/// These are reached cross-origin by external OAuth clients — including
/// browser-based debug tools like MCP Inspector — so they sit under the
/// wider `cors_mcp` layer in `lib.rs` (origins = `dashboard_origin` ∪
/// `mcp_extra_origins`). Nothing here returns user data without a
/// preceding consent step, which is gated by `consent_router` below
/// under the tighter `cors_global` layer.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/oauth/register", post(register))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
}

/// Dashboard-facing consent UI helpers. The dashboard fetches the
/// consent context and posts the user's decision back here while a
/// `/oauth/authorize` request is paused mid-flow. These leak the
/// pending request's metadata to whoever can read the response, so
/// they MUST stay behind the tight `cors_global` layer that only
/// trusts the dashboard origin — never the MCP Inspector origin.
pub fn consent_router() -> Router<AppState> {
    Router::new()
        .route("/v1/oauth/consent/{request_id}", get(consent_context))
        .route(
            "/v1/oauth/consent/{request_id}/finish",
            post(consent_finish),
        )
}

// ---------------------------------------------------------------------------
// Error shape (RFC 6749 §5.2)
// ---------------------------------------------------------------------------

fn oauth_error(status: StatusCode, code: &'static str, desc: impl Into<String>) -> Response {
    (
        status,
        Json(json!({ "error": code, "error_description": desc.into() })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Dynamic Client Registration (RFC 7591)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RegisterRequest {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    software_id: Option<String>,
    software_version: Option<String>,
    token_endpoint_auth_method: Option<String>,
    // All other RFC 7591 fields are accepted but ignored for v1.
    #[serde(flatten)]
    _extra: std::collections::HashMap<String, Value>,
}

async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Response {
    if req.redirect_uris.is_empty() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "at least one redirect_uri is required",
        );
    }
    for uri in &req.redirect_uris {
        if uri.contains(char::is_whitespace) || uri.is_empty() {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_redirect_uri",
                "redirect_uri must be a non-empty URL with no whitespace",
            );
        }
    }
    if let Some(method) = req.token_endpoint_auth_method.as_deref() {
        if method != "none" {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_client_metadata",
                "only public clients are supported (token_endpoint_auth_method=none)",
            );
        }
    }

    let client_id = oauth_as::generate_client_id();
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(512).collect::<String>());
    // Behind a reverse proxy, use X-Forwarded-For; direct calls don't
    // expose the socket addr here (we intentionally keep ConnectInfo out
    // of the handler signature so the route works in tests that don't
    // attach ConnectInfo).
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string());

    let row = match oauth_mcp_client::create(
        &state.db,
        &oauth_mcp_client::CreateOauthMcpClient {
            client_id: &client_id,
            client_name: req.client_name.as_deref(),
            redirect_uris: &req.redirect_uris,
            software_id: req.software_id.as_deref(),
            software_version: req.software_version.as_deref(),
            created_ip: ip.as_deref(),
            created_user_agent: ua.as_deref(),
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("DCR insert failed: {e}");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to register client",
            );
        }
    };

    // RFC 7591 metadata fields are optional. Claude Code's DCR client (Zod
    // schema) rejects explicit `null`s — omit unset fields entirely rather
    // than serialising Option<String>::None into `null`.
    let mut body = serde_json::Map::new();
    body.insert("client_id".into(), json!(row.client_id));
    body.insert("redirect_uris".into(), json!(row.redirect_uris));
    body.insert("token_endpoint_auth_method".into(), json!("none"));
    body.insert(
        "grant_types".into(),
        json!(["authorization_code", "refresh_token"]),
    );
    body.insert("response_types".into(), json!(["code"]));
    if let Some(v) = row.client_name.as_deref() {
        body.insert("client_name".into(), json!(v));
    }
    if let Some(v) = row.software_id.as_deref() {
        body.insert("software_id".into(), json!(v));
    }
    if let Some(v) = row.software_version.as_deref() {
        body.insert("software_version".into(), json!(v));
    }

    (StatusCode::CREATED, Json(Value::Object(body))).into_response()
}

// ---------------------------------------------------------------------------
// Authorize (OAuth 2.1 §4.1 + PKCE)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AuthorizeQuery {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    code_challenge: String,
    code_challenge_method: String,
    scope: Option<String>,
    state: Option<String>,
}

async fn authorize(
    State(state): State<AppState>,
    ctx: Option<Extension<RequestOrgContext>>,
    Query(params): Query<AuthorizeQuery>,
    headers: HeaderMap,
) -> Response {
    // Older test harnesses mount the OAuth router without the subdomain
    // middleware; treat the missing extension as Root so the existing
    // env-var IdP path still works.
    let ctx = ctx.map(|Extension(c)| c).unwrap_or(RequestOrgContext::Root);
    // Reject bad params BEFORE checking auth so every failure is diagnosable.
    if params.response_type != "code" {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_response_type",
            "response_type must be \"code\"",
        );
    }
    if params.code_challenge_method != "S256" {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge_method must be S256",
        );
    }
    if params.code_challenge.is_empty() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_challenge required",
        );
    }
    if !params
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().any(|t| t == "mcp"))
        .unwrap_or(false)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            "scope must include \"mcp\"",
        );
    }

    let client = match oauth_mcp_client::get_by_client_id(&state.db, &params.client_id).await {
        Ok(Some(c)) if !c.is_revoked => c,
        Ok(_) => {
            return oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "unknown or revoked client",
            );
        }
        Err(e) => {
            tracing::error!("DCR lookup failed: {e}");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to look up client",
            );
        }
    };
    if !client
        .redirect_uris
        .iter()
        .any(|r| r == &params.redirect_uri)
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_redirect_uri",
            "redirect_uri does not match any registered URI",
        );
    }

    // Bounce through IdP login if not signed in.
    let session_claims = match session::extract_session(&state, &headers) {
        Some(c) => c,
        None => {
            let authorize_path = rebuild_authorize_path(&params);
            let next = urlencoding::encode(&authorize_path);
            match default_idp_provider_for_request(&state, &ctx).await {
                IdpBounce::Provider(provider) => {
                    // Dev login is a separate endpoint, not the generic
                    // /auth/login/{provider_key} path (which requires an
                    // oauth_providers DB row).
                    let login = if provider == "dev" {
                        format!("/auth/dev/token?next={next}")
                    } else {
                        format!("/auth/login/{provider}?next={next}")
                    };
                    return Redirect::to(&login).into_response();
                }
                IdpBounce::Picker => {
                    // Corp subdomain with multiple enabled IdPs and no
                    // designated default — let the user pick. The dashboard
                    // login page calls /auth/providers and renders the list.
                    return Redirect::to(&format!("/login?next={next}")).into_response();
                }
                IdpBounce::None => {
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "login_required",
                        "no IdP is configured for this org",
                    );
                }
            }
        }
    };

    // Fast path: if this (user, client_id) already has an enrolled agent,
    // skip the consent screen and issue a code bound to that agent. The
    // lookup failure-mode is "fall through to consent" rather than 500 so
    // a transient DB blip doesn't lock the user out of authentication.
    if let Ok(Some(binding)) =
        mcp_client_agent_binding::get_for(&state.db, session_claims.sub, &client.client_id).await
    {
        if let Ok(Some(agent)) =
            identity::get_by_id(&state.db, session_claims.org, binding.agent_identity_id).await
        {
            if agent.archived_at.is_none() && agent.kind == "agent" {
                let email = agent.email.as_deref().unwrap_or(&session_claims.email);
                return issue_authorization_code(
                    &state,
                    &client.client_id,
                    agent.id,
                    session_claims.org,
                    email,
                    &params.redirect_uri,
                    &params.code_challenge,
                    params.state.as_deref(),
                );
            }
        }
        // Binding points at an archived / missing / wrong-kind agent —
        // stale row. Fall through to consent so the user re-enrolls.
    }

    // No binding (or stale): park the authorize request and redirect to the
    // consent screen. The `request_id` lives only in memory (60s TTL) so a
    // consent submission against a stale or forged id fails closed.
    let request_id = oauth_as::generate_auth_code();
    state.pending_authorize_store.insert(
        request_id.clone(),
        oauth_as::PendingAuthorize {
            client_id: client.client_id.clone(),
            redirect_uri: params.redirect_uri.clone(),
            code_challenge: params.code_challenge.clone(),
            state_param: params.state.clone(),
            user_identity_id: session_claims.sub,
            org_id: session_claims.org,
            email: session_claims.email.clone(),
            issued_at: Instant::now(),
        },
    );
    Redirect::to(&state.config.dashboard_url_for(&format!(
        "/oauth/consent?request_id={}",
        urlencoding::encode(&request_id)
    )))
    .into_response()
}

fn rebuild_authorize_path(p: &AuthorizeQuery) -> String {
    let mut qs = format!(
        "/oauth/authorize?response_type={}&client_id={}&redirect_uri={}\
         &code_challenge={}&code_challenge_method={}",
        urlencoding::encode(&p.response_type),
        urlencoding::encode(&p.client_id),
        urlencoding::encode(&p.redirect_uri),
        urlencoding::encode(&p.code_challenge),
        urlencoding::encode(&p.code_challenge_method),
    );
    if let Some(s) = p.scope.as_deref() {
        qs.push_str(&format!("&scope={}", urlencoding::encode(s)));
    }
    if let Some(s) = p.state.as_deref() {
        qs.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    qs
}

/// Build the final authorize-code redirect back to the MCP client. Shared
/// between the fast-path in `authorize` (existing binding) and
/// `consent_finish` (newly-enrolled agent) so there's a single canonical
/// code-issuance site.
#[allow(clippy::too_many_arguments)]
fn issue_authorization_code(
    state: &AppState,
    client_id: &str,
    identity_id: Uuid,
    org_id: Uuid,
    email: &str,
    redirect_uri: &str,
    code_challenge: &str,
    state_param: Option<&str>,
) -> Response {
    let code = oauth_as::generate_auth_code();
    state.auth_code_store.insert(
        code.clone(),
        oauth_as::AuthCodeRecord {
            client_id: client_id.to_string(),
            identity_id,
            org_id,
            email: email.to_string(),
            redirect_uri: redirect_uri.to_string(),
            code_challenge: code_challenge.to_string(),
            issued_at: Instant::now(),
        },
    );
    let mut redirect = format!("{}?code={}", redirect_uri, urlencoding::encode(&code));
    if let Some(s) = state_param {
        redirect.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    Redirect::to(&redirect).into_response()
}

/// Outcome of picking an IdP to bounce an unauthenticated `/oauth/authorize`
/// caller through.
enum IdpBounce {
    /// One specific provider key — redirect straight to its login.
    Provider(String),
    /// Multiple IdPs configured for the org and none marked default — the
    /// dashboard `/login` page should render a picker.
    Picker,
    /// No IdP available at all → service-unavailable.
    None,
}

/// Pick how to bounce an unauthenticated `/oauth/authorize` caller through
/// IdP login.
///
/// On a corp subdomain (`RequestOrgContext::Org`) we honor the org's
/// designated default IdP, then fall back to the picker if any IdPs are
/// enabled. We **never** fall through to env-var (Overslash-managed) login
/// on a corp subdomain — corp subdomains are strict trust domains
/// (DECISIONS.md D12).
///
/// On the apex (`RequestOrgContext::Root`) we keep the existing env-var
/// behavior so personal-org sign-up keeps working without any DB IdP rows.
async fn default_idp_provider_for_request(state: &AppState, ctx: &RequestOrgContext) -> IdpBounce {
    match ctx {
        RequestOrgContext::Org { org_id, .. } => {
            // Designated default first.
            if let Ok(Some(row)) = org_idp_config::get_default_by_org(&state.db, *org_id).await {
                return IdpBounce::Provider(row.provider_key);
            }
            // No default but at least one enabled IdP → picker.
            match org_idp_config::list_enabled_by_org(&state.db, *org_id).await {
                Ok(rows) if !rows.is_empty() => IdpBounce::Picker,
                _ => IdpBounce::None,
            }
        }
        RequestOrgContext::Root => {
            if state.config.google_auth_client_id.is_some()
                && state.config.google_auth_client_secret.is_some()
            {
                return IdpBounce::Provider("google".into());
            }
            if state.config.github_auth_client_id.is_some()
                && state.config.github_auth_client_secret.is_some()
            {
                return IdpBounce::Provider("github".into());
            }
            if state.config.dev_auth_enabled {
                return IdpBounce::Provider("dev".into());
            }
            IdpBounce::None
        }
    }
}

// ---------------------------------------------------------------------------
// Consent (agent enrollment) — JSON API backing the dashboard
// ---------------------------------------------------------------------------
//
// When /oauth/authorize finds no prior (user, client_id) → agent binding, it
// parks the request in `pending_authorize_store` and redirects the user's
// browser to the dashboard at `/oauth/consent?request_id=...`. The dashboard
// page then calls these endpoints (same session cookie as the rest of /v1)
// to render the enrollment card and to complete the flow. The final
// authorization-code redirect back to the MCP client is done by the
// dashboard itself (window.location) based on the `redirect_uri` returned
// from `finish`.

#[derive(Serialize)]
struct ConsentClientInfo {
    client_name: Option<String>,
    software_id: Option<String>,
    software_version: Option<String>,
    elicitation_supported: bool,
}

#[derive(Serialize)]
struct ConsentConnectionInfo {
    ip: Option<String>,
}

#[derive(Serialize)]
struct ConsentParentOption {
    id: Uuid,
    name: String,
    kind: String,
    is_you: bool,
}

#[derive(Serialize)]
struct ConsentGroupOption {
    id: Uuid,
    name: String,
    member_count: i64,
}

#[derive(Serialize)]
struct ConsentReauthTarget {
    agent_id: Uuid,
    agent_name: String,
    parent_id: Option<Uuid>,
    parent_name: Option<String>,
    last_seen_at: Option<String>,
    /// Pre-fill for the elicitation toggle on the consent page so a reauth
    /// doesn't silently flip a user's previously-saved choice back to the
    /// `false` default. Read from the existing binding for this agent.
    elicitation_enabled: bool,
}

#[derive(Serialize)]
struct ConsentContextResponse {
    request_id: String,
    user_email: String,
    client: ConsentClientInfo,
    connection: ConsentConnectionInfo,
    mode: &'static str,
    reauth_target: Option<ConsentReauthTarget>,
    suggested_agent_name: String,
    parents: Vec<ConsentParentOption>,
    groups: Vec<ConsentGroupOption>,
}

#[derive(Deserialize)]
struct ConsentFinishRequest {
    mode: String,
    agent_name: Option<String>,
    parent_id: Option<Uuid>,
    #[serde(default)]
    inherit_permissions: bool,
    #[serde(default)]
    group_names: Vec<String>,
    /// The `reauth_target.agent_id` shown to the user on the consent page,
    /// echoed back verbatim so mode="reauth" binds to the exact agent the
    /// user saw — not whatever a second `find_similar_for_user` call
    /// happens to return (newer enrollments, revocations, etc. could
    /// shift it between GET context and POST finish).
    reauth_agent_id: Option<Uuid>,
    /// User's choice from the Connection Settings card. `None` means the
    /// caller didn't speak the per-binding setting (older dashboard build,
    /// third-party POST) and the existing binding value is preserved.
    /// `Some(b)` is an explicit choice from the consent page; the server
    /// applies it across the agent's bindings, gated by capability.
    elicitation_enabled: Option<bool>,
}

#[derive(Serialize)]
struct ConsentFinishResponse {
    redirect_uri: String,
}

// Slugify a human-typed name into an `agent:<slug>` identifier the way the
// design card does — lowercase, dashes only, no leading/trailing dashes,
// no double dashes. Mirrors the frontend `slugify` so the server and UI
// produce identical output whether the user edits the field or accepts the
// default.
fn slugify_agent_name(raw: &str) -> String {
    let lower = raw.to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut prev_dash = false;
    for ch in lower.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            // Any non-alphanumeric run (including literal dashes) collapses
            // to a single `-` — matches the frontend's
            // `.replace(/[^a-z0-9-]+/g, '-').replace(/-{2,}/g, '-')`.
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "mcp-client".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod slug_tests {
    use super::slugify_agent_name;

    #[test]
    fn slug_matches_frontend_behaviour() {
        assert_eq!(slugify_agent_name("Claude Desktop"), "claude-desktop");
        assert_eq!(slugify_agent_name("foo--bar"), "foo-bar");
        assert_eq!(slugify_agent_name("---foo___bar!!!"), "foo-bar");
        assert_eq!(slugify_agent_name("  spaces  "), "spaces");
        assert_eq!(slugify_agent_name(""), "mcp-client");
        assert_eq!(slugify_agent_name("!!!"), "mcp-client");
    }
}

async fn consent_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> Result<Json<ConsentContextResponse>, AppError> {
    let session_claims = session::extract_session(&state, &headers)
        .ok_or_else(|| AppError::Unauthorized("session expired".into()))?;

    let pending = state
        .pending_authorize_store
        .get(&request_id)
        .ok_or_else(|| AppError::NotFound("authorization request expired".into()))?;

    // The session that landed on /oauth/authorize must be the one finishing
    // consent — protects against a swap-after-redirect attack where a second
    // tab's session accidentally completes someone else's flow.
    if pending.user_identity_id != session_claims.sub {
        return Err(AppError::Forbidden(
            "signed in as a different user than started this authorization".into(),
        ));
    }
    if pending.org_id != session_claims.org {
        return Err(AppError::Forbidden(
            "signed in to a different org than started this authorization".into(),
        ));
    }

    let client = oauth_mcp_client::get_by_client_id(&state.db, &pending.client_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("MCP client is no longer registered".into()))?;

    // Reauth detection: if there's a non-revoked prior binding for this user
    // that matches by client_name + software_id, offer that agent as the
    // reauth target. This covers the case where a client re-registered (new
    // client_id) after losing its persisted config.
    let similar = oauth_mcp_client::find_similar_for_user(
        &state.db,
        pending.user_identity_id,
        client.client_name.as_deref(),
        client.software_id.as_deref(),
    )
    .await?;

    let suggested_agent_name = client
        .client_name
        .clone()
        .filter(|s| !s.trim().is_empty())
        .map(|s| slugify_agent_name(&s))
        .unwrap_or_else(|| "mcp-client".into());

    // User's direct children that qualify as "parents" for a new agent.
    // We include the user themselves plus any existing agents under them
    // so the user can attach the new MCP agent to an automation root.
    let user_row = identity::get_by_id(&state.db, pending.org_id, pending.user_identity_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("user identity not found".into()))?;
    let mut parents = vec![ConsentParentOption {
        id: user_row.id,
        name: user_row.name.clone(),
        kind: user_row.kind.clone(),
        is_you: true,
    }];
    let children = identity::list_children(&state.db, pending.org_id, pending.user_identity_id)
        .await
        .unwrap_or_default();
    for c in children {
        if c.kind == "agent" && c.archived_at.is_none() {
            parents.push(ConsentParentOption {
                id: c.id,
                name: c.name,
                kind: c.kind,
                is_you: false,
            });
        }
    }

    let scope = OrgScope::new(pending.org_id, state.db.clone());
    let groups_rows = scope.list_groups().await.unwrap_or_default();
    let mut groups = Vec::with_capacity(groups_rows.len());
    for g in groups_rows {
        // Filter out system groups ("Everyone", "Admins") — not user-
        // selectable for a new MCP agent.
        if g.is_system {
            continue;
        }
        let member_count = scope.count_members_in_group(g.id).await.unwrap_or(0);
        groups.push(ConsentGroupOption {
            id: g.id,
            name: g.name,
            member_count,
        });
    }

    let elicitation_supported = client.elicitation_supported();

    let (mode, reauth_target) = if let Some(sim) = similar {
        let agent = identity::get_by_id(&state.db, pending.org_id, sim.agent_identity_id).await?;
        match agent {
            Some(a) if a.kind == "agent" && a.archived_at.is_none() => {
                let parent_name = if let Some(pid) = a.parent_id {
                    identity::get_by_id(&state.db, pending.org_id, pid)
                        .await
                        .ok()
                        .flatten()
                        .map(|p| p.name)
                } else {
                    None
                };
                let existing_elicitation =
                    mcp_client_agent_binding::get_by_agent_identity(&state.db, a.id)
                        .await?
                        .map(|b| b.elicitation_enabled)
                        .unwrap_or(false);
                (
                    "reauth",
                    Some(ConsentReauthTarget {
                        agent_id: a.id,
                        agent_name: a.name,
                        parent_id: a.parent_id,
                        parent_name,
                        last_seen_at: sim.client.last_seen_at.map(super::util::fmt_time),
                        elicitation_enabled: existing_elicitation,
                    }),
                )
            }
            _ => ("new", None),
        }
    } else {
        ("new", None)
    };

    Ok(Json(ConsentContextResponse {
        request_id: request_id.clone(),
        user_email: session_claims.email.clone(),
        client: ConsentClientInfo {
            client_name: client.client_name.clone(),
            software_id: client.software_id.clone(),
            software_version: client.software_version.clone(),
            elicitation_supported,
        },
        connection: ConsentConnectionInfo {
            ip: client.created_ip.clone(),
        },
        mode,
        reauth_target,
        suggested_agent_name,
        parents,
        groups,
    }))
}

async fn consent_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(body): Json<ConsentFinishRequest>,
) -> Result<Json<ConsentFinishResponse>, AppError> {
    let session_claims = session::extract_session(&state, &headers)
        .ok_or_else(|| AppError::Unauthorized("session expired".into()))?;

    // Consume the pending record up front — consent is single-use, and a
    // replayable `request_id` would let a second finish call create a
    // duplicate agent and a second auth code. If any downstream lookup
    // fails the user re-starts the flow; the 60s TTL is short enough that
    // this is acceptable.
    let pending = state
        .pending_authorize_store
        .take(&request_id)
        .ok_or_else(|| AppError::BadRequest("authorization request expired".into()))?;

    if pending.user_identity_id != session_claims.sub {
        return Err(AppError::Forbidden(
            "signed in as a different user than started this authorization".into(),
        ));
    }
    if pending.org_id != session_claims.org {
        return Err(AppError::Forbidden(
            "signed in to a different org than started this authorization".into(),
        ));
    }

    let user = identity::get_by_id(&state.db, pending.org_id, pending.user_identity_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("user identity not found".into()))?;

    let client = oauth_mcp_client::get_by_client_id(&state.db, &pending.client_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("MCP client is no longer registered".into()))?;

    let agent_identity_id = match body.mode.as_str() {
        "new" => {
            let raw_name = body.agent_name.as_deref().unwrap_or("").trim();
            let agent_name = if raw_name.is_empty() {
                client
                    .client_name
                    .as_deref()
                    .map(slugify_agent_name)
                    .unwrap_or_else(|| "mcp-client".into())
            } else {
                slugify_agent_name(raw_name)
            };

            // Parent must be the user themselves or one of their existing
            // agents — we already exposed exactly that list in the
            // context endpoint, so anything else is a forged submission.
            let parent_id = body.parent_id.unwrap_or(user.id);
            let parent = identity::get_by_id(&state.db, pending.org_id, parent_id)
                .await?
                .ok_or_else(|| AppError::BadRequest("parent identity not found".into()))?;
            if parent.id != user.id
                && !(parent.kind == "agent"
                    && parent.archived_at.is_none()
                    && parent.owner_id == Some(user.id))
            {
                return Err(AppError::Forbidden(
                    "parent is not eligible for this enrollment".into(),
                ));
            }

            let agent = identity::create_with_parent(
                &state.db,
                pending.org_id,
                &agent_name,
                "agent",
                None,
                parent.id,
                parent.depth + 1,
                user.id,
                body.inherit_permissions,
            )
            .await?;

            // Attach to selected groups, creating any missing ones by name.
            // System groups and duplicates are skipped. Failures are
            // logged but don't abort the enrollment — the user can always
            // fix group membership later from the dashboard.
            if !body.group_names.is_empty() {
                let scope = OrgScope::new(pending.org_id, state.db.clone());
                let existing = scope.list_groups().await.unwrap_or_default();
                for raw in &body.group_names {
                    let name = raw.trim();
                    if name.is_empty() {
                        continue;
                    }
                    let group_id = if let Some(g) = existing.iter().find(|g| g.name == name) {
                        if g.is_system {
                            continue;
                        }
                        g.id
                    } else {
                        match scope.create_group(name, "", false).await {
                            Ok(g) => g.id,
                            Err(e) => {
                                tracing::warn!("consent: create group '{name}' failed: {e}");
                                continue;
                            }
                        }
                    };
                    if let Err(e) = scope.assign_identity_to_group(agent.id, group_id).await {
                        tracing::warn!(
                            "consent: assign agent {} to group '{name}' failed: {e}",
                            agent.id
                        );
                    }
                }
            }

            agent.id
        }
        "reauth" => {
            // The client must echo back the reauth_target.agent_id that
            // `consent_context` resolved — binding to whatever
            // `find_similar_for_user` returns at finish-time would open
            // a race where a concurrent enrollment or revocation between
            // the GET and the POST shifts the target under the user.
            let echoed_agent_id = body
                .reauth_agent_id
                .ok_or_else(|| AppError::BadRequest("reauth_agent_id required".into()))?;

            // Guard against a caller submitting an arbitrary agent_id they
            // happen to know: the agent must be live, an agent-kind
            // identity, owned by the caller, AND there must be at least
            // one non-revoked prior binding from this user to that agent.
            // Together those invariants reduce to "the user already
            // enrolled this MCP client (or a previous one) against this
            // agent" — which is the honest definition of reauth.
            let agent = identity::get_by_id(&state.db, pending.org_id, echoed_agent_id)
                .await?
                .ok_or_else(|| AppError::BadRequest("agent not found".into()))?;
            if agent.kind != "agent"
                || agent.archived_at.is_some()
                || agent.owner_id != Some(user.id)
            {
                return Err(AppError::Forbidden(
                    "agent is not available for reauth".into(),
                ));
            }
            if !oauth_mcp_client::user_has_binding_to_agent(
                &state.db,
                pending.user_identity_id,
                agent.id,
            )
            .await?
            {
                return Err(AppError::Forbidden(
                    "agent has no prior enrollment for this user".into(),
                ));
            }
            agent.id
        }
        _ => {
            return Err(AppError::BadRequest(format!(
                "invalid mode '{}' (expected 'new' or 'reauth')",
                body.mode
            )));
        }
    };

    // Read the agent's existing elicitation value BEFORE upserting. Reauth
    // under a re-registered client_id creates a fresh binding row that
    // defaults to `false`, so without a pre-fetch the new row would hide
    // whatever value the user saved on a prior binding.
    let prior_elicitation =
        mcp_client_agent_binding::get_by_agent_identity(&state.db, agent_identity_id)
            .await?
            .map(|b| b.elicitation_enabled)
            .unwrap_or(false);

    mcp_client_agent_binding::upsert(
        &state.db,
        pending.org_id,
        pending.user_identity_id,
        &pending.client_id,
        agent_identity_id,
    )
    .await?;

    // Resolve the per-agent value: an explicit choice from the consent page
    // wins (gated by capability — a hand-crafted `true` against a client
    // that didn't announce elicitation gets forced to `false`); a missing
    // field inherits the agent's prior value so older dashboard builds /
    // third-party POSTs don't destroy a previously-saved choice. Fan out
    // unconditionally to keep every binding row in sync with the per-agent
    // toggle (see `set_elicitation_enabled_for_agent`).
    let resolved_elicitation = match body.elicitation_enabled {
        Some(requested) => requested && client.elicitation_supported(),
        None => prior_elicitation,
    };
    mcp_client_agent_binding::set_elicitation_enabled_for_agent(
        &state.db,
        agent_identity_id,
        resolved_elicitation,
    )
    .await?;

    // Fetch the agent's email (if any) so the access-token JWT carries a
    // sensible `email` claim. Agents usually inherit the owner's email
    // address for display purposes.
    let email = match identity::get_by_id(&state.db, pending.org_id, agent_identity_id).await {
        Ok(Some(a)) => a.email.unwrap_or_else(|| pending.email.clone()),
        _ => pending.email.clone(),
    };

    let code = oauth_as::generate_auth_code();
    state.auth_code_store.insert(
        code.clone(),
        oauth_as::AuthCodeRecord {
            client_id: pending.client_id.clone(),
            identity_id: agent_identity_id,
            org_id: pending.org_id,
            email,
            redirect_uri: pending.redirect_uri.clone(),
            code_challenge: pending.code_challenge.clone(),
            issued_at: Instant::now(),
        },
    );
    let mut redirect = format!(
        "{}?code={}",
        pending.redirect_uri,
        urlencoding::encode(&code)
    );
    if let Some(s) = pending.state_param.as_deref() {
        redirect.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    Ok(Json(ConsentFinishResponse {
        redirect_uri: redirect,
    }))
}

// ---------------------------------------------------------------------------
// Token endpoint (RFC 6749 §4.1.3 + §6)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    // authorization_code grant
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    code_verifier: Option<String>,
    // refresh_token grant
    refresh_token: Option<String>,
}

async fn token(State(state): State<AppState>, Form(req): Form<TokenRequest>) -> Response {
    let flow = match req.grant_type.as_str() {
        "authorization_code" => "token",
        "refresh_token" => "refresh",
        _ => "unknown_grant",
    };
    let response = match req.grant_type.as_str() {
        "authorization_code" => exchange_authorization_code(&state, req).await,
        "refresh_token" => exchange_refresh_token(&state, req).await,
        other => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            format!("unsupported grant_type: {other}"),
        ),
    };
    let status = if response.status().is_success() {
        "success"
    } else {
        "failure"
    };
    overslash_metrics::oauth::record_event("overslash", flow, status);
    response
}

async fn exchange_authorization_code(state: &AppState, req: TokenRequest) -> Response {
    let code = match req.code {
        Some(c) => c,
        None => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "code required");
        }
    };
    let redirect_uri = match req.redirect_uri {
        Some(r) => r,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "redirect_uri required",
            );
        }
    };
    let client_id = match req.client_id {
        Some(c) => c,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "client_id required",
            );
        }
    };
    let verifier = match req.code_verifier {
        Some(v) => v,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "code_verifier required",
            );
        }
    };

    let record = match state.auth_code_store.take(&code) {
        Some(r) => r,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "authorization code not found or expired",
            );
        }
    };
    if record.client_id != client_id
        || record.redirect_uri != redirect_uri
        || oauth_as::pkce_s256(&verifier) != record.code_challenge
    {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code did not match the expected client/redirect/verifier",
        );
    }

    issue_tokens(
        state,
        &record.client_id,
        record.identity_id,
        record.org_id,
        &record.email,
    )
    .await
}

async fn exchange_refresh_token(state: &AppState, req: TokenRequest) -> Response {
    let raw = match req.refresh_token {
        Some(t) => t,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "refresh_token required",
            );
        }
    };
    let hash = oauth_as::hash_refresh_token(&raw);
    let row = match mcp_refresh_token::get_by_hash(&state.db, &hash).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "unknown refresh_token",
            );
        }
        Err(e) => {
            tracing::error!("refresh lookup failed: {e}");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to look up refresh token",
            );
        }
    };

    // Replay detection: a revoked token being presented is evidence that the
    // previously-legitimate client was compromised. Revoke the entire chain
    // so both the attacker and the original client lose access.
    if row.revoked_at.is_some() {
        if let Err(e) = mcp_refresh_token::revoke_chain_from(&state.db, row.id).await {
            tracing::error!("revoke chain failed: {e}");
        }
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token revoked",
        );
    }
    if row.expires_at < OffsetDateTime::now_utc() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh_token expired",
        );
    }

    // We need the identity's email to mint the access JWT — fetch it.
    let identity = match overslash_db::repos::identity::get_by_id(
        &state.db,
        row.org_id,
        row.identity_id,
    )
    .await
    {
        Ok(Some(i)) => i,
        Ok(None) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "identity no longer exists",
            );
        }
        Err(e) => {
            tracing::error!("identity lookup failed: {e}");
            return oauth_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "failed to look up identity",
            );
        }
    };

    // Mint new tokens and atomically rotate (revoke old + insert new).
    let (raw_new, new_hash) = oauth_as::generate_refresh_token();
    let expires_at =
        OffsetDateTime::now_utc() + Duration::seconds(oauth_as::REFRESH_TOKEN_TTL_SECS);

    if let Err(e) = mcp_refresh_token::rotate(
        &state.db,
        row.id,
        &mcp_refresh_token::CreateMcpRefreshToken {
            client_id: &row.client_id,
            identity_id: row.identity_id,
            org_id: row.org_id,
            hash: &new_hash,
            expires_at,
        },
    )
    .await
    {
        tracing::error!("refresh rotate failed: {e}");
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "failed to rotate refresh token",
        );
    }
    let _ = oauth_mcp_client::mark_seen(&state.db, &row.client_id).await;

    let email = identity.email.as_deref().unwrap_or("");
    let access = match mint_access_token(state, row.identity_id, row.org_id, email, &row.client_id)
    {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    token_response(&access, &raw_new)
}

async fn issue_tokens(
    state: &AppState,
    client_id: &str,
    identity_id: Uuid,
    org_id: Uuid,
    email: &str,
) -> Response {
    let (raw, hash) = oauth_as::generate_refresh_token();
    let expires_at =
        OffsetDateTime::now_utc() + Duration::seconds(oauth_as::REFRESH_TOKEN_TTL_SECS);
    if let Err(e) = mcp_refresh_token::create(
        &state.db,
        &mcp_refresh_token::CreateMcpRefreshToken {
            client_id,
            identity_id,
            org_id,
            hash: &hash,
            expires_at,
        },
    )
    .await
    {
        tracing::error!("refresh insert failed: {e}");
        return oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "failed to persist refresh token",
        );
    }
    let _ = oauth_mcp_client::mark_seen(&state.db, client_id).await;
    let access = match mint_access_token(state, identity_id, org_id, email, client_id) {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    token_response(&access, &raw)
}

#[allow(clippy::result_large_err)]
fn mint_access_token(
    state: &AppState,
    identity_id: Uuid,
    org_id: Uuid,
    email: &str,
    mcp_client_id: &str,
) -> Result<String, Response> {
    let signing_key = hex::decode(&state.config.signing_key)
        .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());
    jwt::mint_mcp(
        &signing_key,
        identity_id,
        org_id,
        email.to_string(),
        oauth_as::ACCESS_TOKEN_TTL_SECS,
        Some(mcp_client_id.to_string()),
    )
    .map_err(|e| {
        tracing::error!("jwt mint failed: {e}");
        oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "failed to mint access token",
        )
    })
}

fn token_response(access: &str, refresh: &str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": oauth_as::ACCESS_TOKEN_TTL_SECS,
            "refresh_token": refresh,
            "scope": "mcp",
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Revoke (RFC 7009)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct RevokeRequest {
    token: String,
    token_type_hint: Option<String>,
}

async fn revoke(State(state): State<AppState>, Form(req): Form<RevokeRequest>) -> Response {
    // RFC 7009: always return 200 on success, even for unknown tokens.
    // `token_type_hint` is advisory — we ignore it because refresh tokens
    // are the only form we persist; access tokens are stateless JWTs and
    // can't be revoked individually (they expire in 1h).
    let _ = req.token_type_hint;

    let hash = oauth_as::hash_refresh_token(&req.token);
    match mcp_refresh_token::get_by_hash(&state.db, &hash).await {
        Ok(Some(row)) => {
            if let Err(e) = mcp_refresh_token::revoke_by_id(&state.db, row.id).await {
                // Log-but-don't-fail: RFC 7009 wants a 200 for success paths
                // so the client doesn't retry into a DB stampede, but an
                // operator needs a signal when the revoke silently misses.
                tracing::error!(
                    token_id = %row.id,
                    error = %e,
                    "refresh token revoke failed at /oauth/revoke"
                );
            }
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "refresh token lookup failed at /oauth/revoke");
        }
    }
    StatusCode::OK.into_response()
}
