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
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    AppState,
    services::{jwt, oauth_as, session},
};
use overslash_db::repos::{
    identity, mcp_client_agent_binding, mcp_refresh_token, oauth_mcp_client,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/oauth/register", post(register))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/consent", get(consent_get))
        .route("/oauth/consent/finish", post(consent_finish))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
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

    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": row.client_id,
            "client_name": row.client_name,
            "redirect_uris": row.redirect_uris,
            "software_id": row.software_id,
            "software_version": row.software_version,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        })),
    )
        .into_response()
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
    Query(params): Query<AuthorizeQuery>,
    headers: HeaderMap,
) -> Response {
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
            let provider = match default_idp_provider(&state) {
                Some(p) => p,
                None => {
                    return oauth_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "login_required",
                        "no IdP is configured on this Overslash deployment",
                    );
                }
            };
            let authorize_path = rebuild_authorize_path(&params);
            let next = urlencoding::encode(&authorize_path);
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
    Redirect::to(&format!(
        "/oauth/consent?request_id={}",
        urlencoding::encode(&request_id)
    ))
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

/// Pick the first configured env-var IdP for bouncing `/oauth/authorize`
/// through login. Production deployments should always have exactly one
/// default; installations with multiple IdPs can pick via a UI redirect
/// layer above `/oauth/authorize`.
fn default_idp_provider(state: &AppState) -> Option<&'static str> {
    if state.config.google_auth_client_id.is_some()
        && state.config.google_auth_client_secret.is_some()
    {
        return Some("google");
    }
    if state.config.github_auth_client_id.is_some()
        && state.config.github_auth_client_secret.is_some()
    {
        return Some("github");
    }
    if state.config.dev_auth_enabled {
        return Some("dev");
    }
    None
}

// ---------------------------------------------------------------------------
// Consent (agent enrollment)
// ---------------------------------------------------------------------------
//
// When /oauth/authorize finds no prior (user, client_id) → agent binding, it
// parks the request in `pending_authorize_store` and redirects here. This
// server-rendered page is intentionally self-contained — no SvelteKit
// coupling — so the Authorization Server can run in modes where the
// dashboard isn't served (e.g. the `overslash serve` cloud mode).

#[derive(Deserialize)]
struct ConsentQuery {
    request_id: String,
}

async fn consent_get(
    State(state): State<AppState>,
    Query(q): Query<ConsentQuery>,
    headers: HeaderMap,
) -> Response {
    // Session must still be valid — consent is a user-authenticated action.
    let session_claims = match session::extract_session(&state, &headers) {
        Some(c) => c,
        None => {
            return consent_error_page(
                StatusCode::UNAUTHORIZED,
                "Your session has expired. Restart the sign-in from your MCP client.",
            );
        }
    };

    let pending = match state.pending_authorize_store.get(&q.request_id) {
        Some(p) => p,
        None => {
            return consent_error_page(
                StatusCode::BAD_REQUEST,
                "This authorization request has expired. Restart the sign-in from your MCP client.",
            );
        }
    };

    // The session that landed on /oauth/authorize must be the one finishing
    // consent — protects against a swap-after-redirect attack where a second
    // tab's session accidentally completes someone else's flow.
    if pending.user_identity_id != session_claims.sub {
        return consent_error_page(
            StatusCode::FORBIDDEN,
            "You're signed in as a different user than started this authorization.",
        );
    }

    let client = match oauth_mcp_client::get_by_client_id(&state.db, &pending.client_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return consent_error_page(
                StatusCode::BAD_REQUEST,
                "The MCP client that started this authorization is no longer registered.",
            );
        }
        Err(e) => {
            tracing::error!("consent: client lookup failed: {e}");
            return consent_error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "We couldn't load this authorization request. Try again.",
            );
        }
    };

    let existing_agents =
        match identity::list_children(&state.db, pending.org_id, pending.user_identity_id).await {
            Ok(rows) => rows
                .into_iter()
                .filter(|r| r.kind == "agent" && r.archived_at.is_none())
                .collect::<Vec<_>>(),
            Err(e) => {
                tracing::error!("consent: list_children failed: {e}");
                Vec::new()
            }
        };

    let suggested_name = client
        .client_name
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "MCP Client".into());

    Html(render_consent_page(
        &q.request_id,
        &session_claims.email,
        client.client_name.as_deref().unwrap_or("(unnamed client)"),
        &suggested_name,
        &existing_agents,
    ))
    .into_response()
}

#[derive(Deserialize)]
struct ConsentForm {
    request_id: String,
    /// "new" | "existing"
    mode: String,
    /// Populated when `mode == "new"`.
    name: Option<String>,
    /// Populated when `mode == "existing"`.
    agent_id: Option<String>,
}

async fn consent_finish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ConsentForm>,
) -> Response {
    let session_claims = match session::extract_session(&state, &headers) {
        Some(c) => c,
        None => {
            return consent_error_page(
                StatusCode::UNAUTHORIZED,
                "Your session has expired. Restart the sign-in from your MCP client.",
            );
        }
    };

    let pending = match state.pending_authorize_store.take(&form.request_id) {
        Some(p) => p,
        None => {
            return consent_error_page(
                StatusCode::BAD_REQUEST,
                "This authorization request has expired. Restart the sign-in from your MCP client.",
            );
        }
    };

    if pending.user_identity_id != session_claims.sub {
        return consent_error_page(
            StatusCode::FORBIDDEN,
            "You're signed in as a different user than started this authorization.",
        );
    }

    let agent_identity_id =
        match form.mode.as_str() {
            "new" => {
                let name = form
                    .name
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("MCP Client");
                let user =
                    match identity::get_by_id(&state.db, pending.org_id, pending.user_identity_id)
                        .await
                    {
                        Ok(Some(u)) => u,
                        Ok(None) => {
                            return consent_error_page(
                                StatusCode::BAD_REQUEST,
                                "Your user identity could not be located.",
                            );
                        }
                        Err(e) => {
                            tracing::error!("consent: user lookup failed: {e}");
                            return consent_error_page(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "We couldn't complete the authorization. Try again.",
                            );
                        }
                    };
                match identity::create_with_parent(
                    &state.db,
                    pending.org_id,
                    name,
                    "agent",
                    None,
                    user.id,
                    user.depth + 1,
                    user.id,
                    true, // inherit_permissions: sensible default, user can tighten later
                )
                .await
                {
                    Ok(row) => row.id,
                    Err(e) => {
                        tracing::error!("consent: agent create failed: {e}");
                        return consent_error_page(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "We couldn't create the agent. Try again.",
                        );
                    }
                }
            }
            "existing" => {
                let agent_id_str = match form.agent_id.as_deref() {
                    Some(s) if !s.is_empty() => s,
                    _ => {
                        return consent_error_page(
                            StatusCode::BAD_REQUEST,
                            "Select an existing agent or create a new one.",
                        );
                    }
                };
                let agent_id = match Uuid::parse_str(agent_id_str) {
                    Ok(u) => u,
                    Err(_) => {
                        return consent_error_page(StatusCode::BAD_REQUEST, "Invalid agent id.");
                    }
                };
                let agent = match identity::get_by_id(&state.db, pending.org_id, agent_id).await {
                    Ok(Some(a)) => a,
                    Ok(None) => {
                        return consent_error_page(StatusCode::BAD_REQUEST, "Unknown agent.");
                    }
                    Err(e) => {
                        tracing::error!("consent: agent lookup failed: {e}");
                        return consent_error_page(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "We couldn't complete the authorization. Try again.",
                        );
                    }
                };
                // Only the user's own agents are eligible — guards against a
                // crafted form submitting another user's agent id.
                if agent.kind != "agent"
                    || agent.archived_at.is_some()
                    || agent.owner_id != Some(pending.user_identity_id)
                {
                    return consent_error_page(
                        StatusCode::FORBIDDEN,
                        "That agent isn't available for this authorization.",
                    );
                }
                agent.id
            }
            _ => {
                return consent_error_page(
                    StatusCode::BAD_REQUEST,
                    "Invalid selection. Restart from your MCP client.",
                );
            }
        };

    if let Err(e) = mcp_client_agent_binding::upsert(
        &state.db,
        pending.org_id,
        pending.user_identity_id,
        &pending.client_id,
        agent_identity_id,
    )
    .await
    {
        tracing::error!("consent: binding upsert failed: {e}");
        return consent_error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "We couldn't record the agent binding. Try again.",
        );
    }

    // Fetch the agent's email (if any) so the access-token JWT carries a
    // sensible `email` claim. Agents usually inherit the owner's email
    // address for display purposes.
    let email = match identity::get_by_id(&state.db, pending.org_id, agent_identity_id).await {
        Ok(Some(a)) => a.email.unwrap_or_else(|| pending.email.clone()),
        _ => pending.email.clone(),
    };

    issue_authorization_code(
        &state,
        &pending.client_id,
        agent_identity_id,
        pending.org_id,
        &email,
        &pending.redirect_uri,
        &pending.code_challenge,
        pending.state_param.as_deref(),
    )
}

const CONSENT_TEMPLATE: &str = include_str!("oauth_consent.html");
const CONSENT_ERROR_TEMPLATE: &str = include_str!("oauth_consent_error.html");

fn consent_error_page(status: StatusCode, message: &str) -> Response {
    let body = CONSENT_ERROR_TEMPLATE.replace("{{message}}", &html_escape(message));
    (status, Html(body)).into_response()
}

fn render_consent_page(
    request_id: &str,
    user_email: &str,
    client_display_name: &str,
    suggested_name: &str,
    existing_agents: &[identity::IdentityRow],
) -> String {
    let existing_options = if existing_agents.is_empty() {
        "<option value=\"\">(no existing agents)</option>".to_string()
    } else {
        existing_agents
            .iter()
            .map(|a| {
                format!(
                    "<option value=\"{}\">{}</option>",
                    html_escape(&a.id.to_string()),
                    html_escape(&a.name),
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let existing_disabled = if existing_agents.is_empty() {
        " disabled"
    } else {
        ""
    };

    CONSENT_TEMPLATE
        .replace("{{user_email}}", &html_escape(user_email))
        .replace("{{client}}", &html_escape(client_display_name))
        .replace("{{request_id}}", &html_escape(request_id))
        .replace("{{suggested}}", &html_escape(suggested_name))
        .replace("{{existing_disabled}}", existing_disabled)
        .replace("{{existing_options}}", &existing_options)
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
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
    match req.grant_type.as_str() {
        "authorization_code" => exchange_authorization_code(&state, req).await,
        "refresh_token" => exchange_refresh_token(&state, req).await,
        other => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            format!("unsupported grant_type: {other}"),
        ),
    }
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
    let access = match mint_access_token(state, row.identity_id, row.org_id, email) {
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
    let access = match mint_access_token(state, identity_id, org_id, email) {
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
) -> Result<String, Response> {
    let signing_key = hex::decode(&state.config.signing_key)
        .unwrap_or_else(|_| state.config.signing_key.as_bytes().to_vec());
    jwt::mint_mcp(
        &signing_key,
        identity_id,
        org_id,
        email.to_string(),
        oauth_as::ACCESS_TOKEN_TTL_SECS,
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
