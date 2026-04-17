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
    response::{IntoResponse, Redirect, Response},
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
use overslash_db::repos::{mcp_refresh_token, oauth_mcp_client};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/oauth/register", post(register))
        .route("/oauth/authorize", get(authorize))
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

    // Issue a one-shot authorization code.
    let code = oauth_as::generate_auth_code();
    state.auth_code_store.insert(
        code.clone(),
        oauth_as::AuthCodeRecord {
            client_id: client.client_id.clone(),
            identity_id: session_claims.sub,
            org_id: session_claims.org,
            email: session_claims.email.clone(),
            redirect_uri: params.redirect_uri.clone(),
            code_challenge: params.code_challenge.clone(),
            issued_at: Instant::now(),
        },
    );

    let mut redirect = format!(
        "{}?code={}",
        params.redirect_uri,
        urlencoding::encode(&code)
    );
    if let Some(s) = params.state.as_deref() {
        redirect.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    Redirect::to(&redirect).into_response()
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
