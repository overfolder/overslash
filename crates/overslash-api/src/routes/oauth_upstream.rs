//! Nested-OAuth gateway: Overslash acting as MCP client to upstream MCP
//! servers. Three public endpoints + one internal helper.
//!
//! Security model: an opaque base62 `flow_id` ties a per-(identity, upstream)
//! flow together. The `mcp_upstream_flows` row is the trusted source of
//! identity, expiry, and PKCE verifier — never trust the URL.
//!
//! - `POST /v1/mcp_upstream/initiate` — authenticated. Discover, register,
//!   mint flow row, return URL forms (proxied/raw).
//! - `GET  /gated-authorize?id=F` — public-facing fail-fast UX gate.
//!   Reads session, redirects to upstream-AS or error/login page.
//! - `GET  /oauth/upstream/callback?code=…&state=F` — public-facing callback.
//!   Re-checks session vs flow identity (the security boundary), atomically
//!   consumes the row, exchanges the code, stores token in vault.

use std::time::Duration as StdDuration;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    AppState,
    error::AppError,
    extractors::SessionAuth,
    routes::connect_gate::{
        ParsedSession, SessionError, gone_html, html_escape, mismatch_html, read_session,
        session_authorized_for_org_identity,
    },
    services::{oauth_upstream as svc, short_url, ssrf_guard},
};
use overslash_core::crypto;
use overslash_db::repos::{
    identity, mcp_upstream_connection, mcp_upstream_flow, mcp_upstream_token, membership,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/mcp_upstream/initiate", post(initiate))
        .route(
            "/v1/identities/{identity_id}/mcp_upstream_connections",
            get(list_connections),
        )
        .route(
            "/v1/identities/{identity_id}/mcp_upstream_connections/{connection_id}/revoke",
            post(revoke_connection),
        )
        .route("/gated-authorize", get(gated_authorize))
        .route("/oauth/upstream/callback", get(callback))
}

// ---------------------------------------------------------------------------
// Dashboard: list + revoke connections
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ConnectionSummary {
    id: Uuid,
    upstream_resource: String,
    status: String,
    has_token: bool,
    access_token_expires_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
    last_refreshed_at: Option<OffsetDateTime>,
}

async fn list_connections(
    State(state): State<AppState>,
    session: SessionAuth,
    Path(identity_id): Path<Uuid>,
) -> Result<Json<Vec<ConnectionSummary>>, AppError> {
    require_owns_identity(&state, &session, identity_id).await?;
    let rows = mcp_upstream_connection::list_for_identity(&state.db, identity_id).await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let token = mcp_upstream_token::get_current(&state.db, row.id).await?;
        out.push(ConnectionSummary {
            id: row.id,
            upstream_resource: row.upstream_resource,
            status: row.status,
            has_token: token.is_some(),
            access_token_expires_at: token.as_ref().and_then(|t| t.access_token_expires_at),
            created_at: row.created_at,
            last_refreshed_at: row.last_refreshed_at,
        });
    }
    Ok(Json(out))
}

async fn revoke_connection(
    State(state): State<AppState>,
    session: SessionAuth,
    Path((identity_id, connection_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    require_owns_identity(&state, &session, identity_id).await?;
    let conn = mcp_upstream_connection::get_by_id(&state.db, connection_id)
        .await?
        .ok_or_else(|| AppError::NotFound("connection not found".into()))?;
    if conn.identity_id != identity_id {
        return Err(AppError::NotFound("connection not found".into()));
    }
    mcp_upstream_token::supersede_all(&state.db, connection_id).await?;
    mcp_upstream_connection::mark_revoked(&state.db, connection_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn require_owns_identity(
    state: &AppState,
    session: &SessionAuth,
    target_identity_id: Uuid,
) -> Result<(), AppError> {
    let target = identity::get_by_id(&state.db, session.org_id, target_identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    if target.id == session.identity_id {
        return Ok(());
    }
    let chain = identity::get_ancestor_chain(&state.db, session.org_id, target_identity_id).await?;
    if chain.iter().any(|row| row.id == session.identity_id) {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "identity must be the caller or an identity they own".into(),
        ))
    }
}

const FLOW_TTL: Duration = Duration::minutes(10);
const HTTP_TIMEOUT: StdDuration = StdDuration::from_secs(15);

// ---------------------------------------------------------------------------
// POST /v1/mcp_upstream/initiate
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct InitiateRequest {
    /// The `resource_metadata` URL the upstream MCP server returned in its
    /// `WWW-Authenticate` 401 challenge (RFC 9728). Either this or
    /// `as_issuer` must be supplied.
    resource_metadata_url: Option<String>,
    /// Direct AS issuer URL — used when the caller already knows the
    /// authorization server (e.g., a configured upstream).
    as_issuer: Option<String>,
    /// The RFC 8707 canonical resource URI of the upstream MCP server.
    /// Goes in the authorize/token `resource` parameter and is stored on
    /// the connection.
    upstream_resource: String,
    /// Optional scopes to request. Defaults to whatever the AS metadata
    /// advertises in `scopes_supported`.
    scopes: Option<Vec<String>>,
    /// Identity the connection should attach to. Must be owned by the
    /// caller (or be the caller's own identity).
    identity_id: Option<Uuid>,
    /// Whether to include the raw upstream URL in the response. Defaults
    /// to false so a leaked response doesn't accidentally hand attackers a
    /// gate-bypass.
    #[serde(default)]
    include_raw: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum InitiateResponse {
    /// Existing connection has a non-expired token. No flow needed; the
    /// caller can use the upstream MCP server immediately.
    Ready {
        connection_id: Uuid,
        upstream_resource: String,
        access_token_expires_at: Option<OffsetDateTime>,
    },
    /// Either no token yet or it's expired and not refreshable. The caller
    /// surfaces `authorize_urls` to the user.
    PendingAuth {
        flow_id: String,
        expires_at: OffsetDateTime,
        authorize_urls: AuthorizeUrls,
    },
}

#[derive(Debug, Serialize)]
struct AuthorizeUrls {
    /// Default. The Overslash-gated path; fail-fast on session mismatch.
    proxied: String,
    /// Optional shortened form (only present if the shortener is configured).
    #[serde(skip_serializing_if = "Option::is_none")]
    short: Option<String>,
    /// Raw upstream-AS URL with `state=<flow_id>`. Opt-in via `include_raw`.
    /// Bypasses the gate; the callback still enforces session-vs-flow.
    #[serde(skip_serializing_if = "Option::is_none")]
    raw: Option<String>,
}

async fn initiate(
    State(state): State<AppState>,
    session: SessionAuth,
    headers: HeaderMap,
    Json(req): Json<InitiateRequest>,
) -> Result<Json<InitiateResponse>, AppError> {
    if req.resource_metadata_url.is_none() && req.as_issuer.is_none() {
        return Err(AppError::BadRequest(
            "either resource_metadata_url or as_issuer is required".into(),
        ));
    }
    if req.upstream_resource.is_empty() {
        return Err(AppError::BadRequest("upstream_resource is required".into()));
    }

    // The connection attaches to either the caller's own identity or one
    // they own. Resolve and validate ownership before doing any I/O.
    let target_identity_id = req.identity_id.unwrap_or(session.identity_id);
    let target_identity = identity::get_by_id(&state.db, session.org_id, target_identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    if target_identity_id != session.identity_id {
        let chain =
            identity::get_ancestor_chain(&state.db, session.org_id, target_identity_id).await?;
        if !chain.iter().any(|row| row.id == session.identity_id) {
            return Err(AppError::Forbidden(
                "identity must be the caller or an identity they own".into(),
            ));
        }
    }

    // Idempotent boot: if a valid token already exists, short-circuit. No
    // discovery, no DCR, no flow row.
    if let Some(conn) =
        mcp_upstream_connection::get(&state.db, target_identity_id, &req.upstream_resource).await?
    {
        if conn.status == mcp_upstream_connection::STATUS_READY {
            if let Some(token) = mcp_upstream_token::get_current(&state.db, conn.id).await? {
                let still_valid = token
                    .access_token_expires_at
                    .map(|exp| exp > OffsetDateTime::now_utc() + Duration::seconds(60))
                    .unwrap_or(true);
                if still_valid {
                    return Ok(Json(InitiateResponse::Ready {
                        connection_id: conn.id,
                        upstream_resource: req.upstream_resource,
                        access_token_expires_at: token.access_token_expires_at,
                    }));
                }
            }
        }
    }

    // If a non-expired flow already exists, reuse it — re-running boot
    // returns the same share URL rather than minting a fresh one.
    if let Some(existing) =
        mcp_upstream_flow::find_active_for(&state.db, target_identity_id, &req.upstream_resource)
            .await?
    {
        let proxied = format!(
            "{}/gated-authorize?id={}",
            state.config.public_url, existing.id
        );
        let short = short_url::mint_short_url(
            &state.http_client,
            state.config.oversla_sh_base_url.as_deref(),
            state.config.oversla_sh_api_key.as_deref(),
            &proxied,
            existing.expires_at,
        )
        .await;
        let raw = req
            .include_raw
            .then(|| existing.upstream_authorize_url.clone());
        return Ok(Json(InitiateResponse::PendingAuth {
            flow_id: existing.id,
            expires_at: existing.expires_at,
            authorize_urls: AuthorizeUrls {
                proxied,
                short,
                raw,
            },
        }));
    }

    // Discover the AS through SSRF-guarded clients. Each discovery URL is
    // validated, host-pinned, and re-fetched once — cooperative redirects
    // are disabled by `build_pinned_client`.
    let as_issuer = match (&req.resource_metadata_url, &req.as_issuer) {
        (Some(url), _) => {
            let (client, _) = ssrf_guard::build_pinned_client(url, HTTP_TIMEOUT).await?;
            let prm = svc::discover_protected_resource(&client, url)
                .await
                .map_err(|e| AppError::BadGateway(e.to_string()))?;
            prm.authorization_servers
                .into_iter()
                .next()
                .ok_or_else(|| {
                    AppError::BadGateway("upstream resource has no authorization_servers".into())
                })?
        }
        (None, Some(issuer)) => issuer.clone(),
        (None, None) => unreachable!("checked above"),
    };

    let (as_client, _) = ssrf_guard::build_pinned_client(&as_issuer, HTTP_TIMEOUT).await?;
    let as_meta = svc::discover_authorization_server(&as_client, &as_issuer)
        .await
        .map_err(|e| AppError::BadGateway(e.to_string()))?;
    let registration_endpoint = as_meta.registration_endpoint.as_deref().ok_or_else(|| {
        AppError::BadGateway(
            "upstream AS does not advertise registration_endpoint (RFC 7591 DCR)".into(),
        )
    })?;
    let (reg_client, _) =
        ssrf_guard::build_pinned_client(registration_endpoint, HTTP_TIMEOUT).await?;

    // Register Overslash as a public client at the upstream AS.
    let redirect_uri = callback_redirect_uri(&state.config.public_url);
    let client_name = format!("Overslash for {}", session.org_id);
    let registered = svc::register_client(
        &reg_client,
        registration_endpoint,
        &redirect_uri,
        &client_name,
    )
    .await
    .map_err(|e| AppError::BadGateway(e.to_string()))?;

    // Mint flow and PKCE, build authorize URL.
    let flow_id = svc::mint_flow_id();
    let pkce = svc::generate_pkce();
    let scopes = req.scopes.unwrap_or(as_meta.scopes_supported.clone());
    let raw_authorize_url = svc::build_authorize_url(
        &as_meta.authorization_endpoint,
        &registered.client_id,
        &redirect_uri,
        &flow_id,
        &pkce.challenge,
        &req.upstream_resource,
        &scopes,
    );

    let now = OffsetDateTime::now_utc();
    let expires_at = now + FLOW_TTL;

    let created_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| raw.split(',').next())
        .map(|s| s.trim());
    let created_user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok());

    let connection_org_id = target_identity.org_id;
    mcp_upstream_connection::upsert_pending(
        &state.db,
        &mcp_upstream_connection::UpsertMcpUpstreamConnection {
            identity_id: target_identity_id,
            org_id: connection_org_id,
            upstream_resource: &req.upstream_resource,
            upstream_client_id: &registered.client_id,
        },
    )
    .await?;

    mcp_upstream_flow::create(
        &state.db,
        &mcp_upstream_flow::CreateMcpUpstreamFlow {
            id: &flow_id,
            identity_id: target_identity_id,
            org_id: connection_org_id,
            upstream_resource: &req.upstream_resource,
            upstream_client_id: &registered.client_id,
            upstream_as_issuer: &as_meta.issuer,
            upstream_token_endpoint: &as_meta.token_endpoint,
            upstream_authorize_url: &raw_authorize_url,
            pkce_code_verifier: &pkce.verifier,
            expires_at,
            created_ip,
            created_user_agent,
        },
    )
    .await?;

    let proxied = format!("{}/gated-authorize?id={}", state.config.public_url, flow_id);
    let short = short_url::mint_short_url(
        &state.http_client,
        state.config.oversla_sh_base_url.as_deref(),
        state.config.oversla_sh_api_key.as_deref(),
        &proxied,
        expires_at,
    )
    .await;
    let raw = req.include_raw.then(|| raw_authorize_url.clone());

    Ok(Json(InitiateResponse::PendingAuth {
        flow_id,
        expires_at,
        authorize_urls: AuthorizeUrls {
            proxied,
            short,
            raw,
        },
    }))
}

fn callback_redirect_uri(public_url: &str) -> String {
    format!(
        "{}/oauth/upstream/callback",
        public_url.trim_end_matches('/')
    )
}

// ---------------------------------------------------------------------------
// GET /gated-authorize?id=F
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GatedAuthorizeParams {
    id: String,
}

async fn gated_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<GatedAuthorizeParams>,
) -> Result<Response, AppError> {
    let flow = mcp_upstream_flow::get_by_id(&state.db, &params.id).await?;
    let Some(flow) = flow else {
        return Ok(gone_html("This OAuth link is invalid or has been revoked."));
    };
    if flow.consumed_at.is_some() {
        return Ok(gone_html(
            "This OAuth link has already been used. Initiate the connection again to retry.",
        ));
    }
    if flow.expires_at <= OffsetDateTime::now_utc() {
        return Ok(gone_html(
            "This OAuth link has expired. Initiate the connection again to retry.",
        ));
    }

    // Look at session to decide what to do.
    let session = match read_session(&state, &headers) {
        Ok(s) => s,
        Err(SessionError::Missing) => {
            // OOB delivery: Slack/email-delivered link clicked without an
            // active session. Bounce through login and resume.
            let return_to = format!("{}/gated-authorize?id={}", state.config.public_url, flow.id);
            let login_url = state.config.dashboard_url_for(&format!(
                "/auth/login?next={}",
                urlencoding::encode(&return_to)
            ));
            return Ok(Redirect::to(&login_url).into_response());
        }
        Err(SessionError::Invalid) => {
            return Err(AppError::Unauthorized("invalid session cookie".into()));
        }
    };

    if session_authorized_for_flow(&state, &session, &flow).await? {
        return Ok(Redirect::to(&flow.upstream_authorize_url).into_response());
    }

    // Multi-org: same human, different org. Offer switch only if the user
    // actually has membership in the flow's org — never leak the existence
    // of the flow's org otherwise.
    if let Some(user_id) = session.user_id {
        if session.org_id != flow.org_id
            && membership::find(&state.db, user_id, flow.org_id)
                .await?
                .is_some()
        {
            return Ok(switch_org_html(
                &state.config.public_url,
                &flow.id,
                flow.org_id,
            ));
        }
    }

    Ok(mismatch_html())
}

// ---------------------------------------------------------------------------
// GET /oauth/upstream/callback?code=…&state=F
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Result<Response, AppError> {
    if let Some(err) = params.error {
        let detail = params.error_description.unwrap_or_default();
        return Ok(error_html(&format!(
            "Upstream authorization failed: {err} {detail}"
        )));
    }
    let flow_id = params
        .state
        .ok_or_else(|| AppError::BadRequest("state parameter is required".into()))?;
    let code = params
        .code
        .ok_or_else(|| AppError::BadRequest("code parameter is required".into()))?;

    // Look up (without consuming) so an attacker cannot pre-burn the row by
    // calling the callback with no/wrong session.
    let flow_preview = mcp_upstream_flow::get_by_id(&state.db, &flow_id).await?;
    let Some(flow_preview) = flow_preview else {
        return Ok(gone_html(
            "This OAuth callback is invalid, expired, or has already been completed.",
        ));
    };
    if flow_preview.consumed_at.is_some() {
        return Ok(gone_html("This OAuth callback has already been completed."));
    }
    if flow_preview.expires_at <= OffsetDateTime::now_utc() {
        return Ok(gone_html(
            "This OAuth callback has expired. Initiate the connection again to retry.",
        ));
    }

    // **The security boundary.** Even if an attacker bypassed `/gated-authorize`
    // by handing the victim the raw upstream URL, the victim's session must
    // match the flow's identity here, or we refuse to bind their token.
    let session = read_session(&state, &headers).map_err(|_| {
        AppError::Forbidden(
            "no active Overslash session — this OAuth flow cannot be completed without it".into(),
        )
    })?;
    if !session_authorized_for_flow(&state, &session, &flow_preview).await? {
        return Err(AppError::Forbidden(
            "Overslash session does not match the identity that initiated this OAuth flow".into(),
        ));
    }

    // Now that the session is authorized, atomically claim the row.
    // Concurrent racing callbacks: the first transaction wins; the second
    // gets None and we 410.
    let flow = mcp_upstream_flow::consume(&state.db, &flow_id).await?;
    let Some(flow) = flow else {
        return Ok(gone_html(
            "This OAuth callback is invalid, expired, or has already been completed.",
        ));
    };

    // Exchange the code at the upstream token endpoint we resolved at mint
    // time. SSRF-guard the connection. No re-discovery — the endpoint was
    // validated and persisted on the flow row, so a path-based multi-tenant
    // AS keeps working without round-tripping its metadata document again.
    let (token_client, _) =
        ssrf_guard::build_pinned_client(&flow.upstream_token_endpoint, HTTP_TIMEOUT).await?;
    let redirect_uri = callback_redirect_uri(&state.config.public_url);
    let tokens = svc::exchange_code(
        &token_client,
        &flow.upstream_token_endpoint,
        &flow.upstream_client_id,
        &code,
        &redirect_uri,
        &flow.pkce_code_verifier,
        &flow.upstream_resource,
    )
    .await
    .map_err(|e| AppError::BadGateway(e.to_string()))?;

    // Encrypt and persist.
    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let access_ct = crypto::encrypt(&enc_key, tokens.access_token.as_bytes())?;
    let refresh_ct = match &tokens.refresh_token {
        Some(rt) => Some(crypto::encrypt(&enc_key, rt.as_bytes())?),
        None => None,
    };
    let access_expires_at = tokens
        .expires_in
        .map(|s| OffsetDateTime::now_utc() + Duration::seconds(s));

    let connection =
        mcp_upstream_connection::get(&state.db, flow.identity_id, &flow.upstream_resource)
            .await?
            .ok_or_else(|| AppError::Internal("flow has no matching connection row".into()))?;

    mcp_upstream_token::insert_current(
        &state.db,
        &mcp_upstream_token::InsertMcpUpstreamToken {
            connection_id: connection.id,
            access_token_ciphertext: &access_ct,
            refresh_token_ciphertext: refresh_ct.as_deref(),
            access_token_expires_at: access_expires_at,
            scope: tokens.scope.as_deref(),
        },
    )
    .await?;
    mcp_upstream_connection::mark_ready(&state.db, connection.id).await?;

    Ok(connected_html(&flow.upstream_resource))
}

// ---------------------------------------------------------------------------
// Flow-specific authorization wrapper around the generic gate primitives.
// ---------------------------------------------------------------------------

async fn session_authorized_for_flow(
    state: &AppState,
    session: &ParsedSession,
    flow: &mcp_upstream_flow::McpUpstreamFlowRow,
) -> Result<bool, AppError> {
    session_authorized_for_org_identity(state, session, flow.org_id, flow.identity_id).await
}

// ---------------------------------------------------------------------------
// Flow-specific HTML — multi-org switch is shaped around the upstream-flow
// id and is not a primitive in `connect_gate`.
// ---------------------------------------------------------------------------

fn switch_org_html(public_url: &str, flow_id: &str, target_org: Uuid) -> Response {
    let return_to = format!("{public_url}/gated-authorize?id={flow_id}");
    // The /auth/switch-org handler expects JSON, not form-encoded — submit
    // via fetch and redirect on success. The button is the only interactive
    // element so the page works fine even if JS doesn't load (the user just
    // sees a static notice).
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>Switch org</title>\
         <body style='font-family:system-ui;max-width:480px;margin:4rem auto;padding:0 1rem'>\
         <h1>Switch org to continue</h1>\
         <p>This OAuth link was created in a different org you belong to. \
         Switch to that org to complete the connection.</p>\
         <button id=switch type=button>Switch and continue</button>\
         <p id=err style='color:#b00;display:none'></p>\
         <script>\
         document.getElementById('switch').addEventListener('click', async () => {{\
           try {{\
             const r = await fetch('/auth/switch-org', {{\
               method: 'POST',\
               credentials: 'include',\
               headers: {{ 'content-type': 'application/json' }},\
               body: JSON.stringify({{ org_id: '{org}' }})\
             }});\
             if (!r.ok) throw new Error('HTTP ' + r.status);\
             window.location.href = '{return_to}';\
           }} catch (e) {{\
             const err = document.getElementById('err');\
             err.textContent = 'Could not switch org: ' + e.message;\
             err.style.display = 'block';\
           }}\
         }});\
         </script></body>",
        org = html_escape(&target_org.to_string()),
        return_to = html_escape(&return_to),
    );
    (StatusCode::OK, Html(body)).into_response()
}

fn error_html(msg: &str) -> Response {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>Connection failed</title>\
         <body style='font-family:system-ui;max-width:480px;margin:4rem auto;padding:0 1rem'>\
         <h1>Connection failed</h1><p>{}</p></body>",
        html_escape(msg)
    );
    (StatusCode::BAD_GATEWAY, Html(body)).into_response()
}

fn connected_html(resource: &str) -> Response {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>Connection ready</title>\
         <body style='font-family:system-ui;max-width:480px;margin:4rem auto;padding:0 1rem'>\
         <h1>Connection ready</h1>\
         <p>Overslash is now connected to <code>{}</code>. You can close this tab.</p>\
         </body>",
        html_escape(resource)
    );
    (StatusCode::OK, Html(body)).into_response()
}
