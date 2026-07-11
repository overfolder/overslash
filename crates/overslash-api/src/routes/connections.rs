use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::{Form, Path, Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::oauth_connection_flow;
use overslash_db::scopes::{OrgScope, UserScope};

use super::connect_gate::{
    ConnectGateOutcome, SessionError, admin_consent_html, evaluate_connect_gate, gone_html,
    mismatch_html, read_session,
};
use super::util::fmt_time;
use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{ClientIp, ReqExt, WriteAcl},
    services::{
        client_credentials, oauth,
        platform_caller::PlatformCallContext,
        platform_connections::{
            CreateConnectionInput, CreateConnectionResponse, RequestMeta, kernel_create_connection,
            kernel_create_connection_for_identity, merge_scopes,
        },
    },
};
use overslash_core::crypto;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/v1/connections",
            post(initiate_connection).get(list_connections),
        )
        .route("/v1/connections/import", post(import_connection))
        .route(
            "/v1/connections/{id}",
            get(get_connection).delete(delete_connection),
        )
        .route(
            "/v1/connections/{id}/set_default",
            post(set_connection_default),
        )
        .route("/v1/connections/{id}/keep", post(set_connection_keep))
        .route(
            "/v1/connections/{id}/upgrade_scopes",
            post(upgrade_connection_scopes),
        )
        .route("/v1/oauth/callback", get(oauth_callback))
        .route("/connect-authorize", get(connect_authorize))
        .route(
            "/connect-authorize/confirm",
            post(connect_authorize_confirm),
        )
}

#[derive(Deserialize)]
struct InitiateConnectionRequest {
    provider: String,
    #[serde(default)]
    scopes: Vec<String>,
    /// Pin a specific BYOC credential for this connection. If omitted, the
    /// cascade resolver picks identity-level → org-level → env fallback.
    #[serde(default)]
    byoc_credential_id: Option<Uuid>,
    /// Bind the resulting connection to this user identity instead of the
    /// calling agent. Caller must be an agent whose owner is this user (or the
    /// user itself). Lets all agents under the user share the connection.
    #[serde(default)]
    on_behalf_of: Option<Uuid>,
    /// Optional tenant-supplied URL the callback redirects to after the
    /// OAuth dance finishes. See [`CreateConnectionInput::return_url`].
    #[serde(default)]
    return_url: Option<String>,
    /// Service instances to atomically bind the resulting connection to when
    /// the callback fires. Plural; the singular `service_instance_id` alias is
    /// merged in. See [`CreateConnectionInput::pin_service_ids`].
    #[serde(default)]
    pin_service_ids: Vec<Uuid>,
    /// Singular back-compat alias for `pin_service_ids`, merged into the list.
    #[serde(default)]
    service_instance_id: Option<Uuid>,
}

/// Wire shape for `POST /v1/connections`.
///
/// Field name `auth_url` is unchanged from the pre-PR shape — the *value*
/// upgrades to the Overslash-gated URL (`/connect-authorize?id=…`) which
/// fail-fasts on session mismatch before redirecting to the provider, so
/// existing callers transparently inherit the chat-delivery hardening
/// described in the kernel doc-comment in
/// `services/platform_connections.rs`. The raw provider authorize URL is
/// never surfaced — white-label partners import tokens instead of wrapping an
/// Overslash-built authorize URL.
#[derive(Serialize)]
struct InitiateConnectionResponse {
    auth_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    short: Option<String>,
    state: String,
    provider: String,
    expires_at: OffsetDateTime,
    flow_id: String,
}

async fn initiate_connection(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    headers: HeaderMap,
    Json(req): Json<InitiateConnectionRequest>,
) -> Result<Json<InitiateConnectionResponse>> {
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let ctx = PlatformCallContext {
        org_id: acl.org_id,
        identity_id: acl.identity_id,
        access_level: acl.access_level,
        db: state.db_pool(&ext),
        registry: state.registry.clone(),
        config: state.config.clone(),
        http_client: state.http_client.clone(),
    };
    // Merge the singular alias into the plural list (dedup preserves order).
    let mut pin_service_ids = req.pin_service_ids;
    if let Some(sid) = req.service_instance_id {
        if !pin_service_ids.contains(&sid) {
            pin_service_ids.push(sid);
        }
    }
    let input = CreateConnectionInput {
        provider: req.provider,
        scopes: req.scopes,
        byoc_credential_id: req.byoc_credential_id,
        on_behalf_of: req.on_behalf_of,
        // REST `POST /v1/connections` is the create-from-scratch entry
        // point. The reauth/upgrade flows go through the action handler's
        // recovery arms (or the dedicated `/upgrade_scopes` route).
        upgrade_connection_id: None,
        return_url: req.return_url,
        service_instance_id: None,
        pin_service_ids,
    };
    let kernel_response: CreateConnectionResponse = kernel_create_connection(
        ctx,
        input,
        RequestMeta {
            ip: ip.0.as_deref(),
            user_agent,
        },
    )
    .await?;

    Ok(Json(InitiateConnectionResponse {
        auth_url: kernel_response.auth_url,
        short: kernel_response.short,
        state: kernel_response.state,
        provider: kernel_response.provider,
        expires_at: kernel_response.expires_at,
        flow_id: kernel_response.flow_id,
    }))
}

// ---------------------------------------------------------------------------
// POST /v1/connections/import — white-label token vault
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ImportConnectionRequest {
    provider: String,
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    account_email: Option<String>,
    #[serde(default)]
    byoc_credential_id: Option<Uuid>,
    #[serde(default)]
    on_behalf_of: Option<Uuid>,
    /// Service instances to atomically bind to the imported connection. The
    /// plural form; the singular `service_instance_id` is accepted as an alias
    /// and merged in.
    #[serde(default)]
    pin_service_ids: Vec<Uuid>,
    /// Singular back-compat alias for `pin_service_ids`. Merged into the list.
    #[serde(default)]
    service_instance_id: Option<Uuid>,
}

#[derive(Serialize)]
struct ImportConnectionResponse {
    connection_id: Uuid,
    provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_email: Option<String>,
    /// `null` when the import didn't declare scopes (unknown — the scope-gate
    /// gives the connection the benefit of the doubt).
    scopes: Option<Vec<String>>,
    is_default: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pinned_service_ids: Vec<Uuid>,
}

/// `POST /v1/connections/import` — vault OAuth tokens a white-label partner
/// minted itself. The partner runs the full OAuth dance against its own client
/// and POSTs the resulting tokens here with an org API key, pinning a
/// **required** `byoc_credential_id`; Overslash stores, self-refreshes via that
/// pinned client, and injects them, and never issues a `redirect_uri`.
/// See `docs/design/white-label-token-vault.md`.
async fn import_connection(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    headers: HeaderMap,
    Json(req): Json<ImportConnectionRequest>,
) -> Result<Json<ImportConnectionResponse>> {
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let ctx = PlatformCallContext {
        org_id: acl.org_id,
        identity_id: acl.identity_id,
        access_level: acl.access_level,
        db: state.db_pool(&ext),
        registry: state.registry.clone(),
        config: state.config.clone(),
        http_client: state.http_client.clone(),
    };
    // Merge the singular alias into the plural list (dedup preserves order).
    let mut pin_service_ids = req.pin_service_ids;
    if let Some(sid) = req.service_instance_id {
        if !pin_service_ids.contains(&sid) {
            pin_service_ids.push(sid);
        }
    }
    let input = crate::services::platform_connections::ImportConnectionInput {
        provider: req.provider,
        access_token: req.access_token,
        refresh_token: req.refresh_token,
        expires_at: req.expires_at,
        expires_in: req.expires_in,
        scopes: req.scopes,
        account_email: req.account_email,
        byoc_credential_id: req.byoc_credential_id,
        on_behalf_of: req.on_behalf_of,
        pin_service_ids,
    };
    let resp = crate::services::platform_connections::kernel_import_connection(
        ctx,
        input,
        RequestMeta {
            ip: ip.0.as_deref(),
            user_agent,
        },
    )
    .await?;

    Ok(Json(ImportConnectionResponse {
        connection_id: resp.connection_id,
        provider: resp.provider,
        account_email: resp.account_email,
        scopes: resp.scopes,
        is_default: resp.is_default,
        pinned_service_ids: resp.pinned_service_ids,
    }))
}

// ---------------------------------------------------------------------------
// GET /connect-authorize?id=F
// ---------------------------------------------------------------------------
//
// Public-facing fail-fast UX gate for the HTTP-OAuth flow. Mirrors
// `oauth_upstream::gated_authorize`: reads the dashboard session, looks up
// the flow row, and only redirects to the provider when the session
// actually matches. This is the chat-delivery hardening described in
// `docs/design/agent-mcp-bootstrap-story.md` §3 ("Is this vulnerable to
// the Obsidian pitfalls?") — without this gate, an agent could hand a
// raw provider URL to the user with no Overslash-branded checkpoint.

#[derive(Debug, Deserialize)]
struct ConnectAuthorizeParams {
    id: String,
}

async fn connect_authorize(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    headers: HeaderMap,
    Query(params): Query<ConnectAuthorizeParams>,
) -> Result<Response> {
    let Some(flow) = oauth_connection_flow::get_by_id(state.db(&ext), &params.id).await? else {
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

    let session = match read_session(&state, &headers) {
        Ok(s) => s,
        Err(SessionError::Missing) => {
            // Out-of-band delivery (Slack/email/agent chat) clicked
            // without an active session. Bounce through login and
            // resume.
            let return_to = format!(
                "{}/connect-authorize?id={}",
                state.config.public_url.trim_end_matches('/'),
                flow.id
            );
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

    match evaluate_connect_gate(&state, &ext, &session, &flow, allow_remint(&ext)).await? {
        ConnectGateOutcome::Deny => Ok(mismatch_html()),
        // Admin/actor who is not the owner: render the loud consent page. The
        // flow is NOT consumed here — the confirm POST is the boundary that
        // re-validates and consumes. `set_cookie` is recomputed on confirm.
        ConnectGateOutcome::NeedsConsent {
            owner_label,
            provider,
            ..
        } => Ok(admin_consent_html(&owner_label, &provider, &flow.id)),
        ConnectGateOutcome::Allow { set_cookie } => {
            consume_and_redirect(&state, &ext, &flow.id, set_cookie).await
        }
    }
}

#[derive(Deserialize)]
struct ConfirmParams {
    id: String,
}

/// POST target of the admin/actor consent interstitial ([`admin_consent_html`]).
/// The consent page is advisory; this handler is the boundary — it re-runs the
/// full gate evaluation server-side (never trusting the page) and only then
/// consumes the flow and redirects to the provider. `SameSite=Lax` on the
/// session cookie blocks a cross-site forge of this POST.
async fn connect_authorize_confirm(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    headers: HeaderMap,
    Form(params): Form<ConfirmParams>,
) -> Result<Response> {
    let Some(flow) = oauth_connection_flow::get_by_id(state.db(&ext), &params.id).await? else {
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
    let session = match read_session(&state, &headers) {
        Ok(s) => s,
        Err(SessionError::Missing) => return Err(AppError::Unauthorized("missing session".into())),
        Err(SessionError::Invalid) => {
            return Err(AppError::Unauthorized("invalid session cookie".into()));
        }
    };
    match evaluate_connect_gate(&state, &ext, &session, &flow, allow_remint(&ext)).await? {
        ConnectGateOutcome::Deny => Ok(mismatch_html()),
        // Owner/auto-switch, or a consented admin/actor — both proceed.
        ConnectGateOutcome::Allow { set_cookie }
        | ConnectGateOutcome::NeedsConsent { set_cookie, .. } => {
            consume_and_redirect(&state, &ext, &flow.id, set_cookie).await
        }
    }
}

/// Whether the connect gate may transparently re-mint the session cookie to the
/// flow's org. On an explicit org subdomain the dashboard already aligns the
/// cookie via `/auth/switch-org`, so we never silently re-scope there; on
/// `Root` (local dev with no subdomains, or the apex) the auto-switch is the
/// fix for multi-org / multi-IdP users.
fn allow_remint(ext: &axum::http::Extensions) -> bool {
    !matches!(
        ext.get::<crate::middleware::subdomain::RequestOrgContext>(),
        Some(crate::middleware::subdomain::RequestOrgContext::Org { .. })
    )
}

/// Atomically claim the flow for redirect and 303 to the upstream provider,
/// attaching `set_cookie` only on the winning consume (so we never re-scope a
/// session for a flow we didn't actually start). `consume` is the gate's
/// single-use UX flag — a concurrent click that already marked the row returns
/// `None`, in which case we render the "already been used" page instead of
/// letting two browser tabs race into the upstream provider. The
/// `/v1/oauth/callback` security boundary still re-validates everything from the
/// OAuth `state` parameter regardless.
async fn consume_and_redirect(
    state: &AppState,
    ext: &axum::http::Extensions,
    flow_id: &str,
    set_cookie: Option<axum::http::HeaderValue>,
) -> Result<Response> {
    match oauth_connection_flow::consume(state.db(ext), flow_id).await? {
        Some(row) => {
            let mut resp = Redirect::to(&row.upstream_authorize_url).into_response();
            if let Some(cookie) = set_cookie {
                resp.headers_mut().insert(header::SET_COOKIE, cookie);
            }
            Ok(resp)
        }
        None => Ok(gone_html(
            "This OAuth link has already been used. Initiate the connection again to retry.",
        )),
    }
}

#[derive(Deserialize)]
struct OAuthCallbackParams {
    code: String,
    state: String,
}

/// Successful-path payload of [`oauth_callback`]. Wrapped here so the
/// outer handler can decide between returning JSON (the legacy default)
/// and a 303 redirect to a tenant-supplied `return_url`. Field shape is identical
/// to the historical `Json(serde_json::json!{...})` body so existing
/// callers keep working without an opt-in.
struct CallbackSuccess {
    connection_id: Uuid,
    provider_key: String,
    account_email: Option<String>,
    scopes: Vec<String>,
    /// When `POST /v1/services` orchestrated this flow AND the callback
    /// successfully bound the new connection to that instance, the id of
    /// that service instance. Suppressed when the bind failed (see
    /// `service_instance_bind_error`) — callers should not infer that
    /// the named instance now points at this connection.
    service_instance_id: Option<Uuid>,
    /// Every instance successfully bound to the new connection (the plural
    /// successor to `service_instance_id`). Empty when no pins were requested
    /// or all failed.
    bound_service_instance_ids: Vec<Uuid>,
    /// Coarse error code when binding the connection to the service
    /// instance failed after the OAuth dance succeeded. The connection
    /// itself is still saved — callers can retry the bind via `PUT
    /// /v1/services/{id}/manage`. Possible codes:
    /// - `service_instance_not_found`: the instance no longer exists.
    /// - `service_instance_owner_mismatch`: the bind would have crossed
    ///   identity ownership (defense against a spoofed
    ///   `service_instance_id` on the flow row).
    /// - `service_instance_bind_failed`: the DB update itself errored.
    service_instance_bind_error: Option<&'static str>,
}

/// Trusted redirect target derived from a flow row that matches the
/// callback's state and whose host is on the operator allow-list. Built
/// once up front so success and error branches share the same gating.
struct VerifiedRedirect {
    url: url::Url,
    provider_key: String,
}

async fn oauth_callback(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    ip: ClientIp,
    Query(params): Query<OAuthCallbackParams>,
) -> Response {
    // `state` is the opaque base62 flow-row id. Every field the callback
    // needs (org/identity/provider/byoc/PKCE/actor/upgrade) is read from
    // the row — no other segments to parse, no cross-check to forge.
    let flow_id = params.state.trim();
    if flow_id.is_empty() {
        return AppError::BadRequest("missing state parameter".into()).into_response();
    }
    let flow = match oauth_connection_flow::get_by_id(state.db(&ext), flow_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return AppError::BadRequest("invalid state parameter".into()).into_response();
        }
        Err(e) => return AppError::from(e).into_response(),
    };

    let redirect_target = resolve_redirect_target(&state, &flow);

    // The default callback `redirect_uri`. Every flow now completes through this
    // browser callback — there is no per-flow redirect override any more.
    // Recomputed from config so it byte-matches what the authorize URL was built
    // with.
    let redirect_uri = crate::services::platform_connections::default_callback_redirect_uri(
        &state.config.public_url,
    );

    // Merge the singular `service_instance_id` (legacy / in-flight flows) with
    // the plural `pin_service_instance_ids`, preserving order and de-duping.
    let mut pin_ids = flow.pin_service_instance_ids.clone();
    if let Some(sid) = flow.service_instance_id {
        if !pin_ids.contains(&sid) {
            pin_ids.insert(0, sid);
        }
    }

    let outcome = oauth_callback_inner(
        &state,
        &ext,
        &ip,
        &params,
        flow.org_id,
        flow.identity_id,
        &flow.provider_key,
        flow.byoc_credential_id,
        flow.pkce_code_verifier.as_deref(),
        flow.actor_identity_id,
        flow.upgrade_connection_id,
        &pin_ids,
        &flow.scopes,
        &redirect_uri,
    )
    .await;

    match (outcome, redirect_target) {
        (Ok(payload), Some(redir)) => success_redirect(redir, &payload),
        (Ok(payload), None) => Json(callback_success_json(&payload)).into_response(),
        (Err(err), Some(redir)) => error_redirect(redir, &err),
        (Err(err), None) => err.into_response(),
    }
}

/// The `status:"connected"` JSON body for a completed OAuth flow — the
/// no-`return_url` branch of [`oauth_callback`].
fn callback_success_json(payload: &CallbackSuccess) -> serde_json::Value {
    let mut body = serde_json::json!({
        "status": "connected",
        "connection_id": payload.connection_id,
        "provider": payload.provider_key,
        "account_email": payload.account_email,
        "scopes": payload.scopes,
    });
    if let Some(id) = payload.service_instance_id {
        body["service_instance_id"] = serde_json::Value::String(id.to_string());
    }
    if !payload.bound_service_instance_ids.is_empty() {
        body["bound_service_instance_ids"] = serde_json::Value::Array(
            payload
                .bound_service_instance_ids
                .iter()
                .map(|id| serde_json::Value::String(id.to_string()))
                .collect(),
        );
    }
    if let Some(code) = payload.service_instance_bind_error {
        body["service_instance_bind_error"] = serde_json::Value::String(code.into());
    }
    body
}

/// Build a verified redirect target from the flow row, or `None` if any
/// gate fails:
///
/// 1. Allow-list is configured (empty list disables the feature).
/// 2. The flow row carries a `return_url`.
/// 3. The `return_url` parses and its host is on the allow-list.
///
/// Per-tenancy cross-checks that used to live here are gone: the OAuth
/// `state` parameter is now the row id itself, so there's no separate
/// state to forge against the row.
fn resolve_redirect_target(
    state: &AppState,
    flow: &oauth_connection_flow::OauthConnectionFlowRow,
) -> Option<VerifiedRedirect> {
    if state.config.connection_return_url_allowed_hosts.is_empty() {
        return None;
    }
    let raw = flow.return_url.as_deref()?;
    let url = url::Url::parse(raw).ok()?;
    let host = url.host_str()?.to_ascii_lowercase();
    if !state
        .config
        .connection_return_url_allowed_hosts
        .contains(&host)
    {
        return None;
    }
    Some(VerifiedRedirect {
        url,
        provider_key: flow.provider_key.clone(),
    })
}

/// Browser-facing success redirect to the tenant's `return_url`.
///
/// The query string carries only the *stable key* — `connection_id` — plus a
/// coarse `service_instance_id`/`service_instance_bind_error` echo kept for
/// back-compat with single-pin callers. It deliberately does **not** enumerate
/// the full `bound_service_instance_ids` set: a browser-visible query string is
/// the wrong transport for authoritative binding state (it can't losslessly
/// carry a list, and the redirect is user-controllable). The authoritative,
/// complete binding set is the DB — a partner reads it back with
/// `GET /v1/connections/{connection_id}` (its `used_by` list), keyed off the
/// `connection_id` already in this redirect. The JSON branch
/// ([`callback_success_json`]) still includes the full list as a convenience
/// for programmatic callers, who receive it in an authenticated response body
/// rather than a URL.
fn success_redirect(redir: VerifiedRedirect, payload: &CallbackSuccess) -> Response {
    let mut url = redir.url;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("status", "success");
        pairs.append_pair("connection_id", &payload.connection_id.to_string());
        pairs.append_pair("provider", &payload.provider_key);
        if let Some(email) = payload.account_email.as_deref() {
            pairs.append_pair("account_email", email);
        }
        // Back-compat single-instance echo only. For the full set, the partner
        // queries `GET /v1/connections/{connection_id}` (see doc comment above).
        if let Some(id) = payload.service_instance_id {
            pairs.append_pair("service_instance_id", &id.to_string());
        }
        if let Some(code) = payload.service_instance_bind_error {
            pairs.append_pair("service_instance_bind_error", code);
        }
    }
    Redirect::to(url.as_str()).into_response()
}

fn error_redirect(redir: VerifiedRedirect, err: &AppError) -> Response {
    let mut url = redir.url;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("status", "error");
        pairs.append_pair("provider", &redir.provider_key);
        pairs.append_pair("reason", redirect_reason_token(err));
    }
    Redirect::to(url.as_str()).into_response()
}

/// Coarse, allow-listed reason token for the redirect URL. The tenant
/// page renders its own copy from this token — we intentionally do NOT
/// pass the raw error text. Echoing `err.to_string()` here would surface
/// internal details (SQL errors, reqwest decode failures, etc.) that
/// `AppError::IntoResponse` deliberately scrubs from the JSON path.
fn redirect_reason_token(err: &AppError) -> &'static str {
    use axum::http::StatusCode;
    match err.status_code() {
        StatusCode::BAD_REQUEST => "bad_request",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::GONE => "gone",
        StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        StatusCode::BAD_GATEWAY => "upstream_error",
        _ => "internal_error",
    }
}

#[allow(clippy::too_many_arguments)]
async fn oauth_callback_inner(
    state: &AppState,
    ext: &axum::http::Extensions,
    ip: &ClientIp,
    params: &OAuthCallbackParams,
    org_id: Uuid,
    identity_id: Uuid,
    provider_key: &str,
    byoc_credential_id: Option<Uuid>,
    code_verifier: Option<&str>,
    actor_identity_id: Uuid,
    upgrade_connection_id: Option<Uuid>,
    service_instance_ids: &[Uuid],
    requested_scopes: &[String],
    redirect_uri: &str,
) -> Result<CallbackSuccess> {
    let provider = overslash_db::repos::oauth_provider::get_by_key(state.db(ext), provider_key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider '{provider_key}' not found")))?;

    let enc_key = state.config.keyring()?;
    let creds = client_credentials::resolve(
        state.db(ext),
        &enc_key,
        org_id,
        Some(identity_id),
        provider_key,
        None,
        byoc_credential_id,
    )
    .await?;

    let effective_byoc_id = creds.byoc_credential_id;

    // Exchange code for tokens. `redirect_uri` is passed in by the caller — it
    // is the exact value the authorize URL was built with (read off the flow
    // row), so it byte-matches what the provider saw. Recomputing it here would
    // break white-label flows whose authorize `redirect_uri` is partner-hosted.
    let tokens = oauth::exchange_code(
        &state.http_client,
        &provider,
        &creds.client_id,
        &creds.client_secret,
        &params.code,
        redirect_uri,
        code_verifier,
    )
    .await
    .map_err(|e| AppError::BadRequest(format!("token exchange failed: {e}")))?;

    // Fetch account identity (email / login) from the provider — best-effort;
    // a failure leaves the label blank but still lands the connection.
    let account_email =
        oauth::fetch_account_email(&state.http_client, &provider, &tokens.access_token)
            .await
            .unwrap_or(None);
    // When the token response omits `scope` entirely (HubSpot always does),
    // RFC 6749 §5.1 means the requested set was granted verbatim — record
    // that instead of a known-empty `[]` the scope gate would then enforce.
    let granted_scopes = tokens.granted_scopes_or_requested(requested_scopes);

    // Encrypt tokens
    let encrypted_access = crypto::encrypt(&enc_key, tokens.access_token.as_bytes())?;
    let encrypted_refresh = tokens
        .refresh_token
        .as_ref()
        .map(|rt| crypto::encrypt(&enc_key, rt.as_bytes()))
        .transpose()?;
    let expires_at = tokens
        .expires_in
        .map(|secs| time::OffsetDateTime::now_utc() + time::Duration::seconds(secs));

    // The OAuth callback is unauthenticated by design (the redirect_uri is
    // public), so all tenancy invariants come from the flow row that the
    // opaque `state` parameter resolved to — that row is what we issued at
    // initiate time and the unguessable id is the only thing the attacker
    // would have to forge.
    let scope = OrgScope::new(org_id, state.db_pool(ext));

    let (connection_id, audit_action, effective_scopes) =
        if let Some(existing_id) = upgrade_connection_id {
            // Incremental upgrade: union the granted scope set with what was on
            // the connection, update tokens, keep the same row id so every
            // service pointing at it stays bound.
            let existing = scope
                .get_connection(existing_id)
                .await?
                .ok_or_else(|| AppError::NotFound("connection not found".into()))?;
            if existing.identity_id != identity_id || existing.provider_key != provider_key {
                return Err(AppError::BadRequest(
                    "state mismatch: upgrade connection does not match identity/provider".into(),
                ));
            }
            let merged: Vec<String> =
                merge_scopes(existing.scopes.as_deref().unwrap_or(&[]), &granted_scopes);
            let updated = scope
                .update_connection_tokens_and_scopes(
                    existing_id,
                    &encrypted_access,
                    encrypted_refresh.as_deref(),
                    expires_at,
                    Some(&merged),
                    // Refresh the label too — the provider may have renamed the
                    // account between the original connect and the upgrade.
                    // `COALESCE` on the repo side leaves the existing value
                    // intact when we pass `None` (userinfo fetch failed).
                    account_email.as_deref(),
                )
                .await?;
            if !updated {
                // Concurrent deletion between the initial get_connection() read
                // and this update. Surface a specific error instead of telling
                // the caller the upgrade succeeded against a row that's gone.
                return Err(AppError::NotFound(
                    "connection was deleted during upgrade".into(),
                ));
            }
            (existing_id, "connection.scopes_upgraded", merged)
        } else {
            let conn = scope
                .create_connection(overslash_db::repos::connection::CreateConnection {
                    org_id,
                    identity_id,
                    provider_key,
                    encrypted_access_token: &encrypted_access,
                    encrypted_refresh_token: encrypted_refresh.as_deref(),
                    token_expires_at: expires_at,
                    // Orchestrated flows always know the granted set (echoed
                    // by the token response, or the requested set when the
                    // provider omitted `scope`) — record it, never NULL.
                    scopes: Some(&granted_scopes),
                    account_email: account_email.as_deref(),
                    byoc_credential_id: effective_byoc_id,
                })
                .await?;
            (conn.id, "connection.created", granted_scopes.clone())
        };

    let _ = scope
        .log_audit(AuditEntry {
            org_id,
            identity_id: Some(actor_identity_id),
            action: audit_action,
            resource_type: Some("connection"),
            resource_id: Some(connection_id),
            detail: serde_json::json!({
                "provider": provider_key,
                "account_email": account_email,
                "scopes": granted_scopes,
            }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    {
        let db = state.db_pool(ext);
        let client = state.http_client.clone();
        let provider_key = provider_key.to_string();
        let account_email = account_email.clone();
        // For upgrades, this is the merged scope set (the connection's full
        // current scopes), not just the delta granted in this OAuth flow.
        // Webhook consumers want the resulting state, not the diff.
        let scopes = effective_scopes;
        tokio::spawn(async move {
            let payload = serde_json::json!({
                "connection_id": connection_id,
                "provider": provider_key,
                "account_email": account_email,
                "scopes": scopes,
                "identity_id": identity_id,
            });
            crate::services::webhook_dispatcher::dispatch(
                &db,
                &client,
                org_id,
                audit_action,
                payload,
            )
            .await;
        });
    }

    // Best-effort bind: if `POST /v1/services` orchestrated this flow, the
    // service instance already exists with `connection_id = NULL`. Update
    // it now so the instance is usable immediately. On failure we keep the
    // connection (the OAuth tokens are valuable) and surface a coarse
    // error code; callers can retry via `PUT /v1/services/{id}/manage`.
    //
    // Ownership gate: the `service_instance_id` rides on the flow row,
    // which an MCP caller can pass directly via
    // `CreateConnectionInput.service_instance_id`. Without this check, an
    // attacker in the same org could spoof another user's instance id and
    // hijack it onto their own new connection. We require the instance's
    // `owner_identity_id` to match the flow's `identity_id` (the
    // connection owner). Org-level instances (owner_identity_id = NULL)
    // are also rejected here — connections are identity-bound and the
    // create-time `kernel_create_service` validation already forbids
    // pinning a connection to an org-level service.
    //
    // Best-effort by design (unlike the fully-atomic `/v1/connections/import`
    // path): the OAuth token exchange already succeeded and the connection is
    // valuable, so a bind failure must NOT discard it. We bind each id
    // independently, keep the connection regardless, and surface the first
    // failing id's coarse code — callers retry via `PUT /v1/services/{id}/manage`.
    let scope = OrgScope::new(org_id, state.db_pool(ext));
    let mut service_instance_bind_error: Option<&'static str> = None;
    let mut bound_service_instance_ids: Vec<Uuid> = Vec::new();
    for &svc_id in service_instance_ids {
        // Once one bind has failed, stop attempting the rest — the caller must
        // retry the whole set anyway, and partial binds are already recorded.
        if service_instance_bind_error.is_some() {
            break;
        }
        match scope.get_service_instance(svc_id).await {
            Ok(None) => {
                service_instance_bind_error = Some("service_instance_not_found");
            }
            Ok(Some(instance)) if instance.owner_identity_id != Some(identity_id) => {
                service_instance_bind_error = Some("service_instance_owner_mismatch");
            }
            Ok(Some(_)) => {
                let bind_input = overslash_db::repos::service_instance::UpdateServiceInstance {
                    name: None,
                    connection_id: Some(Some(connection_id)),
                    secret_name: None,
                    url: None,
                    use_default_connection: None,
                };
                match scope.update_service_instance(svc_id, &bind_input).await {
                    Ok(Some(_)) => bound_service_instance_ids.push(svc_id),
                    Ok(None) => {
                        // Concurrent delete in the gap between the
                        // ownership check above and the UPDATE.
                        service_instance_bind_error = Some("service_instance_not_found");
                    }
                    Err(_) => {
                        service_instance_bind_error = Some("service_instance_bind_failed");
                    }
                }
            }
            Err(_) => {
                service_instance_bind_error = Some("service_instance_bind_failed");
            }
        }
    }

    Ok(CallbackSuccess {
        connection_id,
        provider_key: provider_key.to_string(),
        account_email,
        scopes: granted_scopes,
        // Back-compat: surface the first bound id in the singular field the
        // JSON/redirect shapes have always carried.
        service_instance_id: bound_service_instance_ids.first().copied(),
        bound_service_instance_ids,
        service_instance_bind_error,
    })
}

#[derive(Serialize)]
struct ConnectionSummary {
    id: Uuid,
    /// Owner identity of the connection. Connections are bound to the user
    /// identity (D22), so this is the user who owns the linked account. The
    /// dashboard resolves it to a name in the admin "all users" view.
    owner_identity_id: Uuid,
    provider_key: String,
    account_email: Option<String>,
    /// Scopes the provider actually granted at the last OAuth flow. The
    /// dashboard renders these as chips and compares them to a template's
    /// required scopes when deciding whether to offer the "upgrade" prompt.
    scopes: Vec<String>,
    /// Template keys of active service instances currently bound to this
    /// connection. The dashboard's new-service wizard uses this to prefer a
    /// connection that *isn't* already in use for the template being created.
    used_by_service_templates: Vec<String>,
    is_default: bool,
    /// When true, this connection is preserved from the service-deletion
    /// auto-cleanup — the dashboard renders it as a "kept" toggle.
    keep: bool,
    /// When true, the connection must be re-authorized before use (e.g. its
    /// pinned BYOC client was replaced) — the dashboard renders a warning badge.
    reauth_required: bool,
    created_at: String,
}

/// Query params for `GET /v1/connections`. Mirrors `ListServicesQuery`.
#[derive(Deserialize, Default)]
struct ListConnectionsQuery {
    /// Admin-only: when true, list every connection in the org (all users'
    /// rows) instead of only the caller's own. Silently ignored for non-admin
    /// callers so a stale dashboard tab doesn't start 403'ing when an admin
    /// flag is revoked — same contract as the services list.
    #[serde(default)]
    include_user_level: bool,
    /// Admin-or-self: list connections owned by this specific identity instead
    /// of the caller's own. The service detail page passes the service's
    /// `owner_identity_id` so an admin viewing another user's service sees that
    /// user's bindable connections (connections are identity-scoped). Equal to
    /// the caller's own identity → self path. A non-admin caller passing a
    /// *different* identity is silently downgraded to their own list (no 403,
    /// same contract as `include_user_level`). Takes precedence over
    /// `include_user_level` when both are set.
    #[serde(default)]
    owner_identity_id: Option<Uuid>,
}

async fn list_connections(
    scope: UserScope,
    Query(q): Query<ListConnectionsQuery>,
) -> Result<Json<Vec<ConnectionSummary>>> {
    // `include_user_level` is admin-only. Read `is_org_admin` straight off the
    // identity row (same flag-based check as the services list — `AdminAcl`
    // would instead require the `overslash` service admin grant). Non-admins
    // passing the flag fall through to the standard self-scoped listing.
    let is_org_admin = || async {
        Ok::<bool, AppError>(
            scope
                .org()
                .get_identity(scope.user_id())
                .await?
                .map(|i| i.is_org_admin)
                .unwrap_or(false),
        )
    };

    let rows = if let Some(owner) = q.owner_identity_id {
        // Owner-scoped listing. Self is always allowed; another identity
        // requires org admin, else fall through to the caller's own list.
        if owner == scope.user_id() {
            scope.list_my_connections().await?
        } else if is_org_admin().await? {
            let owner_scope = UserScope::new(scope.org_id(), owner, scope.org().db().clone());
            owner_scope.list_my_connections().await?
        } else {
            scope.list_my_connections().await?
        }
    } else if q.include_user_level && is_org_admin().await? {
        scope.org().list_all_connections().await?
    } else {
        scope.list_my_connections().await?
    };
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    // Usage lookup is org-scoped; downgrade the UserScope to an OrgScope so
    // the service_instances query doesn't need a user bound.
    let usage_rows = scope.org().connection_usage_by_template(&ids).await?;
    let mut usage: HashMap<Uuid, Vec<String>> = HashMap::new();
    for (conn_id, tpl) in usage_rows {
        usage.entry(conn_id).or_default().push(tpl);
    }

    Ok(Json(
        rows.into_iter()
            .map(|r| ConnectionSummary {
                used_by_service_templates: usage.remove(&r.id).unwrap_or_default(),
                id: r.id,
                owner_identity_id: r.identity_id,
                provider_key: r.provider_key,
                account_email: r.account_email,
                scopes: r.scopes.unwrap_or_default(),
                is_default: r.is_default,
                keep: r.keep,
                reauth_required: r.reauth_required,
                created_at: fmt_time(r.created_at),
            })
            .collect(),
    ))
}

/// A service instance bound to a connection, for the detail page's "Used by"
/// list. `name` is what the dashboard links to (`/services/{name}`).
#[derive(Serialize)]
struct UsedByService {
    id: Uuid,
    name: String,
    template_key: String,
}

/// Full connection detail returned by `GET /v1/connections/{id}`. Superset of
/// `ConnectionSummary`: adds `updated_at` (so the dashboard can detect an
/// in-place reconnect by polling) and the resolved `used_by` instance list
/// (vs the summary's bare template-key array).
#[derive(Serialize)]
struct ConnectionDetail {
    id: Uuid,
    provider_key: String,
    account_email: Option<String>,
    scopes: Vec<String>,
    is_default: bool,
    /// When true, this connection is preserved from the service-deletion
    /// auto-cleanup (see `POST /v1/connections/{id}/keep`).
    keep: bool,
    /// When true, the connection must be re-authorized before use (e.g. its
    /// pinned BYOC client was replaced). Cleared on the next successful reconnect.
    reauth_required: bool,
    created_at: String,
    updated_at: String,
    used_by: Vec<UsedByService>,
    /// What OAuth client credentials the next refresh will use. Mirrors the
    /// `client_credentials::resolve()` cascade against current state (the
    /// connection's stored BYOC may have been deleted out from under it) —
    /// a pinned BYOC for imported connections, the org/env cascade otherwise.
    credential_source: client_credentials::CredentialSource,
}

async fn get_connection(scope: UserScope, Path(id): Path<Uuid>) -> Result<Json<ConnectionDetail>> {
    // Caller's own connection takes the fast path. Falling through to an
    // org-scoped lookup only for org admins lets them open another user's
    // connection from the "all users" view; everyone else gets a 404.
    let conn = match scope.get_my_connection(id).await? {
        Some(c) => c,
        None => {
            let org = scope.org();
            let is_admin = org
                .get_identity(scope.user_id())
                .await?
                .map(|i| i.is_org_admin)
                .unwrap_or(false);
            let conn = if is_admin {
                org.get_connection(id).await?
            } else {
                None
            };
            conn.ok_or_else(|| AppError::NotFound("connection not found".into()))?
        }
    };

    // Usage lookup is org-scoped; downgrade to OrgScope like `list_connections`.
    let org = scope.org();
    let used_by = org
        .connection_usage_instances(id)
        .await?
        .into_iter()
        .map(|(id, name, template_key)| UsedByService {
            id,
            name,
            template_key,
        })
        .collect();

    // Every connection refreshes via the credential cascade — a pinned BYOC
    // (imported connections, and orchestrated ones that pinned one) or the
    // org/env fallback. Describe whichever the next refresh would use.
    let credential_source = client_credentials::describe_source(
        &org,
        &conn.provider_key,
        Some(conn.identity_id),
        conn.byoc_credential_id,
    )
    .await?;

    Ok(Json(ConnectionDetail {
        id: conn.id,
        provider_key: conn.provider_key,
        account_email: conn.account_email,
        scopes: conn.scopes.unwrap_or_default(),
        is_default: conn.is_default,
        keep: conn.keep,
        reauth_required: conn.reauth_required,
        created_at: fmt_time(conn.created_at),
        updated_at: fmt_time(conn.updated_at),
        used_by,
        credential_source,
    }))
}

/// Promote a connection to be the default for its (identity, provider). Demotes
/// any sibling that held the flag. Identity-scoped: the caller must own the
/// connection — or be an org admin acting on another user's connection from the
/// "all users" view. Low-risk + idempotent — the dashboard fires it from a
/// radio / toggle with no confirmation.
async fn set_connection_default(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let identity_id = acl.identity_id.ok_or_else(|| {
        AppError::BadRequest("set_default requires an identity-bound API key".into())
    })?;

    // The caller's own connection takes the identity-scoped path. For a
    // connection owned by another user, an org admin may still promote it —
    // the org-scoped path demotes siblings within the *owner's* identity, not
    // the admin's. Non-owner non-admins get a 404 (the row stays invisible).
    let updated = UserScope::new(acl.org_id, identity_id, state.db_pool(&ext))
        .set_my_connection_default(id)
        .await?;

    if !updated {
        let org = OrgScope::new(acl.org_id, state.db_pool(&ext));
        let is_admin = org
            .get_identity(identity_id)
            .await?
            .map(|i| i.is_org_admin)
            .unwrap_or(false);
        let promoted = is_admin && org.set_connection_default(id).await?;
        if !promoted {
            return Err(AppError::NotFound("connection not found".into()));
        }
    }

    let _ = OrgScope::new(acl.org_id, state.db_pool(&ext))
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "connection.set_default",
            resource_type: Some("connection"),
            resource_id: Some(id),
            detail: serde_json::json!({}),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(serde_json::json!({ "is_default": true })))
}

#[derive(Deserialize)]
struct SetKeepRequest {
    /// Whether to preserve this connection from the service-deletion auto-cleanup.
    keep: bool,
}

/// Set (or clear) the `keep` preserve flag on a connection. When `keep` is true
/// the connection survives service deletion even when no service references it.
/// Owner-or-admin gated, mirroring `set_connection_default`: the caller must own
/// the connection, or be an org admin acting on another user's connection from
/// the "all users" view; a non-owner non-admin gets a 404 (the row stays
/// invisible). Low-risk + idempotent — the dashboard fires it from a toggle.
async fn set_connection_keep(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
    Json(req): Json<SetKeepRequest>,
) -> Result<Json<serde_json::Value>> {
    let org = OrgScope::new(acl.org_id, state.db_pool(&ext));

    // Ownership gate: an identity-bound caller must own the connection or be an
    // org admin. An org-level (identity-less) key may set it on any connection
    // in the org — same authority as the org-scoped delete path.
    let allowed = if let Some(identity_id) = acl.identity_id {
        let owns = UserScope::new(acl.org_id, identity_id, state.db_pool(&ext))
            .get_my_connection(id)
            .await?
            .is_some();
        owns || org
            .get_identity(identity_id)
            .await?
            .map(|i| i.is_org_admin)
            .unwrap_or(false)
    } else {
        true
    };
    if !allowed {
        return Err(AppError::NotFound("connection not found".into()));
    }

    if !org.set_connection_keep(id, req.keep).await? {
        return Err(AppError::NotFound("connection not found".into()));
    }

    let _ = org
        .log_audit(AuditEntry {
            org_id: acl.org_id,
            identity_id: acl.identity_id,
            action: "connection.keep_updated",
            resource_type: Some("connection"),
            resource_id: Some(id),
            detail: serde_json::json!({ "keep": req.keep }),
            description: None,
            ip_address: ip.0.as_deref(),
        })
        .await;

    Ok(Json(serde_json::json!({ "keep": req.keep })))
}

#[derive(Deserialize)]
struct UpgradeScopesRequest {
    /// Additional scopes to request on top of the connection's current set.
    /// May overlap the current set — duplicates are deduped.
    scopes: Vec<String>,
}

#[derive(Serialize)]
struct UpgradeScopesResponse {
    auth_url: String,
    state: String,
    connection_id: Uuid,
    /// The union of existing + requested scopes the provider will be asked
    /// for. Useful for the UI to show the user what consent they're about
    /// to give.
    requested_scopes: Vec<String>,
}

/// Start an incremental-scope OAuth flow for an existing connection. Mints a
/// flow row whose `upgrade_connection_id` points at this connection — the
/// callback reads that off the row and updates this connection in place
/// instead of minting a new one. The flow completes through the browser gate
/// at `/v1/oauth/callback` like every other connect flow.
async fn upgrade_connection_scopes(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<UpgradeScopesRequest>,
) -> Result<Json<UpgradeScopesResponse>> {
    let caller_identity_id = acl
        .identity_id
        .ok_or_else(|| AppError::BadRequest("OAuth requires an identity-bound API key".into()))?;

    let org_scope = OrgScope::new(acl.org_id, state.db_pool(&ext));
    let existing = org_scope
        .get_connection(id)
        .await?
        .ok_or_else(|| AppError::NotFound("connection not found".into()))?;

    // Connections live at the owner identity (D22/D23) and are shared by every
    // agent under it, so the caller may upgrade a connection held by itself or
    // by its own ceiling user (its `owner_id`) — but not one owned by an
    // unrelated identity. Accept a legacy agent-owned row (`== caller`) too: the
    // flow is minted at `existing.identity_id` below, so it heals either way.
    let ceiling =
        crate::services::group_ceiling::resolve_ceiling_user_id(&org_scope, caller_identity_id)
            .await?;
    if existing.identity_id != caller_identity_id && existing.identity_id != ceiling {
        return Err(AppError::Forbidden(
            "connection belongs to another identity".into(),
        ));
    }

    // Headless (white-label) orgs drive their own OAuth flow — the gated
    // upgrade flow would mint a `/connect-authorize` link their end users can't
    // open. They broaden the grant on their side and re-import the connection
    // with the wider scopes via `POST /v1/connections/import`.
    if overslash_db::repos::org::get_headless(state.db(&ext), acl.org_id)
        .await?
        .unwrap_or(false)
    {
        return Err(AppError::BadRequest(
            "this org is headless; scopes can't be upgraded through Overslash — broaden \
             the grant and re-import the connection via POST /v1/connections/import"
                .into(),
        ));
    }

    // Union existing + requested scopes. Google with `include_granted_scopes=true`
    // would preserve old ones anyway, but sending the full union is what makes
    // non-Google providers work.
    let merged: Vec<String> = merge_scopes(existing.scopes.as_deref().unwrap_or(&[]), &req.scopes);

    // Mirror what `kernel_create_connection_for_identity` will do: union in
    // the provider's identity scopes so `requested_scopes` on the response
    // matches the actual consent the user is about to grant.
    let provider =
        overslash_db::repos::oauth_provider::get_by_key(state.db(&ext), &existing.provider_key)
            .await?
            .ok_or_else(|| {
                AppError::NotFound(format!("provider '{}' not found", existing.provider_key))
            })?;
    let effective_scopes: Vec<String> = merge_scopes(&merged, &provider.default_identity_scopes);

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok());
    let ctx = PlatformCallContext {
        org_id: acl.org_id,
        identity_id: acl.identity_id,
        access_level: acl.access_level,
        db: state.db_pool(&ext),
        registry: state.registry.clone(),
        config: state.config.clone(),
        http_client: state.http_client.clone(),
    };
    // Mint the upgrade flow at the connection's own identity — the callback
    // rejects a flow whose identity differs from the row it upgrades. Going
    // through `kernel_create_connection` would re-home to the caller's ceiling
    // (D23) and break the upgrade of a legacy agent-owned connection.
    let response = kernel_create_connection_for_identity(
        ctx,
        existing.identity_id,
        caller_identity_id,
        CreateConnectionInput {
            provider: existing.provider_key.clone(),
            scopes: merged.clone(),
            // Pin the same BYOC credential the original connection used so
            // the upgrade flow runs against the same OAuth client.
            byoc_credential_id: existing.byoc_credential_id,
            on_behalf_of: None,
            upgrade_connection_id: Some(id),
            return_url: None,
            service_instance_id: None,
            pin_service_ids: vec![],
        },
        RequestMeta {
            ip: ip.0.as_deref(),
            user_agent,
        },
    )
    .await?;

    Ok(Json(UpgradeScopesResponse {
        auth_url: response.auth_url,
        state: response.state,
        connection_id: id,
        requested_scopes: effective_scopes,
    }))
}

async fn delete_connection(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    ip: ClientIp,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let auth = acl;
    // Scope delete: if identity-bound, must own the connection — unless the
    // caller is an org admin, who may delete any connection in the org (the
    // "all users" view). Org-level keys can delete any connection in the org.
    let deleted = if let Some(identity_id) = auth.identity_id {
        let user_scope = UserScope::new(auth.org_id, identity_id, state.db_pool(&ext));
        if user_scope.delete_my_connection(id).await? {
            true
        } else {
            let org = user_scope.org();
            let is_admin = org
                .get_identity(identity_id)
                .await?
                .map(|i| i.is_org_admin)
                .unwrap_or(false);
            is_admin && org.delete_connection(id).await?
        }
    } else {
        OrgScope::new(auth.org_id, state.db_pool(&ext))
            .delete_connection(id)
            .await?
    };

    if deleted {
        fire_connection_deleted(
            &state,
            &ext,
            auth.org_id,
            auth.identity_id,
            ip.0.as_deref(),
            id,
        )
        .await;
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

/// Fire the side effects of a connection deletion: the `connection.deleted`
/// audit log entry and the `connection.deleted` webhook. Shared by the direct
/// `DELETE /v1/connections/{id}` handler and the service-deletion cascade that
/// cleans up an orphaned connection. Call only after the row was actually
/// deleted.
pub(crate) async fn fire_connection_deleted(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    ip: Option<&str>,
    connection_id: Uuid,
) {
    let _ = OrgScope::new(org_id, state.db_pool(ext))
        .log_audit(AuditEntry {
            org_id,
            identity_id,
            action: "connection.deleted",
            resource_type: Some("connection"),
            resource_id: Some(connection_id),
            detail: serde_json::json!({}),
            description: None,
            ip_address: ip,
        })
        .await;

    let db = state.db_pool(ext);
    let client = state.http_client.clone();
    tokio::spawn(async move {
        let payload = serde_json::json!({
            "connection_id": connection_id,
            "org_id": org_id,
            "identity_id": identity_id,
        });
        crate::services::webhook_dispatcher::dispatch(
            &db,
            &client,
            org_id,
            "connection.deleted",
            payload,
        )
        .await;
    });
}
