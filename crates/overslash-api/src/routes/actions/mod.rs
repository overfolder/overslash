//! Action execution endpoints (`POST /v1/actions/call`, `POST /v1/actions/validate`).
//!
//! Two call shapes per SPEC §8 — `service` is always required (the legacy
//! no-`service` raw-HTTP shape is rejected with 400):
//!
//! - **Service + defined action**: caller supplies `service` + `action` keys
//!   and `params`. The template's path/method/auth are used; permission keys
//!   derive as `{service}:{action}:{arg}`.
//! - **Service + HTTP verb**: caller supplies `service` + `method` +
//!   (`path` or `url`). Auth comes from the instance binding; `svc.hosts`
//!   bounds where the bearer can land. Permission keys derive as
//!   `{service}:{METHOD}:{path}`.
//!
//! Mode A (raw HTTP) is the verb shape against the synthetic `http`
//! pseudo-service (`service: "http"`). Its template ships with `hosts: []`
//! and `auth: []`, so `resolve_verb_host_and_path` extracts the host from
//! the caller-supplied `url` and per-call `secrets[]` are the only auth.
//! Permission keys derive identically to other services
//! (`http:{METHOD}:{host}{path}`).
//!
//! Precedence in `resolve_request`: Service + HTTP verb (if `service` set
//! without `action`) → Service + action (if both set).

use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::AppError,
    extractors::{AuthContext, ClientIp, ReqExt},
    services::{disclosure, response_filter::ResponseFilter},
};
use overslash_core::{
    permissions::SuggestedTier,
    types::{ActionResult, DisclosureField, McpAuth, SecretRef, service::Risk},
};

mod approval_detail;
mod auth;
mod call;
mod errors;
mod resolve;
mod service_resolve;
mod validate;

use call::call_action_impl;
use validate::validate_action_impl;

// Used by the approval-replay path to re-mint the OAuth credential that
// replay payloads deliberately don't persist.
pub(crate) use auth::{resolve_mcp_oauth_bearer, resolve_replay_auth_header};

/// Cap on the number of instance names we surface in `ServiceResolution`
/// error payloads. Agents only need a handful to disambiguate; the full
/// list lives in `overslash_search`.
const ERROR_INSTANCE_HINT_CAP: usize = 10;

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/actions/call", post(call_action))
}

/// `/v1/actions/validate` is a dry-run probe: it runs `validate_args` and
/// the permission chain, but never executes the upstream call, never
/// writes an approval, never logs audit, and is exempt from rate limits.
/// Mounted on its own router so callers can pre-flight bad params without
/// burning their rate budget.
pub fn validate_router() -> Router<AppState> {
    Router::new().route("/v1/actions/validate", post(validate_action))
}

/// Bound a caller-supplied service key to one that actually exists in the
/// registry, so the `template_key` metric label can never blow up
/// Prometheus cardinality: a client could otherwise submit
/// `service: "<arbitrary>"` and mint a new label value even on requests
/// that fail validation inside the inner handler.
pub(crate) fn bounded_template_key(
    registry: &overslash_core::registry::ServiceRegistry,
    service: Option<&str>,
) -> String {
    match service {
        Some(key) if registry.get(key).is_some() => key.to_string(),
        Some(_) => "_unknown".to_string(),
        None => "_invalid".to_string(),
    }
}

/// Query options for `POST /v1/actions/call`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct CallQuery {
    /// Opt-in (dashboard "try it" surface): return the gateway's own auth
    /// errors (`needs_authentication` / `reauth_required`) as a `200` envelope
    /// with the status inside the body, instead of a real `401`. Browser
    /// clients otherwise can't distinguish a target-service auth prompt from an
    /// expired-session `401` and bounce the user to `/login`. The default
    /// (unset) keeps the typed-`401` contract MCP/REST/white-label callers rely
    /// on. Only the gateway's auth `401`s are wrapped — upstream statuses
    /// already ride inside the `status: "called"` envelope, and other gateway
    /// errors (400/403/5xx) pass through unchanged.
    #[serde(default)]
    wrap: Option<bool>,
}

/// When `?wrap=true`, turn the gateway's auth-`401` variants into a `200`
/// `CallResponse`-shaped envelope (`status` discriminant inside the body).
/// Returns `None` for every other error so it propagates as its normal status.
fn wrap_auth_error_as_ok(err: &AppError) -> Option<Response> {
    use serde_json::json;
    match err {
        AppError::NeedsAuthentication {
            service,
            service_instance_id,
            connection_id,
            auth_url,
            short,
            provider,
            required_scopes,
            account_email,
            headless,
        } => {
            let mut body = json!({ "status": "needs_authentication" });
            if let Some(s) = service {
                body["service"] = json!(s);
            }
            if let Some(id) = service_instance_id {
                body["service_instance_id"] = json!(id);
            }
            if let Some(id) = connection_id {
                body["connection_id"] = json!(id);
            }
            if *headless {
                body["headless"] = json!(true);
                if let Some(p) = provider {
                    body["provider"] = json!(p);
                }
                body["required_scopes"] = json!(required_scopes);
                if let Some(e) = account_email {
                    body["account_email"] = json!(e);
                }
            } else {
                if let Some(url) = auth_url {
                    body["auth_url"] = json!(url);
                }
                if let Some(s) = short {
                    body["short"] = json!(s);
                }
            }
            Some((StatusCode::OK, Json(body)).into_response())
        }
        AppError::ReauthRequired {
            connection_id,
            provider,
            auth_url,
            short,
            reason,
            required_scopes,
            account_email,
            headless,
        } => {
            let mut body = json!({
                "status": "reauth_required",
                "connection_id": connection_id,
                "provider": provider,
                "reason": reason,
            });
            if *headless {
                body["headless"] = json!(true);
                body["required_scopes"] = json!(required_scopes);
                if let Some(e) = account_email {
                    body["account_email"] = json!(e);
                }
            } else {
                if let Some(url) = auth_url {
                    body["auth_url"] = json!(url);
                }
                if let Some(s) = short {
                    body["short"] = json!(s);
                }
            }
            Some((StatusCode::OK, Json(body)).into_response())
        }
        _ => None,
    }
}

/// Top-level handler that times the request and emits the
/// `overslash_action_executions_total` / `_duration_seconds` metrics.
/// Granular outcomes (approval_required vs called vs filtered) are encoded in
/// the success-body status tag and would require threading an outcome out of
/// the inner function — we classify by HTTP status, plus the
/// `UpstreamErrored` response-extension marker the executor branches set
/// when the upstream itself failed (MCP in-band `is_error`, HTTP 5xx).
async fn call_action(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    scope: OrgScope,
    ip: ClientIp,
    Query(q): Query<CallQuery>,
    Json(req): Json<CallRequest>,
) -> Result<Response, AppError> {
    let start = std::time::Instant::now();
    // Mode resolution mirrors `resolve_request`: service-without-action is
    // the verb shape (which `http` rides on for raw-HTTP), service+action
    // is the defined-action shape. A request with no `service` is rejected
    // by `resolve_action_metadata` and shows up as `_invalid` here.
    let mode = match (req.service.is_some(), req.action.is_some()) {
        (true, true) => "action",
        (true, false) => "verb",
        _ => "_invalid",
    };
    let template_key = bounded_template_key(&state.registry, req.service.as_deref());

    let result = call_action_impl(State(state), ReqExt(ext), auth, scope, ip, Json(req)).await;

    // Resolve the outcome to its eventual HTTP status so 4xx user-input errors
    // (BadRequest, NotFound, Forbidden, RateLimited) don't count as `failed`.
    let status_code = match &result {
        Ok(resp) => resp.status().as_u16(),
        Err(err) => err.status_code().as_u16(),
    };
    // The marker outranks the status-code rules: an upstream failure rides
    // behind an outer 200 (MCP in-band errors, buffered HTTP 5xx envelope)
    // or passes a 5xx straight through (streaming) — either way it is the
    // upstream's outage, not Overslash's, and without the marker it would
    // count as `called` (looking like 100% success) or `failed` (paging as
    // a gateway error). Same `>= 500` line the replay path draws.
    let status_label = if matches!(
        &result,
        Ok(resp) if resp.extensions().get::<call::UpstreamErrored>().is_some()
    ) {
        "upstream_error"
    } else if status_code >= 500 {
        "failed"
    } else if status_code == 403 {
        "denied"
    } else if status_code >= 400 {
        "rejected"
    } else {
        "called"
    };
    overslash_metrics::actions::record_execution(
        &template_key,
        mode,
        status_label,
        start.elapsed(),
    );

    // Opt-in error wrapping for the dashboard "try it" surface. Done *after*
    // metrics so the auth 401 still counts as `rejected`, not a fake `called`.
    if q.wrap.unwrap_or(false) {
        if let Err(err) = &result {
            if let Some(resp) = wrap_auth_error_as_ok(err) {
                return Ok(resp);
            }
        }
    }
    result
}

/// `POST /v1/actions/validate` — dry-run probe for `/v1/actions/call`.
///
/// Runs the same body shape, the same identity / risk / argument checks,
/// and the same Layer 1 (group ceiling) + Layer 2 (permission chain)
/// gates that `/call` runs — but stops short of executing the upstream
/// request, writing an approval row, logging audit, or dispatching
/// webhooks. Returns 200 `{ok: true, permission: {status, ...}}` on
/// success, or 400 with the structured `invalid_action_args` body when
/// the caller's params don't match the action's input contract.
///
/// Exempt from rate limits (mounted on its own router) so an agent can
/// pre-validate without burning quota on a request it isn't sure of yet.
async fn validate_action(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    scope: OrgScope,
    _ip: ClientIp,
    Json(req): Json<CallRequest>,
) -> Result<Response, AppError> {
    let start = std::time::Instant::now();
    let mode = match (req.service.is_some(), req.action.is_some()) {
        (true, true) => "action",
        (true, false) => "verb",
        _ => "_invalid",
    };
    let template_key = bounded_template_key(&state.registry, req.service.as_deref());

    let result = validate_action_impl(State(state), ReqExt(ext), auth, scope, Json(req)).await;

    let outcome = match &result {
        Ok((_, label)) => *label,
        // Only the `InvalidActionArgs` 400 counts as `invalid_args`;
        // filter-syntax errors and require_risk mismatches are also 400s
        // but unrelated to the schema check, so they fall into `rejected`
        // — keeps the dashboard panel for schema misses honest.
        Err(AppError::InvalidActionArgs { .. }) => "invalid_args",
        Err(err) => {
            let code = err.status_code().as_u16();
            if code >= 500 {
                "failed"
            } else if code == 403 {
                "denied"
            } else {
                "rejected"
            }
        }
    };
    overslash_metrics::actions::record_validation(&template_key, mode, outcome, start.elapsed());

    result.map(|(resp, _)| resp)
}

/// Unified call request — `service` is required and selects between the
/// two SPEC §8 shapes: Service + defined action (when `action` is set) and
/// Service + HTTP verb (when only `method` + `url`/`path` is set). Mode A
/// raw HTTP rides on the verb shape against the synthetic `http`
/// pseudo-service. See module docs for the field-presence selection rules.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CallRequest {
    // Raw HTTP fields (also reused by service + HTTP verb)
    method: Option<String>,
    url: Option<String>,
    #[serde(default)]
    headers: HashMap<String, String>,
    body: Option<String>,
    #[serde(default)]
    secrets: Vec<SecretRef>,

    // Service + action / Service + HTTP verb fields
    service: Option<String>,
    /// Optional instance UUID. When present, the resolver looks the instance
    /// up by id (org-scoped) instead of by caller-shadowed name — required for
    /// an org admin to invoke an instance owned by another user, since
    /// name-based lookup is intentionally caller-scoped.
    service_id: Option<Uuid>,
    action: Option<String>,
    /// Service + HTTP verb (SPEC §8): path-only form (host comes from
    /// `svc.hosts`). Mutually exclusive with `action`.
    path: Option<String>,
    #[serde(default)]
    params: HashMap<String, serde_json::Value>,

    // Large file handling
    #[serde(default)]
    prefer_stream: Option<bool>,

    // Optional server-side filter applied to the upstream response body
    // (e.g., jq). Output is attached to `result.filtered_body`; the
    // original `body` is always preserved.
    #[serde(default)]
    filter: Option<ResponseFilter>,

    // Caller-asserted risk class. Today only `read` is meaningful: when set
    // to `read`, the resolved action's risk must be `Read` or the call is
    // rejected with 400. `write` / `delete` are accepted by the parser but
    // do not gate anything (no caller currently asks for them). Set by the
    // MCP `overslash_read` tool to enforce its readOnlyHint.
    #[serde(default)]
    require_risk: Option<Risk>,

    // Response shape selector. `Some(true)` → current full ActionResult
    // (headers, raw stringified body, no crop). `Some(false)` → compact
    // shape (headers dropped, body parsed as JSON when possible, output
    // capped at ~8 KB). `None` defaults to `true` on the HTTP API to keep
    // direct callers wire-compatible. The MCP layer forwards `false` by
    // default and only flips to `true` when the caller passes `verbose: true`
    // on the tool args.
    #[serde(default)]
    verbose: Option<bool>,

    // Optional URL the OAuth callback redirects the user back to if this
    // call triggers a reactive auth flow (reauth_required / missing_scopes /
    // needs_authentication). Mirrors `return_url` on the connect endpoint
    // (`routes/connections.rs::InitiateConnectionRequest`); validated by
    // `parse_return_url` at the request boundary and gated at callback time
    // by `OVERSLASH_CONNECTION_RETURN_URL_HOSTS` — when the host isn't on the
    // allow-list the callback falls back to the historical JSON response.
    #[serde(default)]
    return_url: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "status")]
enum CallResponse {
    #[serde(rename = "called")]
    Called {
        /// Pre-rendered `ActionResult` view. Verbose mode encodes the full
        /// struct (status_code, headers, raw body string, duration_ms,
        /// optional filtered_body). Compact mode returns the shape from
        /// `services::compact_response::compact` (headers dropped, body
        /// parsed as JSON, ≤8 KB). The selector lives on `CallRequest.verbose`.
        result: serde_json::Value,
        action_description: Option<String>,
        /// True when the upstream itself reported failure — an MCP envelope
        /// with `is_error: true`, or an upstream HTTP status >= 400 — even
        /// though the call executed. Mirrors `detail.is_error` on the
        /// `action.executed` audit entry so callers (dashboard Try It, MCP
        /// clients) can flag the result without parsing the body.
        is_error: bool,
    },
    #[serde(rename = "pending_approval")]
    PendingApproval {
        approval_id: Uuid,
        approval_url: String,
        action_description: String,
        expires_at: String,
        /// Caller↔requester relationship as classified server-side. The agent
        /// uses this to pick `overslash_approve_self` vs
        /// `overslash_approve` on the first try instead of
        /// trial-and-error against the typed-error envelope. Always `"self"`
        /// when this payload comes from the same agent that triggered the
        /// action; `"downstream"` when listed by an ancestor.
        relationship: String,
        /// Same broadening ladder GET /v1/approvals/{id} returns — included
        /// here so callers can offer "remember at a broader scope" prompts
        /// without a second round-trip. Deterministic on the approval's
        /// `permission_keys`.
        suggested_tiers: Vec<SuggestedTier>,
        /// Mirrors the *requesting* agent's `identities.auto_call_on_approve`.
        /// When `true` (default), an `allow` / `allow_remember` resolution
        /// auto-replays the call in the background and the execution result
        /// lands via webhook/audit — the MCP client does **not** need to
        /// follow up with `POST /v1/approvals/{id}/call`. When `false`, the
        /// agent is in deferred-execution mode and the caller must replay
        /// explicitly (e.g. `overslash_call` with `approval_id`) after the
        /// approval is granted. Surfaced so MCP clients can choose whether
        /// to wait or to issue an explicit follow-up.
        auto_call_on_approve: bool,
        // ── Render-form fields ───────────────────────────────────────────
        // White-label integrations (Telegram/WhatsApp/web bots) render an
        // approval prompt straight off this envelope. The four fields below
        // mirror the matching `ApprovalResponse` fields the dashboard's
        // `ApprovalResolver` renders from, so a caller can draw the same card
        // without a second `GET /v1/approvals/{id}` round-trip.
        /// Labeled, human-readable slice of the resolved request extracted via
        /// the template's `x-overslash-disclose` filters. Omitted when the
        /// template declared none. Same shape as
        /// `ApprovalResponse.disclosed_fields`.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        disclosed_fields: Vec<disclosure::DisclosedField>,
        /// Risk class for the gated action: `"low" | "med" | "high"`. Drives
        /// the approval card's severity styling. Mirrors `ApprovalResponse.risk`
        /// (defaults to `"med"` for verb/http shapes with no declared risk).
        risk: String,
        /// Permission key(s) being requested — what the approver grants.
        /// Mirrors `ApprovalResponse.permission_keys`.
        permission_keys: Vec<String>,
        /// Redacted, pretty-printed request payload (`x-overslash-redact`
        /// applied), truncated at the same 100 KB UTF-8 boundary as the read
        /// path. Omitted when no detail was stored. Mirrors
        /// `ApprovalResponse.action_detail` + its truncation companions.
        #[serde(skip_serializing_if = "Option::is_none")]
        action_detail: Option<String>,
        action_detail_truncated: bool,
        action_detail_size_bytes: usize,
    },
    #[serde(rename = "denied")]
    Denied { reason: String },
}

/// Render `ActionResult` according to the caller's `verbose` selector.
/// Defaults to verbose (`true`) when the caller didn't say — keeps the
/// HTTP API wire-compatible for the dashboard and direct REST consumers.
/// The MCP forwarder explicitly passes `verbose: false` to opt into the
/// compact shape on behalf of LLM clients.
fn render_action_result(result: &ActionResult, verbose: Option<bool>) -> serde_json::Value {
    if verbose.unwrap_or(true) {
        serde_json::to_value(result).unwrap_or(serde_json::Value::Null)
    } else {
        crate::services::compact_response::compact(result)
    }
}

/// Metadata from request resolution, used to derive the correct permission key type.
struct ResolvedMeta {
    description: Option<String>,
    /// Present for service shapes (action / verb); carries info to derive
    /// service permission keys.
    service_scope: Option<ServiceScope>,
    /// Risk level of the action (action shape only, from the action definition).
    risk: Option<Risk>,
    /// Disclosure declarations from the action template (action shape only;
    /// empty for verb / `http`). Runs at approval-create and audit-write time.
    disclose: Vec<DisclosureField>,
    /// Redact paths from the action template (action shape only; empty for
    /// verb / `http`). Applied to the request projection before it's
    /// persisted as `approvals.action_detail`.
    redact: Vec<String>,
    /// Original resolved params (before url/body assembly), retained for the
    /// disclosure `.params.*` projection. Empty for verb / `http` shapes.
    params: HashMap<String, serde_json::Value>,
    /// Display names from the template's `resolve` declarations (param name →
    /// human-readable string), feeding both description interpolation and the
    /// disclosure `.resolved.*` projection. Populated for the HTTP action
    /// shape only — resolvers are HTTP-only today, so verb / MCP / platform
    /// shapes carry an empty map. Resolution happens once, at resolve time,
    /// and rides here across execution: audit-write disclosure for a delete
    /// action still names the object even though it's gone upstream.
    resolved: HashMap<String, String>,
    /// When the resolved service has `runtime: Mcp`, dispatch skips the HTTP
    /// executor and goes through `mcp_caller::invoke` with this payload.
    mcp_target: Option<McpTarget>,
    /// When the resolved service has `runtime: Platform`, dispatch calls the
    /// in-process handler registry instead of making any outgoing call.
    platform_target: Option<PlatformTarget>,
    /// Resolved service-instance id (HTTP shapes only). Stored on approval
    /// replay payloads so the replay path can re-resolve OAuth against the
    /// same binding instead of persisting a live token.
    instance_id: Option<uuid::Uuid>,
}

struct McpTarget {
    /// Resolved MCP server URL (instance.url ?? template mcp.url).
    url: String,
    /// Resolved auth — for Bearer, secret_name is always Some at this point.
    auth: McpAuth,
    /// Live OAuth bearer for `McpAuth::OAuth`, resolved out-of-band from the
    /// caller's connection (never persisted in the request). `None` for
    /// `None`/`Bearer` auth. Merged into the outbound MCP headers at send time.
    auth_header: Option<overslash_core::types::AuthHeader>,
    tool: String,
    arguments: serde_json::Value,
}

struct PlatformTarget {
    action_key: String,
    params: serde_json::Map<String, serde_json::Value>,
}

struct ServiceScope {
    service_key: String,
    /// Empty string for the Service + HTTP verb shape (then `http_verb` is `Some`).
    action_key: String,
    scope_param: Option<String>,
    /// Service + HTTP verb (SPEC §8) — when `Some`, permission keys derive as
    /// `{service_key}:{METHOD}:{path}` instead of `{service_key}:{action_key}:{arg}`.
    http_verb: Option<HttpVerb>,
}

#[derive(Clone)]
struct HttpVerb {
    method: String,
    path: String,
}

/// Cheap, side-effect-free pre-resolution of a `CallRequest`.
///
/// Returns enough information for the top-level handler to:
///   1. Validate caller-supplied args against the action's schema
///      (action shape only; verb / `http` carry an empty schema).
///   2. Derive permission keys.
///   3. Run the caller-asserted risk gate.
///
/// Raw HTTP doesn't touch the DB. Service shapes load the template and
/// (for the action shape) look up the action — no OAuth refresh, no
/// `param_resolver` HTTP, no scope checks, no audit. Used by both
/// `/v1/actions/call` (so `validate_args` can sit at the top of the
/// handler, structurally before any approval-creation work) and
/// `/v1/actions/validate` (which only runs the cheap path and never
/// builds a real request).
///
/// For service shapes, the resolved template + instance ride along in
/// the returned tuple so `resolve_request` can reuse them and avoid the
/// duplicate DB lookup that a separate metadata pre-resolve would
/// otherwise force on the call hot path.
struct ActionMetadata {
    /// Schema for `validate_args`. Empty for verb / `http` shapes.
    validation_params: HashMap<String, overslash_core::types::ActionParam>,
    /// Service info for permission-key derivation (service shapes only).
    service_scope: Option<ServiceScope>,
    /// Risk class — action shape reads it from the template; verb /
    /// `http` shapes leave it `None` and the caller infers from method.
    risk: Option<Risk>,
    /// Caller-supplied raw HTTP fields used for `http`-pseudo-service
    /// permission-key derivation. Service shapes use `service_scope`.
    raw_method: String,
    raw_url: String,
    /// Whether this request needs Layer 2 (permission-chain) gating.
    /// Service shapes are always gated (templates ship with auth or are
    /// platform/MCP); raw HTTP is gated only when secrets are injected.
    needs_gate: bool,
}

/// Pre-resolved service template + instance, threaded
/// from `resolve_action_metadata` into `resolve_request` so the call
/// path doesn't re-fetch them.
struct ResolvedModeC {
    svc: overslash_core::types::ServiceDefinition,
    instance: Option<overslash_db::repos::service_instance::ServiceInstanceRow>,
}

/// Classify an OAuth resolver error so the action handler can respond
/// with the right HTTP status. The split mirrors RFC 7231 semantics:
///   * `Reauth(reason)` → 401, the user can fix it by clicking a link.
///   * `Internal` → 500, server-side problem the user can't fix
///     (crypto, DB, parse, provider config missing from the DB).
///   * `Upstream` → 502, the *provider* is the broken party (transport
///     error, provider rejected the credentials with a non-refresh body).
#[derive(Debug)]
enum OAuthOutcome {
    Reauth(&'static str),
    Internal,
    Upstream,
}
