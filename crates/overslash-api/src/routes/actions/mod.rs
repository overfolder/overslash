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
    extractors::{AuthContext, CallerTransport, ClientIp, ReqExt},
    services::{disclosure, events::EventType, response_filter::ResponseFilter},
};
use overslash_core::{
    permissions::SuggestedTier,
    types::{
        ActionResult, DisclosureField, McpAuth, ScopeParams, SecretRef,
        service::{DeclaredRisk, Risk},
    },
};

mod approval_detail;
mod auth;
mod auth_envelopes;
mod auth_resolve;
mod auth_scopes;
mod call;
mod deferred;
mod dto;
mod errors;
mod filter_apply;
mod mcp_resolve;
mod permission_gate;
mod resolve;
mod resolve_encode;
mod resolve_metadata;
mod service_resolve;
mod tags;
mod upstream_error;
mod validate;

use call::call_action_impl;
use validate::validate_action_impl;

// Shared DTOs live in `dto`; re-exported here so every sibling's
// `use super::*;` keeps resolving them exactly as when they were inline.
use dto::*;

// Used by the approval-replay path to re-mint the OAuth credential that
// replay payloads deliberately don't persist.
pub(crate) use auth::{resolve_mcp_oauth_bearer, resolve_replay_auth_header};

// Effective-MCP resolution shared with the instance-scoped resync route.
pub(crate) use mcp_resolve::{
    ResolvedMcp, overlay_instance_discovered_tools, resolve_effective_mcp,
};

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

/// Everything the `action.*` pair needs, resolved once before the call so the
/// two events agree on identity, target and `call_id`.
///
/// The pair is deliberately *not* ordered. It brackets the upstream call, so
/// `emit_all` — which exists precisely to keep a derived event behind its
/// cause — cannot cover it: each `emit` spawns its own task and the inserts
/// race. A consumer must tolerate `action.completed` arriving first, which is
/// why `call_id` is minted here rather than inferred from arrival order.
struct CallActivity {
    call_id: Uuid,
    actor: Uuid,
    org_id: Uuid,
    service: Option<String>,
    action: Option<String>,
    pool: sqlx::PgPool,
    http_client: reqwest::Client,
    audience: Vec<Uuid>,
}

impl CallActivity {
    /// `extra` is merged over the shared identity fields. Only the two call
    /// sites below pass it, and neither reuses a shared key.
    fn emit(&self, event_type: EventType, extra: serde_json::Value) {
        let mut payload = serde_json::json!({
            "call_id": self.call_id,
            "actor_identity_id": self.actor,
            "service": self.service,
            "action": self.action,
        });
        let obj = payload.as_object_mut().expect("payload is a json object");
        if let Some(extra) = extra.as_object() {
            for (k, v) in extra {
                obj.insert(k.clone(), v.clone());
            }
        }
        crate::services::events::emit(
            self.pool.clone(),
            self.http_client.clone(),
            crate::services::events::EventDraft {
                org_id: self.org_id,
                event_type,
                payload,
                audience: self.audience.clone(),
            },
        );
    }
}

/// Top-level handler that times the request and emits the
/// `overslash_action_executions_total` / `_duration_seconds` metrics.
/// Granular outcomes (approval_required vs called vs filtered) are encoded in
/// the success-body status tag and would require threading an outcome out of
/// the inner function — we classify by HTTP status, plus the
/// `UpstreamErrored` response-extension marker the executor branches set
/// when the upstream itself failed (MCP in-band `is_error`, HTTP 5xx).
// Same reason as `call_action_impl`: an axum handler's arguments are its
// extractors, so the list is a flat function of what the request carries.
#[allow(clippy::too_many_arguments)]
async fn call_action(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    auth: AuthContext,
    scope: OrgScope,
    ip: ClientIp,
    transport: CallerTransport,
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

    // Live Map feed. Both events are emitted here rather than at the four
    // terminal sites inside `call_action_impl` (MCP ok / MCP transport error /
    // HTTP ok / HTTP transport error) because this wrapper is already the one
    // place that brackets the call and classifies its outcome — see
    // `status_label` below. Duplicating those rules four times to gain a
    // slightly earlier `service` resolution would be a bad trade.
    //
    // Gated: each call costs one durable `events` row, on the hottest path in
    // the system. `live_map_enabled` is set on dev, never in production.
    let activity = match (state.config.live_map_enabled, auth.identity_id) {
        (true, Some(actor)) => Some(CallActivity {
            call_id: Uuid::new_v4(),
            actor,
            org_id: auth.org_id,
            service: req.service.clone(),
            action: req.action.clone(),
            pool: state.db_pool(&ext),
            http_client: state.http_client.clone(),
            // Resolved once, here, and reused by both events. The chain walk
            // is a query, so doing it per-event would double the cost of a
            // feature that is already the most expensive observer we have.
            audience: crate::services::events::audience::for_action(&scope, actor).await,
        }),
        _ => None,
    };
    if let Some(a) = activity.as_ref() {
        a.emit(EventType::ActionCalled, serde_json::json!({}));
    }

    let result = call_action_impl(
        State(state),
        ReqExt(ext),
        auth,
        scope,
        ip,
        transport,
        Json(req),
    )
    .await;

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
    let elapsed = start.elapsed();
    overslash_metrics::actions::record_execution(&template_key, mode, status_label, elapsed);

    if let Some(a) = activity.as_ref() {
        a.emit(
            EventType::ActionCompleted,
            serde_json::json!({
                "outcome": status_label,
                "duration_ms": elapsed.as_millis() as u64,
            }),
        );
    }

    // Opt-in error wrapping for the dashboard "try it" surface. Done *after*
    // metrics so the auth 401 still counts as `rejected`, not a fake `called`.
    if q.wrap.unwrap_or(false)
        && let Err(err) = &result
        && let Some(resp) = wrap_auth_error_as_ok(err)
    {
        return Ok(resp);
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

/// Overlay the pinned `config` onto a call's args — the instance's own pins
/// first, then any an org layer supplies as defaults.
///
/// Precedence falls out of `entry().or_insert_with()` and the pass ordering:
///
/// ```text
/// caller arg  >  instance.config  >  layer instance_defaults.config  >  template default
/// ```
///
/// (`apply_defaults` runs after this, so template defaults stay last.)
///
/// Only params the template marks `x-overslash-instance-config` are eligible —
/// the API refuses to store anything else, and re-checking here means a
/// template that *stops* declaring a param can't have a stale pinned value
/// keep flowing into requests, from either source.
///
/// A key the caller already supplied is left alone: the pin is a default for
/// the deployment, not an override of an explicit argument. Values are stored
/// as strings; `coerce_args` (which runs just after this) casts them to the
/// param's declared type, so a pinned `"993"` on an integer param behaves
/// exactly like a caller-supplied `"993"`.
fn apply_instance_config(
    params: &std::collections::HashMap<String, overslash_core::types::ActionParam>,
    resolved: Option<&ResolvedModeC>,
    args: &mut std::collections::HashMap<String, serde_json::Value>,
) {
    let Some(resolved) = resolved else { return };
    let instance_config = resolved.instance.as_ref().map(|i| &i.config.0);
    let layer_config = resolved
        .svc
        .instance_defaults
        .as_ref()
        .map(|d| &d.config)
        .filter(|c| !c.is_empty());

    for source in [instance_config, layer_config].into_iter().flatten() {
        for (key, value) in source.iter() {
            if !params.get(key).is_some_and(|p| p.instance_config) {
                continue;
            }
            args.entry(key.clone())
                .or_insert_with(|| serde_json::Value::String(value.clone()));
        }
    }
}

/// Evaluate the D42 SQL content policy for one call: locate the
/// `x-overslash-sql-field` param, resolve the target database's dialect +
/// label (jq expression over the call params → `sql_databases` instance
/// config), parse and classify the SQL, and derive the per-table /
/// per-column permission keys.
///
/// Fail-closed at every step: an unresolvable database defaults to postgres
/// with the raw key (or "unknown") as label; a non-postgres dialect, an
/// unparseable statement, or a build without the `sql_policy` feature all
/// classify Write with the all-tables sentinel key.
async fn evaluate_sql_policy(
    filter_timeout: std::time::Duration,
    meta: &ActionMetadata,
    resolved: Option<&ResolvedModeC>,
    params: &std::collections::HashMap<String, serde_json::Value>,
) -> Option<SqlPolicyOutcome> {
    use overslash_core::permissions::PermissionKey;
    use overslash_core::sql_policy::{self, SqlAnalysis, SqlClass, WriteReason};

    let scope = meta.service_scope.as_ref()?;
    let (sql_param_name, sql_param) = meta
        .validation_params
        .iter()
        .find(|(_, p)| p.sql_field.is_some())?;
    // Optional SQL param not supplied this call: nothing to classify. The
    // caller still fails closed for `risk: dynamic` (no analysis → Write).
    let supplied = params.contains_key(sql_param_name.as_str());
    if !supplied {
        return None;
    }

    // ── Resolve the database key via the template's jq expression. ──
    let db_expr = meta
        .validation_params
        .values()
        .find_map(|p| p.sql_database.clone());
    let db_key: Option<String> = match db_expr {
        Some(expr) => {
            let body = serde_json::to_string(params).unwrap_or_else(|_| "{}".to_string());
            let join = tokio::task::spawn_blocking(move || {
                crate::services::response_filter::run_jq_blocking(&expr, &body)
            });
            match tokio::time::timeout(filter_timeout, join).await {
                Ok(Ok(Ok((outputs, _)))) => outputs.first().and_then(|v| match v {
                    serde_json::Value::String(s) => Some(s.clone()),
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    _ => None,
                }),
                // jq error / panic / timeout → unresolved (fail-closed
                // default below), but the call itself proceeds.
                _ => None,
            }
        }
        None => None,
    };

    // ── Key into the instance's `sql_databases` config map. ──
    let entry = db_key.as_deref().and_then(|key| {
        let raw = resolved.and_then(|r| {
            r.instance
                .as_ref()
                .and_then(|i| i.config.0.get(sql_policy::SQL_DATABASES_CONFIG_KEY))
                .or_else(|| {
                    r.svc
                        .instance_defaults
                        .as_ref()
                        .and_then(|d| d.config.get(sql_policy::SQL_DATABASES_CONFIG_KEY))
                })
        })?;
        match sql_policy::parse_sql_databases(raw) {
            Ok(mut map) => map.remove(key),
            Err(e) => {
                tracing::warn!(
                    service = %scope.service_key,
                    "malformed sql_databases instance config ({e}); using defaults"
                );
                None
            }
        }
    });
    let dialect = entry
        .as_ref()
        .and_then(|e| e.dialect.clone())
        .unwrap_or_else(|| "postgres".to_string());
    let db_label = entry
        .as_ref()
        .and_then(|e| e.label.clone())
        .or(db_key)
        .unwrap_or_else(|| "unknown".to_string());

    // ── Locate and classify the SQL. ──
    let sql_field = sql_param.sql_field.as_deref().unwrap_or_default();
    let analysis = if !dialect.eq_ignore_ascii_case("postgres") {
        // Parsing with the wrong grammar proves nothing — fail closed. A
        // best-effort second backend (sqlparser-rs) can slot in here later.
        SqlAnalysis {
            class: SqlClass::Write,
            write_reason: Some(WriteReason::UnsupportedDialect(dialect)),
            read_tables: Vec::new(),
            mut_tables: Vec::new(),
            columns: Vec::new(),
            tables_exhaustive: false,
        }
    } else {
        match sql_policy::extract_sql(sql_param_name, sql_field, params) {
            Some(sql) => sql_policy::analyze(sql),
            // Present but not a string at the nominated path — validate_args
            // should have rejected it; refuse to guess.
            None => SqlAnalysis {
                class: SqlClass::Write,
                write_reason: Some(WriteReason::ParseError(
                    "sql param value is not a string at the nominated path".to_string(),
                )),
                read_tables: Vec::new(),
                mut_tables: Vec::new(),
                columns: Vec::new(),
                tables_exhaustive: false,
            },
        }
    };

    let table_keys = PermissionKey::from_sql_analysis(
        &scope.service_key,
        &scope.action_key,
        &db_label,
        &analysis,
    );
    let column_keys = PermissionKey::from_sql_columns(
        &scope.service_key,
        &scope.action_key,
        &db_label,
        &analysis,
    );

    Some(SqlPolicyOutcome {
        floor: analysis.class.as_risk(),
        table_keys,
        column_keys,
        db_label,
        analysis,
    })
}

/// Merge a call's declared risk, its SQL classification, and the HTTP-method
/// fallback into the single effective risk both the `require_risk` gate and
/// the group ceiling evaluate.
///
/// - static risk: the declared class, elevated by the SQL floor when a
///   classified query is on board;
/// - `dynamic`: starts at read and takes the classifier's verdict — with
///   **no analysis** (SQL param not supplied, or any earlier bail) it is
///   Write, because nothing proved the call read-only;
/// - no declared risk (verb / `http` shapes): inferred from the method.
fn effective_risk(
    declared: Option<DeclaredRisk>,
    sql_policy: Option<&SqlPolicyOutcome>,
    method: &str,
) -> Risk {
    match declared {
        Some(d) => {
            let base = d.base_risk();
            match sql_policy {
                Some(sp) => base.max_severity(sp.floor),
                None if d.is_dynamic() => Risk::Write,
                None => base,
            }
        }
        None => Risk::from_http_method(method),
    }
}

/// Overlay `resolve.scope` values onto the params used to derive permission
/// keys.
///
/// The same human is reachable at several opaque addresses — a WhatsApp
/// contact answers to both a phone JID and a privacy `@lid` — and each would
/// otherwise mint its own permission key, so a grant made against one
/// silently misses the other. A resolver that declares `scope` collapses them
/// onto the canonical value (the phone number), which is both stable across
/// addresses and legible in the rules list.
///
/// Only key derivation sees this. The outgoing request keeps the caller's raw
/// arguments: canonicalization renames the permission, it must never silently
/// retarget the call.
///
/// When resolution failed there is no canonical value and the raw argument
/// stands. That direction is safe — the call derives a *different* key,
/// matches no existing grant, and raises an approval.
pub(super) fn canonical_scope_params(
    params: &HashMap<String, serde_json::Value>,
    canonical: &HashMap<String, String>,
) -> HashMap<String, serde_json::Value> {
    if canonical.is_empty() {
        return params.clone();
    }
    let mut out = params.clone();
    for (name, value) in canonical {
        // Only rewrite params the caller actually supplied — a resolver must
        // not conjure a scope value for an argument that was never passed.
        if out.contains_key(name) {
            out.insert(name.clone(), serde_json::Value::String(value.clone()));
        }
    }
    out
}

/// Merge D42 table keys into the scope_param-derived key set.
///
/// Appended when real scoped keys exist (DB-scoping and table-scoping are
/// separate operator decisions), but they **replace** the unscoped
/// `{service}:{action}:*` fallback: the chain walk requires *every* key
/// covered, and no table-shaped rule can cover `:*`, so keeping it would
/// collapse the per-table tier into "grant the whole action".
fn merge_sql_keys(
    mut perm_keys: Vec<overslash_core::permissions::PermissionKey>,
    scope: &ServiceScope,
    sql_policy: Option<&SqlPolicyOutcome>,
) -> Vec<overslash_core::permissions::PermissionKey> {
    let Some(sp) = sql_policy else {
        return perm_keys;
    };
    if sp.table_keys.is_empty() {
        return perm_keys;
    }
    let fallback = format!("{}:{}:*", scope.service_key, scope.action_key);
    if perm_keys.len() == 1 && perm_keys[0].0 == fallback {
        perm_keys.clear();
    }
    for key in &sp.table_keys {
        if !perm_keys.contains(key) {
            perm_keys.push(key.clone());
        }
    }
    perm_keys
}

#[cfg(test)]
mod canonical_scope_tests {
    use super::canonical_scope_params;
    use std::collections::HashMap;

    fn params(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn no_canonical_values_passes_the_params_through() {
        let raw = params(&[("recipient", serde_json::json!("239135323373760@lid"))]);
        assert_eq!(canonical_scope_params(&raw, &HashMap::new()), raw);
    }

    #[test]
    fn canonical_value_replaces_the_raw_argument() {
        let raw = params(&[
            ("recipient", serde_json::json!("239135323373760@lid")),
            ("text", serde_json::json!("hola")),
        ]);
        let canonical: HashMap<String, String> =
            [("recipient".to_string(), "+34600111222".to_string())]
                .into_iter()
                .collect();
        let out = canonical_scope_params(&raw, &canonical);
        assert_eq!(out["recipient"], serde_json::json!("+34600111222"));
        // Untouched params ride through unchanged.
        assert_eq!(out["text"], serde_json::json!("hola"));
    }

    /// A resolver must not conjure a scope value for an argument the caller
    /// never passed — that would mint a key for a param not in the request.
    #[test]
    fn a_canonical_value_for_an_absent_param_is_ignored() {
        let raw = params(&[("text", serde_json::json!("hola"))]);
        let canonical: HashMap<String, String> =
            [("recipient".to_string(), "+34600111222".to_string())]
                .into_iter()
                .collect();
        let out = canonical_scope_params(&raw, &canonical);
        assert!(!out.contains_key("recipient"));
        assert_eq!(out.len(), 1);
    }
}
