//! Shared call pipeline used by both direct `POST /v1/actions/call`
//! callers and the approval-replay path at `POST /v1/approvals/{id}/call`.
//!
//! Given a resolved `ActionRequest`, this:
//!   1. Decrypts each referenced secret and injects it.
//!   2. Performs the upstream HTTP call — streaming or buffered.
//!   3. Applies the optional `jq` filter (buffered path only).
//!   4. Writes an `action.executed` / `action.streamed` audit entry.
//!
//! Replay callers pass `AuditSource::Replay { approval_id, execution_id }` and
//! `prefer_stream: false` (replay always buffers — there's no original caller
//! connection to stream to).

use std::collections::HashMap;

use axum::response::Response;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use overslash_core::{
    crypto,
    secret_injection::inject_secrets,
    types::{ActionRequest, ActionResult, AuthHeader, FilteredBody, McpAuth},
};
use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::AppError,
    services::{
        audit_capture::{self, AuditResponseBodyMode},
        http_caller,
        response_filter::{self, ResponseFilter},
    },
};

/// Wrapper written into `approvals.replay_payload` at approval-creation
/// time. Carries the resolved `ActionRequest` plus the two side-channel
/// fields the original `CallRequest` passed in (`filter`, `prefer_stream`)
/// so a replay at `/v1/approvals/{id}/call` faithfully reproduces the shape
/// of the response the agent would have received.
///
/// `action` is credential-free: the live OAuth token never enters
/// `ActionRequest.headers` (see `overslash_core::types::AuthHeader`).
/// When the original call resolved OAuth, `service_key`/`instance_id`
/// record where the credential came from so the replay path can re-resolve
/// a fresh token instead of persisting one — which also keeps replays
/// working after the original token would have expired.
///
/// Reading old rows: `from_stored_detail` falls back to a bare `ActionRequest`
/// value so pre-migration approvals stay replayable (filter=None,
/// prefer_stream=false). Pre-fix rows have no `service_key` and still carry
/// their baked-in header — they replay as-is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCallRequest {
    pub action: ActionRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<ResponseFilter>,
    #[serde(default)]
    pub prefer_stream: bool,
    /// Service whose auth must be re-resolved at replay time. `Some` exactly
    /// when the original resolve produced a live OAuth header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_key: Option<String>,
    /// Instance binding the original resolve used, when there was one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<Uuid>,
}

impl StoredCallRequest {
    pub fn new(
        action: ActionRequest,
        filter: Option<ResponseFilter>,
        prefer_stream: bool,
        service_key: Option<String>,
        instance_id: Option<Uuid>,
    ) -> Self {
        Self {
            action,
            filter,
            prefer_stream,
            service_key,
            instance_id,
        }
    }

    /// Parse `approvals.action_detail`. First tries the wrapper shape; if that
    /// fails (pre-migration rows), falls back to a bare `ActionRequest`.
    pub fn from_stored_detail(value: &serde_json::Value) -> Result<Self, serde_json::Error> {
        if let Ok(wrapped) = serde_json::from_value::<StoredCallRequest>(value.clone()) {
            return Ok(wrapped);
        }
        let action: ActionRequest = serde_json::from_value(value.clone())?;
        Ok(Self {
            action,
            filter: None,
            prefer_stream: false,
            service_key: None,
            instance_id: None,
        })
    }
}

/// Replay payload for an MCP-runtime approval. Stored on
/// `approvals.replay_payload` and read back by the MCP branch of the replay
/// handler at `POST /v1/approvals/{id}/call`. Top-level `tool` key is what
/// distinguishes this shape from `StoredCallRequest` at parse time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMcpCall {
    pub url: String,
    pub auth: McpAuth,
    pub tool: String,
    pub arguments: serde_json::Value,
}

/// Replay payload for a platform-runtime approval. Stored on
/// `approvals.replay_payload` and read back by the Platform branch of the
/// replay handler at `POST /v1/approvals/{id}/call`. The top-level
/// `"runtime": "platform"` marker is what distinguishes this shape from
/// `StoredCallRequest` and `StoredMcpCall` at parse time. The fields mirror
/// the `action_detail` projection (`runtime`/`service`/`action`/`params`) so
/// legacy rows whose `replay_payload` is NULL but whose `action_detail`
/// carries the same shape can also be replayed via the existing fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPlatformCall {
    pub runtime: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    pub action: String,
    #[serde(default)]
    pub params: serde_json::Map<String, serde_json::Value>,
}

/// Replay payload for any runtime, disambiguated by JSON shape rather than a
/// serde tag — older HTTP rows on disk have no `runtime` field, so a tagged
/// enum would break them. Detection order: platform (explicit
/// `runtime: "platform"`), then MCP (`tool` key), then HTTP (everything
/// else / pre-feature shape).
pub enum ReplayPayload {
    Http(StoredCallRequest),
    Mcp(StoredMcpCall),
    Platform(StoredPlatformCall),
}

impl ReplayPayload {
    pub fn from_stored(value: &serde_json::Value) -> Result<Self, serde_json::Error> {
        if value.get("runtime").and_then(|v| v.as_str()) == Some("platform") {
            return Ok(Self::Platform(serde_json::from_value(value.clone())?));
        }
        if value.get("tool").is_some() {
            return Ok(Self::Mcp(serde_json::from_value(value.clone())?));
        }
        Ok(Self::Http(StoredCallRequest::from_stored_detail(value)?))
    }
}

pub enum AuditSource {
    Direct,
    Replay {
        approval_id: Uuid,
        execution_id: Uuid,
    },
}

pub struct CallContext<'a> {
    pub state: &'a AppState,
    pub scope: &'a OrgScope,
    pub identity_id: Uuid,
    pub ip: Option<&'a str>,
    pub description: Option<&'a str>,
    pub service_key: Option<&'a str>,
    pub action_key: Option<&'a str>,
    pub filter: Option<ResponseFilter>,
    pub prefer_stream: bool,
    pub audit_source: AuditSource,
    /// Org-level response-body capture mode for the audit row, resolved by
    /// the caller (one PK lookup) so this pipeline stays query-free.
    pub audit_body_mode: AuditResponseBodyMode,
}

pub enum CallOutcome {
    /// Buffered response — the only shape `/call` on an approval can produce.
    Buffered {
        result: ActionResult,
        description: Option<String>,
    },
    /// Streaming response bypasses buffering; only the direct caller path
    /// produces this.
    Streamed(Response),
}

/// Execute a resolved, credential-free `ActionRequest`. The live OAuth
/// credential (when the service resolved one) is passed separately as
/// `auth_header` and merged into the outgoing header map at send time —
/// it must never be baked into `action_req.headers`, which is what gets
/// persisted on approvals and replay payloads.
pub async fn call_action_request(
    ctx: CallContext<'_>,
    action_req: &ActionRequest,
    auth_header: Option<&AuthHeader>,
) -> Result<CallOutcome, AppError> {
    // ── Resolve secrets ──────────────────────────────────────────────
    let enc_key = ctx.state.config.keyring()?;
    let mut secret_values = HashMap::new();
    for secret_ref in &action_req.secrets {
        let version = ctx
            .scope
            .get_current_secret_value(&secret_ref.name)
            .await?
            .ok_or_else(|| AppError::CredentialMissing {
                service: ctx.service_key.map(str::to_string),
                secret_name: secret_ref.name.clone(),
                hint_url: Some(ctx.state.config.dashboard_url_for(&format!(
                    "/secrets?name={}",
                    urlencoding::encode(&secret_ref.name)
                ))),
            })?;
        let decrypted = crypto::decrypt(&enc_key, &version.encrypted_value)?;
        let value = String::from_utf8(decrypted)
            .map_err(|_| AppError::Internal("secret is not valid utf-8".into()))?;
        secret_values.insert(secret_ref.name.clone(), value);
    }

    let (resolved_url, mut resolved_headers) = inject_secrets(action_req, &secret_values)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    // Send-time merge of the live OAuth credential — the only point where
    // the token and the outgoing request meet.
    if let Some(ah) = auth_header {
        resolved_headers.insert(ah.name.clone(), ah.value.clone());
    }
    let resolved_url = ctx.state.config.apply_base_overrides(&resolved_url);

    // ── Streaming path ───────────────────────────────────────────────
    if ctx.prefer_stream {
        let upstream = match http_caller::call_streaming(
            &ctx.state.http_client,
            &action_req.method,
            &resolved_url,
            &resolved_headers,
            action_req.body.as_deref(),
        )
        .await
        {
            Ok(upstream) => upstream,
            Err(e) => {
                let e = http_caller::CallError::Request(e);
                log_transport_error_audit(
                    &ctx,
                    action_req,
                    audit_capture::scrub_transport_error(&e),
                )
                .await;
                return Err(map_call_error(e));
            }
        };

        let upstream_status = upstream.status();
        let upstream_headers = upstream.headers().clone();
        let content_length = upstream
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        write_stream_audit(&ctx, action_req, upstream_status.as_u16(), content_length).await;

        let stream = upstream.bytes_stream();
        let body = axum::body::Body::from_stream(stream);

        let mut response = Response::builder().status(upstream_status.as_u16());
        for (name, value) in upstream_headers.iter() {
            let name_str = name.as_str();
            match name_str {
                "content-type"
                | "content-length"
                | "content-disposition"
                | "etag"
                | "last-modified"
                | "cache-control" => {
                    response = response.header(name, value);
                }
                _ => {}
            }
        }
        return Ok(CallOutcome::Streamed(response.body(body).unwrap()));
    }

    // ── Buffered path (default) ──────────────────────────────────────
    let mut result = match http_caller::call(
        &ctx.state.http_client,
        &action_req.method,
        &resolved_url,
        &resolved_headers,
        action_req.body.as_deref(),
        ctx.state.config.max_response_body_bytes,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            // Transport failures / oversized bodies used to bail with no
            // audit trail at all. Record the attempt with a secret-safe
            // error summary before propagating.
            log_transport_error_audit(&ctx, action_req, audit_capture::scrub_transport_error(&e))
                .await;
            return Err(map_call_error(e));
        }
    };

    let filter_audit = if let Some(filter) = ctx.filter.clone() {
        let lang = filter.lang().to_string();
        let expr = filter.expr().to_string();
        let timeout = std::time::Duration::from_millis(ctx.state.config.filter_timeout_ms);
        let filtered = response_filter::apply(filter, result.body.clone(), timeout).await;
        let audit = filter_audit_entry(&lang, &expr, &filtered);
        result.filtered_body = Some(filtered);
        Some(audit)
    } else {
        None
    };

    let mut audit_detail = serde_json::json!({
        "method": action_req.method,
        "url": action_req.url,
        "status_code": result.status_code,
        // Normalized upstream-failure flag, same field MCP audit details
        // carry — keeps replay rows consistent with inline executions.
        "is_error": result.status_code >= 400,
        "duration_ms": result.duration_ms,
        "service": ctx.service_key,
        "action": ctx.action_key,
    });
    // Org-gated response capture (off / errors_only / all), truncated at
    // AUDIT_RESPONSE_BODY_MAX_BYTES.
    if audit_capture::should_capture(ctx.audit_body_mode, result.status_code >= 400) {
        audit_detail
            .as_object_mut()
            .expect("audit_detail is a json object")
            .insert(
                "response".to_string(),
                audit_capture::capture_body(
                    &result.body,
                    result.headers.get("content-type").map(String::as_str),
                    ctx.state.config.audit_response_body_max_bytes,
                ),
            );
    }
    if let Some(filter_audit) = filter_audit {
        audit_detail
            .as_object_mut()
            .expect("audit_detail is a json object")
            .insert("filter".to_string(), filter_audit);
    }
    if let AuditSource::Replay {
        approval_id,
        execution_id,
    } = ctx.audit_source
    {
        let obj = audit_detail
            .as_object_mut()
            .expect("audit_detail is a json object");
        obj.insert(
            "replayed_from_approval".to_string(),
            serde_json::json!(approval_id),
        );
        obj.insert("execution_id".to_string(), serde_json::json!(execution_id));
    }

    let _ = OrgScope::new(ctx.scope.org_id(), ctx.state.db.clone())
        .log_audit(AuditEntry {
            org_id: ctx.scope.org_id(),
            identity_id: Some(ctx.identity_id),
            action: "action.executed",
            resource_type: ctx.service_key,
            resource_id: None,
            detail: audit_detail,
            description: ctx.description,
            ip_address: ctx.ip,
        })
        .await;

    Ok(CallOutcome::Buffered {
        result,
        description: ctx.description.map(|s| s.to_string()),
    })
}

/// Map a transport-level `CallError` to the client-facing `AppError`.
/// Kept identical to the pre-audit-row error contract.
fn map_call_error(e: http_caller::CallError) -> AppError {
    match e {
        http_caller::CallError::ResponseTooLarge {
            content_length,
            content_type,
            limit_bytes,
        } => AppError::ResponseTooLarge {
            content_length,
            content_type,
            limit_bytes,
        },
        http_caller::CallError::Request(e) => AppError::Request(e),
    }
}

/// Write the `action.executed` audit row for a call whose upstream never
/// produced a response (DNS/connect/timeout, or a body over the buffering
/// limit). No `status_code` — nothing arrived. `error_detail` comes from
/// `audit_capture::scrub_transport_error`, so it never carries the
/// resolved URL or injected secrets; `action_req.url` is the same
/// secret-free template URL the success rows store.
async fn log_transport_error_audit(
    ctx: &CallContext<'_>,
    action_req: &ActionRequest,
    error_detail: serde_json::Value,
) {
    let mut audit_detail = serde_json::json!({
        "method": action_req.method,
        "url": action_req.url,
        "is_error": true,
        "error": error_detail,
        "service": ctx.service_key,
        "action": ctx.action_key,
    });
    if let AuditSource::Replay {
        approval_id,
        execution_id,
    } = ctx.audit_source
    {
        let obj = audit_detail
            .as_object_mut()
            .expect("audit_detail is a json object");
        obj.insert(
            "replayed_from_approval".to_string(),
            serde_json::json!(approval_id),
        );
        obj.insert("execution_id".to_string(), serde_json::json!(execution_id));
    }

    let _ = OrgScope::new(ctx.scope.org_id(), ctx.state.db.clone())
        .log_audit(AuditEntry {
            org_id: ctx.scope.org_id(),
            identity_id: Some(ctx.identity_id),
            action: "action.executed",
            resource_type: ctx.service_key,
            resource_id: None,
            detail: audit_detail,
            description: ctx.description,
            ip_address: ctx.ip,
        })
        .await;
}

async fn write_stream_audit(
    ctx: &CallContext<'_>,
    action_req: &ActionRequest,
    status_code: u16,
    content_length: Option<u64>,
) {
    let mut audit_detail = serde_json::json!({
        "method": action_req.method,
        "url": action_req.url,
        "status_code": status_code,
        // Normalized upstream-failure flag — see the buffered path above.
        "is_error": status_code >= 400,
        "content_length": content_length,
        "service": ctx.service_key,
        "action": ctx.action_key,
    });
    // The streamed body is never buffered, so it can't be captured. A small
    // marker keeps "streamed, body unavailable" distinguishable from
    // "capture off" on rows where capture would have applied.
    if audit_capture::should_capture(ctx.audit_body_mode, status_code >= 400) {
        audit_detail
            .as_object_mut()
            .expect("audit_detail is a json object")
            .insert(
                "response".to_string(),
                serde_json::json!({ "skipped": "streamed" }),
            );
    }
    if let AuditSource::Replay {
        approval_id,
        execution_id,
    } = ctx.audit_source
    {
        let obj = audit_detail
            .as_object_mut()
            .expect("audit_detail is a json object");
        obj.insert(
            "replayed_from_approval".to_string(),
            serde_json::json!(approval_id),
        );
        obj.insert("execution_id".to_string(), serde_json::json!(execution_id));
    }

    let _ = OrgScope::new(ctx.scope.org_id(), ctx.state.db.clone())
        .log_audit(AuditEntry {
            org_id: ctx.scope.org_id(),
            identity_id: Some(ctx.identity_id),
            action: "action.streamed",
            resource_type: ctx.service_key,
            resource_id: None,
            detail: audit_detail,
            description: ctx.description,
            ip_address: ctx.ip,
        })
        .await;
}

fn filter_audit_entry(lang: &str, expr: &str, outcome: &FilteredBody) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    const EXPR_LOG_MAX: usize = 256;

    let expr_truncated: String = expr.chars().take(EXPR_LOG_MAX).collect();
    let expr_sha256 = hex::encode(Sha256::digest(expr.as_bytes()));

    let (result, original_bytes, filtered_bytes) = match outcome {
        FilteredBody::Ok {
            original_bytes,
            filtered_bytes,
            ..
        } => ("ok", *original_bytes, Some(*filtered_bytes)),
        FilteredBody::Error {
            kind,
            original_bytes,
            ..
        } => {
            let r = match kind {
                overslash_core::types::FilterErrorKind::BodyNotJson => "body_not_json",
                overslash_core::types::FilterErrorKind::RuntimeError => "runtime_error",
                overslash_core::types::FilterErrorKind::Timeout => "timeout",
                overslash_core::types::FilterErrorKind::OutputOverflow => "output_overflow",
            };
            (r, *original_bytes, None)
        }
    };

    let mut entry = serde_json::json!({
        "lang": lang,
        "expr_truncated": expr_truncated,
        "expr_sha256": expr_sha256,
        "result": result,
        "original_bytes": original_bytes,
    });
    if let Some(fb) = filtered_bytes {
        entry
            .as_object_mut()
            .expect("entry is a json object")
            .insert("filtered_bytes".to_string(), serde_json::json!(fb));
    }
    entry
}
