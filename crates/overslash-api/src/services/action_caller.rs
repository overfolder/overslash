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
    types::{ActionRequest, ActionResult, FilteredBody, McpAuth},
};
use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    error::AppError,
    services::{
        http_caller,
        response_filter::{self, ResponseFilter},
    },
};

/// Wrapper written into `approvals.action_detail` at approval-creation time.
/// Carries the resolved `ActionRequest` plus the two side-channel fields the
/// original `CallRequest` passed in (`filter`, `prefer_stream`) so a replay
/// at `/v1/approvals/{id}/call` faithfully reproduces the shape of the
/// response the agent would have received.
///
/// Reading old rows: `from_stored_detail` falls back to a bare `ActionRequest`
/// value so pre-migration approvals stay replayable (filter=None,
/// prefer_stream=false).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCallRequest {
    pub action: ActionRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<ResponseFilter>,
    #[serde(default)]
    pub prefer_stream: bool,
}

impl StoredCallRequest {
    pub fn new(action: ActionRequest, filter: Option<ResponseFilter>, prefer_stream: bool) -> Self {
        Self {
            action,
            filter,
            prefer_stream,
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

/// Either runtime's replay payload, disambiguated by JSON shape rather than a
/// serde tag — older HTTP rows on disk have no `runtime` field, so a tagged
/// enum would break them. HTTP and MCP shapes have disjoint top-level keys
/// (`action`/`method` vs `tool`), so detection is unambiguous.
pub enum ReplayPayload {
    Http(StoredCallRequest),
    Mcp(StoredMcpCall),
}

impl ReplayPayload {
    pub fn from_stored(value: &serde_json::Value) -> Result<Self, serde_json::Error> {
        if value.get("tool").is_some() {
            Ok(Self::Mcp(serde_json::from_value(value.clone())?))
        } else {
            Ok(Self::Http(StoredCallRequest::from_stored_detail(value)?))
        }
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

pub async fn call_action_request(
    ctx: CallContext<'_>,
    action_req: &ActionRequest,
) -> Result<CallOutcome, AppError> {
    // ── Resolve secrets ──────────────────────────────────────────────
    let enc_key = crypto::parse_hex_key(&ctx.state.config.secrets_encryption_key)?;
    let mut secret_values = HashMap::new();
    for secret_ref in &action_req.secrets {
        let version = ctx
            .scope
            .get_current_secret_value(&secret_ref.name)
            .await?
            .ok_or_else(|| {
                AppError::BadRequest(format!("secret '{}' not found", secret_ref.name))
            })?;
        let decrypted = crypto::decrypt(&enc_key, &version.encrypted_value)?;
        let value = String::from_utf8(decrypted)
            .map_err(|_| AppError::Internal("secret is not valid utf-8".into()))?;
        secret_values.insert(secret_ref.name.clone(), value);
    }

    let (resolved_url, resolved_headers) = inject_secrets(action_req, &secret_values)
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    let resolved_url = ctx.state.config.apply_base_overrides(&resolved_url);

    // ── Streaming path ───────────────────────────────────────────────
    if ctx.prefer_stream {
        let upstream = http_caller::call_streaming(
            &ctx.state.http_client,
            &action_req.method,
            &resolved_url,
            &resolved_headers,
            action_req.body.as_deref(),
        )
        .await?;

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
    let mut result = http_caller::call(
        &ctx.state.http_client,
        &action_req.method,
        &resolved_url,
        &resolved_headers,
        action_req.body.as_deref(),
        ctx.state.config.max_response_body_bytes,
    )
    .await
    .map_err(|e| match e {
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
    })?;

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
        "duration_ms": result.duration_ms,
        "service": ctx.service_key,
        "action": ctx.action_key,
    });
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
        "content_length": content_length,
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
