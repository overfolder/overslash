//! `overslash:upload_file` — mint a single-use URL to stage bytes for a later
//! action.
//!
//! A platform action rather than a REST route of its own, because the MCP
//! surface reaches the gateway only through `overslash_call`, and an agent is
//! who needs this. It runs through the ordinary permission and approval
//! pipeline like any other write.

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::{Value, json};

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::staged_upload::{self, MintOutcome, NewStagedUpload, Quota};

use super::{parse_content_type, sanitize_filename};
use crate::error::AppError;
use crate::services::{deferred_download, group_ceiling, platform_caller::PlatformCallContext};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadFileInput {
    filename: Option<String>,
    size_bytes: Option<i64>,
    content_type: Option<String>,
    sha256: Option<String>,
    #[serde(default)]
    force: bool,
}

pub(crate) async fn kernel_upload_file(
    ctx: PlatformCallContext,
    params: HashMap<String, Value>,
) -> Result<Value, AppError> {
    let cfg = &ctx.config.staged_uploads;
    if !cfg.enabled {
        return Err(AppError::Forbidden(
            "staged uploads are disabled on this deployment".into(),
        ));
    }
    let identity_id = ctx.identity_id.ok_or_else(|| {
        AppError::BadRequest("upload_file needs an identity-bound credential".into())
    })?;
    let input: UploadFileInput = serde_json::from_value(Value::Object(
        params.into_iter().collect::<serde_json::Map<_, _>>(),
    ))
    .map_err(|e| AppError::BadRequest(format!("invalid params: {e}")))?;

    let filename = input
        .filename
        .as_deref()
        .map(sanitize_filename)
        .ok_or_else(|| AppError::BadRequest("'filename' is required".into()))?;
    // Required, unlike the D76 upload's optional size: this number is the
    // quota reservation, and the push is held to it exactly.
    let size = input
        .size_bytes
        .filter(|n| *n > 0)
        .ok_or_else(|| AppError::BadRequest("'size_bytes' must be a positive integer".into()))?;
    if size as u64 > cfg.max_bytes {
        return Err(AppError::BadRequest(format!(
            "size_bytes {size} exceeds the {}-byte limit for one upload",
            cfg.max_bytes
        )));
    }
    let content_type = match input.content_type.as_deref() {
        None => "application/octet-stream".to_string(),
        Some(raw) => parse_content_type(raw).ok_or_else(|| {
            AppError::BadRequest(format!(
                "content_type '{raw}' is not a type/subtype media type"
            ))
        })?,
    };
    let sha256 = input.sha256.map(|s| s.trim().to_ascii_lowercase());
    if let Some(h) = &sha256
        && (h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(AppError::BadRequest(
            "sha256 must be 64 hexadecimal characters".into(),
        ));
    }

    let scope = OrgScope::new(ctx.org_id, ctx.db.clone());
    let identity = scope
        .get_identity(identity_id)
        .await?
        .ok_or_else(|| AppError::NotFound("identity not found".into()))?;
    let owner_user_id = group_ceiling::ceiling_user_id_from_identity(&identity)?;

    let (raw_token, token_hash) = deferred_download::new_token();
    let outcome = staged_upload::mint(
        &ctx.db,
        NewStagedUpload {
            org_id: ctx.org_id,
            identity_id,
            owner_user_id,
            token_hash: &token_hash,
            filename: &filename,
            content_type: &content_type,
            declared_size_bytes: size,
            declared_sha256: sha256.as_deref(),
            token_ttl_secs: ctx.config.upload_token_ttl_secs,
        },
        Quota {
            identity_bytes: cfg.identity_quota_bytes,
            identity_count: cfg.identity_max_count,
            org_bytes: cfg.org_quota_bytes,
        },
        input.force,
    )
    .await?;

    let (id, expires_at, evicted) = match outcome {
        MintOutcome::Minted {
            id,
            expires_at,
            evicted,
        } => (id, expires_at, evicted),
        MintOutcome::QuotaExceeded {
            usage,
            evictable_bytes,
            evictable_count,
        } => {
            let hint = if evictable_count > 0 {
                "retry with force: true to evict your own oldest staged uploads \
                 (never ones a pending approval is waiting on) until this one fits"
            } else {
                "forcing would not help: what you could evict is not enough, or is \
                 pinned by a pending approval. Wait for uploads to expire, or send \
                 fewer or smaller files"
            };
            return Err(AppError::StagedUploadQuotaExceeded {
                detail: json!({
                    "usage": {
                        "identity_bytes": usage.identity_bytes,
                        "identity_count": usage.identity_count,
                        "org_bytes": usage.org_bytes,
                    },
                    "limits": {
                        "identity_bytes": cfg.identity_quota_bytes,
                        "identity_count": cfg.identity_max_count,
                        "org_bytes": cfg.org_quota_bytes,
                    },
                    "requested_bytes": size,
                    "evictable_bytes": evictable_bytes,
                    "evictable_count": evictable_count,
                }),
                hint: hint.to_string(),
            });
        }
    };

    for evicted_id in &evicted {
        let _ = scope
            .log_audit(AuditEntry {
                org_id: ctx.org_id,
                identity_id: Some(identity_id),
                action: "upload.evicted",
                resource_type: Some("staged_upload"),
                resource_id: Some(*evicted_id),
                detail: json!({"reason": "forced", "replaced_by": id}),
                description: None,
                ip_address: None,
            })
            .await;
    }

    let base = ctx.config.public_url.trim_end_matches('/');
    let upload_url = format!("{base}/v1/uploads/{raw_token}");
    Ok(json!({
        "upload_id": id,
        "upload_url": upload_url,
        "method": "PUT",
        "expires_at": crate::routes::util::fmt_time(expires_at),
        "max_bytes": size,
        "filename": filename,
        "content_type": content_type,
        "evicted": evicted,
        "hint": format!(
            "curl -sSf -X PUT --data-binary @FILE '{upload_url}' — the body must be \
             exactly {size} bytes. Then pass {{\"upload_id\": \"{id}\"}} in the action's \
             attachments; the file stays sendable for {}h.",
            cfg.ttl_secs / 3600
        ),
    }))
}
