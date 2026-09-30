//! Step one of the two-step move: swap each `{upload_id}` for the stored
//! descriptor, at resolution time, before any gate.
//!
//! Everything downstream of resolution — the disclosure a reviewer reads, the
//! replay payload an approval persists, the audit row — sees the *real*
//! filename, type, size and digest from our own table. Whatever else a caller
//! put next to `upload_id` is discarded, so a caller cannot label
//! `payroll.xlsx` as `notes.txt` on the approval screen.

use std::collections::HashMap;

use serde_json::{Value, json};
use uuid::Uuid;

use overslash_core::types::{ServiceAction, StagedUploadField};
use overslash_db::repos::staged_upload;

use super::MAX_PER_CALL;
use crate::config::StagedUploadConfig;
use crate::error::AppError;

/// Rewrite the staged-upload fields of `params` in place and return the list
/// the outgoing request carries so the send path knows which fields to inline.
///
/// `ceiling_user_id` is the caller's owner user: an upload resolves for any
/// identity under the user who staged it, and for no one else. Unknown,
/// expired, foreign-org and foreign-user ids all get the same answer, so the
/// error cannot be used to probe for someone else's uploads.
pub(crate) async fn describe(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    ceiling_user_id: Uuid,
    cfg: &StagedUploadConfig,
    action: &ServiceAction,
    params: &mut HashMap<String, Value>,
) -> Result<Vec<StagedUploadField>, AppError> {
    let mut fields: Vec<(String, overslash_core::types::StagedInline)> = action
        .params
        .iter()
        .filter_map(|(name, p)| p.staged_upload.map(|i| (name.clone(), i)))
        .filter(|(name, _)| params.contains_key(name))
        .collect();
    if fields.is_empty() {
        return Ok(Vec::new());
    }
    // Deterministic order for the persisted request, whatever the map's.
    fields.sort_by(|a, b| a.0.cmp(&b.0));

    // Parse every reference first, so a malformed one fails before any query.
    let mut refs: Vec<(String, Vec<Uuid>)> = Vec::with_capacity(fields.len());
    let mut nulls = Vec::new();
    for (name, _) in &fields {
        let items = match params.get(name) {
            Some(Value::Array(items)) => items,
            // An explicit null means "none", and is dropped rather than sent:
            // the upstream reads the field as a list.
            Some(Value::Null) => {
                nulls.push(name.clone());
                continue;
            }
            _ => {
                return Err(AppError::BadRequest(format!(
                    "'{name}' must be a list of {{\"upload_id\": \"…\"}} objects"
                )));
            }
        };
        let mut ids = Vec::with_capacity(items.len());
        for item in items {
            let id = item
                .get("upload_id")
                .and_then(Value::as_str)
                .and_then(|s| Uuid::parse_str(s.trim()).ok())
                .ok_or_else(|| {
                    AppError::BadRequest(format!(
                        "every item in '{name}' needs an upload_id from overslash \
                         upload_file"
                    ))
                })?;
            ids.push(id);
        }
        refs.push((name.clone(), ids));
    }
    for name in nulls {
        params.remove(&name);
    }

    let all: Vec<Uuid> = refs
        .iter()
        .flat_map(|(_, ids)| ids.iter().copied())
        .collect();
    if all.len() > MAX_PER_CALL {
        return Err(AppError::BadRequest(format!(
            "{} attachments exceed the limit of {MAX_PER_CALL} per call",
            all.len()
        )));
    }
    let found = staged_upload::find_ready(pool, org_id, &all).await?;
    let by_id: HashMap<Uuid, &staged_upload::StagedUploadMeta> = found
        .iter()
        .filter(|m| m.owner_user_id == ceiling_user_id)
        .map(|m| (m.id, m))
        .collect();

    let mut total: u64 = 0;
    for (name, ids) in &refs {
        let mut described = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(m) = by_id.get(id) else {
                return Err(AppError::BadRequest(format!(
                    "upload {id} is unknown, expired or not finished uploading. Staged \
                     uploads last {}h; stage the file again with overslash upload_file",
                    cfg.ttl_secs / 3600
                )));
            };
            let size = m.size_bytes.unwrap_or_default();
            total += size.max(0) as u64;
            described.push(json!({
                "upload_id": m.id,
                "filename": m.filename,
                "content_type": m.content_type,
                "size_bytes": size,
                "sha256": m.sha256,
            }));
        }
        params.insert(name.clone(), Value::Array(described));
    }
    if total > cfg.max_bytes {
        return Err(AppError::BadRequest(format!(
            "attachments total {total} bytes, over the {}-byte limit for one call",
            cfg.max_bytes
        )));
    }

    // Only fields that name at least one upload go on the request. An empty
    // list (`attachments: []`) is sent as-is and has nothing to inline, so
    // listing it would make the send path take — and hold for the whole
    // upstream call — a buffer slot it never uses.
    Ok(fields
        .into_iter()
        .filter(|(name, _)| refs.iter().any(|(n, ids)| n == name && !ids.is_empty()))
        .map(|(field, inline_as)| StagedUploadField { field, inline_as })
        .collect())
}
