//! Step two: the bytes, at send time.
//!
//! Called on every path that dials an HTTP action — inline, approval replay,
//! the async worker — at the same point credentials are injected, and for the
//! same reason: what is persisted between resolution and the dial must never
//! hold the thing itself.

use base64::Engine as _;
use serde_json::{Value, json};
use tokio::sync::OwnedSemaphorePermit;
use uuid::Uuid;

use overslash_core::types::{ActionRequest, StagedInline};
use overslash_db::repos::staged_upload;

use crate::AppState;
use crate::error::AppError;

/// The body to send, when inlining changed it. Holds the replica's buffer
/// permit for as long as it lives, so keep it in scope until the upstream call
/// has finished — dropping it early releases the memory bound while the
/// base64 body is still in flight.
pub(crate) struct WireBody {
    body: Option<String>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl WireBody {
    /// The body to put on the wire: the inlined one, or the request's own.
    pub(crate) fn or<'a>(&'a self, original: Option<&'a str>) -> Option<&'a str> {
        self.body.as_deref().or(original)
    }
}

/// Inline every staged upload `req` names. A request that names none costs
/// nothing and holds no permit.
pub(crate) async fn wire_body(
    state: &AppState,
    pool: &sqlx::PgPool,
    org_id: Uuid,
    req: &ActionRequest,
) -> Result<WireBody, AppError> {
    if req.staged_uploads.is_empty() {
        return Ok(WireBody {
            body: None,
            _permit: None,
        });
    }
    let permit = super::permit(&state.config.staged_uploads).await?;
    let mut body: Value = req
        .body
        .as_deref()
        .map(serde_json::from_str)
        .transpose()?
        .ok_or_else(|| AppError::Internal("staged uploads named on a bodyless request".into()))?;
    let keyring = state.config.keyring()?;

    for field in &req.staged_uploads {
        let Some(items) = body.get_mut(&field.field).and_then(Value::as_array_mut) else {
            continue;
        };
        for item in items.iter_mut() {
            let get = |k: &str| item.get(k).and_then(Value::as_str).map(str::to_string);
            let id = get("upload_id")
                .and_then(|s| Uuid::parse_str(&s).ok())
                .ok_or_else(|| AppError::Internal("described upload lost its id".into()))?;
            let filename = get("filename").unwrap_or_else(|| "attachment".into());
            let content_type =
                get("content_type").unwrap_or_else(|| "application/octet-stream".into());
            let approved_sha = get("sha256");

            let Some((stored_sha, ciphertext)) =
                staged_upload::load_ciphertext(pool, org_id, id).await?
            else {
                return Err(AppError::Gone(format!(
                    "attachment '{filename}' ({id}) expired before this call was sent; \
                     stage it again with overslash upload_file and re-send"
                )));
            };
            // Rows are never rewritten, so this can only fire on a replay whose
            // stored descriptor names different bytes than the table holds —
            // which is exactly the case where sending anyway would send
            // something nobody approved.
            if approved_sha.as_deref() != Some(stored_sha.as_str()) {
                return Err(AppError::Conflict(format!(
                    "attachment '{filename}' ({id}) no longer matches what was approved"
                )));
            }
            let plaintext = overslash_core::crypto::decrypt(&keyring, &ciphertext)?;
            drop(ciphertext);
            *item = match field.inline_as {
                StagedInline::Base64 => json!({
                    "filename": filename,
                    "content_type": content_type,
                    "content_base64": base64::engine::general_purpose::STANDARD.encode(&plaintext),
                }),
            };
        }
    }

    Ok(WireBody {
        body: Some(serde_json::to_string(&body)?),
        _permit: Some(permit),
    })
}
