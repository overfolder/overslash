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

use super::multipart::{self, FilePart};
use crate::AppState;
use crate::error::AppError;
use crate::services::http_caller::Payload;

/// The body to send, when inlining changed it. Holds the replica's buffer
/// permit for as long as it lives, so keep it in scope until the upstream call
/// has finished — dropping it early releases the memory bound while the
/// inlined body is still in flight.
pub(crate) struct WireBody {
    body: Option<Vec<u8>>,
    /// Set only for `multipart/form-data`, whose boundary is minted here.
    content_type: Option<String>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl WireBody {
    /// The body to put on the wire: the inlined one, or the request's own.
    pub(crate) fn or<'a>(&'a self, original: Option<&'a str>) -> Option<Payload<'a>> {
        match &self.body {
            Some(bytes) => Some(Payload {
                bytes,
                content_type: self.content_type.as_deref(),
            }),
            None => original.map(Payload::from),
        }
    }
}

/// Inline every staged upload `req` names. A request that names none, and is
/// not a form, costs nothing and holds no permit.
pub(crate) async fn wire_body(
    state: &AppState,
    pool: &sqlx::PgPool,
    org_id: Uuid,
    req: &ActionRequest,
) -> Result<WireBody, AppError> {
    // Keyed off the template-set list, never the `Content-Type`: a raw HTTP
    // call may carry a real multipart body of its own, and that must pass
    // through untouched. `describe` lists a form's file fields even when the
    // file was omitted, so such a form still goes out as one.
    let multipart = req
        .staged_uploads
        .iter()
        .any(|f| f.inline_as == StagedInline::Multipart);
    if req.staged_uploads.is_empty() {
        return Ok(WireBody {
            body: None,
            content_type: None,
            _permit: None,
        });
    }
    let mut body: Value = match req.body.as_deref() {
        Some(b) => serde_json::from_str(b)?,
        None if multipart => json!({}),
        None => {
            return Err(AppError::Internal(
                "staged uploads named on a bodyless request".into(),
            ));
        }
    };
    // The buffer slot is only worth holding when there are bytes to inline; a
    // form whose file field is empty is just text parts.
    let has_items = req.staged_uploads.iter().any(|f| {
        body.get(&f.field)
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
    });
    let permit = match has_items {
        true => Some(super::permit(&state.config.staged_uploads).await?),
        false => None,
    };
    let keyring = state.config.keyring()?;
    let mut files = Vec::new();

    for field in &req.staged_uploads {
        let Some(items) = body.get_mut(&field.field).and_then(Value::as_array_mut) else {
            continue;
        };
        for item in items.iter_mut() {
            let (filename, content_type, plaintext) = load(pool, org_id, &keyring, item).await?;
            match field.inline_as {
                StagedInline::Base64 => {
                    *item = json!({
                        "filename": filename,
                        "content_type": content_type,
                        "content_base64": base64::engine::general_purpose::STANDARD
                            .encode(&plaintext),
                    });
                }
                StagedInline::Multipart => files.push(FilePart {
                    field: field.field.clone(),
                    filename,
                    content_type,
                    bytes: plaintext,
                }),
            }
        }
    }

    if !multipart {
        return Ok(WireBody {
            body: Some(serde_json::to_vec(&body)?),
            content_type: None,
            _permit: permit,
        });
    }
    let mut fields = match body {
        Value::Object(map) => map,
        _ => return Err(AppError::Internal("form body is not an object".into())),
    };
    // Each file field leaves the text fields: its bytes go out as parts.
    for field in &req.staged_uploads {
        fields.remove(&field.field);
    }
    let (bytes, content_type) = multipart::encode(&fields, &files)?;
    Ok(WireBody {
        body: Some(bytes),
        content_type: Some(content_type),
        _permit: permit,
    })
}

/// One described item's bytes, checked against the digest that was approved.
async fn load(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    keyring: &overslash_core::crypto::Keyring,
    item: &Value,
) -> Result<(String, String, Vec<u8>), AppError> {
    let get = |k: &str| item.get(k).and_then(Value::as_str).map(str::to_string);
    let id = get("upload_id")
        .and_then(|s| Uuid::parse_str(&s).ok())
        .ok_or_else(|| AppError::Internal("described upload lost its id".into()))?;
    let filename = get("filename").unwrap_or_else(|| "attachment".into());
    let content_type = get("content_type").unwrap_or_else(|| "application/octet-stream".into());
    let approved_sha = get("sha256");

    let Some((stored_sha, ciphertext)) = staged_upload::load_ciphertext(pool, org_id, id).await?
    else {
        return Err(AppError::Gone(format!(
            "attachment '{filename}' ({id}) expired before this call was sent; \
             stage it again with overslash upload_file and re-send"
        )));
    };
    // Rows are never rewritten, so this can only fire on a replay whose
    // stored descriptor names different bytes than the table holds — which is
    // exactly the case where sending anyway would send something nobody
    // approved.
    if approved_sha.as_deref() != Some(stored_sha.as_str()) {
        return Err(AppError::Conflict(format!(
            "attachment '{filename}' ({id}) no longer matches what was approved"
        )));
    }
    let plaintext = overslash_core::crypto::decrypt(keyring, &ciphertext)?;
    Ok((filename, content_type, plaintext))
}
