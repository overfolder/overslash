//! Redeeming a staged-upload token: `POST|PUT /v1/uploads/{token}` when the
//! token names a `staged_uploads` row rather than an `upload_tokens` one.
//!
//! Same anonymous-redeemer rules as the D76 route this shares: the token is
//! the only authority, the redeemer contributes bytes and nothing else, and
//! every failure after the claim spends the token.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use serde_json::json;
use sha2::{Digest, Sha256};

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::staged_upload::{self, ClaimedUpload};

use crate::AppState;

/// Take the token and store what is pushed to it. `None` means no staged row
/// holds this token either, and the caller answers its uniform 404.
pub(crate) async fn redeem(
    state: &AppState,
    ext: &axum::http::Extensions,
    ip: &str,
    token_hash: &[u8],
    headers: &HeaderMap,
    body: axum::body::Body,
) -> Option<Response> {
    let cfg = &state.config.staged_uploads;
    // Acquired *before* the claim, so a saturated replica answers 503 without
    // spending the token — the caller can simply retry the same URL. Unknown
    // tokens wait too, which keeps the answer the same for valid and invalid
    // ones rather than turning saturation into an oracle.
    let _permit = match super::permit(cfg).await {
        Ok(p) => p,
        Err(e) => return Some(e.into_response()),
    };

    let row = match staged_upload::claim(state.db(ext), token_hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return None,
        Err(e) => {
            tracing::error!(error = %e, "staged upload: token lookup failed");
            return Some((StatusCode::INTERNAL_SERVER_ERROR, "upload failed").into_response());
        }
    };
    let scope = OrgScope::new(row.org_id, state.db_pool(ext));

    // The minter was checked at mint; this catches it being deleted since, so
    // an outstanding token dies with its principal.
    match scope.get_identity(row.identity_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            let _ = staged_upload::abandon(state.db(ext), row.id).await;
            return None;
        }
        Err(e) => {
            tracing::error!(error = %e, "staged upload: identity lookup failed");
            let _ = staged_upload::abandon(state.db(ext), row.id).await;
            return Some((StatusCode::INTERNAL_SERVER_ERROR, "upload failed").into_response());
        }
    }

    let outcome = store(state, ext, &row, headers, body).await;
    if outcome.is_err() {
        // Frees the reservation now rather than at token expiry. Deleting
        // rather than re-arming is deliberate: see the repo's module docs.
        let _ = staged_upload::abandon(state.db(ext), row.id).await;
    }
    let (status, detail, response) = match outcome {
        Ok((body, sha256, size)) => (
            StatusCode::CREATED,
            json!({"size_bytes": size, "sha256": sha256}),
            (StatusCode::CREATED, axum::Json(body)).into_response(),
        ),
        Err((status, msg)) => (status, json!({"error": msg}), (status, msg).into_response()),
    };
    let mut detail = detail;
    if let Some(d) = detail.as_object_mut() {
        d.insert("status".into(), json!(status.as_u16()));
        d.insert("filename".into(), json!(row.filename));
        d.insert("content_type".into(), json!(row.content_type));
        d.insert("declared_size_bytes".into(), json!(row.declared_size_bytes));
    }
    let _ = scope
        .log_audit(AuditEntry {
            org_id: row.org_id,
            identity_id: Some(row.identity_id),
            action: if status.is_success() {
                "upload.staged"
            } else {
                "upload.failed"
            },
            resource_type: Some("staged_upload"),
            resource_id: Some(row.id),
            detail,
            description: None,
            ip_address: Some(ip),
        })
        .await;
    Some(response)
}

type Stored = (serde_json::Value, String, i64);

/// Read, verify, encrypt, store. Every refusal is an `Err` the caller abandons
/// the row on.
async fn store(
    state: &AppState,
    ext: &axum::http::Extensions,
    row: &ClaimedUpload,
    headers: &HeaderMap,
    body: axum::body::Body,
) -> Result<Stored, (StatusCode, String)> {
    let declared = row.declared_size_bytes.max(0) as u64;
    // A stated length that disagrees is refused before a byte is buffered. The
    // loop below is still the real bound — a chunked body states no length.
    if let Some(len) = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        && len != declared
    {
        let status = if len > declared {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::UNPROCESSABLE_ENTITY
        };
        return Err((
            status,
            format!("upload is {len} bytes; this token was minted for exactly {declared}"),
        ));
    }

    let idle = std::time::Duration::from_millis(state.config.call_stream_idle_timeout_ms);
    let mut stream = body.into_data_stream();
    let mut buf: Vec<u8> = Vec::with_capacity(declared as usize);
    let mut hasher = Sha256::new();
    loop {
        match tokio::time::timeout(idle, stream.next()).await {
            Ok(Some(Ok(chunk))) => {
                if buf.len() as u64 + chunk.len() as u64 > declared {
                    return Err((
                        StatusCode::PAYLOAD_TOO_LARGE,
                        format!("upload exceeds the {declared} bytes this token was minted for"),
                    ));
                }
                hasher.update(&chunk);
                buf.extend_from_slice(&chunk);
            }
            Ok(Some(Err(e))) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("upload body unreadable: {e}"),
                ));
            }
            Ok(None) => break,
            Err(_elapsed) => {
                return Err((StatusCode::REQUEST_TIMEOUT, "upload stalled".to_string()));
            }
        }
    }
    if buf.len() as u64 != declared {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "upload size mismatch: declared {declared} bytes, received {}",
                buf.len()
            ),
        ));
    }
    let digest = hex(&hasher.finalize());
    if let Some(expected) = row.declared_sha256.as_deref()
        && !expected.eq_ignore_ascii_case(&digest)
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("upload content mismatch: declared sha256 {expected}, received {digest}"),
        ));
    }

    let internal = |what: &str| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("upload failed: {what}"),
        )
    };
    let keyring = state.config.keyring().map_err(|_| internal("keyring"))?;
    let ciphertext =
        overslash_core::crypto::encrypt(&keyring, &buf).map_err(|_| internal("encryption"))?;
    drop(buf);
    let size = declared as i64;
    let expires_at = staged_upload::complete(
        state.db(ext),
        row.id,
        size,
        &digest,
        &ciphertext,
        state.config.staged_uploads.ttl_secs,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "staged upload: store failed");
        internal("store")
    })?
    .ok_or_else(|| internal("row vanished"))?;

    Ok((
        json!({
            "upload_id": row.id,
            "filename": row.filename,
            "content_type": row.content_type,
            "size_bytes": size,
            "sha256": digest,
            "expires_at": crate::routes::util::fmt_time(expires_at),
        }),
        digest,
        size,
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}
