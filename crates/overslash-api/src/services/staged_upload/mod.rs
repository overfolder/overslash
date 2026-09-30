//! Gateway-staged uploads: bytes Overslash holds briefly so an HTTP action can
//! carry them inline — an email attachment through the stateless Mailbox
//! Gateway, which has nowhere of its own to keep a file.
//!
//! The capability model is D76's, pointed at a different sink. `upload_file`
//! mints a single-use URL; the anonymous push to `POST /v1/uploads/{token}`
//! contributes bytes and nothing else; everything a reviewer could care about
//! — filename, type, size, digest — is fixed before or verified during that
//! push. Where D76 streams the bytes into the *service's* storage and hands
//! back its reference, here they land in `staged_uploads`, encrypted, and the
//! reference is ours.
//!
//! An action opts in per body property with `x-overslash-staged-upload`. The
//! bytes then move in two steps, and the split is the whole design:
//!
//! 1. [`describe`] — at resolution, before any gate. Each `{upload_id}` is
//!    replaced by its stored descriptor, so the approval a human reads and the
//!    replay payload that gets persisted both name the real file, and neither
//!    holds a byte of it.
//! 2. [`wire_body`] — at send time, on every path that dials: inline, approval
//!    replay, the async worker. Only here do the bytes leave the table,
//!    base64-encoded into the outgoing body, exactly as a `SecretRef` only
//!    becomes a header at send time.
//!
//! Bounds (see `StagedUploadConfig`): a per-upload and per-call byte ceiling,
//! per-identity and per-org quotas counted from mint (reservations included),
//! a count cap, a TTL, and one process-wide semaphore over every place this
//! module holds a large body in memory.

mod describe;
mod inline;
mod mint;
mod redeem;

pub(crate) use describe::describe;
pub(crate) use inline::wire_body;
pub(crate) use mint::kernel_upload_file;
pub(crate) use redeem::redeem;

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use overslash_core::types::ActionRequest;

use crate::config::StagedUploadConfig;
use crate::error::AppError;

/// Attachments one call may carry, across every staged field. Matches overfwd's
/// own cap, so the gateway refuses what the upstream would refuse anyway, and
/// refuses it before a byte is decrypted.
pub(crate) const MAX_PER_CALL: usize = 20;

/// How long a caller waits for a buffer slot before a 503. Long enough to ride
/// out a burst, short enough that a saturated replica says so rather than
/// holding connections open until the proxy cuts them.
const PERMIT_WAIT: Duration = Duration::from_secs(30);

/// One semaphore per process, sized from the first config that asks. Process
/// scope is the point: the thing it bounds is this process's memory, which
/// every request in it shares.
static PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();

/// Take one of this replica's large-body slots, or answer 503.
pub(crate) async fn permit(cfg: &StagedUploadConfig) -> Result<OwnedSemaphorePermit, AppError> {
    let sem = PERMITS
        .get_or_init(|| Arc::new(Semaphore::new(cfg.concurrency.max(1))))
        .clone();
    match tokio::time::timeout(PERMIT_WAIT, sem.acquire_owned()).await {
        Ok(Ok(p)) => Ok(p),
        Ok(Err(_closed)) => Err(AppError::Internal("staged upload semaphore closed".into())),
        Err(_elapsed) => Err(AppError::Unavailable(
            "too many uploads in flight on this replica; retry shortly".into(),
        )),
    }
}

/// Every upload a resolved request names, for pinning. Reads the descriptors
/// [`describe`] wrote, so it never has to know how a template spelled them.
pub(crate) fn upload_ids(req: &ActionRequest) -> Vec<Uuid> {
    if req.staged_uploads.is_empty() {
        return Vec::new();
    }
    let Some(body) = req
        .body
        .as_deref()
        .and_then(|b| serde_json::from_str::<serde_json::Value>(b).ok())
    else {
        return Vec::new();
    };
    req.staged_uploads
        .iter()
        .filter_map(|f| body.get(&f.field).and_then(serde_json::Value::as_array))
        .flatten()
        .filter_map(|item| item.get("upload_id").and_then(serde_json::Value::as_str))
        .filter_map(|s| Uuid::parse_str(s).ok())
        .collect()
}

/// Keep a request's uploads alive and unevictable until `until`. Best-effort:
/// a failed pin costs protection against a later forced eviction, never the
/// call it belongs to.
pub(crate) async fn pin_for(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    req: &ActionRequest,
    until: time::OffsetDateTime,
) {
    let ids = upload_ids(req);
    if ids.is_empty() {
        return;
    }
    if let Err(e) = overslash_db::repos::staged_upload::pin(pool, org_id, &ids, until).await {
        tracing::warn!(error = %e, "staged upload: pin not recorded");
    }
}

/// Filenames reach an email `Content-Disposition` and an approval screen, so
/// anything that could split a header or climb a path goes. Clamped by
/// characters, never by byte index.
pub(crate) fn sanitize_filename(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '/' | '\\'))
        .collect();
    let trimmed = cleaned.trim().trim_matches('.').trim();
    let clamped: String = trimmed.chars().take(255).collect();
    if clamped.is_empty() {
        "attachment".to_string()
    } else {
        clamped
    }
}

/// `type/subtype` in RFC 6838 token characters, lowercased. Parameters are
/// dropped: nothing downstream needs a charset on an opaque attachment, and a
/// parameter is exactly where a CRLF would hide.
pub(crate) fn parse_content_type(raw: &str) -> Option<String> {
    let essence = raw.split(';').next()?.trim().to_ascii_lowercase();
    let (ty, sub) = essence.split_once('/')?;
    let token = |s: &str| {
        !s.is_empty()
            && s.len() <= 127
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
    };
    (token(ty) && token(sub)).then_some(essence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_strips_header_and_path_breakers() {
        assert_eq!(sanitize_filename("a\r\nBcc: x@y.z.pdf"), "aBcc: x@y.z.pdf");
        assert_eq!(sanitize_filename("../../etc/passwd"), "etcpasswd");
        assert_eq!(sanitize_filename("  \u{7}  "), "attachment");
        assert_eq!(sanitize_filename("résumé.pdf"), "résumé.pdf");
        let long = "é".repeat(400);
        assert_eq!(sanitize_filename(&long).chars().count(), 255);
    }

    #[test]
    fn content_type_is_a_bare_essence() {
        assert_eq!(
            parse_content_type("Application/PDF; charset=x").as_deref(),
            Some("application/pdf")
        );
        assert_eq!(
            parse_content_type("image/svg+xml").as_deref(),
            Some("image/svg+xml")
        );
        assert_eq!(parse_content_type("text/plain\r\nX: y"), None);
        assert_eq!(parse_content_type("pdf"), None);
        assert_eq!(parse_content_type("/pdf"), None);
    }

    #[test]
    fn upload_ids_reads_described_items() {
        let id = Uuid::new_v4();
        let req = ActionRequest {
            method: "POST".into(),
            url: "https://x".into(),
            headers: Default::default(),
            body: Some(
                serde_json::json!({"attachments": [{"upload_id": id.to_string()}], "subject": "s"})
                    .to_string(),
            ),
            secrets: Vec::new(),
            staged_uploads: vec![overslash_core::types::StagedUploadField {
                field: "attachments".into(),
                inline_as: Default::default(),
            }],
        };
        assert_eq!(upload_ids(&req), vec![id]);
    }
}
