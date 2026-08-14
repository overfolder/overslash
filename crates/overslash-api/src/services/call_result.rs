//! Stored call results: keep the bytes an agent already paid for.
//!
//! # Why this exists
//!
//! An agent over MCP gets the compact rendering (`verbose: false`), which crops
//! the body to [`compact_response::COMPACT_BUDGET_BYTES`]. Until this module,
//! the only way past that crop was to issue a *new* call — `verbose: true`, or
//! `deliver: "url"`. Both re-run the upstream. A field report has an agent
//! re-running a 30-second Metabase query purely to change the delivery mode of
//! bytes the gateway had held in memory and discarded.
//!
//! So: when a render truncates, stash the full [`ActionResult`] and mint a
//! [`deferred_download`] token pointing at it. The caller gets the URL in the
//! same envelope as the cropped body — no extra round trip to discover it.
//!
//! # What this is not
//!
//! It is not a second authorization system, for the same reason
//! [`deferred_download`] is not: the call that produced these bytes was
//! permission-checked, gated, and audited before they existed. Storing defers
//! *rendering*, never the decision. And it is not history — the row shares the
//! download token's short TTL. History is the audit log.
//!
//! # Why the blob is encrypted
//!
//! We do not choose the contents. An upstream is free to return a refresh token
//! in a JSON field, and the response headers — `Set-Cookie`, an echoed
//! `Authorization` — are serialized into the same blob. [`deferred_download`]
//! goes to real lengths to keep live credentials out of `download_tokens`;
//! storing response bodies in plaintext would re-open that from the other
//! direction. Note the consequence in migration 111: the column is `BYTEA`, so
//! nothing can query *inside* a stored result. Audit capture is the consented
//! path for that.

use overslash_core::crypto;
use overslash_core::types::ActionResult;
use overslash_db::repos::call_result::{self, NewCallResult};
use uuid::Uuid;

use crate::{AppState, error::AppError, services::deferred_download};

/// What a store needs to know about the call that produced the bytes.
pub struct Stored<'a> {
    pub org_id: Uuid,
    pub identity_id: Uuid,
    pub service_key: Option<&'a str>,
    pub action_key: Option<&'a str>,
}

/// Persist a completed result and mint a capability URL for it.
///
/// Returns `None` — never an error — when the result should not be stored:
/// the feature is disabled, the body is over the cap, or the write failed. The
/// call it belongs to has *already succeeded*; a storage problem must not turn
/// a 200 into a 500, exactly as an audit-write failure doesn't. The caller
/// simply omits `_full_result` and the agent falls back to the old advice.
pub async fn store(
    state: &AppState,
    ext: &axum::http::Extensions,
    s: Stored<'_>,
    result: &ActionResult,
) -> Option<deferred_download::Descriptor> {
    let max = state.config.call_result_max_bytes;
    if max == 0 {
        return None;
    }

    let plaintext = match serde_json::to_vec(result) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "call_result: result not serializable; not storing");
            return None;
        }
    };
    if plaintext.len() > max {
        // Deliberately not a truncated copy. An agent that fetched a silently
        // shortened "full result" would believe it complete and be wrong —
        // strictly worse than having no stored copy at all.
        tracing::debug!(
            bytes = plaintext.len(),
            max,
            "call_result: over cap, not storing"
        );
        return None;
    }

    match store_inner(state, ext, s, result, &plaintext).await {
        Ok(d) => Some(d),
        Err(e) => {
            tracing::warn!(error = %e, "call_result: store failed; result not re-fetchable");
            None
        }
    }
}

/// The fallible half, split out so [`store`] reads as the policy it is and
/// every `?` here lands in one `warn!` rather than five.
async fn store_inner(
    state: &AppState,
    ext: &axum::http::Extensions,
    s: Stored<'_>,
    result: &ActionResult,
    plaintext: &[u8],
) -> Result<deferred_download::Descriptor, AppError> {
    let keyring = state.config.keyring()?;
    let ciphertext = crypto::encrypt(&keyring, plaintext)?;

    // Cleartext so a redemption can build response headers without decrypting.
    let content_type = result
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone());

    let row = call_result::create(
        state.db(ext),
        NewCallResult {
            org_id: s.org_id,
            identity_id: s.identity_id,
            service_key: s.service_key,
            action_key: s.action_key,
            body_ciphertext: &ciphertext,
            status_code: i32::from(result.status_code),
            content_type: content_type.as_deref(),
            // The *body's* length, not the encrypted envelope's: this is what
            // the descriptor advertises and what a redemption actually writes.
            // The cap above is measured on the envelope instead, since that is
            // what occupies the row.
            body_bytes: result.body.len() as i64,
            ttl_secs: state.config.download_token_ttl_secs,
        },
    )
    .await?;

    deferred_download::mint(
        state,
        ext,
        deferred_download::Mint {
            org_id: s.org_id,
            identity_id: s.identity_id,
            // All four name a *replayable request*, which a result-backed token
            // has none of — the bytes are the row.
            service_instance_id: None,
            service_key: s.service_key,
            action_key: s.action_key,
            request: None,
            call_result_id: Some(row.id),
            mime: row.content_type.clone(),
            size_bytes: Some(row.body_bytes),
            filename: None,
            // Clamp the token to the result it points at, so the `expires_at`
            // the agent is handed is true rather than optimistic.
            expires_at_ceiling: Some(row.expires_at),
        },
    )
    .await
}

/// Read back a stored result for a token redemption.
///
/// Returns `Ok(None)` when the row is gone or expired — the redemption path
/// turns that into the same bare 404 as an unknown token, preserving the
/// deliberate indistinguishability of unknown / expired / revoked.
pub async fn load(
    state: &AppState,
    pool: &sqlx::PgPool,
    id: Uuid,
) -> Result<Option<ActionResult>, AppError> {
    let Some(row) = call_result::get_unexpired(pool, id).await? else {
        return Ok(None);
    };
    let keyring = state.config.keyring()?;
    let plaintext = crypto::decrypt(&keyring, &row.body_ciphertext)?;
    let result: ActionResult = serde_json::from_slice(&plaintext)
        .map_err(|e| AppError::Internal(format!("stored call result unreadable: {e}")))?;
    Ok(Some(result))
}
