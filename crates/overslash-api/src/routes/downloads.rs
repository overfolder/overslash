//! `GET /v1/downloads/{token}` — redeem a deferred-download capability.
//!
//! Mounted **outside** the auth and rate-limit layers, like
//! [`super::unsubscribe`]: the fetching process is deliberately not the caller.
//! It is `curl` inside a sandboxed VM, or a browser — something that holds none
//! of the caller's credentials and cannot be handed any. The token in the URL
//! is the sole authority, which is why it is 256 bits of randomness, stored
//! only as a hash, and short-lived.
//!
//! The authorization decision was already made and audited when the action call
//! minted the token; see [`crate::services::deferred_download`]. What happens
//! here is the *second* half: re-resolve the upstream credential from the vault
//! as it stands right now, dial the upstream, and pipe bytes straight through.
//!
//! Failure modes are deliberately indistinguishable. Unknown token, expired
//! token, and deleted-identity all return the same bare `404` — a
//! distinguishable "expired" would confirm to someone probing that a given
//! token string was once real.

use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use overslash_core::types::ActionRequest;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::download_token;
use overslash_db::scopes::OrgScope;

use crate::{
    AppState,
    extractors::{ClientIp, ReqExt},
    services::deferred_download,
};

/// Per-IP ceiling on redemption attempts. Generous enough that a resumed
/// multi-part download of one large file never trips it, tight enough that
/// brute-forcing the token space is pointless (which it already is at 256
/// bits — this is the volumetric backstop, not the security boundary).
const DOWNLOAD_IP_MAX: u32 = 120;
const DOWNLOAD_IP_WINDOW_SECS: u32 = 60;

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/downloads/{token}", get(redeem))
}

async fn redeem(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    client_ip: ClientIp,
    Path(token): Path<String>,
) -> Response {
    // This endpoint is anonymous, and the global rate-limit middleware keys on
    // the API-key prefix — so it skips requests without one entirely. Throttle
    // here on the shared store directly, the same way the magic-link endpoints
    // do.
    let ip = client_ip.0.as_deref().unwrap_or("unknown");
    let rl = state
        .rate_limiter(&ext)
        .check_and_increment(
            &format!("dl:redeem:ip:{ip}"),
            DOWNLOAD_IP_MAX,
            DOWNLOAD_IP_WINDOW_SECS,
        )
        .await;
    if !rl.allowed {
        let retry_after = rl
            .reset_at
            .saturating_sub(crate::services::rate_limit::now_unix());
        return crate::error::AppError::RateLimited {
            limit: rl.limit,
            reset_at: rl.reset_at,
            retry_after,
        }
        .into_response();
    }

    let not_found = || (StatusCode::NOT_FOUND, "unknown or expired token").into_response();

    // `claim` matches on hash and unexpired in one statement, so an expired row
    // is indistinguishable from a missing one from here.
    let row =
        match download_token::claim(state.db(&ext), &deferred_download::hash_token(&token)).await {
            Ok(Some(r)) => r,
            Ok(None) => return not_found(),
            Err(e) => {
                tracing::error!(error = %e, "download: token lookup failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "download failed").into_response();
            }
        };

    let scope = OrgScope::new(row.org_id, state.db_pool(&ext));

    // Re-check the identity still exists. The permission decision itself was
    // made and audited at mint time; this catches the case where the identity
    // was deleted or disabled in between, so outstanding tokens die with it
    // rather than outliving their principal.
    match scope.get_identity(row.identity_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "download: identity lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "download failed").into_response();
        }
    }

    // Two byte sources, exactly one per row (migration 111's CHECK). A stored
    // result is already in hand — no upstream, no credential to re-resolve.
    if let Some(call_result_id) = row.call_result_id {
        return serve_stored(&state, &ext, &scope, &row, ip, call_result_id).await;
    }

    let Some(raw_request) = row.request.clone() else {
        // Unreachable under the CHECK: a row with neither source cannot exist.
        tracing::error!(token_id = %row.id, "download: token names no byte source");
        return (StatusCode::INTERNAL_SERVER_ERROR, "download failed").into_response();
    };
    let request: ActionRequest = match serde_json::from_value(raw_request) {
        Ok(r) => r,
        Err(e) => {
            // Only reachable if a row was written by an incompatible build.
            tracing::error!(token_id = %row.id, error = %e, "download: stored request unreadable");
            return (StatusCode::INTERNAL_SERVER_ERROR, "download failed").into_response();
        }
    };

    let upstream = match deferred_download::open_upstream(
        &state,
        &scope,
        row.service_key.as_deref(),
        &request,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            log_download(&scope, &row, ip, Redeemed::Failed).await;
            return e.into_response();
        }
    };

    let status = upstream.status().as_u16();
    log_download(&scope, &row, ip, Redeemed::Upstream { status }).await;
    deferred_download::stream_through(
        upstream,
        std::time::Duration::from_millis(state.config.call_stream_idle_timeout_ms),
    )
}

/// Serve a stored call result: the bytes this token was minted from.
///
/// The mirror of the replay path above, minus everything that makes replay
/// expensive — no credential re-resolution, no upstream dial, no idle guard.
/// That absence is also why this path works for OAuth-authenticated services,
/// which `deliver: "url"` still refuses on a fresh call: there is no bearer to
/// re-mint when the answer is already on disk.
///
/// A missing or expired backing row returns the same bare 404 as an unknown
/// token. Distinguishing them would confirm to someone probing that a given
/// token was once real.
async fn serve_stored(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    row: &overslash_db::repos::download_token::DownloadTokenRow,
    ip: &str,
    call_result_id: uuid::Uuid,
) -> Response {
    let result = match crate::services::call_result::load(state, state.db(ext), call_result_id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "unknown or expired token").into_response(),
        Err(e) => {
            tracing::error!(token_id = %row.id, error = %e, "download: stored result unreadable");
            log_download(scope, row, ip, Redeemed::Failed).await;
            return (StatusCode::INTERNAL_SERVER_ERROR, "download failed").into_response();
        }
    };

    log_download(
        scope,
        row,
        ip,
        Redeemed::Stored {
            stored_status: result.status_code,
        },
    )
    .await;

    // The upstream status is *not* replayed onto this response. The stored body
    // may well be a 404 the agent asked to look at again; the fetch of it
    // succeeded, and a curl that saw 404 here would write nothing and report a
    // failure that did not happen. The status travels in the body, which is the
    // serialized ActionResult the caller already knows how to read.
    let mut builder = Response::builder().status(StatusCode::OK);
    for name in deferred_download::FORWARDED_HEADERS {
        // `content-length` is deliberately dropped: the stored body went
        // through `String::from_utf8_lossy` on the way in, so the upstream's
        // byte count can disagree with what we are about to write, and a
        // mismatched length is a framing error rather than a cosmetic one.
        // Everything else in the allowlist describes the payload, not its size.
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        if let Some((_, value)) = result
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
        {
            builder = builder.header(name, value);
        }
    }
    builder
        .body(axum::body::Body::from(result.body))
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "download: stored result response failed to build");
            (StatusCode::INTERNAL_SERVER_ERROR, "download failed").into_response()
        })
}

/// What a redemption actually did, so the audit row can describe *this fetch*
/// rather than smuggling two different meanings through one `status_code`.
///
/// The distinction is not cosmetic. On the replay path the client receives the
/// upstream's own status, so "the status" and "what the caller got" are the
/// same number. On the stored path they are not: the caller always gets 200
/// (the bytes were served), while the stored body may itself record a 404 the
/// agent asked to look at again. Logging the stored 404 as `status_code`
/// produced rows reading `status_code: 404, is_error: false` — contradictory
/// on their face, and misleading either way you resolve them. Two facts, two
/// fields.
enum Redeemed {
    /// Replayed upstream; `status` is what the caller received.
    Upstream { status: u16 },
    /// Served stored bytes. The caller received 200; `stored_status` is the
    /// status the *original* call recorded, which its own `action.executed`
    /// row already carries.
    Stored { stored_status: u16 },
    /// The redemption failed before any bytes could be chosen.
    Failed,
}

/// Audit the redemption. Sibling of `action.streamed`: like that row, the body
/// is never buffered so it cannot be captured, and like it the row exists so a
/// deferred fetch is not a hole in the trail between "agent asked for a file"
/// and "bytes left the building".
async fn log_download(
    scope: &OrgScope,
    row: &overslash_db::repos::download_token::DownloadTokenRow,
    ip: &str,
    outcome: Redeemed,
) {
    let (status, is_error, stored_status) = match outcome {
        Redeemed::Upstream { status } => (Some(status), status >= 400, None),
        Redeemed::Stored { stored_status } => (Some(200), false, Some(stored_status)),
        Redeemed::Failed => (None, true, None),
    };
    let _ = scope
        .clone()
        .log_audit(AuditEntry {
            org_id: row.org_id,
            identity_id: Some(row.identity_id),
            action: "action.downloaded",
            resource_type: row.service_key.as_deref(),
            resource_id: None,
            detail: serde_json::json!({
                "runtime": "download",
                "service": row.service_key,
                "action": row.action_key,
                "status_code": status,
                "is_error": is_error,
                // Only on the stored path, and deliberately a separate key:
                // it describes the call the bytes came from, not this fetch.
                "stored_status_code": stored_status,
                "mime": row.mime,
                "size_bytes": row.size_bytes,
                "filename": row.filename,
                // How many times this capability has been redeemed. A resumed
                // transfer legitimately bumps it; a number far past that is
                // the signal that the URL leaked.
                "use_count": row.use_count,
                "response": { "skipped": "streamed" },
            }),
            description: Some("Deferred download redeemed"),
            ip_address: Some(ip),
        })
        .await;
}
