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

    let request: ActionRequest = match serde_json::from_value(row.request.clone()) {
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
            log_download(&scope, &row, ip, None, true).await;
            return e.into_response();
        }
    };

    let status = upstream.status().as_u16();
    log_download(&scope, &row, ip, Some(status), status >= 400).await;
    deferred_download::stream_through(
        upstream,
        std::time::Duration::from_millis(state.config.call_stream_idle_timeout_ms),
    )
}

/// Audit the redemption. Sibling of `action.streamed`: like that row, the body
/// is never buffered so it cannot be captured, and like it the row exists so a
/// deferred fetch is not a hole in the trail between "agent asked for a file"
/// and "bytes left the building".
async fn log_download(
    scope: &OrgScope,
    row: &overslash_db::repos::download_token::DownloadTokenRow,
    ip: &str,
    status: Option<u16>,
    is_error: bool,
) {
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
