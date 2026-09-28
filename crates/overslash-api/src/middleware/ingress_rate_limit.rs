//! Throttles for the MCP transport and the OAuth handshake around it — the
//! subrouter `lib.rs` mounts outside the `/v1` rate-limit layer, because most
//! of it is reached before the caller holds any credential at all.
//!
//! * `/oauth/*` and `/.well-known/oauth-*` — per client IP ([`ClientIp`],
//!   which honours the trusted-proxy configuration, so the key is the real
//!   client and not whatever the caller wrote in `X-Forwarded-For`).
//! * `POST /oauth/register` — additionally a much smaller per-IP cap. Dynamic
//!   Client Registration is unauthenticated and every success writes a row.
//! * `/mcp` — per MCP client when the request carries a valid MCP token (per
//!   identity for an `osk_` key or a dashboard session); per IP, on the
//!   handshake bucket, when it carries nothing usable.
//!
//! The tool calls an MCP client makes are *also* metered against its owner's
//! user budget, by `middleware::rate_limit` on the loopback `/v1` request
//! `routes::mcp::forward` issues. The `/mcp` bucket is a transport ceiling on
//! top of that — it is what bounds `tools/list`, `ping` and the other methods
//! that never reach `/v1`.

use axum::http::{Extensions, HeaderMap, Method};
use axum::{extract::State, http::Request, middleware::Next, response::Response};

use crate::AppState;
use crate::extractors::ClientIp;
use crate::middleware::rate_limit::{
    osk_prefix, resolve_identity, verify_mcp_bearer, verify_session_cookie,
};
use crate::services::rate_limit::{RateLimitConfig, too_many_requests};

pub async fn ingress_rate_limit_middleware(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let limits = &state.config.ingress_rate_limits;
    let ext = request.extensions();

    let mut checks: Vec<(&'static str, String, RateLimitConfig)> = Vec::with_capacity(2);
    if request.uri().path() == "/mcp" {
        if let Some(key) = mcp_client_key(&state, request.headers(), ext).await {
            if let Some(cfg) = limits.mcp_client {
                checks.push(("mcp_client", key, cfg));
            }
        } else if let Some(cfg) = limits.oauth_ip {
            checks.push(("oauth_ip", ip_key("oauth", &state, &request), cfg));
        }
    } else {
        // DCR first: it is the tighter cap, and a registration it refuses
        // should not also spend the handshake budget the rest of the flow needs.
        if request.method() == Method::POST
            && request.uri().path() == "/oauth/register"
            && let Some(cfg) = limits.oauth_register_ip
        {
            checks.push(("oauth_register_ip", ip_key("dcr", &state, &request), cfg));
        }
        if let Some(cfg) = limits.oauth_ip {
            checks.push(("oauth_ip", ip_key("oauth", &state, &request), cfg));
        }
    }

    for (scope, key, cfg) in checks {
        let result = state
            .rate_limiter(ext)
            .check_and_increment(&key, cfg.max_requests, cfg.window_seconds)
            .await;
        if !result.allowed {
            overslash_metrics::rate_limit::record_decision(scope, "deny");
            return too_many_requests(&result);
        }
        overslash_metrics::rate_limit::record_decision(scope, "allow");
    }

    next.run(request).await
}

fn ip_key(bucket: &str, state: &AppState, request: &Request<axum::body::Body>) -> String {
    // Same "unknown" fallback as the other per-IP throttles
    // (`routes::downloads`): no socket peer only happens off the real
    // listener, and one shared bucket is the safe failure.
    let ip = ClientIp::resolve_from(request.headers(), request.extensions(), state).0;
    format!("rl:ip:{bucket}:{}", ip.as_deref().unwrap_or("unknown"))
}

/// The bucket for an authenticated `/mcp` caller: its MCP client when the
/// token names one, otherwise the identity — including a dashboard session,
/// which `/mcp` also accepts. Same precedence as `AuthContext`: cookie, then
/// bearer. `None` when the request carries no credential we can attribute —
/// it is then an anonymous handshake probe.
async fn mcp_client_key(state: &AppState, headers: &HeaderMap, ext: &Extensions) -> Option<String> {
    if let Some(claims) = verify_session_cookie(state, headers) {
        return Some(format!("rl:{}:mcp:id:{}", claims.org, claims.sub));
    }
    if let Some(claims) = verify_mcp_bearer(state, headers) {
        return Some(match claims.mcp_client_id {
            Some(client) => format!("rl:{}:mcp:client:{client}", claims.org),
            None => format!("rl:{}:mcp:id:{}", claims.org, claims.sub),
        });
    }
    let prefix = osk_prefix(headers)?;
    let (org_id, identity_id, _) = resolve_identity(state, ext, &prefix).await?;
    Some(format!("rl:{org_id}:mcp:id:{}", identity_id?))
}
