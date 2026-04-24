//! Resolves a per-request org from the `Host` header. Runs before auth so
//! extractors can cross-check the JWT's `org` claim against the subdomain
//! the browser actually hit.
//!
//! Behavior:
//! - `SINGLE_ORG_MODE=<slug>` set → always `Org { <that-slug> }`, regardless
//!   of host. Self-hosted single-org deployments.
//! - `APP_HOST_SUFFIX=app.example.com` set, request host = `acme.app.example.com`
//!   → look up `orgs` by slug, reject personal orgs (404 `personal_org_unreachable`),
//!   attach `Org { org_id, slug }`.
//! - Same apex as a bare host (no subdomain, or `www.`) → `Root`.
//! - Apex not set → `Root` always (no wildcard routing to do).
//! - Unknown subdomain → 404 `org_not_found`.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::AppState;

/// Attached to every request by `subdomain_middleware`. Downstream extractors
/// pick this up to decide whether to enforce a subdomain↔JWT match.
#[derive(Debug, Clone)]
pub enum RequestOrgContext {
    /// Request hit the root apex (`app.overslash.com`) or subdomain routing
    /// is disabled. The JWT's `org` claim, if any, is authoritative.
    Root,
    /// Request hit `<slug>.<apex>`. Any session must already be scoped to
    /// this org (or get re-minted via `/auth/switch-org`).
    Org { org_id: uuid::Uuid, slug: String },
}

pub async fn subdomain_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let ctx = match resolve_context(&state, request.headers()).await {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };
    request.extensions_mut().insert(ctx);
    next.run(request).await
}

async fn resolve_context(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<RequestOrgContext, Response> {
    // Single-org override takes precedence — every request is scoped to the
    // named slug and subdomain parsing is skipped entirely.
    if let Some(slug) = state.config.single_org_mode.as_deref() {
        return resolve_by_slug(state, slug).await;
    }

    let Some(apex) = state.config.app_host_suffix.as_deref() else {
        return Ok(RequestOrgContext::Root);
    };

    let Some(host) = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
    else {
        return Ok(RequestOrgContext::Root);
    };
    // Strip port + lowercase for case-insensitive comparison.
    let host = host.split(':').next().unwrap_or(host).to_ascii_lowercase();
    let apex = apex.to_ascii_lowercase();

    // Exact apex, or the `www.` convenience form → Root.
    if host == apex || host == format!("www.{apex}") {
        return Ok(RequestOrgContext::Root);
    }

    // `<slug>.<apex>` → look up the slug.
    let Some(slug) = host.strip_suffix(&format!(".{apex}")) else {
        // Host isn't under the configured apex at all — treat as Root so
        // local dev + health probes keep working. Production traffic is
        // steered to the apex by DNS.
        return Ok(RequestOrgContext::Root);
    };
    // Disallow dotted sub-sub-domains (e.g. `foo.bar.app.example.com`) —
    // slugs are single DNS labels. Forbid rather than silently coerce.
    if slug.contains('.') || slug.is_empty() {
        return Err(json_response(
            StatusCode::NOT_FOUND,
            "org_not_found",
            "Unknown subdomain.",
        ));
    }
    resolve_by_slug(state, slug).await
}

async fn resolve_by_slug(state: &AppState, slug: &str) -> Result<RequestOrgContext, Response> {
    match overslash_db::repos::org::get_by_slug(&state.db, slug).await {
        Ok(Some(row)) if row.is_personal => Err(json_response(
            StatusCode::NOT_FOUND,
            "personal_org_unreachable",
            "Personal orgs live on the root domain.",
        )),
        Ok(Some(row)) => Ok(RequestOrgContext::Org {
            org_id: row.id,
            slug: row.slug,
        }),
        Ok(None) => Err(json_response(
            StatusCode::NOT_FOUND,
            "org_not_found",
            "No org with that subdomain slug.",
        )),
        Err(e) => Err(json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "org_lookup_failed",
            &format!("{e}"),
        )),
    }
}

fn json_response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        axum::Json(json!({ "error": code, "message": message })),
    )
        .into_response()
}
