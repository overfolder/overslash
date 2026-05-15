//! Resolves a per-request org from the request host. Runs before auth so
//! extractors can cross-check the JWT's `org` claim against the subdomain
//! the browser/agent actually hit.
//!
//! Two suffixes are accepted: `APP_HOST_SUFFIX` (browser dashboard,
//! e.g. `app.overslash.com`) and `API_HOST_SUFFIX` (programmatic /
//! MCP / OAuth-AS surface, e.g. `api.overslash.com`). Slugs resolve the
//! same way under either; only the issuer URL builder cares about the
//! distinction.
//!
//! Behavior:
//! - `SINGLE_ORG_MODE=<slug>` set → always `Org { <that-slug> }`, regardless
//!   of host. Self-hosted single-org deployments.
//! - `<APP_HOST_SUFFIX>` or `<API_HOST_SUFFIX>` set, request host =
//!   `<slug>.<one-of-them>` → look up `orgs` by slug, reject personal orgs
//!   (404 `personal_org_unreachable`), attach `Org { org_id, slug }`.
//! - Same apex as a bare host (no subdomain, or `www.`) → `Root`.
//! - Neither apex set → `Root` always (no wildcard routing to do).
//! - Unknown subdomain → 404 `org_not_found`.
//!
//! The effective host is read from `X-Forwarded-Host` first when present
//! and trustworthy (Cloud Run / GCLB / Vercel set it), falling back to
//! `Host`. Cloud Run forwards the original `Host` unchanged from GCLB,
//! so this is mostly defensive — but we want one code path so future
//! proxies don't introduce a host-trust mismatch.

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

    let app_apex = state.config.app_host_suffix.as_deref();
    let api_apex = state.config.api_host_suffix.as_deref();
    if app_apex.is_none() && api_apex.is_none() {
        return Ok(RequestOrgContext::Root);
    }

    let Some(host) = effective_host(headers) else {
        return Ok(RequestOrgContext::Root);
    };

    // Try each configured apex in turn. First match wins; the two surfaces
    // resolve slugs identically.
    for apex in [app_apex, api_apex].into_iter().flatten() {
        let apex = apex.to_ascii_lowercase();
        match match_against_apex(&host, &apex) {
            ApexMatch::Root => return Ok(RequestOrgContext::Root),
            ApexMatch::Slug(slug) => return resolve_by_slug(state, &slug).await,
            ApexMatch::Invalid => {
                return Err(json_response(
                    StatusCode::NOT_FOUND,
                    "org_not_found",
                    "Unknown subdomain.",
                ));
            }
            ApexMatch::Miss => {}
        }
    }

    // Host isn't under any configured apex — treat as Root so local dev
    // + health probes keep working. Production traffic is steered to the
    // apex by DNS.
    Ok(RequestOrgContext::Root)
}

enum ApexMatch {
    /// Host matched the apex itself (or `www.<apex>`).
    Root,
    /// Host matched `<slug>.<apex>`.
    Slug(String),
    /// Host matched `<something>.<apex>` but the something isn't a valid
    /// slug (e.g. dotted sub-sub-domain). Reject closed.
    Invalid,
    /// Host doesn't end in `.<apex>` at all.
    Miss,
}

fn match_against_apex(host: &str, apex: &str) -> ApexMatch {
    if host == apex || host == format!("www.{apex}") {
        return ApexMatch::Root;
    }
    let Some(slug) = host.strip_suffix(&format!(".{apex}")) else {
        return ApexMatch::Miss;
    };
    if slug.contains('.') || slug.is_empty() {
        return ApexMatch::Invalid;
    }
    ApexMatch::Slug(slug.to_string())
}

/// Resolve the effective host to dispatch on. Prefer `X-Forwarded-Host`
/// (the original Host before our edge proxy forwarded the request),
/// fall back to `Host`. Strip port and lowercase for comparison.
///
/// Public so the OAuth-AS metadata endpoints and the MCP `WWW-Authenticate`
/// challenge can build issuer URLs that reflect the host the client
/// connected to (otherwise discovery returns the apex `public_url` and
/// org-subdomain MCP clients fail to validate the issuer).
pub fn effective_host(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        // `X-Forwarded-Host` may carry a comma-separated chain when multiple
        // proxies sit in front of us (e.g. Cloudflare → Vercel → us). The
        // left-most value is the original client-supplied host.
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get(axum::http::header::HOST)
                .and_then(|v| v.to_str().ok())
        })?;
    Some(raw.split(':').next().unwrap_or(raw).to_ascii_lowercase())
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, v.parse().unwrap());
        }
        h
    }

    #[test]
    fn effective_host_prefers_xfh_over_host() {
        // GCLB / Vercel sets X-Forwarded-Host with the original; an internal
        // proxy may rewrite Host to its own. We dispatch on the original.
        let h = headers(&[
            ("x-forwarded-host", "acme.api.overslash.com"),
            ("host", "internal-loopback:8080"),
        ]);
        assert_eq!(
            effective_host(&h),
            Some("acme.api.overslash.com".to_string())
        );
    }

    #[test]
    fn effective_host_strips_port_and_lowercases() {
        let h = headers(&[("host", "ACME.api.overslash.com:443")]);
        assert_eq!(
            effective_host(&h),
            Some("acme.api.overslash.com".to_string())
        );
    }

    #[test]
    fn effective_host_picks_leftmost_xfh_when_chained() {
        // `X-Forwarded-Host: original, hop1, hop2` — the original is left-most.
        let h = headers(&[(
            "x-forwarded-host",
            "acme.api.overslash.com, lb.example, internal",
        )]);
        assert_eq!(
            effective_host(&h),
            Some("acme.api.overslash.com".to_string())
        );
    }

    #[test]
    fn match_against_apex_root_and_www() {
        assert!(matches!(
            match_against_apex("api.overslash.com", "api.overslash.com"),
            ApexMatch::Root
        ));
        assert!(matches!(
            match_against_apex("www.api.overslash.com", "api.overslash.com"),
            ApexMatch::Root
        ));
    }

    #[test]
    fn match_against_apex_slug() {
        match match_against_apex("acme.api.overslash.com", "api.overslash.com") {
            ApexMatch::Slug(s) => assert_eq!(s, "acme"),
            other => panic!("expected Slug(\"acme\"), got {other:?}"),
        }
    }

    #[test]
    fn match_against_apex_rejects_dotted_subsubdomain() {
        // `foo.bar.api.overslash.com` — slug would be "foo.bar", not a single
        // DNS label. Reject closed rather than silently coerce.
        assert!(matches!(
            match_against_apex("foo.bar.api.overslash.com", "api.overslash.com"),
            ApexMatch::Invalid
        ));
    }

    #[test]
    fn match_against_apex_miss_when_under_different_apex() {
        // `acme.app.overslash.com` is not under `api.overslash.com`.
        assert!(matches!(
            match_against_apex("acme.app.overslash.com", "api.overslash.com"),
            ApexMatch::Miss
        ));
    }

    impl std::fmt::Debug for ApexMatch {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ApexMatch::Root => write!(f, "Root"),
                ApexMatch::Slug(s) => write!(f, "Slug({s:?})"),
                ApexMatch::Invalid => write!(f, "Invalid"),
                ApexMatch::Miss => write!(f, "Miss"),
            }
        }
    }
}
