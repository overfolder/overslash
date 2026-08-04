//! Deferred delivery (`deliver: "url"`) for `POST /v1/actions/call`.
//!
//! Split out of `call.rs` because it is one self-contained concern with two
//! shapes: an HTTP action *is* its own download, so the token captures the
//! request that was about to be made; an MCP tool merely returns a descriptor
//! *pointing at* the bytes, so the action's `x-overslash-download` block says
//! which field of that descriptor is the object.
//!
//! The transport-level machinery — minting, credential re-resolution, and the
//! shared streaming-response builder — lives in
//! [`crate::services::deferred_download`]. This module is only the call-path
//! glue: evaluate the declaration, decide what to hand back, audit it.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use overslash_core::types::ActionRequest;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::scopes::OrgScope;

use crate::{AppState, error::AppError};

use super::render_action_result;
use super::*;

/// Validate the request-level delivery flags, returning whether this call
/// defers.
///
/// Both rejections exist for the same reason the `filter` + `prefer_stream`
/// guard does: silently dropping one of a pair of contradictory instructions
/// is how a caller ends up with a multi-MB body it thought it had narrowed.
/// With `deliver: "url"` the body never passes through the gateway at call
/// time at all, so a filter has nothing to read; and `prefer_stream` says
/// "stream the bytes on this response" while `deliver` says "defer them to a
/// second request".
pub(super) fn validate_flags(req: &CallRequest) -> Result<bool, AppError> {
    let deliver_url = req.deliver.is_some_and(Delivery::is_url);
    if deliver_url && req.filter.is_some() {
        return Err(AppError::BadRequest(
            "filter cannot be combined with deliver: \"url\"".into(),
        ));
    }
    if deliver_url && req.prefer_stream.unwrap_or(false) {
        return Err(AppError::BadRequest(
            "prefer_stream cannot be combined with deliver: \"url\" — \
             prefer_stream streams the bytes inline on this response, \
             deliver: \"url\" defers them to a second request"
                .into(),
        ));
    }
    Ok(deliver_url)
}

/// Replace a tool result's body with a download descriptor, in place.
///
/// The tool already ran and returned a descriptor pointing at the bytes; this
/// swaps that pointer for a capability URL of ours. Callers gate on success —
/// a tool that errored has no object to point at, and minting from a failed
/// result would hand back a URL that 502s later instead of an error now.
#[allow(clippy::too_many_arguments)]
pub(super) async fn swap_in_mcp_download(
    state: &AppState,
    ext: &axum::http::Extensions,
    result: &mut overslash_core::types::ActionResult,
    org_id: uuid::Uuid,
    identity_id: uuid::Uuid,
    target: &McpTarget,
    meta: &ResolvedMeta,
    req: &CallRequest,
) -> Result<(), AppError> {
    let descriptor = mint_mcp_download(
        state,
        ext,
        org_id,
        identity_id,
        target,
        meta.download.as_ref(),
        result,
        req.service.as_deref(),
        req.action.as_deref(),
        std::time::Duration::from_millis(state.config.filter_timeout_ms),
    )
    .await?;
    result.body = serde_json::to_string(&descriptor).unwrap_or_default();
    result.filtered_body = None;
    Ok(())
}

/// Turn a completed MCP tool result into a capability URL.
///
/// The tool ran and handed back a descriptor — `{media_path, mime, size, …}`.
/// The action's `x-overslash-download` block says which of those fields is the
/// object; this evaluates those jq filters against the result envelope and
/// mints a token for the URL they name.
///
/// # Why the resolved URL must be same-origin
///
/// The minted token causes Overslash to later dial that URL *with the service
/// instance's credential attached*. The URL comes from the MCP server's own
/// response, so without a constraint a hostile or compromised server could name
/// any host — `http://169.254.169.254/…` — and have the gateway deliver the
/// instance's bearer to it. Requiring the object to live on the same origin
/// that served the tool call closes that off completely, and costs nothing:
/// "the bytes are on the host you just talked to" is the actual contract.
#[allow(clippy::too_many_arguments)]
async fn mint_mcp_download(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: uuid::Uuid,
    identity_id: uuid::Uuid,
    mcp_target: &McpTarget,
    spec: Option<&overslash_core::types::DownloadSpec>,
    result: &overslash_core::types::ActionResult,
    service_key: Option<&str>,
    action_key: Option<&str>,
    filter_timeout: std::time::Duration,
) -> Result<crate::services::deferred_download::Descriptor, AppError> {
    use overslash_core::types::{DisclosureField, DownloadAuth, McpAuth};

    let Some(spec) = spec else {
        return Err(AppError::BadRequest(format!(
            "action `{}` does not declare x-overslash-download, so deliver: \"url\" \
             has no object to point at; call it without `deliver` and read the result",
            action_key.unwrap_or("<unknown>")
        )));
    };

    // The MCP envelope, as jq sees it: {runtime, tool, structured, content,
    // is_error}. Same input shape the `disclose` filters address.
    let envelope: serde_json::Value =
        serde_json::from_str(&result.body).unwrap_or(serde_json::Value::Null);

    // Reuse the disclosure runner rather than a second jq harness: it already
    // owns the timeout, the input-size ceiling, and spawn_blocking. Labels are
    // the join key because it drops zero-yield filters, so positions shift.
    let mut fields = vec![DisclosureField {
        label: "url".into(),
        filter: spec.url.clone(),
        max_chars: None,
        primary: false,
    }];
    for (label, filter) in [
        ("mime", spec.mime.as_ref()),
        ("size", spec.size.as_ref()),
        ("filename", spec.filename.as_ref()),
    ] {
        if let Some(f) = filter {
            fields.push(DisclosureField {
                label: label.into(),
                filter: f.clone(),
                max_chars: None,
                primary: false,
            });
        }
    }

    let disclosed =
        crate::services::disclosure::run_disclosures(&fields, &envelope, filter_timeout)
            .await
            .map_err(|e| AppError::BadGateway(format!("download filters failed: {e}")))?;
    let pick = |label: &str| -> Option<String> {
        disclosed
            .iter()
            .find(|d| d.label == label)
            .and_then(|d| d.value.clone())
    };

    let Some(raw_url) = pick("url").filter(|s| !s.trim().is_empty()) else {
        return Err(AppError::BadGateway(format!(
            "tool `{}` returned no value for the declared download url filter (`{}`)",
            mcp_target.tool, spec.url
        )));
    };

    let url = resolve_download_url(&mcp_target.url, raw_url.trim())?;

    let secret_name = match (&mcp_target.auth, spec.auth) {
        (_, DownloadAuth::None) => None,
        (McpAuth::Bearer { secret_name }, DownloadAuth::Inherit) => secret_name.as_deref(),
        (McpAuth::None, DownloadAuth::Inherit) => None,
        (McpAuth::OAuth { .. }, DownloadAuth::Inherit) => {
            // An OAuth bearer is minted live from the caller's connection and
            // is deliberately not persistable (`AuthHeader` has no Serialize).
            // Re-minting it at fetch time is real work — connection lookup,
            // refresh, scope check — and nothing shipped needs it yet.
            return Err(AppError::BadRequest(
                "deliver: \"url\" is not supported for OAuth-authenticated MCP services yet; \
                 the deferred fetch cannot re-mint an OAuth bearer"
                    .into(),
            ));
        }
    };

    let size_bytes = pick("size").and_then(|s| s.trim().parse::<i64>().ok());

    crate::services::deferred_download::mint(
        state,
        ext,
        crate::services::deferred_download::Mint {
            org_id,
            identity_id,
            // MCP resolution doesn't thread the instance id through
            // `ResolvedMeta` (it's an HTTP-replay concern), and the token
            // doesn't need it — `request` already names everything the fetch
            // re-resolves.
            service_instance_id: None,
            service_key,
            action_key,
            request: crate::services::deferred_download::bearer_request(url, secret_name),
            mime: pick("mime"),
            size_bytes,
            filename: pick("filename"),
        },
    )
    .await
}

/// Resolve a download location from a tool result against the MCP server's own
/// URL, rejecting anything that would send the credential elsewhere.
///
/// Accepts a path (`/media/abc`) or an absolute URL on the same origin.
/// Everything else — a different host, a different scheme, a non-URL — is an
/// error rather than a best-effort fetch.
fn resolve_download_url(mcp_url: &str, raw: &str) -> Result<String, AppError> {
    let base = url::Url::parse(mcp_url)
        .map_err(|e| AppError::Internal(format!("mcp instance url is not a url: {e}")))?;

    let joined = base.join(raw).map_err(|e| {
        AppError::BadGateway(format!("download url `{raw}` is not resolvable: {e}"))
    })?;

    let same_origin = joined.scheme() == base.scheme()
        && joined.host_str() == base.host_str()
        && joined.port_or_known_default() == base.port_or_known_default();
    if !same_origin {
        return Err(AppError::BadGateway(format!(
            "download url `{raw}` points outside the MCP server's origin ({}); \
             refusing to send this service's credential to another host",
            base.origin().ascii_serialization()
        )));
    }
    Ok(joined.to_string())
}

/// The call-handler context an HTTP-runtime mint reads from.
///
/// Borrows the resolved objects rather than exploding them into scalars: the
/// scalar form was ten parameters, four of them adjacent `Option<&str>`s that
/// would swap silently at the call site with no type error to catch it.
pub(super) struct HttpDeferred<'a> {
    pub(super) auth: &'a AuthContext,
    pub(super) req: &'a CallRequest,
    pub(super) meta: &'a ResolvedMeta,
    pub(super) identity_id: uuid::Uuid,
    pub(super) ip: Option<&'a str>,
    pub(super) tags: &'a [String],
}

/// Mint a capability URL for an HTTP-runtime action instead of calling it.
///
/// Unlike the MCP fork, nothing is called here: an HTTP action that returns
/// bytes *is* the download, so the token simply captures the request we were
/// about to make and it gets replayed at fetch time. Minting before secret
/// resolution is deliberate — `action_req` is credential-free by construction,
/// so there is no window where a live value could be written into the row.
pub(super) async fn mint_http_download(
    state: &AppState,
    ext: &axum::http::Extensions,
    scope: &OrgScope,
    action_req: &ActionRequest,
    d: HttpDeferred<'_>,
) -> Result<Response, AppError> {
    // `oauth_injected`, not `auth_header.is_some()`: a template declaring a
    // query-param token injection resolves OAuth successfully but builds no
    // header, so the header check reads as "no credential" and would mint a
    // token the fetch cannot authenticate — a URL that 401s later instead of
    // an error now.
    if d.meta.oauth_injected {
        // OAuth credentials are minted live per call and `AuthHeader` has no
        // `Serialize` precisely so they can't be persisted. Re-minting at
        // fetch time is real work nothing shipped needs yet.
        return Err(AppError::BadRequest(
            "deliver: \"url\" is not supported for OAuth-authenticated services yet; \
             the deferred fetch cannot re-mint an OAuth token"
                .into(),
        ));
    }

    // Raw HTTP is the one shape whose `headers` come straight from the
    // caller, so it's the one shape that could smuggle a plaintext
    // credential into the persisted request.
    crate::services::deferred_download::reject_inline_credentials(action_req)?;

    let descriptor = crate::services::deferred_download::mint(
        state,
        ext,
        crate::services::deferred_download::Mint {
            org_id: d.auth.org_id,
            identity_id: d.identity_id,
            service_instance_id: d.meta.instance_id,
            service_key: d.req.service.as_deref(),
            action_key: d.req.action.as_deref(),
            request: action_req.clone(),
            // Nothing has been fetched yet, so there is no upstream
            // content-type or length to report. The caller learns them
            // from the fetch response headers.
            mime: None,
            size_bytes: None,
            filename: None,
        },
    )
    .await?;

    // No upstream call happened, so there is no `action.executed` row.
    // Record the mint instead — otherwise a deferred call would leave no
    // trace at all between "agent asked" and a later `action.downloaded`.
    let _ = scope
        .clone()
        .log_audit_tagged(
            AuditEntry {
                org_id: d.auth.org_id,
                identity_id: Some(d.identity_id),
                action: "action.deferred",
                resource_type: d.req.service.as_deref(),
                resource_id: None,
                detail: serde_json::json!({
                    "runtime": "http",
                    "method": action_req.method,
                    "url": action_req.url,
                    "service": d.req.service,
                    "action": d.req.action,
                    "expires_at": descriptor.expires_at,
                }),
                description: d.meta.description.as_deref(),
                ip_address: d.ip,
            },
            &tags::with_outcome(d.tags.to_vec(), false),
        )
        .await;

    let result = overslash_core::types::ActionResult {
        status_code: 200,
        headers: std::collections::HashMap::new(),
        body: serde_json::to_string(&descriptor).unwrap_or_default(),
        duration_ms: 0,
        filtered_body: None,
    };
    Ok((
        StatusCode::OK,
        Json(CallResponse::Called {
            result: render_action_result(&result, d.req.verbose),
            action_description: d.meta.description.clone(),
            is_error: false,
        }),
    )
        .into_response())
}

#[cfg(test)]
mod download_url_tests {
    use super::resolve_download_url;

    const MCP: &str = "https://wa.example.com:8443/mcp";

    /// The shape the shipped WhatsApp template uses: the tool hands back a
    /// path, which resolves against the server that served the tool call.
    #[test]
    fn a_relative_path_resolves_against_the_mcp_server() {
        let out = resolve_download_url(MCP, "/media/abc123").unwrap();
        assert_eq!(out, "https://wa.example.com:8443/media/abc123");
    }

    #[test]
    fn an_absolute_same_origin_url_is_accepted_verbatim() {
        let out =
            resolve_download_url(MCP, "https://wa.example.com:8443/media/abc123?x=1").unwrap();
        assert_eq!(out, "https://wa.example.com:8443/media/abc123?x=1");
    }

    /// The control that matters. The URL comes from the MCP server's own
    /// response and the deferred fetch attaches that instance's credential —
    /// so a hostile or compromised server naming another host must not be able
    /// to have the gateway deliver the bearer to it.
    #[test]
    fn a_different_host_is_refused() {
        let err = resolve_download_url(MCP, "http://169.254.169.254/latest/meta-data/")
            .expect_err("off-origin must be refused");
        assert!(
            format!("{err:?}").contains("outside the MCP server's origin"),
            "{err:?}"
        );
    }

    #[test]
    fn a_different_scheme_on_the_same_host_is_refused() {
        // Downgrading https→http on the same host would put the credential on
        // the wire in plaintext, so origin comparison includes the scheme.
        resolve_download_url(MCP, "http://wa.example.com:8443/media/abc")
            .expect_err("scheme change must be refused");
    }

    #[test]
    fn a_different_port_on_the_same_host_is_refused() {
        resolve_download_url(MCP, "https://wa.example.com:9999/media/abc")
            .expect_err("port change must be refused");
    }

    /// Default ports compare equal to their explicit form — otherwise a server
    /// configured as `https://host/mcp` returning `https://host:443/…` would
    /// be rejected for no reason.
    #[test]
    fn an_implicit_default_port_matches_its_explicit_form() {
        resolve_download_url(
            "https://wa.example.com/mcp",
            "https://wa.example.com:443/media/abc",
        )
        .expect("443 is https's default port");
    }

    #[test]
    fn a_protocol_relative_url_cannot_smuggle_a_new_host() {
        // `//evil.com/x` inherits the scheme but not the host — the classic
        // way past a naive "starts with http" check.
        resolve_download_url(MCP, "//evil.com/media/abc")
            .expect_err("protocol-relative host swap must be refused");
    }

    /// The guarantee is "never leaves the origin", not "rejects anything odd".
    /// A non-URL string joins as a relative path and stays on the MCP host, so
    /// the worst case is a 404 upstream — and the control characters that could
    /// otherwise smuggle a second request get percent-encoded on the way.
    #[test]
    fn a_non_url_string_stays_on_the_origin_and_is_escaped() {
        let out = resolve_download_url(MCP, "not a url at all\n").unwrap();
        assert!(out.starts_with("https://wa.example.com:8443/"), "{out}");
        assert!(!out.contains('\n') && !out.contains(' '), "{out}");
    }
}
