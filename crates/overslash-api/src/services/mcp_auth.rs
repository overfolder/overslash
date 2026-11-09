//! Resolve `McpAuth` into the HTTP headers Overslash sends to the external
//! MCP server. Secret lookup goes through the same namespaced vault that
//! HTTP-runtime auth uses (`scope.get_current_secret_value` + AES-GCM).
//!
//! `Bearer` may carry a second, deployment-level gateway key in its own
//! header (`McpGateway`, hosted-runtimes.md Phase 0). Future `Header` /
//! `Headers` variants will extend this file — the router is a `match` on the
//! `McpAuth` enum and is intentionally exhaustive so the compiler flags
//! new variants as they're added.

use overslash_core::crypto;
use overslash_core::types::{McpAuth, McpGateway, ParsedBinding, SecretNamespace, SecretPath};
use overslash_db::scopes::OrgScope;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};

use crate::AppState;
use crate::error::AppError;

/// Translate an `McpAuth` into the HeaderMap to attach to every outbound
/// MCP JSON-RPC request. Empty headers for `McpAuth::None`; populated from
/// the org secret vault for `McpAuth::Bearer`.
///
/// `url` is the request's destination *before* any test-only base override:
/// a platform credential (D39) is only ever released to the host it is pinned
/// to, and this is where that is re-checked for every send — an approval
/// resolved against the platform gateway and replayed after the instance was
/// repointed cannot carry the key out.
pub async fn resolve_headers(
    state: &AppState,
    scope: &OrgScope,
    auth: &McpAuth,
    url: &str,
) -> Result<HeaderMap, AppError> {
    let mut headers = HeaderMap::new();
    match auth {
        McpAuth::None => {}
        // OAuth tokens are resolved earlier (in the action resolver, which has
        // the caller's owner identity + connection context) and injected
        // out-of-band via `McpTarget.auth_header`. Nothing to add from the
        // vault here — return empty and let the caller merge the bearer.
        McpAuth::OAuth { .. } => {}
        McpAuth::Bearer {
            secret_name,
            gateway,
            ..
        } => {
            // secret_name must be resolved to Some before invocation; None here
            // is an internal bug (resolution should have caught it in actions.rs).
            let name = secret_name.as_deref().ok_or_else(|| {
                AppError::Internal("mcp bearer secret_name not resolved before invocation".into())
            })?;
            let value = fetch_secret(state, scope, name).await?;
            let header_value = HeaderValue::from_str(&format!("Bearer {value}")).map_err(|_| {
                AppError::BadRequest(format!(
                    "secret `{name}` contains characters not allowed in an HTTP header"
                ))
            })?;
            headers.insert(AUTHORIZATION, header_value);
            if let Some(gw) = gateway
                && let Some(key) = gateway_value(state, scope, gw, url).await?
            {
                let name = HeaderName::from_bytes(gw.header.as_bytes()).map_err(|_| {
                    AppError::Internal(format!("invalid MCP gateway header name `{}`", gw.header))
                })?;
                let value = HeaderValue::from_str(&key).map_err(|_| {
                    AppError::BadRequest(format!(
                        "the gateway key for `{}` contains characters not allowed in an HTTP header",
                        gw.header
                    ))
                })?;
                headers.insert(name, value);
            }
        }
    }
    Ok(headers)
}

/// The gateway key for a *resolved* [`McpGateway`] (see
/// `mcp_resolve::resolve_mcp_gateway`): its qualified path from the vault,
/// else — for an org path only — the platform credential pinned to `url`'s
/// host. `Ok(None)` when an optional key has gone missing since resolution.
async fn gateway_value(
    state: &AppState,
    scope: &OrgScope,
    gw: &McpGateway,
    url: &str,
) -> Result<Option<String>, AppError> {
    let ParsedBinding::Qualified(path) = SecretPath::parse(&gw.default_secret_name) else {
        return Err(AppError::Internal(format!(
            "mcp gateway secret `{}` was not qualified before invocation",
            gw.default_secret_name
        )));
    };
    if !gw.platform_only
        && let Some(version) = scope.get_current_secret_value(&path).await?
    {
        let key = state.config.keyring()?;
        let decrypted = crypto::decrypt(&key, &version.encrypted_value)?;
        return String::from_utf8(decrypted)
            .map(Some)
            .map_err(|_| AppError::Internal("mcp gateway secret is not valid utf-8".into()));
    }
    // The platform stands in for an org default, never for a user's own
    // secret — same rule as the HTTP path (`action_caller`).
    if path.ns == SecretNamespace::Org
        && let Some(v) = state.config.platform_credential_for(&path.name, url)
    {
        return Ok(Some(v.to_string()));
    }
    if gw.optional {
        return Ok(None);
    }
    Err(AppError::CredentialMissing {
        service: None,
        secret_name: path.name.clone(),
        hint_url: Some(state.config.dashboard_url_for(&format!(
            "/secrets?name={}",
            urlencoding::encode(&path.name)
        ))),
    })
}

/// `name` is the secret path `resolve_effective_mcp` qualified under the
/// instance read rule; anything unqualified here is an internal bug.
async fn fetch_secret(state: &AppState, scope: &OrgScope, name: &str) -> Result<String, AppError> {
    let ParsedBinding::Qualified(path) = SecretPath::parse(name) else {
        return Err(AppError::Internal(format!(
            "mcp bearer secret `{name}` was not qualified before invocation"
        )));
    };
    let version = scope
        .get_current_secret_value(&path)
        .await?
        .ok_or_else(|| AppError::BadRequest(format!("secret `{}` not found", path.name)))?;
    let key = state.config.keyring()?;
    let decrypted = crypto::decrypt(&key, &version.encrypted_value)?;
    String::from_utf8(decrypted)
        .map_err(|_| AppError::Internal("mcp secret is not valid utf-8".into()))
}

#[cfg(test)]
mod tests {
    use reqwest::header::{AUTHORIZATION, HeaderValue};

    /// Bearer values that contain invalid header chars (control bytes, newlines)
    /// must be rejected at the HeaderValue boundary — otherwise they'd either
    /// panic or silently corrupt the outbound request.
    #[test]
    fn bearer_with_control_char_is_rejected_by_headervalue() {
        let bad = "Bearer abc\ndef";
        assert!(HeaderValue::from_str(bad).is_err());
    }

    #[test]
    fn bearer_with_plain_ascii_is_accepted() {
        let ok = HeaderValue::from_str("Bearer abcdef123").expect("valid header value");
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(AUTHORIZATION, ok);
        assert_eq!(h.get(AUTHORIZATION).unwrap(), "Bearer abcdef123");
    }
}
