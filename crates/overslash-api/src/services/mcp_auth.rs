//! Resolve `McpAuth` into the HTTP headers Overslash sends to the external
//! MCP server. Secret lookup goes through the same org vault that
//! HTTP-runtime auth uses (`scope.get_current_secret_value` + AES-GCM).
//!
//! v1 supports only `None` and `Bearer`. Future `Header` / `Headers` /
//! `Oauth` variants will extend this file — the router is a `match` on the
//! `McpAuth` enum and is intentionally exhaustive so the compiler flags
//! new variants as they're added.

use overslash_core::crypto;
use overslash_core::types::McpAuth;
use overslash_db::scopes::OrgScope;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use crate::AppState;
use crate::error::AppError;

/// Translate an `McpAuth` into the HeaderMap to attach to every outbound
/// MCP JSON-RPC request. Empty headers for `McpAuth::None`; populated from
/// the org secret vault for `McpAuth::Bearer`.
pub async fn resolve_headers(
    state: &AppState,
    scope: &OrgScope,
    auth: &McpAuth,
) -> Result<HeaderMap, AppError> {
    let mut headers = HeaderMap::new();
    match auth {
        McpAuth::None => {}
        McpAuth::Bearer { secret_name } => {
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
        }
    }
    Ok(headers)
}

async fn fetch_secret(state: &AppState, scope: &OrgScope, name: &str) -> Result<String, AppError> {
    let version = scope
        .get_current_secret_value(name)
        .await?
        .ok_or_else(|| AppError::BadRequest(format!("secret `{name}` not found")))?;
    let key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
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
