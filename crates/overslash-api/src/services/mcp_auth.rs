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
            let value = fetch_secret(state, scope, secret_name).await?;
            let header_value = HeaderValue::from_str(&format!("Bearer {value}")).map_err(|_| {
                AppError::BadRequest(format!(
                    "secret `{secret_name}` contains characters not allowed in an HTTP header"
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
