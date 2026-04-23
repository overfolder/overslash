//! Resolve `McpEnvBinding` entries on a service template into the env map
//! we send to the MCP runtime. Each binding is either:
//!
//! - `Secret`      — look up a versioned org secret, decrypt, pass plaintext.
//! - `OauthToken`  — pick a connection for the provider and resolve (refresh
//!   if needed) the access token.
//! - `Literal`     — non-sensitive value baked into the template.
//!
//! A deterministic SHA-256 of the resulting env map is returned alongside,
//! so the runtime can detect env rotation (e.g. OAuth refresh) and restart
//! the subprocess before the next `/invoke`.

use std::collections::{BTreeMap, HashMap};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use overslash_core::crypto;
use overslash_core::types::{McpEnvBinding, McpSpec};
use overslash_db::scopes::{OrgScope, UserScope};

use crate::AppState;
use crate::error::AppError;

/// Resolve all env bindings declared on `mcp.env` against this identity's
/// secrets + OAuth connections. Returns the env map plus its SHA-256 hash.
pub async fn resolve_env(
    state: &AppState,
    scope: &OrgScope,
    identity_id: Uuid,
    org_id: Uuid,
    mcp: &McpSpec,
) -> Result<(HashMap<String, String>, String), AppError> {
    let enc_key = crypto::parse_hex_key(&state.config.secrets_encryption_key)?;
    let mut env: HashMap<String, String> = HashMap::with_capacity(mcp.env.len());

    for (var_name, binding) in &mcp.env {
        let value = match binding {
            McpEnvBinding::Secret {
                default_secret_name,
            } => {
                let secret_name = default_secret_name
                    .clone()
                    .unwrap_or_else(|| var_name.clone());
                let version = scope
                    .get_current_secret_value(&secret_name)
                    .await?
                    .ok_or_else(|| {
                        AppError::BadRequest(format!(
                            "MCP env var '{var_name}' requires secret '{secret_name}' which is not set"
                        ))
                    })?;
                let bytes = crypto::decrypt(&enc_key, &version.encrypted_value)?;
                String::from_utf8(bytes)
                    .map_err(|_| AppError::Internal("secret is not valid utf-8".into()))?
            }
            McpEnvBinding::OauthToken { provider } => {
                let user_scope = UserScope::new(org_id, identity_id, state.db.clone());
                let conn = user_scope
                    .find_my_connection_by_provider(provider)
                    .await?
                    .ok_or_else(|| {
                        AppError::BadRequest(format!(
                            "MCP env var '{var_name}' requires an OAuth connection for provider '{provider}'"
                        ))
                    })?;
                let creds = crate::services::client_credentials::resolve(
                    &state.db,
                    &enc_key,
                    org_id,
                    Some(identity_id),
                    provider,
                    Some(&conn),
                    None,
                )
                .await?;
                crate::services::oauth::resolve_access_token(
                    scope,
                    &state.http_client,
                    &enc_key,
                    &conn,
                    &creds.client_id,
                    &creds.client_secret,
                )
                .await
                .map_err(|e| AppError::Internal(format!("OAuth token resolution failed: {e}")))?
            }
            McpEnvBinding::Literal { value } => value.clone(),
        };
        env.insert(var_name.clone(), value);
    }

    let hash = hash_env(&env);
    Ok((env, hash))
}

/// Deterministic SHA-256 of the env map. Keys are sorted so insertion order
/// doesn't change the hash, and we include both keys and values so rotating
/// either is detected by the runtime.
pub fn hash_env(env: &HashMap<String, String>) -> String {
    let sorted: BTreeMap<&str, &str> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut h = Sha256::new();
    for (k, v) in sorted {
        h.update(k.as_bytes());
        h.update([0u8]);
        h.update(v.as_bytes());
        h.update([0u8]);
    }
    let digest = h.finalize();
    let mut hex = String::with_capacity(7 + digest.len() * 2);
    hex.push_str("sha256:");
    for byte in digest.iter() {
        use std::fmt::Write;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_order_independent() {
        let mut a = HashMap::new();
        a.insert("X".into(), "1".into());
        a.insert("Y".into(), "2".into());
        let mut b = HashMap::new();
        b.insert("Y".into(), "2".into());
        b.insert("X".into(), "1".into());
        assert_eq!(hash_env(&a), hash_env(&b));
    }

    #[test]
    fn hash_changes_when_value_rotates() {
        let mut a = HashMap::new();
        a.insert("T".into(), "v1".into());
        let mut b = HashMap::new();
        b.insert("T".into(), "v2".into());
        assert_ne!(hash_env(&a), hash_env(&b));
    }

    #[test]
    fn hash_differs_when_key_added() {
        let mut a = HashMap::new();
        a.insert("T".into(), "v".into());
        let mut b = a.clone();
        b.insert("U".into(), "x".into());
        assert_ne!(hash_env(&a), hash_env(&b));
    }

    #[test]
    fn hash_format_is_sha256_prefix() {
        let env = HashMap::new();
        let h = hash_env(&env);
        assert!(h.starts_with("sha256:"));
        // SHA-256 hex = 64 chars + 7-char prefix.
        assert_eq!(h.len(), 7 + 64);
    }
}
