use overslash_core::crypto;
use overslash_db::OrgScope;
use overslash_db::repos::{byoc_credential, connection::ConnectionRow};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppError;

pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: String,
    /// The BYOC credential ID that was used, if any. Should be persisted on the
    /// connection so token refreshes use the same credential.
    pub byoc_credential_id: Option<Uuid>,
}

/// Resolve OAuth client credentials for a provider.
///
/// Resolution cascade (first match wins):
/// 1. Explicit `pinned_byoc_id` or connection's pinned `byoc_credential_id`
/// 2. Identity-level BYOC credential
/// 3. Environment variables (only if OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS is set)
/// 4. Error
///
/// Org-level BYOC credentials (identity_id IS NULL) were removed in
/// migration 028. BYOC is always identity-bound.
pub async fn resolve(
    pool: &PgPool,
    enc_key: &[u8; 32],
    org_id: Uuid,
    identity_id: Option<Uuid>,
    provider_key: &str,
    connection: Option<&ConnectionRow>,
    pinned_byoc_id: Option<Uuid>,
) -> Result<ClientCredentials, AppError> {
    // 1. Check explicit pin first, then connection's pinned BYOC credential.
    //    If a pinned credential was specified but no longer exists, error immediately
    //    rather than silently falling through to a different credential.
    let pinned = pinned_byoc_id.or_else(|| connection.and_then(|c| c.byoc_credential_id));
    let scope = OrgScope::new(org_id, pool.clone());
    if let Some(byoc_id) = pinned {
        let row = scope.get_byoc_credential(byoc_id).await?.ok_or_else(|| {
            AppError::BadRequest(format!(
                "pinned BYOC credential '{byoc_id}' not found — \
                     it may have been deleted. Create a new connection."
            ))
        })?;
        return decrypt_byoc(&row, enc_key);
    }

    // 2. Identity-level BYOC. BYOC requires an identity-bound caller.
    if let Some(identity_id) = identity_id {
        if let Some(row) = scope
            .resolve_byoc_credential(identity_id, provider_key)
            .await?
        {
            return decrypt_byoc(&row, enc_key);
        }
    }

    // 4. Env var fallback — only with explicit opt-in
    if std::env::var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS").is_ok() {
        let upper = provider_key.to_uppercase();
        let client_id = std::env::var(format!("OAUTH_{upper}_CLIENT_ID")).map_err(|_| {
            AppError::BadRequest(format!(
                "no OAuth client configured for provider '{provider_key}'"
            ))
        })?;
        let client_secret =
            std::env::var(format!("OAUTH_{upper}_CLIENT_SECRET")).map_err(|_| {
                AppError::BadRequest(format!(
                    "no OAuth client_secret configured for provider '{provider_key}'"
                ))
            })?;
        return Ok(ClientCredentials {
            client_id,
            client_secret,
            byoc_credential_id: None,
        });
    }

    // 5. No credentials found
    Err(AppError::BadRequest(format!(
        "no OAuth client credentials configured for provider '{provider_key}'. \
         Create BYOC credentials via POST /v1/byoc-credentials"
    )))
}

fn decrypt_byoc(
    row: &byoc_credential::ByocCredentialRow,
    enc_key: &[u8; 32],
) -> Result<ClientCredentials, AppError> {
    let client_id = String::from_utf8(crypto::decrypt(enc_key, &row.encrypted_client_id)?)
        .map_err(|e| AppError::Internal(format!("BYOC client_id is not valid UTF-8: {e}")))?;
    let client_secret = String::from_utf8(crypto::decrypt(enc_key, &row.encrypted_client_secret)?)
        .map_err(|e| AppError::Internal(format!("BYOC client_secret is not valid UTF-8: {e}")))?;
    Ok(ClientCredentials {
        client_id,
        client_secret,
        byoc_credential_id: Some(row.id),
    })
}
