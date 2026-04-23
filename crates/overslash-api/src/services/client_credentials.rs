use overslash_core::crypto;
use overslash_db::OrgScope;
use overslash_db::repos::{byoc_credential, connection::ConnectionRow};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::AppError;

/// The well-known secret / env-var names for a provider's OAuth app credentials.
/// Returns `(client_id_name, client_secret_name)`.
pub fn oauth_secret_names(provider_key: &str) -> (String, String) {
    let upper = provider_key.to_uppercase();
    (
        format!("OAUTH_{upper}_CLIENT_ID"),
        format!("OAUTH_{upper}_CLIENT_SECRET"),
    )
}

pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: String,
    /// The BYOC credential ID that was used, if any. Should be persisted on the
    /// connection so token refreshes use the same credential.
    pub byoc_credential_id: Option<Uuid>,
}

/// Resolve OAuth client credentials for a provider.
///
/// Resolution cascade (first match wins — SPEC §7 three-tier cascade):
/// 1. Explicit `pinned_byoc_id` or connection's pinned `byoc_credential_id`
/// 2. Identity-level BYOC credential
/// 3. Org-level OAuth App Credentials — org secrets named
///    `OAUTH_{PROVIDER}_CLIENT_ID` / `OAUTH_{PROVIDER}_CLIENT_SECRET`
/// 4. System env vars (only if OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS is set)
/// 5. Error
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

    // 3. Org-level OAuth App Credentials.
    if let Some(creds) = resolve_org_oauth_secrets(&scope, enc_key, provider_key).await? {
        return Ok(creds);
    }

    // 4. Env var fallback — only with explicit opt-in
    if std::env::var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS").is_ok() {
        let (id_name, secret_name) = oauth_secret_names(provider_key);
        let id_env = std::env::var(&id_name);
        let secret_env = std::env::var(&secret_name);
        match (id_env, secret_env) {
            (Ok(client_id), Ok(client_secret)) => {
                return Ok(ClientCredentials {
                    client_id,
                    client_secret,
                    byoc_credential_id: None,
                });
            }
            // A half-configured env pair is almost certainly an operator
            // misconfiguration — surface it instead of silently falling
            // through to the generic "not configured" error.
            (Ok(_), Err(_)) => {
                return Err(AppError::BadRequest(format!(
                    "{id_name} is set but {secret_name} is missing — \
                     configure both or remove both."
                )));
            }
            (Err(_), Ok(_)) => {
                return Err(AppError::BadRequest(format!(
                    "{secret_name} is set but {id_name} is missing — \
                     configure both or remove both."
                )));
            }
            (Err(_), Err(_)) => {}
        }
    }

    // 5. No credentials found
    Err(AppError::BadRequest(format!(
        "no OAuth client credentials configured for provider '{provider_key}'. \
         Configure org-level OAuth App Credentials in Org Settings, \
         or create a BYOC credential via POST /v1/byoc-credentials"
    )))
}

/// Tier 3 of the cascade: look up org-level OAuth App Credentials stored as
/// well-known org secrets (`OAUTH_{PROVIDER}_CLIENT_ID` / `OAUTH_{PROVIDER}_CLIENT_SECRET`).
///
/// Returns `Ok(None)` when either secret is missing — the caller continues
/// to the next tier. Returns an error only on decryption failure.
pub(crate) async fn resolve_org_oauth_secrets(
    scope: &OrgScope,
    enc_key: &[u8; 32],
    provider_key: &str,
) -> Result<Option<ClientCredentials>, AppError> {
    let (id_name, secret_name) = oauth_secret_names(provider_key);

    let Some(id_version) = scope.get_current_secret_value(&id_name).await? else {
        return Ok(None);
    };
    let Some(secret_version) = scope.get_current_secret_value(&secret_name).await? else {
        return Ok(None);
    };

    let client_id = String::from_utf8(crypto::decrypt(enc_key, &id_version.encrypted_value)?)
        .map_err(|e| AppError::Internal(format!("org OAuth client_id is not valid UTF-8: {e}")))?;
    let client_secret =
        String::from_utf8(crypto::decrypt(enc_key, &secret_version.encrypted_value)?).map_err(
            |e| AppError::Internal(format!("org OAuth client_secret is not valid UTF-8: {e}")),
        )?;

    Ok(Some(ClientCredentials {
        client_id,
        client_secret,
        byoc_credential_id: None,
    }))
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
