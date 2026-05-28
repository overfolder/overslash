use overslash_core::crypto;
use overslash_db::OrgScope;
use overslash_db::repos::{byoc_credential, connection::ConnectionRow};
use serde::Serialize;
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
/// 1. Explicit `pinned_byoc_id` (hard pin — errors if missing).
/// 2. Connection's stored `byoc_credential_id` (soft preference — falls
///    through to the next tier if the BYOC row has since been deleted).
/// 3. Identity-level BYOC credential.
/// 4. Org-level OAuth App Credentials — org secrets named
///    `OAUTH_{PROVIDER}_CLIENT_ID` / `OAUTH_{PROVIDER}_CLIENT_SECRET`.
/// 5. System env vars (only if `OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS` is set).
/// 6. Error.
pub async fn resolve(
    pool: &PgPool,
    enc_key: &crypto::Keyring,
    org_id: Uuid,
    identity_id: Option<Uuid>,
    provider_key: &str,
    connection: Option<&ConnectionRow>,
    pinned_byoc_id: Option<Uuid>,
) -> Result<ClientCredentials, AppError> {
    let scope = OrgScope::new(org_id, pool.clone());

    // 1. Explicit pin — the caller asked for this specific BYOC credential.
    //    If it's gone, error rather than silently switching to a different one.
    if let Some(byoc_id) = pinned_byoc_id {
        let row = scope.get_byoc_credential(byoc_id).await?.ok_or_else(|| {
            AppError::BadRequest(format!(
                "pinned BYOC credential '{byoc_id}' not found — \
                     it may have been deleted. Create a new connection."
            ))
        })?;
        return decrypt_byoc(&row, enc_key);
    }

    // 1a. Connection's stored BYOC — a soft preference. If the row still
    //     exists, use it; if it's been deleted, fall through to the cascade
    //     so the next refresh recovers instead of breaking the connection.
    if let Some(byoc_id) = connection.and_then(|c| c.byoc_credential_id) {
        if let Some(row) = scope.get_byoc_credential(byoc_id).await? {
            return decrypt_byoc(&row, enc_key);
        }
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
    enc_key: &crypto::Keyring,
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
    enc_key: &crypto::Keyring,
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

/// What OAuth client credentials a connection will use on its next refresh.
/// Mirrors the tiers of `resolve()` but reports the resolution without
/// decrypting anything — safe to expose via the API.
///
/// Note on a missing branch: deleting a BYOC row auto-nulls
/// `connections.byoc_credential_id` (FK `ON DELETE SET NULL`), so the
/// "row pinned but credential gone" case never reaches this enum — the
/// cascade simply continues into the next tier on its own.
#[derive(Serialize, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialSource {
    /// A BYOC credential (the connection's stored pin OR an identity-level
    /// BYOC discovered via tier 2) will be used.
    Byoc,
    /// Org-level `OAUTH_{PROVIDER}_CLIENT_ID` / `..._CLIENT_SECRET` are set.
    OrgSecret,
    /// Env-var fallback is active (requires `OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS`).
    System,
    /// Nothing resolves — the next refresh will fail.
    Missing,
}

/// Compute the `CredentialSource` that `resolve()` would produce, without
/// decrypting any secret. Used by `GET /v1/connections/{id}` to surface the
/// credential posture in the dashboard.
///
/// Mirrors every tier of `resolve()`: connection's stored BYOC (tier 1a) →
/// identity-level BYOC (tier 2) → org OAuth app secrets (tier 3) → env-var
/// fallback (tier 4) → `Missing`. Tier 1 (explicit `pinned_byoc_id`) is not
/// represented here because it's a per-request argument, not a property of
/// a stored connection.
pub async fn describe_source(
    scope: &OrgScope,
    provider_key: &str,
    identity_id: Option<Uuid>,
    connection_byoc_id: Option<Uuid>,
) -> Result<CredentialSource, AppError> {
    // Tier 1a: connection's stored BYOC pin. The FK auto-nulls the column
    // when the BYOC row is deleted, so an `Option::None` lookup here would
    // be a cross-org filter mismatch; either way we just fall through.
    if let Some(byoc_id) = connection_byoc_id {
        if scope.get_byoc_credential(byoc_id).await?.is_some() {
            return Ok(CredentialSource::Byoc);
        }
    }

    // Tier 2: any identity-level BYOC for this provider — what `resolve()`
    // would pick next.
    if let Some(identity_id) = identity_id {
        if scope
            .resolve_byoc_credential(identity_id, provider_key)
            .await?
            .is_some()
        {
            return Ok(CredentialSource::Byoc);
        }
    }

    let (id_name, secret_name) = oauth_secret_names(provider_key);
    let id_present = scope.get_secret_by_name(&id_name).await?.is_some();
    let secret_present = scope.get_secret_by_name(&secret_name).await?.is_some();
    if id_present && secret_present {
        return Ok(CredentialSource::OrgSecret);
    }

    if std::env::var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS").is_ok()
        && std::env::var(&id_name).is_ok()
        && std::env::var(&secret_name).is_ok()
    {
        return Ok(CredentialSource::System);
    }

    Ok(CredentialSource::Missing)
}
