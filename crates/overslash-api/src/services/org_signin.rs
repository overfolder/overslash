//! Which IdPs can an org sign in with, and with whose OAuth app?
//!
//! The rule, in one place so `/auth/providers`, `/oauth/authorize`,
//! `/v1/org-idp-configs` and credential resolution cannot disagree:
//!
//! - An `org_idp_configs` row **claims** its provider key for the org. The
//!   row's `enabled` flag then decides whether that provider can be used —
//!   a disabled row means the admin turned that provider off, not that
//!   Overslash should quietly sign users in through its own OAuth app.
//! - For keys no row claims, `orgs.allow_overslash_managed_signin` makes the
//!   Overslash-managed providers ([`MANAGED_PROVIDER_KEYS`]) available on the
//!   deployment's `{PROVIDER}_AUTH_*` credentials — where configured.
//!
//! Availability is **not** admission. Whether the authenticated human may
//! become a member is decided separately by `require_invite_admission` /
//! `managed_signin_allowed_domains` in `routes::auth::provisioning` — see
//! DECISIONS.md D12 and its 2026-05 / 2026-07 amendments.

use std::collections::HashSet;

use overslash_core::crypto;
use overslash_db::OrgScope;
use overslash_db::repos::oauth_provider;
use overslash_db::repos::org_idp_config::OrgIdpConfigRow;
use uuid::Uuid;

use crate::AppState;
use crate::error::AppError;

/// The providers Overslash can offer out of its own OAuth apps. Mirrors the
/// keys [`crate::config::Config::env_auth_credentials`] knows how to answer
/// for; a key here without configured env credentials is simply skipped.
pub const MANAGED_PROVIDER_KEYS: [&str; 2] = ["google", "github"];

/// The human-facing name for a provider key, from the `oauth_providers`
/// catalog. Falls back to the key itself for a provider that somehow has no
/// catalog row. Shared so the managed providers are labelled from the same
/// source as dedicated ones instead of a hardcoded table.
pub async fn display_name_for(
    state: &AppState,
    ext: &axum::http::Extensions,
    provider_key: &str,
) -> Result<String, AppError> {
    Ok(oauth_provider::get_by_key(state.db(ext), provider_key)
        .await?
        .map(|p| p.display_name)
        .unwrap_or_else(|| provider_key.to_string()))
}

/// The Overslash-managed provider keys available to `org_id`, skipping any
/// key in `claimed` (i.e. one the org has its own `org_idp_configs` row for)
/// and any the deployment has no credentials for. Empty unless the org opted
/// into managed sign-in.
///
/// Exposed separately from [`list_org_signin_providers`] for the admin
/// listing, which needs *all* its own rows — disabled ones included — and so
/// can't reuse the availability list, but must not re-derive the managed half.
pub async fn managed_provider_keys(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
    claimed: &HashSet<String>,
) -> Result<Vec<String>, AppError> {
    if !managed_signin_enabled(state, ext, org_id).await? {
        return Ok(Vec::new());
    }
    Ok(MANAGED_PROVIDER_KEYS
        .iter()
        .filter(|key| !claimed.contains(**key))
        .filter(|key| state.config.env_auth_credentials(key).is_some())
        .map(|key| key.to_string())
        .collect())
}

/// Whose OAuth app an org's sign-in provider uses.
pub enum SigninSource {
    /// The org configured this provider itself. Carries the row so callers
    /// that need the richer fields (`allowed_email_domains`, timestamps,
    /// whether it defers to org OAuth App Credentials) don't re-query.
    Dedicated(Box<OrgIdpConfigRow>),
    /// Overslash-managed sign-in, backed by the deployment's env credentials.
    Managed,
}

pub struct OrgSigninProvider {
    pub provider_key: String,
    /// The org's designated default for the `/oauth/authorize` bounce.
    /// Always `false` for [`SigninSource::Managed`] — there is no row to mark.
    pub is_default: bool,
    pub source: SigninSource,
}

impl OrgSigninProvider {
    /// The dedicated config row, or `None` when this is a managed provider.
    pub fn dedicated(&self) -> Option<&OrgIdpConfigRow> {
        match &self.source {
            SigninSource::Dedicated(row) => Some(row),
            SigninSource::Managed => None,
        }
    }

    pub fn is_managed(&self) -> bool {
        matches!(self.source, SigninSource::Managed)
    }
}

/// Every provider `org_id` can authenticate through right now: its enabled
/// `org_idp_configs` rows in `created_at` order, then the managed providers
/// for keys no row of the org's claims.
///
/// Ordering is the login picker's ordering — dedicated first, because an org
/// that bothered to configure its own IdP wants it seen first.
pub async fn list_org_signin_providers(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
) -> Result<Vec<OrgSigninProvider>, AppError> {
    Ok(resolve_availability(state, ext, org_id).await?.0)
}

/// The availability list plus the keys a *disabled* row claims. Kept together
/// because both fall out of the same `org_idp_configs` read: a caller that
/// needs to tell "switched off" from "never configured" would otherwise have
/// to query the table a second time.
async fn resolve_availability(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
) -> Result<(Vec<OrgSigninProvider>, HashSet<String>), AppError> {
    // All rows, not just enabled ones: a disabled row still claims its key,
    // so turning a dedicated Google IdP off turns Google off for the org
    // rather than handing sign-in to Overslash's OAuth app behind the
    // admin's back.
    let rows = overslash_db::repos::org_idp_config::list_by_org(state.db(ext), org_id).await?;
    let claimed: HashSet<String> = rows.iter().map(|r| r.provider_key.clone()).collect();
    let disabled: HashSet<String> = rows
        .iter()
        .filter(|r| !r.enabled)
        .map(|r| r.provider_key.clone())
        .collect();

    let mut providers: Vec<OrgSigninProvider> = rows
        .into_iter()
        .filter(|row| row.enabled)
        .map(|row| OrgSigninProvider {
            provider_key: row.provider_key.clone(),
            is_default: row.is_default,
            source: SigninSource::Dedicated(Box::new(row)),
        })
        .collect();

    for key in managed_provider_keys(state, ext, org_id, &claimed).await? {
        providers.push(OrgSigninProvider {
            provider_key: key,
            is_default: false,
            source: SigninSource::Managed,
        });
    }

    Ok((providers, disabled))
}

/// Outcome of asking for a provider's credentials. The two unavailable cases
/// are distinct because they point an admin at different fixes — add an IdP
/// versus flip a toggle — and the caller owns the wording, since it knows the
/// request context (slug, subdomain).
pub enum CredentialLookup {
    Found(String, String),
    /// A row claims this provider key but is switched off.
    Disabled,
    /// No row claims it, and managed sign-in doesn't cover it either.
    NotConfigured,
}

/// Resolve the OAuth client credentials to drive `provider_key`'s login for
/// `org_id`, following the availability rule above.
///
/// An `Err` means the provider *is* available but misconfigured, which is an
/// operator-facing problem in its own right — distinct from the unavailable
/// cases carried by [`CredentialLookup`].
///
/// Precedence within a dedicated row: the row's own encrypted credentials,
/// else the org's OAuth App Credentials (`OAUTH_{PROVIDER}_CLIENT_ID/SECRET`
/// org secrets) it defers to. A managed provider prefers the org's OAuth App
/// Credentials — an explicit admin override — over the shared env pair.
pub async fn resolve_org_signin_credentials(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
    provider_key: &str,
) -> Result<CredentialLookup, AppError> {
    let (providers, disabled) = resolve_availability(state, ext, org_id).await?;
    let Some(provider) = providers.iter().find(|p| p.provider_key == provider_key) else {
        return Ok(if disabled.contains(provider_key) {
            CredentialLookup::Disabled
        } else {
            CredentialLookup::NotConfigured
        });
    };

    let scope = OrgScope::new(org_id, state.db_pool(ext));
    let enc_key = state
        .config
        .keyring()
        .map_err(|e| AppError::Internal(format!("invalid encryption key: {e}")))?;

    if let Some(config) = provider.dedicated() {
        // Dedicated credentials — decrypt them directly.
        if let (Some(enc_id), Some(enc_secret)) = (
            config.encrypted_client_id.as_deref(),
            config.encrypted_client_secret.as_deref(),
        ) {
            let client_id = String::from_utf8(
                crypto::decrypt(&enc_key, enc_id)
                    .map_err(|e| AppError::Internal(format!("decrypt client_id: {e}")))?,
            )
            .map_err(|_| AppError::Internal("invalid client_id utf-8".into()))?;
            let client_secret = String::from_utf8(
                crypto::decrypt(&enc_key, enc_secret)
                    .map_err(|e| AppError::Internal(format!("decrypt client_secret: {e}")))?,
            )
            .map_err(|_| AppError::Internal("invalid client_secret utf-8".into()))?;
            return Ok(CredentialLookup::Found(client_id, client_secret));
        }

        // The row defers to org-level OAuth App Credentials (SPEC §3). Their
        // absence is an admin misconfiguration, not a fallthrough: the admin
        // said "use the org credentials" and there are none.
        let creds = crate::services::client_credentials::resolve_org_oauth_secrets(
            &scope,
            &enc_key,
            provider_key,
        )
        .await?
        .ok_or_else(|| {
            AppError::BadRequest(format!(
                "IdP for provider '{provider_key}' is configured to use org OAuth App \
                     Credentials, but no org-level credentials are set. \
                     Add them in Org Settings → OAuth App Credentials, or reconfigure \
                     the IdP with dedicated credentials."
            ))
        })?;
        return Ok(CredentialLookup::Found(
            creds.client_id,
            creds.client_secret,
        ));
    }

    // Managed: org OAuth App Credentials win over the operator-shared env pair.
    if let Some(creds) = crate::services::client_credentials::resolve_org_oauth_secrets(
        &scope,
        &enc_key,
        provider_key,
    )
    .await?
    {
        return Ok(CredentialLookup::Found(
            creds.client_id,
            creds.client_secret,
        ));
    }
    // The availability list only offers a managed provider when the env pair
    // is present, so this is belt-and-braces against a config swap.
    Ok(match state.config.env_auth_credentials(provider_key) {
        Some((id, secret)) => CredentialLookup::Found(id, secret),
        None => CredentialLookup::NotConfigured,
    })
}

async fn managed_signin_enabled(
    state: &AppState,
    ext: &axum::http::Extensions,
    org_id: Uuid,
) -> Result<bool, AppError> {
    Ok(
        overslash_db::repos::org::get_allow_overslash_managed_signin(state.db(ext), org_id)
            .await?
            .unwrap_or(false),
    )
}
