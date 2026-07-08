//! `/v1/oauth-providers` — read-only provider catalog for the dashboard.
//!
//! Every authenticated user needs this list to pick a provider for a
//! template and to decide whether BYOC is optional (org/system fallback
//! present) or required (no fallback). Org-admin-only admin endpoints
//! (`/v1/org-oauth-credentials`) surface more detail; this one surfaces
//! just enough to drive the Create Service and Template Editor UX.

use std::collections::HashSet;

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use serde::Serialize;

use overslash_db::OrgScope;
use overslash_db::repos::oauth_provider;

use crate::{
    AppState,
    error::{AppError, Result},
    extractors::{ReqExt, WriteAcl},
    services::client_credentials::oauth_secret_names,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/v1/oauth-providers", get(list_providers))
        .route("/v1/oauth-providers/{key}", get(get_provider))
}

#[derive(Serialize)]
struct ProviderRow {
    key: String,
    display_name: String,
    supports_pkce: bool,
    /// True when the org has its own `OAUTH_{PROVIDER}_CLIENT_ID`/`_SECRET`
    /// secrets configured (SPEC §7 tier 2).
    has_org_credential: bool,
    /// True when system env vars are opted in (`OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS`)
    /// and env vars for this provider are set (SPEC §7 tier 3).
    has_system_credential: bool,
    /// True when the caller's own identity already has a BYOC credential for
    /// this provider (SPEC §7 tier 1). Drives the Create Service UX so we
    /// don't demand the user re-paste creds they configured on a prior
    /// service for the same provider.
    has_user_byoc_credential: bool,
    /// Authorized redirect URI the user must register in their own OAuth app
    /// when bringing their own credentials. Mirrors the value used at token
    /// exchange (`{public_url}/v1/oauth/callback`). Same for every provider.
    oauth_redirect_uri: String,
    /// Authorized JavaScript origin to register alongside the redirect URI —
    /// the public origin Overslash is served from. Same for every provider.
    oauth_js_origin: String,
    /// Identity scopes the backend always merges into any initiate/upgrade
    /// flow for this provider so the OAuth callback can resolve
    /// `account_email` via the provider's userinfo endpoint. The dashboard
    /// renders these as fixed (non-removable) chips alongside the
    /// service-specific scopes the user picks.
    default_identity_scopes: Vec<String>,
}

async fn list_providers(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(acl): WriteAcl,
    scope: OrgScope,
) -> Result<Json<Vec<ProviderRow>>> {
    let providers = oauth_provider::list_all(state.db(&ext)).await?;
    let env_fallback_enabled =
        std::env::var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS").is_ok();

    // BYOC setup values the user pastes into their own OAuth app. Provider-
    // independent: the redirect URI matches the one used at token exchange
    // (connections.rs), and the JS origin is the public origin we're served on.
    // The redirect URI keeps any configured subpath (e.g. behind a reverse
    // proxy at `https://host/overslash`), but a JS origin must be scheme + host
    // + port with no path, so derive it from the parsed URL's origin.
    let public_url = state.config.public_url.trim_end_matches('/');
    let redirect_uri = format!("{public_url}/v1/oauth/callback");
    let js_origin = url::Url::parse(public_url)
        .ok()
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_else(|| public_url.to_string());

    // Pre-compute the set of providers for which the caller already has a BYOC
    // credential. BYOC is identity-bound; if there's no identity on the ACL
    // (e.g. org-level key) there can't be any user BYOC.
    let user_byoc_providers: HashSet<String> = if let Some(identity_id) = acl.identity_id {
        scope
            .list_byoc_credentials()
            .await?
            .into_iter()
            .filter(|r| r.identity_id == identity_id)
            .map(|r| r.provider_key)
            .collect()
    } else {
        HashSet::new()
    };

    let mut rows = Vec::with_capacity(providers.len());
    for p in providers {
        let (id_name, secret_name) = oauth_secret_names(&p.key);

        // Org credential = both halves of the pair are present in the org vault.
        let has_org_credential = scope.get_current_secret_value(&id_name).await?.is_some()
            && scope
                .get_current_secret_value(&secret_name)
                .await?
                .is_some();

        let has_system_credential = env_fallback_enabled
            && std::env::var(&id_name).is_ok()
            && std::env::var(&secret_name).is_ok();

        let has_user_byoc_credential = user_byoc_providers.contains(&p.key);

        rows.push(ProviderRow {
            key: p.key,
            display_name: p.display_name,
            supports_pkce: p.supports_pkce,
            has_org_credential,
            has_system_credential,
            has_user_byoc_credential,
            oauth_redirect_uri: redirect_uri.clone(),
            oauth_js_origin: js_origin.clone(),
            default_identity_scopes: p.default_identity_scopes,
        });
    }

    Ok(Json(rows))
}

/// Full OAuth metadata for a single provider — everything a white-label
/// partner (e.g. Overfolder) needs to run the authorize + code-exchange dance
/// against its own OAuth client and then `POST /v1/connections/import` the
/// resulting tokens (token-vault model, DECISIONS D20). Read-only catalog
/// data; the secrets (client_id/secret) stay on the partner side. The partner
/// never duplicates this metadata — it reads it here so a new provider is a
/// `oauth_providers` row, not partner code.
#[derive(Serialize)]
struct ProviderDetail {
    key: String,
    display_name: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    userinfo_endpoint: Option<String>,
    supports_pkce: bool,
    supports_refresh: bool,
    /// `client_secret_post` | `client_secret_basic` | `none` — how the partner
    /// must authenticate the token-endpoint request.
    token_auth_method: String,
    /// Provider-specific authorize-URL params the partner must append verbatim
    /// (e.g. Google's `access_type=offline` + `prompt=consent` to mint a
    /// refresh token, tenant routing, etc.).
    extra_auth_params: serde_json::Value,
    /// Identity scopes the partner must union into every authorize request so
    /// the imported token can resolve `account_email` via `userinfo_endpoint`.
    default_identity_scopes: Vec<String>,
}

/// `GET /v1/oauth-providers/{key}` — full OAuth metadata for one provider.
async fn get_provider(
    State(state): State<AppState>,
    ReqExt(ext): ReqExt,
    WriteAcl(_acl): WriteAcl,
    Path(key): Path<String>,
) -> Result<Json<ProviderDetail>> {
    let p = oauth_provider::get_by_key(state.db(&ext), &key)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("provider '{key}' not found")))?;

    Ok(Json(ProviderDetail {
        key: p.key,
        display_name: p.display_name,
        authorization_endpoint: p.authorization_endpoint,
        token_endpoint: p.token_endpoint,
        userinfo_endpoint: p.userinfo_endpoint,
        supports_pkce: p.supports_pkce,
        supports_refresh: p.supports_refresh,
        token_auth_method: p.token_auth_method,
        extra_auth_params: p.extra_auth_params,
        default_identity_scopes: p.default_identity_scopes,
    }))
}
