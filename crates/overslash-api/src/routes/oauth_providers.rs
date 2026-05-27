//! `/v1/oauth-providers` — read-only provider catalog for the dashboard.
//!
//! Every authenticated user needs this list to pick a provider for a
//! template and to decide whether BYOC is optional (org/system fallback
//! present) or required (no fallback). Org-admin-only admin endpoints
//! (`/v1/org-oauth-credentials`) surface more detail; this one surfaces
//! just enough to drive the Create Service and Template Editor UX.

use std::collections::HashSet;

use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;

use overslash_db::OrgScope;
use overslash_db::repos::oauth_provider;

use crate::{
    AppState,
    error::Result,
    extractors::{ReqExt, WriteAcl},
    services::client_credentials::oauth_secret_names,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/v1/oauth-providers", get(list_providers))
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
        });
    }

    Ok(Json(rows))
}
