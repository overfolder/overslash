//! `/v1/oauth-providers` — read-only provider catalog for the dashboard.
//!
//! Every authenticated user needs this list to pick a provider for a
//! template and to decide whether BYOC is optional (org/system fallback
//! present) or required (no fallback). Org-admin-only admin endpoints
//! (`/v1/org-oauth-credentials`) surface more detail; this one surfaces
//! just enough to drive the Create Service and Template Editor UX.

use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;

use overslash_db::OrgScope;
use overslash_db::repos::oauth_provider;

use crate::{
    AppState, error::Result, extractors::WriteAcl, services::client_credentials::oauth_secret_names,
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
}

async fn list_providers(
    State(state): State<AppState>,
    _acl: WriteAcl,
    scope: OrgScope,
) -> Result<Json<Vec<ProviderRow>>> {
    let providers = oauth_provider::list_all(&state.db).await?;
    let env_fallback_enabled =
        std::env::var("OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS").is_ok();

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

        rows.push(ProviderRow {
            key: p.key,
            display_name: p.display_name,
            supports_pkce: p.supports_pkce,
            has_org_credential,
            has_system_credential,
        });
    }

    Ok(Json(rows))
}
