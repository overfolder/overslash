//! OAuth / credential resolution, scope checks, and re-auth envelopes.
//!
//! This module hosts the shared [`ResolvedAuth`] type, the `OAuthError`
//! classifier and the headless-org probe. The rest of the surface lives in
//! sibling modules and is re-exported here so existing paths keep resolving:
//! `auth_envelopes` (recovery envelopes), `auth_scopes` (scope gating) and
//! `auth_resolve` (the credential resolvers).

use uuid::Uuid;

use crate::services::oauth::OAuthError;
use overslash_core::types::{AuthHeader, SecretRef};

// Named rather than glob-imported: `actions::mod` re-exports two of the
// names this module re-exports below, and a `use super::*;` here would make
// those bindings resolve back through `mod.rs` in a circle.
use super::OAuthOutcome;

// `resolve_mcp_oauth_bearer` / `resolve_replay_auth_header` moved to
// `auth_resolve`; re-exported so `actions::mod`'s `pub(crate) use auth::{…}`
// (and `mcp_resolve`'s `use super::auth::resolve_mcp_oauth_bearer`) keep
// resolving unchanged.
pub(crate) use super::auth_resolve::{resolve_mcp_oauth_bearer, resolve_replay_auth_header};
// Likewise for the two items `call.rs` reaches via `super::auth::…`.
pub(super) use super::auth_envelopes::metadata_scope_reauth_envelope;
pub(super) use super::auth_scopes::is_metadata_scope_denial;

/// Outcome of service/instance auth resolution.
///
/// The live OAuth credential rides in `auth_header` — a non-`Serialize`
/// type merged into the outgoing header map only at send time — instead of
/// being baked into the request's header map, so approval/audit/replay
/// persistence can never capture it.
pub(crate) struct ResolvedAuth {
    pub secrets: Vec<SecretRef>,
    pub auth_header: Option<AuthHeader>,
    /// Whether OAuth resolution succeeded. Distinct from
    /// `auth_header.is_some()` only for templates that declare a query-param
    /// token injection (no header to build); kept so the
    /// `needs_authentication` gate behaves identically for those.
    pub oauth_injected: bool,
    /// The account this call authenticates *as* — the resolved connection's
    /// `account_email`. Not a credential: it names the principal, which is
    /// what the `connection:` metadata tag records. Populated only on OAuth
    /// paths, where the connection row was loaded anyway; secret-based
    /// instances fall back to the template's identity config var (see
    /// [`crate::services::principals`]).
    pub principal: Option<String>,
}

impl ResolvedAuth {
    pub(super) fn secrets_only(secrets: Vec<SecretRef>) -> Self {
        Self {
            secrets,
            auth_header: None,
            oauth_injected: false,
            principal: None,
        }
    }

    pub(super) fn oauth(auth_header: Option<AuthHeader>) -> Self {
        Self {
            secrets: Vec::new(),
            auth_header,
            oauth_injected: true,
            principal: None,
        }
    }

    pub(super) fn none() -> Self {
        Self::secrets_only(Vec::new())
    }

    /// Name the account this resolution authenticates as. Called at the OAuth
    /// return sites, where the connection row is already in hand — naming the
    /// principal costs no extra query.
    pub(super) fn with_principal(mut self, principal: Option<String>) -> Self {
        self.principal = principal;
        self
    }
}

pub(super) fn classify_oauth(err: &OAuthError) -> OAuthOutcome {
    match err {
        OAuthError::RefreshFailed(_) => OAuthOutcome::Reauth("refresh_token_failed"),
        OAuthError::NoRefreshToken => OAuthOutcome::Reauth("no_refresh_token"),
        OAuthError::ReauthRequired(_) => OAuthOutcome::Reauth("credential_replaced"),
        OAuthError::CryptoError(_)
        | OAuthError::DbError(_)
        | OAuthError::ParseError(_)
        | OAuthError::ProviderNotFound(_) => OAuthOutcome::Internal,
        OAuthError::HttpError(_) | OAuthError::TokenExchangeFailed(_) => OAuthOutcome::Upstream,
    }
}

/// Whether `org_id` is a headless (white-label) org: auth-recovery returns
/// URL-less typed envelopes instead of minting gated `/connect-authorize`
/// links (and no `oauth_connection_flows` row). A read failure or missing org
/// defaults to `false` — the safe, gated path for normal dashboard customers.
///
/// Pass the request's pool (`state.db(ext)` or `scope.db()`) so the lookup hits
/// the right database under the shared-router test harness (in production /
/// per-test routers that is `&state.db`).
pub(super) async fn org_is_headless(db: &sqlx::PgPool, org_id: Uuid) -> bool {
    overslash_db::repos::org::get_headless(db, org_id)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_oauth_reauth_signals() {
        match classify_oauth(&OAuthError::RefreshFailed("provider said no".into())) {
            OAuthOutcome::Reauth(reason) => assert_eq!(reason, "refresh_token_failed"),
            other => panic!("expected Reauth, got {other:?}"),
        }
        match classify_oauth(&OAuthError::NoRefreshToken) {
            OAuthOutcome::Reauth(reason) => assert_eq!(reason, "no_refresh_token"),
            other => panic!("expected Reauth, got {other:?}"),
        }
        // A connection flagged `reauth_required` (its BYOC client was replaced)
        // maps to the distinct `credential_replaced` reason.
        match classify_oauth(&OAuthError::ReauthRequired("byoc_client_replaced".into())) {
            OAuthOutcome::Reauth(reason) => assert_eq!(reason, "credential_replaced"),
            other => panic!("expected Reauth, got {other:?}"),
        }
    }

    #[test]
    fn classify_oauth_internal_signals() {
        for err in [
            OAuthError::CryptoError("bad key".into()),
            OAuthError::DbError("conn refused".into()),
            OAuthError::ParseError("bad json".into()),
            OAuthError::ProviderNotFound("x".into()),
        ] {
            assert!(
                matches!(classify_oauth(&err), OAuthOutcome::Internal),
                "{err:?} should be Internal"
            );
        }
    }

    #[test]
    fn classify_oauth_upstream_signals() {
        for err in [
            OAuthError::HttpError("timeout".into()),
            OAuthError::TokenExchangeFailed("provider 500".into()),
        ] {
            assert!(
                matches!(classify_oauth(&err), OAuthOutcome::Upstream),
                "{err:?} should be Upstream"
            );
        }
    }
}
