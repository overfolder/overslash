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

/// The template-declared fields an instance failed to supply, when credential
/// resolution came up empty.
///
/// Carried out of the resolver rather than recomputed by the caller: the
/// resolution chain (per-slot binding → legacy scalar `secret_name` → org
/// default → platform credential, plus the D38 config-var pass) is intricate
/// enough that a second implementation would drift, and the drift would be
/// invisible — a wrong field name in an error message, not a failing call.
///
/// Both halves are deduped on insert, which is why the fields are private:
/// the resolver walks the template's auth entries one scheme at a time, and
/// two schemes may legitimately read the same slot or config key (which is
/// why [`ServiceDefinition::all_slots`] dedupes for the same reason). Without
/// it a shared unresolved key would be reported once per scheme, and this
/// list is read by a human as a to-do — naming a field twice reads as a bug
/// in the gateway, in the one message whose whole job is to be clear.
///
/// [`ServiceDefinition::all_slots`]: overslash_core::types::ServiceDefinition::all_slots
#[derive(Default)]
pub(crate) struct MissingCredentials {
    /// Credential slot keys with no vault secret bound (`mailbox_pass`).
    slots: Vec<String>,
    /// `required` config vars with no value (`mailbox_user`).
    config: Vec<String>,
}

impl MissingCredentials {
    /// Record a credential slot the instance never bound.
    pub(super) fn add_slot(&mut self, key: &str) {
        push_unique(&mut self.slots, key);
    }

    /// Record a `required` config var with no value.
    pub(super) fn add_config(&mut self, key: &str) {
        push_unique(&mut self.config, key);
    }

    pub(super) fn is_empty(&self) -> bool {
        self.slots.is_empty() && self.config.is_empty()
    }

    /// Every missing key, config before slots. The config half is the
    /// human-recognisable one (a username before its password), so it reads
    /// better first in the envelope the agent relays to the user.
    pub(super) fn keys(&self) -> Vec<String> {
        self.config
            .iter()
            .chain(self.slots.iter())
            .cloned()
            .collect()
    }
}

fn push_unique(v: &mut Vec<String>, key: &str) {
    if !v.iter().any(|k| k == key) {
        v.push(key.to_string());
    }
}

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
    /// Why resolution came up empty, when it did: the credential slots and
    /// `required` config vars the instance never supplied. `None` whenever
    /// resolution succeeded, and whenever it failed for a reason that isn't
    /// missing instance configuration (an OAuth template with no connection
    /// yet — that path recovers through `auth_url`).
    pub missing: Option<MissingCredentials>,
}

impl ResolvedAuth {
    pub(super) fn secrets_only(secrets: Vec<SecretRef>) -> Self {
        Self {
            secrets,
            auth_header: None,
            oauth_injected: false,
            principal: None,
            missing: None,
        }
    }

    pub(super) fn oauth(auth_header: Option<AuthHeader>) -> Self {
        Self {
            secrets: Vec::new(),
            auth_header,
            oauth_injected: true,
            principal: None,
            missing: None,
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

    /// Record why resolution came up empty. Only meaningful on an otherwise
    /// empty result — the gate reads it exclusively when nothing was injected.
    pub(super) fn with_missing(mut self, missing: MissingCredentials) -> Self {
        self.missing = Some(missing);
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

    /// Two auth schemes reading the same unresolved slot (or config var) is a
    /// legal template shape, and the resolver visits schemes one at a time.
    /// The caller must still be told the field once.
    #[test]
    fn missing_credentials_reports_a_shared_key_once() {
        let mut m = MissingCredentials::default();
        m.add_slot("mailbox_pass");
        m.add_slot("mailbox_pass");
        m.add_config("mailbox_user");
        m.add_config("mailbox_user");
        assert_eq!(m.keys(), vec!["mailbox_user", "mailbox_pass"]);
    }

    /// Config before slots: the username reads better ahead of its password.
    #[test]
    fn missing_credentials_orders_config_before_slots() {
        let mut m = MissingCredentials::default();
        assert!(m.is_empty());
        m.add_slot("token");
        m.add_config("host");
        assert!(!m.is_empty());
        assert_eq!(m.keys(), vec!["host", "token"]);
    }

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
