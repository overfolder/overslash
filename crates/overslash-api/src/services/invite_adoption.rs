//! Turning a pre-created identity into a real member.
//!
//! Since migration 103 an "invite" is not a row in a side table — it is a
//! `kind='user'` identity with an email, no `external_id`, and no `user_id`.
//! Adoption is the moment a human claims it: the identity gets linked to a
//! `users` row, joins the org's system groups, and gains a membership whose
//! role comes from the invite (`is_org_admin`).
//!
//! Two paths reach that moment and must not drift:
//!
//! 1. **SSO on the org's subdomain** — the historical path. The IdP callback
//!    finds the row by email and adopts it (`routes/auth/provisioning.rs`).
//! 2. **In-app accept** — the invitee is already signed in elsewhere (usually
//!    the apex) and accepts from the sidebar
//!    (`routes/account_invitations.rs`).
//!
//! Everything after "we know which `users` row owns this identity" is shared
//! and lives here. Setting `external_id` stays with the SSO path: it records
//! the IdP subject that claimed the identity, and an in-app accept has no
//! subject for that org to record.

use overslash_db::OrgScope;
use overslash_db::repos::audit::AuditEntry;
use overslash_db::repos::identity::IdentityRow;
use overslash_db::repos::org::OrgRow;
use overslash_db::repos::{membership, org_bootstrap};
use uuid::Uuid;

use crate::{AppState, error::AppError};

/// How the human proved they own the pre-created identity.
pub enum AdoptionVia<'a> {
    /// First sign-in through an IdP on the org's own subdomain.
    Sso { provider: &'a str },
    /// Accepted from the dashboard on a session the invitee already held.
    /// The email match against the caller's `users.email` is the proof.
    InAppAccept,
}

impl AdoptionVia<'_> {
    fn provider(&self) -> Option<&str> {
        match self {
            AdoptionVia::Sso { provider } => Some(provider),
            AdoptionVia::InAppAccept => None,
        }
    }

    fn description(&self, email: &str, provisioned_by: &str) -> String {
        match self {
            AdoptionVia::Sso { .. } => format!(
                "{email} signed in for the first time and adopted their pre-created identity ({provisioned_by})"
            ),
            AdoptionVia::InAppAccept => {
                format!("{email} accepted their invitation from the dashboard ({provisioned_by})")
            }
        }
    }
}

/// Link `identity` to `user_id`, bootstrap its groups, and create the org
/// membership. Idempotent on the membership insert (a concurrent adoption
/// racing to the same row is a no-op, not a 500).
///
/// The caller must have already established that `user_id` is entitled to
/// this identity — by IdP subject or by verified email. This function does
/// no admission checks of its own.
pub async fn adopt_pending_identity(
    state: &AppState,
    ext: &axum::http::Extensions,
    org: &OrgRow,
    identity: &IdentityRow,
    user_id: Uuid,
    email: &str,
    via: AdoptionVia<'_>,
) -> Result<(), AppError> {
    overslash_db::repos::identity::set_user_id(state.db(ext), org.id, identity.id, Some(user_id))
        .await?;
    org_bootstrap::bootstrap_user_in_org(state.db(ext), org.id, identity.id).await?;

    // The invite's role lives on the identity: admin invites carry
    // `is_org_admin = true` (set at invite creation / by migration 103).
    // Keep the membership row consistent with it.
    let role = if identity.is_org_admin {
        membership::ROLE_ADMIN
    } else {
        membership::ROLE_MEMBER
    };
    match membership::create(state.db(ext), user_id, org.id, role).await {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {}
        Err(e) => return Err(e.into()),
    }

    let dashboard_url = crate::routes::auth::build_org_redirect(state, org);
    crate::services::welcome_email::send_if_due(state, user_id, org.id, dashboard_url).await;

    // Record the adoption. This is the moment a pre-created identity becomes a
    // human-usable login, so it is the security-relevant event an admin wants
    // to see — especially when the identity was provisioned as a side effect
    // of name-based impersonation rather than an explicit invite.
    // (Provisioning via an admin-minted `impersonate` key IS an admission
    // decision, so this is not a `require_invite_admission` bypass; it is made
    // auditable so the org can tell the two admission paths apart after the
    // fact.)
    let provisioned_by = identity
        .metadata
        .get("provisioned_by")
        .and_then(|v| v.as_str())
        .unwrap_or("invite");
    let scope = OrgScope::new(org.id, state.db_pool(ext));
    let _ = scope
        .log_audit(AuditEntry {
            org_id: org.id,
            identity_id: Some(identity.id),
            action: "identity.adopted",
            resource_type: Some("identity"),
            resource_id: Some(identity.id),
            detail: serde_json::json!({
                "email": email,
                "provider": via.provider(),
                "provisioned_by": provisioned_by,
                "via": match via {
                    AdoptionVia::Sso { .. } => "sso",
                    AdoptionVia::InAppAccept => "in_app_accept",
                },
                "role": role,
            }),
            description: Some(&via.description(email, provisioned_by)),
            ip_address: None,
        })
        .await;

    Ok(())
}
