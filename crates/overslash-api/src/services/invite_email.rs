//! Org-invite notification email. Sent from `POST /v1/org-invites` right
//! after the invite row + audit entry are persisted.
//!
//! **Transactional**, unlike `welcome_email`: the send is triggered by a
//! direct admin action, addressed to a specific person, and the recipient
//! typically has no `users` row yet (the invite is the pre-membership
//! gate for Overslash-managed sign-in — see migration 066). So:
//!
//! * we do **not** check `users.welcome_emails_unsubscribed_at` (there is no
//!   user to check against, and even if one exists this email is one-shot,
//!   not promotional),
//! * we do **not** mint an `email_unsubscribe_tokens` row or add
//!   `List-Unsubscribe` headers (one-click unsubscribe semantics don't apply
//!   to a one-time action notification).
//!
//! Best-effort: every failure mode is logged at `warn` and swallowed so a
//! transient mailer hiccup never breaks invite creation. The invite row is
//! the source of truth; admins can revoke + re-invite if delivery fails.
//! Mirrors the swallow-and-log pattern in [`super::welcome_email`].

use std::collections::HashMap;

use overslash_core::email::{
    EmailMessage, ORG_INVITE_TEMPLATE_HTML, ORG_INVITE_TEMPLATE_SUBJECT, render,
};
use overslash_db::repos::org::OrgRow;
use serde_json::Value;
use uuid::Uuid;

use crate::AppState;
use crate::routes::auth::build_org_redirect;

/// Send the invite notification for a pre-created member identity.
///
/// A pending invite is now an `identities` row (`external_id IS NULL`) rather
/// than an `org_invites` row, so this takes the recipient's `(email, role,
/// identity_id)` directly. `inviter_name` falls back to a generic label when
/// the caller can't resolve a display name for the inviter identity (e.g. the
/// invite was minted via an API key with no user identity).
pub async fn send(
    state: &AppState,
    email: &str,
    role: &str,
    identity_id: Uuid,
    org: &OrgRow,
    inviter_name: Option<&str>,
) {
    let accept_url = build_org_redirect(state, org);
    let inviter_label = inviter_name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("An Overslash admin");

    let mut params: HashMap<String, Value> = HashMap::new();
    params.insert("org_name".into(), Value::String(org.name.clone()));
    params.insert(
        "inviter_name".into(),
        Value::String(inviter_label.to_string()),
    );
    params.insert("role".into(), Value::String(role.to_string()));
    params.insert("accept_url".into(), Value::String(accept_url));

    let html = render(ORG_INVITE_TEMPLATE_HTML, &params);
    let subject = render(ORG_INVITE_TEMPLATE_SUBJECT, &params);

    let msg = EmailMessage {
        from: String::new(), // ResendMailer falls back to default_from
        to: email.to_string(),
        subject,
        html,
        reply_to: None,
        headers: HashMap::new(),
    };

    if let Err(e) = state.mailer.send(msg).await {
        tracing::warn!(
            identity_id = %identity_id,
            org_id = %org.id,
            error = %e,
            "org-invite email send failed",
        );
    }
}
