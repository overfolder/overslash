//! Passwordless email magic-link sign-in email.
//!
//! Categorized as **transactional** — the user just asked for it, one-to-one,
//! so it is not gated by `welcome_emails_unsubscribed_at` and ships without an
//! unsubscribe link (same policy as `invite_email`).
//!
//! Unlike `welcome_email`, the send error is surfaced to the caller so the
//! request handler can drop the just-minted token row (a valid login link that
//! never reached an inbox should not linger). The handler still translates the
//! error into the same opaque `200 {"sent": true}` response so a probing
//! client can't distinguish "sent" from "mailer down".

use std::collections::HashMap;

use overslash_core::email::{
    EmailMessage, MAGIC_LINK_TEMPLATE_HTML, MAGIC_LINK_TEMPLATE_SUBJECT, MailerError, render,
};
use serde_json::Value;

use crate::AppState;

/// Magic-link validity window. Short on purpose: the link is a full session
/// grant, so it must expire well before a leaked inbox could be replayed.
pub const MAGIC_LINK_TOKEN_TTL_SECS: i64 = 15 * 60;

/// Render and send the sign-in email. `verify_url` is the absolute
/// `/auth/magic-link/verify?token=<raw>` URL — the raw token lives only here
/// and in the recipient's inbox.
pub async fn send(state: &AppState, to_email: &str, verify_url: &str) -> Result<(), MailerError> {
    let mut params: HashMap<String, Value> = HashMap::new();
    params.insert("verify_url".into(), Value::String(verify_url.to_string()));
    let html = render(MAGIC_LINK_TEMPLATE_HTML, &params);

    let msg = EmailMessage {
        from: String::new(), // ResendMailer falls back to default_from
        to: to_email.to_string(),
        subject: MAGIC_LINK_TEMPLATE_SUBJECT.to_string(),
        html,
        reply_to: None,
        headers: HashMap::new(),
    };

    state.mailer.send(msg).await
}
