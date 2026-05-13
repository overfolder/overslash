//! Transactional-email abstraction.
//!
//! `Mailer` is the dyn-compatible interface every provider implements. The
//! trait stays in `overslash-core` so internal callers (billing, onboarding,
//! webhook DLQ digest) depend on a pure abstraction rather than a specific
//! provider crate. The HTTP-backed provider impls (Resend, future SendGrid,
//! etc.) live in `overslash-api/services/email.rs` where the shared
//! `reqwest::Client` is constructed.
//!
//! Templates ship as `pub const &'static str` baked in via `include_str!`
//! from `crates/overslash-core/templates/email/`. Use [`render`] to
//! interpolate `{var}` and `[optional]` placeholders — same grammar as
//! action descriptions, but without the 60-char display clamp.

use std::collections::HashMap;

use crate::description::interpolate_template;

pub mod errors;
pub mod mailer;
pub mod noop;

pub use errors::MailerError;
pub use mailer::{EmailMessage, Mailer};
pub use noop::NoopMailer;

/// Smoke-test template — used by the email pipeline integration test and as
/// the canonical example for adding new templates. Not wired to any caller.
pub const TEST_TEMPLATE_SUBJECT: &str = "Overslash email pipeline test";
pub const TEST_TEMPLATE_HTML: &str = include_str!("../../templates/email/test.html");

/// Welcome / first-login email. Sent on root signup and corp-org JIT
/// provisioning. Placeholders: `{display_name}`, `{dashboard_url}`,
/// `{unsubscribe_url}`.
pub const WELCOME_TEMPLATE_SUBJECT: &str = "Welcome to Overslash";
pub const WELCOME_TEMPLATE_HTML: &str = include_str!("../../templates/email/welcome.html");

/// Daily webhook DLQ digest. One email per (org admin, day) when the org has
/// terminal webhook failures in the last 24 hours. Placeholders:
/// `{org_name}`, `{endpoint_count}`, `{rows_html}` (pre-rendered `<tr>` block
/// — the interpolator doesn't loop), `{dashboard_url}`, `{unsubscribe_url}`.
pub const WEBHOOK_DIGEST_TEMPLATE_SUBJECT: &str = "Webhook delivery failures in the last 24 hours";
pub const WEBHOOK_DIGEST_TEMPLATE_HTML: &str =
    include_str!("../../templates/email/webhook_digest.html");

/// Org-invite notification. Transactional (admin-initiated, one-to-one) —
/// not gated by `welcome_emails_unsubscribed_at` and ships without an
/// unsubscribe link or `List-Unsubscribe` header. Placeholders:
/// `{org_name}`, `{inviter_name}`, `{role}`, `{accept_url}`.
pub const ORG_INVITE_TEMPLATE_SUBJECT: &str = "You've been invited to {org_name} on Overslash";
pub const ORG_INVITE_TEMPLATE_HTML: &str = include_str!("../../templates/email/org_invite.html");

/// Billing receipt. Sent on Stripe `invoice.payment_succeeded`. Transactional —
/// exempt from `welcome_emails_unsubscribed_at` by policy (TODO.md §1.1).
/// Placeholders: `{org_name}`, `{amount_display}`, `{currency_upper}`,
/// `{invoice_number}` (optional), `{period_end_display}`,
/// `{hosted_invoice_url}`, `{billing_portal_url}`.
pub const INVOICE_PAID_SUBJECT: &str = "Receipt for your Overslash subscription";
pub const INVOICE_PAID_HTML: &str = include_str!("../../templates/email/invoice_paid.html");

/// Dunning. Sent on Stripe `invoice.payment_failed`. Transactional.
/// Placeholders: `{org_name}`, `{amount_display}`, `{currency_upper}`,
/// `{attempt_count}`, `{next_attempt_display}` (optional),
/// `{billing_portal_url}`.
pub const INVOICE_PAYMENT_FAILED_SUBJECT: &str = "Your Overslash payment didn't go through";
pub const INVOICE_PAYMENT_FAILED_HTML: &str =
    include_str!("../../templates/email/invoice_payment_failed.html");

/// Subscription canceled. Sent on Stripe `customer.subscription.deleted`.
/// Transactional. Placeholders: `{org_name}`, `{access_until_display}`
/// (optional), `{billing_portal_url}`.
pub const SUBSCRIPTION_CANCELED_SUBJECT: &str = "Your Overslash subscription has been canceled";
pub const SUBSCRIPTION_CANCELED_HTML: &str =
    include_str!("../../templates/email/subscription_canceled.html");

/// Interpolate a template with the same grammar action descriptions use,
/// without the display-character cap that would truncate URLs / long values.
pub fn render(template: &str, params: &HashMap<String, serde_json::Value>) -> String {
    interpolate_template(template, params)
}
