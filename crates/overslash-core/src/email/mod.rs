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

/// Interpolate a template with the same grammar action descriptions use,
/// without the display-character cap that would truncate URLs / long values.
pub fn render(template: &str, params: &HashMap<String, serde_json::Value>) -> String {
    interpolate_template(template, params)
}
