use std::collections::HashMap;

use async_trait::async_trait;

use super::errors::MailerError;

/// A single outbound transactional email. Fields map 1:1 to the
/// provider-agnostic surface — `from`, `to`, `subject`, an HTML body, and an
/// optional `Reply-To`. Plaintext-alternative bodies are deferred until a
/// caller needs them (no current call site does).
///
/// `headers` is forwarded verbatim to the provider's `headers` field. The
/// welcome-email caller uses it to attach RFC 8058 `List-Unsubscribe` /
/// `List-Unsubscribe-Post` headers so Gmail's native unsubscribe button
/// works. Defaults to an empty map; providers skip serialization when empty.
#[derive(Debug, Clone, Default)]
pub struct EmailMessage {
    pub from: String,
    pub to: String,
    pub subject: String,
    pub html: String,
    pub reply_to: Option<String>,
    pub headers: HashMap<String, String>,
}

/// Outbound transactional-email sender. Implementations are kept thin: pick
/// a provider, mint an HTTP request, propagate transport / upstream errors
/// via [`MailerError`]. No retries, no template rendering — those belong to
/// the caller, alongside whichever audit / metric surface they want.
#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, msg: EmailMessage) -> Result<(), MailerError>;
}
