use async_trait::async_trait;

use super::errors::MailerError;
use super::mailer::{EmailMessage, Mailer};

/// Mailer used when `EMAIL_PROVIDER` is unset. Logs the would-be send at
/// `info` level and returns `Ok(())`. Lets local dev, the test suite, and
/// self-hosted operators boot without provider credentials — callers stay
/// oblivious to whether email is wired.
pub struct NoopMailer;

#[async_trait]
impl Mailer for NoopMailer {
    async fn send(&self, msg: EmailMessage) -> Result<(), MailerError> {
        tracing::info!(
            to = %msg.to,
            from = %msg.from,
            subject = %msg.subject,
            "noop mailer: dropping email (no EMAIL_PROVIDER configured)"
        );
        Ok(())
    }
}
