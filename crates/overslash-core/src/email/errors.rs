use thiserror::Error;

#[derive(Debug, Error)]
pub enum MailerError {
    /// Network / transport failure reaching the provider.
    #[error("email transport error: {0}")]
    Transport(String),
    /// Provider returned a non-success status. Body is captured so the caller
    /// (and operators reading logs) can see the upstream error verbatim.
    #[error("email provider rejected request: {status} {body}")]
    Upstream { status: u16, body: String },
}
