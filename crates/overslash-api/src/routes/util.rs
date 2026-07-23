//! Helpers shared across route handlers.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::{AppError, Result};

/// Serialize an `OffsetDateTime` as an RFC3339 string for API responses.
///
/// The frontend parses these via `Date.parse()` which accepts RFC3339 but not
/// the `time` crate's default `Display` format. Using `.to_string()` instead
/// of this helper reintroduces the "Invalid Date" bug.
pub fn fmt_time(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_else(|_| t.to_string())
}

/// Structural email check + normalization to lower-case, shared by the
/// invite path and any other caller that persists a user email. This is a
/// cheap gate matching the dashboard's client-side check — real verification
/// comes from the IdP at sign-in — but it also keeps header/body-smuggled
/// whitespace out of stored emails.
pub fn validate_email(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("email is required".into()));
    }
    if !trimmed.contains('@') || trimmed.contains(' ') {
        return Err(AppError::BadRequest("invalid email".into()));
    }
    Ok(trimmed.to_lowercase())
}
