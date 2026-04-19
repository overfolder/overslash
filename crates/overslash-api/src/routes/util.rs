//! Helpers shared across route handlers.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Serialize an `OffsetDateTime` as an RFC3339 string for API responses.
///
/// The frontend parses these via `Date.parse()` which accepts RFC3339 but not
/// the `time` crate's default `Display` format. Using `.to_string()` instead
/// of this helper reintroduces the "Invalid Date" bug.
pub fn fmt_time(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_else(|_| t.to_string())
}
