//! Org slug validation: format rules, reserved subdomains and the
//! stable rejection codes the dashboard renders.

/// Slug rejection reason, kept as a stable string so the dashboard can render
/// human-readable copy without string-matching error messages.
#[derive(Debug, Clone, Copy)]
pub(super) enum SlugReject {
    TooShort,
    TooLong,
    InvalidChars,
    LeadingOrTrailingHyphen,
    Reserved,
}

impl SlugReject {
    pub(super) fn code(self) -> &'static str {
        match self {
            SlugReject::TooShort => "slug_too_short",
            SlugReject::TooLong => "slug_too_long",
            SlugReject::InvalidChars => "slug_invalid_chars",
            SlugReject::LeadingOrTrailingHyphen => "slug_leading_or_trailing_hyphen",
            SlugReject::Reserved => "slug_reserved",
        }
    }
}

const SLUG_MIN: usize = 2;
// DNS label max is 63 octets. We use the slug as a subdomain label, so
// anything above that cannot be represented as `<slug>.<apex>`.
const SLUG_MAX: usize = 63;

/// Subdomains we can't route to an org because the middleware already
/// reserves them for the root apex or operator-controlled hosts. Keep in
/// sync with `middleware::subdomain`.
const RESERVED_SLUGS: &[&str] = &[
    "www",
    "app",
    "api",
    "auth",
    "admin",
    "dashboard",
    "root",
    "static",
    "mcp",
];

/// Validate slug format without touching the DB. Mirrors DNS-label rules and
/// the dashboard's client-side check.
/// Public wrapper used by the billing route to validate a slug before Stripe
/// round-trips. Returns the rejection code as a static str on error.
pub(crate) fn validate_slug_format_pub(slug: &str) -> std::result::Result<(), &'static str> {
    validate_slug_format(slug).map_err(|r| r.code())
}

pub(super) fn validate_slug_format(slug: &str) -> std::result::Result<(), SlugReject> {
    if slug.len() < SLUG_MIN {
        return Err(SlugReject::TooShort);
    }
    if slug.len() > SLUG_MAX {
        return Err(SlugReject::TooLong);
    }
    if !slug
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(SlugReject::InvalidChars);
    }
    if slug.starts_with('-') || slug.ends_with('-') {
        return Err(SlugReject::LeadingOrTrailingHyphen);
    }
    if RESERVED_SLUGS.contains(&slug) {
        return Err(SlugReject::Reserved);
    }
    Ok(())
}
