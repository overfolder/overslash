//! Gate-flow TTL, caller-supplied `return_url` parsing, and the default
//! OAuth callback `redirect_uri`.
//!
//! Deliberately does *not* `use super::*`: the glob would pull this
//! module's own name into scope and shadow the `url` crate that
//! [`parse_return_url`] parses with.

use time::Duration as TimeDuration;

use crate::error::AppError;

/// Gate-flow TTL. Matches `mcp_upstream_flow` (10 min) — long enough to
/// survive a chat delivery + email round-trip, short enough that an
/// abandoned link doesn't sit forever.
pub(super) const FLOW_TTL: TimeDuration = TimeDuration::minutes(10);

/// Maximum byte length for caller-supplied `return_url`. Cap is generous
/// (we don't expect tenants to pack significant data into the URL) but
/// finite — keeps the DB column honest and the redirect header sane.
const RETURN_URL_MAX_LEN: usize = 2048;

/// Parse and validate a caller-supplied `return_url`. Allow-list membership
/// is intentionally **not** checked here — that gate lives at the callback
/// so an allow-list misconfiguration falls back to JSON instead of
/// breaking flow creation. See [`oauth_callback`].
pub(crate) fn parse_return_url(raw: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if raw.len() > RETURN_URL_MAX_LEN {
        return Err(AppError::BadRequest(format!(
            "return_url exceeds {RETURN_URL_MAX_LEN}-byte limit"
        )));
    }
    let parsed = url::Url::parse(raw)
        .map_err(|e| AppError::BadRequest(format!("return_url is not a valid URL: {e}")))?;
    // `url::Url::parse` accepts relative-looking inputs like `foo:bar` as
    // opaque-data URLs; require a real authority with a host instead.
    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::BadRequest("return_url must include a host".into()))?
        .to_ascii_lowercase();
    let scheme = parsed.scheme();
    let scheme_ok = scheme == "https"
        || (scheme == "http" && matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1"));
    if !scheme_ok {
        return Err(AppError::BadRequest(
            "return_url must use https (http allowed only for localhost)".into(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(AppError::BadRequest(
            "return_url must not contain a fragment".into(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(AppError::BadRequest(
            "return_url must not contain userinfo".into(),
        ));
    }
    Ok(Some(parsed.into()))
}

/// The provider `redirect_uri`: `{public_url}/v1/oauth/callback`. Every
/// orchestrated OAuth flow uses this single default at both authorize build
/// and token exchange — white-label partners no longer orchestrate through
/// Overslash (they import tokens via `/v1/connections/import`), so there is no
/// per-flow or per-org redirect override any more.
pub(crate) fn default_callback_redirect_uri(public_url: &str) -> String {
    format!("{}/v1/oauth/callback", public_url.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_return_url_accepts_https() {
        let parsed = parse_return_url(Some("https://cloud.overfolder.com/cb"))
            .expect("valid")
            .expect("present");
        assert_eq!(parsed, "https://cloud.overfolder.com/cb");
    }

    #[test]
    fn parse_return_url_accepts_http_localhost() {
        let parsed = parse_return_url(Some("http://localhost:5173/cb?ref=x"))
            .expect("valid")
            .expect("present");
        assert_eq!(parsed, "http://localhost:5173/cb?ref=x");
    }

    #[test]
    fn parse_return_url_none_and_blank_pass_through_as_none() {
        assert!(parse_return_url(None).unwrap().is_none());
        assert!(parse_return_url(Some("")).unwrap().is_none());
        assert!(parse_return_url(Some("   ")).unwrap().is_none());
    }

    #[test]
    fn parse_return_url_rejects_plain_http_non_localhost() {
        assert!(parse_return_url(Some("http://evil.example.com/cb")).is_err());
    }

    #[test]
    fn parse_return_url_rejects_fragment() {
        assert!(parse_return_url(Some("https://cloud.overfolder.com/cb#frag")).is_err());
    }

    #[test]
    fn parse_return_url_rejects_userinfo() {
        assert!(parse_return_url(Some("https://attacker@cloud.overfolder.com/cb")).is_err());
        assert!(parse_return_url(Some("https://u:p@cloud.overfolder.com/cb")).is_err());
    }

    #[test]
    fn parse_return_url_rejects_overlong() {
        let mut s = String::from("https://cloud.overfolder.com/");
        s.extend(std::iter::repeat_n('a', RETURN_URL_MAX_LEN));
        assert!(parse_return_url(Some(&s)).is_err());
    }

    #[test]
    fn parse_return_url_rejects_relative_and_unparseable() {
        assert!(parse_return_url(Some("/just/a/path")).is_err());
        assert!(parse_return_url(Some("not a url")).is_err());
        // Schemes without an authority (no host) — e.g. `mailto:`,
        // `javascript:` — must be rejected so the redirect can't escape
        // to a non-HTTP target.
        assert!(parse_return_url(Some("javascript:alert(1)")).is_err());
        assert!(parse_return_url(Some("mailto:foo@example.com")).is_err());
    }
    #[test]
    fn default_callback_redirect_uri_trims_trailing_slash() {
        assert_eq!(
            default_callback_redirect_uri("https://api.overslash.com/"),
            "https://api.overslash.com/v1/oauth/callback"
        );
        assert_eq!(
            default_callback_redirect_uri("https://api.overslash.com"),
            "https://api.overslash.com/v1/oauth/callback"
        );
    }
}
