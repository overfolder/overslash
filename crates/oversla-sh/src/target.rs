//! Which URLs the shortener will point at.
//!
//! oversla.sh only ever shortens links the Overslash API mints for a human —
//! approvals, secret requests, OAuth captures — all on an Overslash host. Any
//! other destination makes it an open redirector for whoever holds the API
//! key, so both minting and redirecting check the target against this policy.

use url::{Host, Url};

/// Default for `ALLOWED_REDIRECT_DOMAINS`.
pub const DEFAULT_ALLOWED_DOMAINS: &[&str] = &["overslash.com"];

/// Normalise one configured domain: trim, lowercase, drop a leading `.`.
/// `None` for an empty entry; `Err` for one that is not a bare hostname.
pub fn parse_domain(raw: &str) -> Result<Option<String>, String> {
    let d = raw.trim().trim_start_matches('.').to_ascii_lowercase();
    if d.is_empty() {
        return Ok(None);
    }
    if d.contains(|c: char| c == '/' || c == ':' || c == '*' || c == '@' || c.is_whitespace()) {
        return Err(format!("{raw:?} is not a bare domain"));
    }
    Ok(Some(d))
}

/// `true` iff `url` is `https`, carries no userinfo, and its host is one of
/// `allowed` or a subdomain of one. Suffix matching happens on a label
/// boundary, so `evil-overslash.com` does not match `overslash.com`.
pub fn is_allowed(url: &Url, allowed: &[String]) -> bool {
    if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    // `Url` lowercases domain hosts; IP literals never match.
    let Some(Host::Domain(host)) = url.host() else {
        return false;
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    allowed.iter().any(|d| {
        host == d
            || host
                .strip_suffix(d.as_str())
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(url: &str) -> bool {
        is_allowed(&Url::parse(url).unwrap(), &["overslash.com".to_string()])
    }

    #[test]
    fn overslash_hosts_are_allowed() {
        for url in [
            "https://overslash.com",
            "https://app.overslash.com/approvals/abc?token=x",
            "https://acme.app.overslash.com/x",
            "https://api.dev.overslash.com/oauth/x",
            "https://OVERSLASH.COM/",
            "https://app.overslash.com./x",
            "https://app.overslash.com:8443/x",
        ] {
            assert!(allowed(url), "{url} should be allowed");
        }
    }

    #[test]
    fn everything_else_is_refused() {
        for url in [
            "https://example.com",
            "https://evil-overslash.com",
            "https://overslash.com.evil.net",
            "https://overslash.co",
            "http://app.overslash.com",
            "ftp://app.overslash.com",
            "https://app.overslash.com@evil.net/",
            "https://user@app.overslash.com/",
            "https://user:pw@app.overslash.com/",
            "https://127.0.0.1/",
            "https://[::1]/",
        ] {
            assert!(!allowed(url), "{url} should be refused");
        }
    }

    #[test]
    fn domains_are_normalised() {
        assert_eq!(
            parse_domain("  .Overslash.COM ").unwrap().as_deref(),
            Some("overslash.com")
        );
        assert_eq!(parse_domain(" ").unwrap(), None);
        for bad in [
            "*.overslash.com",
            "https://overslash.com",
            "overslash.com:443",
            "a b",
        ] {
            assert!(parse_domain(bad).is_err(), "{bad} should be rejected");
        }
    }
}
