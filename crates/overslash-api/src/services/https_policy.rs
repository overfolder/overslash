//! Where plain `http` is tolerated on an outbound call: nowhere, except to
//! loopback, and only when the SSRF guard already lets loopback through.
//!
//! Loopback is refused by the guard's deny-list unless the operator puts it on
//! `OVERSLASH_SSRF_ALLOWED_CIDRS` — which is exactly what the test suite and
//! `scripts/e2e-up.sh` do for their fakes, and what a self-hoster does for a
//! receiver on the same box. So there is no second knob: the one allow-list
//! decides both "may we dial it" and "may we dial it in the clear". A private
//! range on the allow-list still does **not** get plain `http` — a receiver on
//! the operator's network still speaks TLS; only traffic that never leaves the
//! host may skip it.
//!
//! Two checks, used together by every caller:
//!
//! - [`HttpsUrl::parse`] at the input boundary, from the string alone, before
//!   any lookup — so a bad URL is a 400 at registration, not a failure on the
//!   first delivery.
//! - [`scheme_allowed`] per request, on the address the guard resolved and
//!   pinned — so `localhost` that resolves elsewhere, a row written before the
//!   boundary check existed, or a redirect cannot get past it either.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Url;

use crate::services::ssrf_guard;

/// `https` anywhere the guard allows; `http` only to loopback.
pub fn scheme_allowed(scheme: &str, ip: &IpAddr) -> bool {
    match scheme {
        "https" => true,
        "http" => is_loopback(ip),
        _ => false,
    }
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4().is_some_and(|m| m.is_loopback()),
    }
}

/// Whether the URL's host is written as loopback: `localhost` or a loopback
/// literal. Only a pre-filter — the resolved address is what counts.
pub fn names_loopback(url: &Url) -> bool {
    !loopback_addresses(url).is_empty()
}

/// Every loopback address the URL's host could be dialed at, if it spells
/// loopback at all. A literal is itself. `localhost` is **both** `127.0.0.1`
/// and `::1`: the resolver may answer with either or both, and the guard
/// refuses the call if *any* answer is blocked — so registration has to clear
/// both, or an allow-list covering only one family accepts a URL that no
/// delivery can reach.
fn loopback_addresses(url: &Url) -> Vec<IpAddr> {
    let ips = match url.host() {
        Some(url::Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") => vec![
            IpAddr::from(Ipv4Addr::LOCALHOST),
            IpAddr::from(Ipv6Addr::LOCALHOST),
        ],
        Some(url::Host::Ipv4(v4)) => vec![IpAddr::V4(v4)],
        Some(url::Host::Ipv6(v6)) => vec![IpAddr::V6(v6)],
        Some(url::Host::Domain(_)) | None => return Vec::new(),
    };
    if ips.iter().all(is_loopback) {
        ips
    } else {
        Vec::new()
    }
}

/// A URL that is safe to send credentials or signed payloads to as far as
/// transport goes: `https`, or `http` to a loopback host the SSRF guard's
/// allow-list covers.
///
/// Parsed at the boundary (CLAUDE.md rule 2) so the rest of the code holds a
/// value that already passed, rather than a `String` that might have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsUrl(Url);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HttpsUrlError {
    #[error("URL does not parse ({0})")]
    Invalid(String),
    #[error("URL has no host")]
    NoHost,
    #[error(
        "URL must use https:// (plain http:// is only accepted to localhost, and only when the \
         deployment allow-lists loopback)"
    )]
    NotHttps,
}

impl HttpsUrl {
    pub fn parse(raw: &str) -> Result<Self, HttpsUrlError> {
        Self::parse_with(raw, ssrf_guard::default_policy)
    }

    /// [`Self::parse`] with the guard's policy supplied, so the decision table
    /// is testable without mutating the process-wide allow-list.
    fn parse_with(raw: &str, is_blocked: impl Fn(&IpAddr) -> bool) -> Result<Self, HttpsUrlError> {
        let url = Url::parse(raw.trim()).map_err(|e| HttpsUrlError::Invalid(e.to_string()))?;
        match url.scheme() {
            "https" => {}
            "http" => {
                let ips = loopback_addresses(&url);
                if ips.is_empty() || ips.iter().any(&is_blocked) {
                    return Err(HttpsUrlError::NotHttps);
                }
            }
            _ => return Err(HttpsUrlError::NotHttps),
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err(HttpsUrlError::NoHost);
        }
        Ok(Self(url))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn https_is_accepted_wherever_the_guard_allows() {
        assert!(scheme_allowed("https", &ip("8.8.8.8")));
        assert!(scheme_allowed("https", &ip("127.0.0.1")));
    }

    #[test]
    fn http_is_accepted_only_to_loopback() {
        assert!(scheme_allowed("http", &ip("127.0.0.1")));
        assert!(scheme_allowed("http", &ip("::1")));
        assert!(scheme_allowed("http", &ip("::ffff:127.0.0.1")));

        assert!(!scheme_allowed("http", &ip("8.8.8.8")));
        assert!(!scheme_allowed("http", &ip("10.0.0.1")));
        assert!(!scheme_allowed("http", &ip("fd00::1")));
    }

    #[test]
    fn other_schemes_are_refused() {
        assert!(!scheme_allowed("ftp", &ip("127.0.0.1")));
    }

    #[test]
    fn loopback_hosts_are_recognised_from_the_string() {
        for url in [
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://[::1]:9",
        ] {
            assert!(names_loopback(&Url::parse(url).unwrap()), "{url}");
        }
        for url in ["http://issuer.example", "http://10.0.0.1"] {
            assert!(!names_loopback(&Url::parse(url).unwrap()), "{url}");
        }
    }

    const LOOPBACK_ALLOWED: fn(&IpAddr) -> bool = |_| false;
    const LOOPBACK_BLOCKED: fn(&IpAddr) -> bool = |ip| is_loopback(ip);

    #[test]
    fn https_urls_parse() {
        let u = HttpsUrl::parse_with("https://hooks.example.com/x", LOOPBACK_BLOCKED).unwrap();
        assert_eq!(u.as_str(), "https://hooks.example.com/x");
    }

    #[test]
    fn plain_http_to_a_public_or_private_host_is_refused_even_when_allow_listed() {
        for raw in ["http://hooks.example.com/x", "http://10.0.0.5/x"] {
            assert_eq!(
                HttpsUrl::parse_with(raw, LOOPBACK_ALLOWED),
                Err(HttpsUrlError::NotHttps),
                "{raw}"
            );
        }
    }

    #[test]
    fn plain_http_to_loopback_follows_the_guard_allow_list() {
        for raw in [
            "http://127.0.0.1:9/x",
            "http://localhost/x",
            "http://[::1]:8080/",
        ] {
            assert!(HttpsUrl::parse_with(raw, LOOPBACK_ALLOWED).is_ok(), "{raw}");
            assert_eq!(
                HttpsUrl::parse_with(raw, LOOPBACK_BLOCKED),
                Err(HttpsUrlError::NotHttps),
                "{raw}"
            );
        }
    }

    /// An allow-list of `127.0.0.0/8` alone: IPv4 loopback reachable, `::1`
    /// still on the deny-list.
    const ONLY_V4_LOOPBACK_ALLOWED: fn(&IpAddr) -> bool =
        |ip| !matches!(ip, IpAddr::V4(v4) if v4.is_loopback()) && is_loopback(ip);

    /// Delivery refuses if *any* address `localhost` resolves to is blocked,
    /// and the resolver may hand back `::1`. So `localhost` registers only when
    /// both families are allowed; a literal needs only its own.
    #[test]
    fn plain_http_to_localhost_needs_both_loopback_families_allowed() {
        assert_eq!(
            HttpsUrl::parse_with("http://localhost:8080/x", ONLY_V4_LOOPBACK_ALLOWED),
            Err(HttpsUrlError::NotHttps)
        );
        assert!(HttpsUrl::parse_with("http://127.0.0.1:8080/x", ONLY_V4_LOOPBACK_ALLOWED).is_ok());
        assert_eq!(
            HttpsUrl::parse_with("http://[::1]:8080/x", ONLY_V4_LOOPBACK_ALLOWED),
            Err(HttpsUrlError::NotHttps)
        );
    }

    #[test]
    fn other_schemes_and_garbage_are_refused() {
        assert_eq!(
            HttpsUrl::parse_with("ftp://127.0.0.1/", LOOPBACK_ALLOWED),
            Err(HttpsUrlError::NotHttps)
        );
        assert_eq!(
            HttpsUrl::parse_with("javascript:alert(1)", LOOPBACK_ALLOWED),
            Err(HttpsUrlError::NotHttps)
        );
        assert!(matches!(
            HttpsUrl::parse_with("not a url", LOOPBACK_ALLOWED),
            Err(HttpsUrlError::Invalid(_))
        ));
    }
}
