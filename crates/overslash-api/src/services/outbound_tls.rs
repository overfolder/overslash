//! TLS on outbound action traffic (CASA 4.1.1).
//!
//! Every request an action call sends can carry a vault value — a bearer, an
//! API key, an OAuth access token — so it goes over `https`. Plain `http` is
//! refused, whether or not this particular call injects anything: an
//! uncredentialed Mode A call is the one case with nothing to leak, and it is
//! not worth a second rule that has to decide, correctly and forever, which
//! calls are "uncredentialed". An agent that wants a plaintext page can fetch
//! it itself.
//!
//! # The one way past it
//!
//! A self-hosted deployment beside its own internal services — a GitLab on
//! `10.42.0.7`, a MinIO on a container network — may genuinely have no TLS
//! there. That deployment already told the SSRF guard so, with
//! `OVERSLASH_SSRF_ALLOWED_CIDRS` (see [`crate::services::ssrf_guard`]); the
//! same declaration is what lets plain `http` through here, and only to an
//! address inside it. No new knob, and nothing a tenant can reach: the
//! multi-tenant deployment never sets that variable, so it never speaks plain
//! `http` to anyone. The integration suite and `scripts/e2e-up.sh` allow
//! loopback that way, which is how their `http://127.0.0.1` fakes keep working.
//!
//! # Two checks, one rule
//!
//! [`check_resolved`] is the enforcement: the transport runs it on every hop,
//! against the address the guard actually pinned, so it is exact. The MCP
//! caller and the upstream OAuth hops (discovery, registration, token exchange
//! — [`crate::routes::oauth_upstream`]) run it the same way.
//!
//! [`check_url`] is the same rule applied to a string, before anything is
//! resolved — at the boundary where an instance `url`, an org layer's
//! `instance_defaults.url` or a template's `mcp.url` is written, and again when
//! a call is resolved, so a doomed request fails with a clear 400 instead of
//! creating an approval nobody can ever execute. Without DNS it can only be
//! decisive for an IP literal or `localhost`; a hostname under an allow-list is
//! let through and left to [`check_resolved`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Url;

use crate::error::AppError;
use crate::services::ssrf_guard;

/// Enforce the rule on a request about to be dialed at `ip`.
///
/// The error names the host, never the URL: on the action path this runs after
/// secret injection, and a vault value can sit in a path or a query.
pub fn check_resolved(url: &Url, ip: &IpAddr) -> Result<(), AppError> {
    check_resolved_with(url, ip, ssrf_guard::operator_allowed_ranges())
}

/// The rule on a URL string, before resolution. See the module docs for what it
/// can and cannot decide.
pub fn check_url(raw: &str) -> Result<(), AppError> {
    check_url_with(raw, ssrf_guard::operator_allowed_ranges())
}

/// [`check_url`] for an endpoint being written — an instance `url`, a layer's
/// `instance_defaults.url`, a template's `mcp.url` — with the field named, so
/// the form that sent it can say which input is wrong.
pub fn check_endpoint(field: &str, raw: &str) -> Result<(), AppError> {
    check_url(raw).map_err(|e| match e {
        AppError::BadRequest(msg) => AppError::BadRequest(format!("`{field}`: {msg}")),
        other => other,
    })
}

fn check_resolved_with(url: &Url, ip: &IpAddr, allowed: &[ipnet::IpNet]) -> Result<(), AppError> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if allowed.iter().any(|net| net.contains(ip)) => Ok(()),
        "http" => Err(plaintext_refused(url.host_str().unwrap_or(""))),
        other => Err(unsupported_scheme(other)),
    }
}

fn check_url_with(raw: &str, allowed: &[ipnet::IpNet]) -> Result<(), AppError> {
    let url = Url::parse(raw).map_err(|e| AppError::BadRequest(format!("invalid URL: {e}")))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" if plaintext_may_reach(&url, allowed) => Ok(()),
        "http" => Err(plaintext_refused(url.host_str().unwrap_or(""))),
        other => Err(unsupported_scheme(other)),
    }
}

/// Whether a plain-`http` URL could land inside an operator-allowed range.
///
/// No allow-list at all is a definite no — the multi-tenant case. An address
/// literal, or `localhost`, can be answered from the string. A hostname cannot,
/// so it gets the benefit of the doubt and [`check_resolved`] decides at
/// dial time.
fn plaintext_may_reach(url: &Url, allowed: &[ipnet::IpNet]) -> bool {
    if allowed.is_empty() {
        return false;
    }
    let covered = |ip: IpAddr| allowed.iter().any(|net| net.contains(&ip));
    match url.host() {
        Some(url::Host::Ipv4(v4)) => covered(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => covered(IpAddr::V6(v6)),
        // Both, not either: `localhost` usually resolves to 127.0.0.1 *and*
        // ::1, and the guard refuses a host if any answer is outside the list —
        // so accepting it on one family would pass a save that no call can use.
        Some(url::Host::Domain(d)) if d.eq_ignore_ascii_case("localhost") => {
            covered(IpAddr::V4(Ipv4Addr::LOCALHOST)) && covered(IpAddr::V6(Ipv6Addr::LOCALHOST))
        }
        Some(url::Host::Domain(_)) => true,
        None => false,
    }
}

fn plaintext_refused(host: &str) -> AppError {
    AppError::BadRequest(format!(
        "refusing plain http:// to {host:?}: Overslash only sends service requests over \
         https://, because they can carry credentials from the vault. Use the https:// \
         endpoint. (A self-hosted deployment reaching its own private network can allow \
         plain http to that range with OVERSLASH_SSRF_ALLOWED_CIDRS.)"
    ))
}

fn unsupported_scheme(scheme: &str) -> AppError {
    AppError::BadRequest(format!(
        "unsupported URL scheme {scheme:?}; service requests must use https://"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nets(list: &[&str]) -> Vec<ipnet::IpNet> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn refused(r: Result<(), AppError>) -> bool {
        matches!(r, Err(AppError::BadRequest(m)) if m.contains("plain http://"))
    }

    #[test]
    fn https_is_always_accepted() {
        for allowed in [nets(&[]), nets(&["127.0.0.0/8"])] {
            assert!(check_url_with("https://api.example.com/x", &allowed).is_ok());
            let url = Url::parse("https://api.example.com/x").unwrap();
            assert!(check_resolved_with(&url, &ip("93.184.216.34"), &allowed).is_ok());
        }
    }

    /// The multi-tenant deployment: no allow-list, so no plain http anywhere —
    /// including loopback, and including a public host.
    #[test]
    fn without_an_allow_list_http_is_refused_everywhere() {
        let none = nets(&[]);
        for raw in [
            "http://api.example.com/x",
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://10.0.0.7",
        ] {
            assert!(refused(check_url_with(raw, &none)), "{raw}");
        }
        let url = Url::parse("http://api.example.com/x").unwrap();
        assert!(refused(check_resolved_with(
            &url,
            &ip("93.184.216.34"),
            &none
        )));
    }

    /// The escape hatch opens the declared range and nothing else — a public
    /// host is still refused, both from the string (literal) and at dial time.
    #[test]
    fn an_allowed_range_permits_http_only_inside_it() {
        let allowed = nets(&["10.42.0.0/16", "127.0.0.0/8", "::1/128"]);
        assert!(check_url_with("http://10.42.0.7:8080/api", &allowed).is_ok());
        assert!(check_url_with("http://localhost:1234", &allowed).is_ok());
        assert!(refused(check_url_with("http://10.99.0.7", &allowed)));
        assert!(refused(check_url_with("http://8.8.8.8", &allowed)));

        let url = Url::parse("http://gitlab.internal/api").unwrap();
        assert!(check_resolved_with(&url, &ip("10.42.0.7"), &allowed).is_ok());
        assert!(refused(check_resolved_with(
            &url,
            &ip("93.184.216.34"),
            &allowed
        )));
    }

    /// A hostname cannot be judged without DNS, so the string check defers it
    /// — but only once an allow-list exists at all.
    #[test]
    fn a_hostname_is_deferred_to_dial_time_under_an_allow_list() {
        assert!(check_url_with("http://gitlab.internal", &nets(&["10.0.0.0/8"])).is_ok());
        assert!(refused(check_url_with(
            "http://gitlab.internal",
            &nets(&[])
        )));
    }

    #[test]
    fn localhost_needs_loopback_in_the_list() {
        assert!(refused(check_url_with(
            "http://localhost:1",
            &nets(&["10.0.0.0/8"])
        )));
        // One family is not enough — see `plaintext_may_reach`.
        assert!(refused(check_url_with(
            "http://localhost:1",
            &nets(&["::1/128"])
        )));
        assert!(check_url_with("http://localhost:1", &nets(&["127.0.0.0/8", "::1/128"])).is_ok());
    }

    #[test]
    fn other_schemes_and_garbage_are_refused() {
        let allowed = nets(&["0.0.0.0/0"]);
        assert!(check_url_with("ftp://10.0.0.1", &allowed).is_err());
        assert!(check_url_with("not a url", &allowed).is_err());
    }

    /// The execution-time message must not echo the URL: it can carry an
    /// injected secret in its query.
    #[test]
    fn the_refusal_names_the_host_not_the_url() {
        let url = Url::parse("http://api.example.com/x?key=s3cret").unwrap();
        let Err(AppError::BadRequest(msg)) =
            check_resolved_with(&url, &ip("93.184.216.34"), &nets(&[]))
        else {
            panic!("expected a refusal");
        };
        assert!(msg.contains("api.example.com"));
        assert!(!msg.contains("s3cret"), "{msg}");
    }
}
