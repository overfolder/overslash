//! SSRF-safe outbound HTTP: resolve the URL's host once, reject private /
//! loopback / link-local / carrier-grade-NAT addresses, and pin the
//! validated IP via reqwest's `resolve` override to close the DNS-rebinding
//! window between validation and dial.
//!
//! Shared by template OpenAPI import and MCP dispatch (`/actions/call` +
//! `/templates/:key/mcp/resync`) so every user-controllable outbound URL
//! goes through the same gate.

use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

use url::Url;

use crate::error::AppError;

pub fn is_disallowed_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_documentation()
                // carrier-grade NAT 100.64.0.0/10
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                // unique local fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped (::ffff:x.x.x.x) and IPv4-compatible (::x.x.x.x) — recurse as v4.
                // to_ipv4() covers both formats; to_ipv4_mapped() only catches the ::ffff: variant.
                || v6.to_ipv4().map(|m| is_disallowed_ip(&IpAddr::V4(m))).unwrap_or(false)
        }
    }
}

/// Validate a user-controlled URL and return a reqwest client that will
/// only connect to the validated IP. The client carries connect/read
/// timeouts and disables redirects so a cooperative server cannot 3xx us
/// to an internal host after the initial validation.
///
/// Returns `AppError::BadRequest` for any input the SSRF guard rejects
/// (non-http schemes, unresolvable hosts, private/loopback/link-local IPs).
/// `AppError::Internal` only for resolver join failures and client builder
/// failures — both of which indicate host-level problems, not caller input.
pub async fn build_pinned_client(
    url_str: &str,
    timeout: Duration,
) -> Result<(reqwest::Client, Url), AppError> {
    // Integration tests point MCP clients at loopback axum stubs. Expose a
    // single escape hatch — `OVERSLASH_SSRF_ALLOW_PRIVATE=1` — so tests can
    // opt out. Production never sets this; the binary and infra don't read
    // it. Keeping the hatch at the env-var boundary avoids introducing a
    // third-party test-only code path through every caller.
    if std::env::var("OVERSLASH_SSRF_ALLOW_PRIVATE").as_deref() == Ok("1") {
        return build_pinned_client_with_policy(url_str, timeout, |_| false).await;
    }
    build_pinned_client_with_policy(url_str, timeout, is_disallowed_ip).await
}

/// Test seam for `build_pinned_client`. Production callers go through
/// [`build_pinned_client`]; integration tests that need to point at a
/// loopback mock inject a permissive policy so the guard doesn't trip.
pub async fn build_pinned_client_with_policy<F>(
    url_str: &str,
    timeout: Duration,
    is_blocked: F,
) -> Result<(reqwest::Client, Url), AppError>
where
    F: Fn(&IpAddr) -> bool,
{
    let parsed = Url::parse(url_str)
        .map_err(|e| AppError::BadRequest(format!("invalid URL {url_str:?}: {e}")))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(AppError::BadRequest(format!(
            "unsupported URL scheme {scheme:?}; only http(s) are allowed"
        )));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| AppError::BadRequest("URL has no host".into()))?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| AppError::BadRequest("URL has no port".into()))?;

    let host_for_resolve = host.clone();
    let addrs: Vec<IpAddr> = tokio::task::spawn_blocking(move || {
        (host_for_resolve.as_str(), port)
            .to_socket_addrs()
            .map(|iter| iter.map(|a| a.ip()).collect::<Vec<_>>())
    })
    .await
    .map_err(|e| AppError::Internal(format!("dns resolver join error: {e}")))?
    .map_err(|e| AppError::BadRequest(format!("could not resolve host {host:?}: {e}")))?;

    if addrs.is_empty() {
        return Err(AppError::BadRequest(format!(
            "host {host:?} resolved to no addresses"
        )));
    }
    for ip in &addrs {
        if is_blocked(ip) {
            return Err(AppError::BadRequest(format!(
                "refusing to connect to {ip}: private / loopback / link-local addresses are blocked"
            )));
        }
    }

    let pinned_ip = addrs[0];
    let pinned_sock = std::net::SocketAddr::new(pinned_ip, port);
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(timeout)
        .timeout(timeout)
        .resolve(&host, pinned_sock)
        .build()
        .map_err(|e| AppError::Internal(format!("could not build pinned client: {e}")))?;

    Ok((client, parsed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn blocks_ipv4_loopback_and_private_and_cgnat() {
        assert!(is_disallowed_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_disallowed_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_disallowed_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_disallowed_ip(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
        assert!(is_disallowed_ip(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)))); // CGN
    }

    #[test]
    fn allows_ipv4_public() {
        assert!(!is_disallowed_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_disallowed_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn blocks_ipv6_loopback_ula_linklocal() {
        assert!(is_disallowed_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        let ula: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(is_disallowed_ip(&IpAddr::V6(ula)));
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_disallowed_ip(&IpAddr::V6(ll)));
    }

    #[test]
    fn blocks_ipv4_mapped_private() {
        let mapped: Ipv6Addr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(is_disallowed_ip(&IpAddr::V6(mapped)));
    }

    #[test]
    fn blocks_ipv4_compatible_private() {
        // Deprecated IPv4-compatible format ::x.x.x.x (no ::ffff: prefix).
        // to_ipv4() catches this; to_ipv4_mapped() would miss it.
        let compat: Ipv6Addr = "::10.0.0.1".parse().unwrap();
        assert!(is_disallowed_ip(&IpAddr::V6(compat)));
        let loopback_compat: Ipv6Addr = "::127.0.0.1".parse().unwrap();
        assert!(is_disallowed_ip(&IpAddr::V6(loopback_compat)));
    }

    #[tokio::test]
    async fn rejects_non_http_scheme() {
        let err = build_pinned_client("ftp://example.com/path", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn rejects_malformed_url() {
        let err = build_pinned_client("not a url", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[tokio::test]
    async fn rejects_private_host_via_guard() {
        // IP-literal URL so the test doesn't rely on DNS being available.
        // The injected policy blocks every address, so the guard must trip
        // even on a well-formed address.
        let err = build_pinned_client_with_policy(
            "http://8.8.8.8:80",
            Duration::from_secs(5),
            |_| true, // always block
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }
}
