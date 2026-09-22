//! SSRF-safe outbound HTTP: resolve the URL's host once, reject private /
//! loopback / link-local / carrier-grade-NAT addresses, and pin the
//! validated IP via reqwest's `resolve` override to close the DNS-rebinding
//! window between validation and dial.
//!
//! Every outbound request whose URL a caller can influence goes through here:
//! template OpenAPI import, MCP dispatch, OAuth upstream discovery, the
//! action-execution transport ([`crate::services::http_caller`]) and webhook
//! delivery ([`crate::services::webhook_dispatcher`]).
//!
//! # Two entry points, one policy
//!
//! [`build_pinned_client`] hands back a single-use client with a total
//! deadline baked in — right for a one-shot discovery fetch. [`outbound_client`]
//! is the hot path: the same resolution and the same policy on every call, but
//! the client is cached per validated `(host, port, ip)` so a proxied action
//! call doesn't pay a TCP + TLS handshake that keep-alive already paid for.
//! See [`outbound_client`] for why reusing a client cannot re-open the
//! rebinding window the pin closes.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

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

/// Loopback in either family, including the v4-in-v6 spellings.
fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4().map(|m| m.is_loopback()).unwrap_or(false)
        }
    }
}

/// The policy every production caller runs under.
///
/// Integration tests and `scripts/e2e-up.sh` point Mode A / Mode C / MCP at
/// axum fakes bound to 127.0.0.1 (and at `localtest.me` subdomains that
/// resolve there), so `OVERSLASH_SSRF_ALLOW_PRIVATE=1` opens **loopback, and
/// only loopback**. A blanket bypass would mean the integration suite could
/// never prove the guard refuses the addresses that actually matter — the
/// cloud metadata endpoint at 169.254.169.254, RFC1918, CGNAT — because the
/// one env var that makes the fakes reachable would make those reachable too.
/// Narrowing it keeps the fakes working and keeps the refusal tests honest.
///
/// Production never sets the var: neither the binary nor the infra reads it.
pub fn default_policy(ip: &IpAddr) -> bool {
    if is_loopback(ip) && std::env::var("OVERSLASH_SSRF_ALLOW_PRIVATE").as_deref() == Ok("1") {
        return false;
    }
    is_disallowed_ip(ip)
}

/// A URL that cleared the guard: parsed, resolved, and reduced to the one
/// address we are willing to dial.
struct Validated {
    url: Url,
    host: String,
    port: u16,
    ip: IpAddr,
}

/// Parse, resolve, and check every address the host answers with.
///
/// *Every* address, not just the one we end up dialing: a host that resolves
/// to a public address and a private one is a rebinding attempt wearing a
/// round-robin costume, and there is no legitimate upstream that looks like
/// that.
async fn resolve_and_validate<F>(url_str: &str, is_blocked: F) -> Result<Validated, AppError>
where
    F: Fn(&IpAddr) -> bool,
{
    // The message deliberately does not echo `url_str`. On the action path
    // this function runs *after* secret injection, so the string can carry a
    // vault value in its path or query — the same reason
    // `audit_capture::scrub_transport_error` never prints a resolved URL.
    // `url::ParseError`'s Display names the defect without quoting the input.
    let parsed =
        Url::parse(url_str).map_err(|e| AppError::BadRequest(format!("invalid URL: {e}")))?;

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

    let ip = addrs[0];
    Ok(Validated {
        url: parsed,
        host,
        port,
        ip,
    })
}

/// A client that can only ever dial `v.ip`, and will not follow a redirect
/// away from it.
fn pinned_client(
    v: &Validated,
    connect_timeout: Duration,
    total_timeout: Option<Duration>,
) -> Result<reqwest::Client, AppError> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(connect_timeout)
        .resolve(&v.host, SocketAddr::new(v.ip, v.port));
    if let Some(t) = total_timeout {
        builder = builder.timeout(t);
    }
    builder
        .build()
        .map_err(|e| AppError::Internal(format!("could not build pinned client: {e}")))
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
    build_pinned_client_with_policy(url_str, timeout, default_policy).await
}

/// Test seam for `build_pinned_client`. Production callers go through
/// [`build_pinned_client`]; the template-import path injects a permissive
/// policy from its own tests so it can point at a loopback mock.
pub async fn build_pinned_client_with_policy<F>(
    url_str: &str,
    timeout: Duration,
    is_blocked: F,
) -> Result<(reqwest::Client, Url), AppError>
where
    F: Fn(&IpAddr) -> bool,
{
    let v = resolve_and_validate(url_str, is_blocked).await?;
    let client = pinned_client(&v, timeout, Some(timeout))?;
    Ok((client, v.url))
}

// ── The hot path ────────────────────────────────────────────────────────

/// Connect budget for the pooled outbound clients.
///
/// Fixed rather than per-call, because the per-call deadline belongs on the
/// *request* (`RequestBuilder::timeout`), not on a client that several calls
/// share — and a client whose configuration varied per call could not be
/// pooled at all. A short per-call deadline still bounds connect: it is a
/// total deadline and connect happens inside it.
const OUTBOUND_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an unused pooled client is kept. Long enough to span a burst of
/// calls to the same upstream, short enough that a host nobody talks to any
/// more stops holding idle sockets.
const CLIENT_TTL: Duration = Duration::from_secs(300);

/// Ceiling on distinct cached clients. The key is caller-influenced (any host
/// reachable from a Mode A call), so it needs a bound; on overflow the cache
/// is emptied rather than evicted one-by-one, because the failure mode we are
/// bounding is a sweep across thousands of hosts, where no entry is hot.
const MAX_CACHED_CLIENTS: usize = 512;

/// `(host, port, validated ip)` — the IP is *in* the key, which is the whole
/// reason the cache is safe. See [`outbound_client`].
type ClientKey = (String, u16, IpAddr);

struct CachedClient {
    client: reqwest::Client,
    last_used: Instant,
}

fn cache() -> &'static Mutex<HashMap<ClientKey, CachedClient>> {
    static CACHE: OnceLock<Mutex<HashMap<ClientKey, CachedClient>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
fn cached_client_count() -> usize {
    cache().lock().unwrap_or_else(|e| e.into_inner()).len()
}

/// The guarded client for an outbound action or webhook request.
///
/// Runs the full guard — parse, resolve, check every returned address — on
/// **every call**, then reuses a pinned client when one already exists for the
/// address this call validated.
///
/// # Why a cached client is still rebinding-proof
///
/// The pin is what closes the window between "we checked this IP" and "we
/// dialed"; caching does not widen it, because the validated IP is part of the
/// cache key. A hit means this call resolved to exactly the address the cached
/// client is pinned to, so the client can only dial an address this call just
/// approved. If DNS moves the host — legitimately or as an attack — the next
/// call resolves somewhere else, misses the cache, and gets a fresh pin. A
/// client pinned to a stale address is never reused, only dropped at TTL.
///
/// The cost of that strictness is a host whose resolver *rotates* its answer:
/// each new first address is a new key, so the pool churns instead of hitting.
/// `getaddrinfo` sorts (RFC 6724) rather than rotating for the common case, and
/// the TTL plus the entry ceiling bound the churn, so this is a missed
/// optimisation rather than a leak — and the alternative, pinning a host to one
/// address for the TTL, would take failover away from the upstream.
///
/// # Why not one shared client
///
/// `state.http_client` is a bare `reqwest::Client`: reqwest's default redirect
/// policy (follow up to 10) and no pin, so a 302 or a rebind defeats any check
/// made at the URL layer. That is exactly the hole this closes.
pub async fn outbound_client(url_str: &str) -> Result<(reqwest::Client, Url), AppError> {
    let v = resolve_and_validate(url_str, default_policy).await?;
    let key: ClientKey = (v.host.clone(), v.port, v.ip);

    {
        let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.get_mut(&key) {
            entry.last_used = Instant::now();
            return Ok((entry.client.clone(), v.url));
        }
    }

    let client = pinned_client(&v, OUTBOUND_CONNECT_TIMEOUT, None)?;

    {
        let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        guard.retain(|_, e| now.duration_since(e.last_used) < CLIENT_TTL);
        if guard.len() >= MAX_CACHED_CLIENTS {
            guard.clear();
        }
        guard.insert(
            key,
            CachedClient {
                client: client.clone(),
                last_used: now,
            },
        );
    }

    Ok((client, v.url))
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

    /// The hatch is scoped to loopback. This is the property the integration
    /// tests lean on: the suite runs with the var set *and* still proves a
    /// Mode A call to the metadata endpoint is refused.
    #[test]
    fn hatch_opens_loopback_only() {
        let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let loop4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let loop6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

        // `default_policy` reads the env, so assert the pieces it composes
        // rather than mutating a process-wide var under a parallel runner.
        assert!(is_loopback(&loop4) && is_loopback(&loop6));
        assert!(!is_loopback(&metadata) && !is_loopback(&private));
        assert!(is_disallowed_ip(&metadata) && is_disallowed_ip(&private));
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

    /// The metadata endpoint is an IP literal, so this needs no DNS.
    #[tokio::test]
    async fn outbound_client_refuses_link_local_metadata() {
        let err = outbound_client("http://169.254.169.254/latest/meta-data/")
            .await
            .unwrap_err();
        let AppError::BadRequest(msg) = err else {
            panic!("expected BadRequest");
        };
        assert!(msg.contains("169.254.169.254"), "{msg}");
    }

    /// Second call to the same validated address reuses the pooled client
    /// rather than building a fresh one — the property the latency argument
    /// rests on. Uses an IP literal so no DNS is involved.
    #[tokio::test]
    async fn outbound_client_pools_per_validated_address() {
        // A public IP literal: allowed by the default policy, needs no DNS,
        // and never dialed — only the client is built. Deliberately not a
        // loopback address, because that would mean writing the hatch env var
        // from a unit test that shares a process with the config tests which
        // read it.
        let before = cached_client_count();
        outbound_client("http://8.8.8.8:9/x").await.unwrap();
        let after_first = cached_client_count();
        outbound_client("http://8.8.8.8:9/y").await.unwrap();
        let after_second = cached_client_count();

        assert_eq!(after_first, before + 1, "first call should pin a client");
        assert_eq!(
            after_second, after_first,
            "same host:port:ip must reuse the pinned client"
        );

        // A different port is a different pin, so it is a different client.
        outbound_client("http://8.8.8.8:10/x").await.unwrap();
        assert_eq!(cached_client_count(), after_second + 1);
    }
}
