//! SSRF-safe outbound HTTP: resolve the URL's host once, reject private /
//! loopback / link-local / carrier-grade-NAT addresses, and pin the
//! validated IP via reqwest's `resolve` override to close the DNS-rebinding
//! window between validation and dial.
//!
//! A self-hosted deployment that must reach its own private network says so
//! with `OVERSLASH_SSRF_ALLOWED_CIDRS` — see [`operator_allowed_ranges`]. That
//! is the only way past the deny-list; there is no boolean bypass.
//!
//! Every outbound request whose URL a caller can influence goes through here:
//! template OpenAPI import, MCP dispatch, OAuth upstream discovery, the
//! action-execution transport ([`crate::services::http_caller`]), webhook
//! delivery ([`crate::services::webhook_dispatcher`]) and OIDC issuer
//! discovery ([`crate::services::oidc_discovery`]).
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

/// The instance-metadata ranges, which the allow-list **cannot** reach.
///
/// `169.254.169.254` is the single most valuable target an SSRF can hit: on
/// every major cloud it hands out credentials for the instance's own service
/// account, and a token minted there is not "one internal service" but the
/// whole deployment. `fd00:ec2::/32` is AWS's IPv6 spelling of the same
/// endpoint and lives inside ULA, so a self-hoster allowing their own ULA
/// prefix would otherwise open it by accident.
///
/// These are denied **before** the allow-list is consulted, so no
/// `OVERSLASH_SSRF_ALLOWED_CIDRS` entry — however broad, however
/// well-intentioned — reaches them. Past that deny stands exactly one gate,
/// [`METADATA_OVERRIDE_VAR`], and it does not open the ranges by itself: it
/// only lets the allow-list cover them. Two deliberate acts, because one is
/// what a mistake looks like.
const METADATA_CIDRS: [&str; 2] = ["169.254.0.0/16", "fd00:ec2::/32"];

/// The one gate past [`METADATA_CIDRS`]. Named `DANGER` for the same reason
/// `OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS` is: nobody should be able
/// to set it without noticing what they are doing.
const METADATA_OVERRIDE_VAR: &str = "OVERSLASH_DANGER_ALLOW_METADATA_CIDR";

fn metadata_cidrs() -> &'static [ipnet::IpNet] {
    static NETS: OnceLock<Vec<ipnet::IpNet>> = OnceLock::new();
    NETS.get_or_init(|| {
        METADATA_CIDRS
            .iter()
            .map(|c| c.parse().expect("static CIDR"))
            .collect()
    })
}

/// Whether `ip` is an instance-metadata address, in any of its spellings —
/// including the v4-mapped and deprecated v4-compatible IPv6 forms, which are
/// the same address wearing a different hat and must not slip past a check that
/// only looked at `IpAddr::V4`.
fn is_metadata_ip(ip: &IpAddr) -> bool {
    if metadata_cidrs().iter().any(|net| net.contains(ip)) {
        return true;
    }
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4().is_some_and(|m| {
            metadata_cidrs()
                .iter()
                .any(|net| net.contains(&IpAddr::V4(m)))
        }),
        IpAddr::V4(_) => false,
    }
}

/// Whether the operator has explicitly opened [`METADATA_CIDRS`] to the
/// allow-list. Read per call rather than cached: it is one boolean env lookup,
/// and the cost of getting a stale answer here is higher than the cost of
/// reading it.
fn metadata_override_set() -> bool {
    overslash_env::flag(METADATA_OVERRIDE_VAR)
}

/// Ranges the *deployment operator* has declared reachable, from
/// `OVERSLASH_SSRF_ALLOWED_CIDRS` — a comma-separated list of CIDR blocks.
///
/// Overslash self-hosted beside internal services has a need the deny-list
/// would otherwise refuse outright: a GitLab on `10.42.0.7`, a MinIO on a
/// container network, a webhook consumer that never leaves the VPC. Without a
/// supported way to say so, the only way back would be to disable the guard —
/// which is the vulnerability again. This is that way, and it is the **only**
/// one. There is deliberately no boolean bypass, because a boolean cannot tell
/// "my GitLab" from "the instance-metadata endpoint", and a knob that cannot
/// make that distinction ends up set in places where it should not be.
///
/// Four properties make it a narrowing rather than a hole:
///
/// - **Operator-only.** Read from the process environment. No org, user,
///   template or API request can reach it, so a tenant cannot widen its own
///   egress, and the multi-tenant deployment simply never sets it.
/// - **Explicit about what it opens.** `10.42.0.0/16` permits that range and
///   nothing else. Allowing one private range does not re-open link-local,
///   CGNAT, or the rest of RFC1918.
/// - **It cannot reach the metadata endpoint.** [`METADATA_CIDRS`] are denied
///   before this list is consulted, so even `0.0.0.0/0` here does not open
///   them. Only [`METADATA_OVERRIDE_VAR`] lifts that, and only in combination
///   with an entry here that covers them.
/// - **Checked against the resolved address, not the URL.** A hostname that
///   resolves outside every listed range is refused like any other, so a
///   rebind cannot smuggle an address in under an allow-listed name.
/// - **Still pinned.** An allowed address is validated and pinned exactly like
///   a public one, and a redirect away from it is re-checked from scratch.
///
/// Parsed once, at boot (see [`log_egress_configuration`]). A malformed entry
/// is dropped with a warning rather than widening anything, and the accepted
/// set is logged, because an operator deserves to see in the log that this
/// control was loosened and by how much — see
/// [`warn_about_egress_configuration`] for what else is said and when.
///
/// The integration suite and `scripts/e2e-up.sh` use the same mechanism —
/// `127.0.0.0/8,::1/128`, because the fakes bind to loopback. One mechanism
/// rather than a test-only bypass means the suite exercises the code path a
/// self-hoster actually runs, and `tests/ssrf_guard.rs` still proves the
/// metadata endpoint, RFC1918 and CGNAT are refused while it is set.
fn operator_allowed_ranges() -> &'static [ipnet::IpNet] {
    static RANGES: OnceLock<Vec<ipnet::IpNet>> = OnceLock::new();
    RANGES.get_or_init(|| {
        let ranges = overslash_env::optional("OVERSLASH_SSRF_ALLOWED_CIDRS")
            .map(|raw| parse_allowed_cidrs(&raw))
            .unwrap_or_default();
        warn_about_egress_configuration(&ranges);
        ranges
    })
}

/// Force the one-time parse and its log lines at boot.
///
/// The allow-list is otherwise read lazily, on the first guarded call, which
/// would put a "your egress is wider than default" line somewhere in the middle
/// of the day's traffic instead of next to the rest of startup — and would say
/// nothing at all on a deployment that is misconfigured precisely because
/// nothing is calling out.
pub fn log_egress_configuration() {
    let _ = operator_allowed_ranges();
}

/// Everything worth telling an operator about their egress configuration, in
/// one place, reached on **every** startup — including the one where nothing is
/// configured, because "you set the dangerous variable and it is doing nothing"
/// is exactly the case that otherwise stays silent.
///
/// The four combinations of (allow-list overlaps metadata) × (override set) do
/// not collapse into two. Whether the metadata endpoint is reachable is a
/// question about *both* variables, and an operator should not have to hold
/// both in their head to read the log — so each line names
/// [`METADATA_OVERRIDE_VAR`] and says which way it is set.
fn warn_about_egress_configuration(ranges: &[ipnet::IpNet]) {
    let override_set = metadata_override_set();
    let metadata = METADATA_CIDRS.join(", ");

    if !ranges.is_empty() {
        let listed = ranges
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        tracing::warn!(
            "SSRF guard: outbound calls are permitted to operator-allowed ranges [{listed}]. \
             Anyone who can make Overslash issue a request can reach them."
        );
    }

    // An overlap is nearly always a mistake rather than a homelab — an operator
    // reaching for 169.254.0.0/16 usually wants some other link-local device.
    // Warned about either way, because the interesting question is not "is it
    // blocked" but "did you mean this".
    let overlapping: Vec<String> = ranges
        .iter()
        .filter(|n| overlaps_metadata(n))
        .map(|n| n.to_string())
        .collect();

    match (overlapping.is_empty(), override_set) {
        (false, true) => {
            let overlapping = overlapping.join(", ");
            tracing::warn!(
                "SSRF guard: allowed range(s) [{overlapping}] overlap the cloud \
                 instance-metadata ranges [{metadata}], and {METADATA_OVERRIDE_VAR} IS SET — so \
                 the metadata endpoint is REACHABLE from this deployment. A token minted there \
                 is the whole deployment, and anyone who can make Overslash issue a request can \
                 mint one. Unset {METADATA_OVERRIDE_VAR} unless you are certain."
            );
        }
        (false, false) => {
            let overlapping = overlapping.join(", ");
            tracing::warn!(
                "SSRF guard: allowed range(s) [{overlapping}] overlap the cloud \
                 instance-metadata ranges [{metadata}]. Those addresses stay REFUSED, because \
                 {METADATA_OVERRIDE_VAR} is not set. Narrow the range if the overlap was \
                 accidental; set {METADATA_OVERRIDE_VAR} only if reaching metadata is genuinely \
                 what you want."
            );
        }
        // The case the early-return used to swallow: the dangerous variable is
        // set, and on its own it does nothing, because it does not grant — it
        // only lets OVERSLASH_SSRF_ALLOWED_CIDRS cover those ranges. Someone who
        // set it and stopped there is expecting an effect they have not got.
        (true, true) => {
            tracing::warn!(
                "SSRF guard: {METADATA_OVERRIDE_VAR} is set, but no OVERSLASH_SSRF_ALLOWED_CIDRS \
                 entry covers the instance-metadata ranges [{metadata}], so it grants nothing \
                 and the metadata endpoint stays REFUSED. It does not open those ranges by \
                 itself. Unset it, or — only if you mean it — also list the range."
            );
        }
        (true, false) => {}
    }
}

/// Whether an allowed range touches [`METADATA_CIDRS`] at all.
///
/// Containment in either direction: a `/32` inside the metadata range, and a
/// range broad enough to swallow it, are both overlaps and both worth a word.
/// Mismatched families never overlap, which `IpNet::contains` already gives us
/// — so allowing `10.0.0.0/8` says nothing about `fd00:ec2::/32`.
fn overlaps_metadata(range: &ipnet::IpNet) -> bool {
    metadata_cidrs()
        .iter()
        .any(|m| m.contains(&range.network()) || range.contains(&m.network()))
}

/// Parse an `OVERSLASH_SSRF_ALLOWED_CIDRS` value.
///
/// Shared with the `OVERSLASH_SERVICE_BASE_OVERRIDES` gate in
/// [`crate::config`], which asks the same question about a rewrite target that
/// this module asks about a request target. One parser, so the two cannot come
/// to different conclusions about the same string.
///
/// A malformed entry is dropped with a warning rather than widening anything:
/// the fail-closed direction, since a typo that silently allowed a range would
/// be the one mistake here that matters.
pub(crate) fn parse_allowed_cidrs(raw: &str) -> Vec<ipnet::IpNet> {
    let mut ranges = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        match entry.parse::<ipnet::IpNet>() {
            Ok(net) => ranges.push(net),
            Err(e) => tracing::warn!(
                "OVERSLASH_SSRF_ALLOWED_CIDRS: ignoring {entry:?} — not a CIDR range ({e})"
            ),
        }
    }
    ranges
}

/// The policy every caller runs under: the metadata hard deny, then the
/// operator's allow-list, then the deny-list.
pub fn default_policy(ip: &IpAddr) -> bool {
    policy_with(ip, operator_allowed_ranges(), metadata_override_set())
}

/// [`default_policy`] with its two environment reads supplied.
///
/// Split so the decision table can be unit-tested without a test mutating
/// process-wide state that its neighbours read.
///
/// The order is the whole design. The metadata deny comes **first**, so it is
/// not something an allow-list entry can outrank; `allow_metadata` does not
/// permit anything on its own, it only stops that first rule from
/// short-circuiting, leaving the allow-list to decide as it would for any other
/// address. An operator therefore needs two separate deliberate acts to reach
/// the metadata endpoint, and neither reads like a typo.
fn policy_with(ip: &IpAddr, allowed: &[ipnet::IpNet], allow_metadata: bool) -> bool {
    if !allow_metadata && is_metadata_ip(ip) {
        return true;
    }
    if allowed.iter().any(|net| net.contains(ip)) {
        return false;
    }
    is_disallowed_ip(ip)
}

/// Ceiling on one host lookup. Generous against a slow resolver, finite
/// against a stalled one — the point is only that it ends.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

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

    // `host_str()` keeps the brackets on an IPv6 literal (`[::1]`), and neither
    // `to_socket_addrs` nor reqwest's `resolve` override accepts them — the
    // first fails with "Name or service not known", which reads as a DNS
    // problem and is really a spelling one. Take the bare form from `host()`.
    let host = match parsed.host() {
        Some(url::Host::Ipv6(v6)) => v6.to_string(),
        Some(url::Host::Ipv4(v4)) => v4.to_string(),
        Some(url::Host::Domain(d)) => d.to_string(),
        None => return Err(AppError::BadRequest("URL has no host".into())),
    };
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| AppError::BadRequest("URL has no port".into()))?;

    let host_for_resolve = host.clone();
    let resolve = tokio::task::spawn_blocking(move || {
        (host_for_resolve.as_str(), port)
            .to_socket_addrs()
            .map(|iter| iter.map(|a| a.ip()).collect::<Vec<_>>())
    });
    // `getaddrinfo` has no deadline of its own, and it runs *before* the
    // reqwest client that carries one exists — so without this a hostile or
    // merely broken resolver stalls a call past whatever budget the caller
    // was promised. Bounded here rather than at each call site because every
    // guard caller has the same problem and only this one has the lookup.
    let addrs: Vec<IpAddr> = match tokio::time::timeout(DNS_TIMEOUT, resolve).await {
        Ok(joined) => joined
            .map_err(|e| AppError::Internal(format!("dns resolver join error: {e}")))?
            .map_err(|e| AppError::BadRequest(format!("could not resolve host {host:?}: {e}")))?,
        Err(_elapsed) => {
            return Err(AppError::BadRequest(format!(
                "could not resolve host {host:?} within {}s",
                DNS_TIMEOUT.as_secs()
            )));
        }
    };

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
    let (client, url, _ip) = outbound_client_validated(url_str).await?;
    Ok((client, url))
}

/// [`outbound_client`], also handing back the address the client is pinned
/// to — for a caller whose own rule depends on *where* the request lands, not
/// just whether the guard allows it (OIDC discovery accepts plain `http` only
/// to loopback).
pub async fn outbound_client_validated(
    url_str: &str,
) -> Result<(reqwest::Client, Url, IpAddr), AppError> {
    let v = resolve_and_validate(url_str, default_policy).await?;
    let key: ClientKey = (v.host.clone(), v.port, v.ip);

    {
        let mut guard = cache().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.get_mut(&key) {
            entry.last_used = Instant::now();
            return Ok((entry.client.clone(), v.url, v.ip));
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

    Ok((client, v.url, v.ip))
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

    fn nets(list: &[&str]) -> Vec<ipnet::IpNet> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    /// The self-hosted case: a declared range is reachable, and *only* it.
    #[test]
    fn an_allowed_range_is_reachable_and_nothing_else_is() {
        let allowed = nets(&["10.42.0.0/16"]);

        assert!(
            !policy_with(&IpAddr::V4(Ipv4Addr::new(10, 42, 0, 7)), &allowed, false),
            "the listed range must be reachable"
        );
        assert!(
            policy_with(&IpAddr::V4(Ipv4Addr::new(10, 99, 0, 7)), &allowed, false),
            "a private address outside the listed range is still refused"
        );
        // Allowing one private range must not quietly re-open the ones that
        // matter most.
        assert!(policy_with(
            &IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            &allowed,
            false
        ));
        assert!(policy_with(
            &IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            &allowed,
            false
        ));
    }

    /// The hard deny: **no** allow-list entry reaches the metadata ranges,
    /// including one that covers the entire address space.
    #[test]
    fn no_allow_list_entry_reaches_metadata_without_the_override() {
        let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        for allowed in [
            nets(&["169.254.169.254/32"]),
            nets(&["169.254.0.0/16"]),
            nets(&["0.0.0.0/0"]),
        ] {
            assert!(
                policy_with(&metadata, &allowed, false),
                "{allowed:?} must not reach the metadata endpoint"
            );
        }
        // AWS's IPv6 spelling sits inside ULA, so a self-hoster allowing their
        // own fd00::/8 prefix must not open it by accident.
        let v6 = IpAddr::V6("fd00:ec2::254".parse().unwrap());
        assert!(policy_with(&v6, &nets(&["fd00::/8"]), false));
        // And the v4-in-v6 spellings are the same address wearing a hat.
        for mapped in ["::ffff:169.254.169.254", "::169.254.169.254"] {
            let ip = IpAddr::V6(mapped.parse().unwrap());
            assert!(
                policy_with(&ip, &nets(&["0.0.0.0/0", "::/0"]), false),
                "{mapped} must not reach the metadata endpoint"
            );
        }
    }

    /// The predicate behind the startup warning. It has to fire on a range
    /// that *contains* the metadata ranges as well as one contained by them,
    /// and stay quiet on an unrelated private range.
    #[test]
    fn metadata_overlap_is_detected_in_both_directions() {
        for overlapping in ["169.254.169.254/32", "169.254.0.0/16", "0.0.0.0/0"] {
            let net: ipnet::IpNet = overlapping.parse().unwrap();
            assert!(overlaps_metadata(&net), "{overlapping} overlaps");
        }
        // The IPv6 endpoint sits inside ULA, so a self-hoster's own prefix
        // overlaps it and must be called out.
        assert!(overlaps_metadata(&"fd00::/8".parse().unwrap()));
        assert!(overlaps_metadata(&"::/0".parse().unwrap()));

        for unrelated in ["10.0.0.0/8", "192.168.1.0/24", "127.0.0.0/8", "fe80::/10"] {
            let net: ipnet::IpNet = unrelated.parse().unwrap();
            assert!(!overlaps_metadata(&net), "{unrelated} does not overlap");
        }
    }

    /// The override alone opens nothing — it only stops the hard deny from
    /// short-circuiting, leaving the allow-list to decide. Two deliberate acts.
    #[test]
    fn the_override_alone_opens_nothing() {
        let metadata = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));

        assert!(
            policy_with(&metadata, &[], true),
            "override set but nothing allowed: link-local is still denied"
        );
        assert!(
            policy_with(&metadata, &nets(&["10.42.0.0/16"]), true),
            "override set and an unrelated range allowed: still denied"
        );
        assert!(
            !policy_with(&metadata, &nets(&["169.254.169.254/32"]), true),
            "override set *and* the range allowed: reachable, as documented"
        );
    }

    /// This is the property the integration suite leans on: it runs with
    /// loopback allowed and still proves the metadata endpoint is refused.
    #[test]
    fn the_suites_loopback_allowance_opens_loopback_only() {
        let allowed = nets(&["127.0.0.0/8", "::1/128"]);

        assert!(!policy_with(
            &IpAddr::V4(Ipv4Addr::LOCALHOST),
            &allowed,
            false
        ));
        assert!(!policy_with(
            &IpAddr::V6(Ipv6Addr::LOCALHOST),
            &allowed,
            false
        ));
        for still_refused in [
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V6("fd00::1".parse().unwrap()),
        ] {
            assert!(
                policy_with(&still_refused, &allowed, false),
                "{still_refused} must stay refused"
            );
        }
    }

    /// An empty allow-list is the production default: the deny-list alone.
    #[test]
    fn an_empty_allow_list_is_the_deny_list_alone() {
        assert!(policy_with(&IpAddr::V4(Ipv4Addr::LOCALHOST), &[], false));
        assert!(policy_with(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            &[],
            false
        ));
        assert!(!policy_with(
            &IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            &[],
            false
        ));
    }

    /// An IPv6 range works the same way, and does not leak into IPv4.
    #[test]
    fn an_allowed_ipv6_range_does_not_open_ipv4() {
        let allowed = nets(&["fd00::/8"]);
        assert!(!policy_with(
            &IpAddr::V6("fd00::1".parse().unwrap()),
            &allowed,
            false
        ));
        assert!(policy_with(
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            &allowed,
            false
        ));
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

    /// An IPv6 literal is spelled with brackets in a URL and without them
    /// everywhere else. Regression guard: this used to fail as "could not
    /// resolve host \"[::1]\"", which reads as a DNS outage.
    #[tokio::test]
    async fn an_ipv6_literal_resolves_without_its_brackets() {
        // A ULA address: syntactically fine, refused on policy, which is the
        // proof it got past parsing and resolution rather than failing there.
        let err = outbound_client("http://[fd00::1]:80/x").await.unwrap_err();
        let AppError::BadRequest(msg) = err else {
            panic!("expected BadRequest");
        };
        assert!(
            msg.contains("refusing to connect"),
            "should fail on policy, not resolution: {msg}"
        );
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
        // loopback address, because reaching one would mean writing
        // `OVERSLASH_SSRF_ALLOWED_CIDRS` from a unit test that shares a process
        // with the config tests which read the same variable.
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
