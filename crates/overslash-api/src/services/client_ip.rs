//! Which address a request came from, given the proxies in front of us.
//!
//! `X-Forwarded-For` is a list every hop appends to, so only its right-hand
//! end was written by infrastructure we run; everything to the left of the
//! first address we don't trust was supplied by the client and is worth
//! nothing. The resolver walks the chain from the socket peer leftwards and
//! returns the first address it has no reason to trust — the rightmost
//! untrusted address — instead of the leftmost header value, which any caller
//! can set to anything.
//!
//! Four knobs, parsed once at boot into [`TrustedProxies`]:
//!
//! - `OVERSLASH_TRUSTED_PROXY_HOPS` — how many addresses, counting the socket
//!   peer, are trusted by position. For platforms whose frontend has no fixed
//!   address but always appends the client: Cloud Run is `1` (the peer is
//!   Google's frontend, the rightmost XFF entry is the client it saw).
//! - `OVERSLASH_TRUSTED_PROXIES` — CIDRs trusted wherever they appear: a
//!   load balancer's own address, an nginx on loopback.
//! - `OVERSLASH_TRUSTED_PROXY_SECRET` — a proxy that has no stable address
//!   (Vercel's rewrite egress) proves itself by stamping this value in
//!   [`PROXY_SECRET_HEADER`], and names the client it saw in
//!   [`CLIENT_IP_HEADER`]. A match makes that header the client in place of
//!   the proxy's own hop. XFF left of a vouching proxy is never read: Vercel
//!   forwards the browser's `X-Forwarded-For` upstream and does not reliably
//!   apply a middleware override of it, so that part of the list is the
//!   caller's claim (measured on dev, see DECISIONS D102).
//! - `OVERSLASH_TRUSTED_CLIENT_IP_HEADER` — a header the edge in front of us
//!   *overwrites* with the address it saw (the GCLB's
//!   `{client_ip_address}` custom header). When present it is that hop and
//!   XFF is not walked at all: behind the GCLB, Google appends hops of its
//!   own whose position and range aren't published, so counting them is a
//!   guess. Sound only if nothing reaches us around that edge (prod's ingress
//!   is LB-only); a missing or unparseable value falls back to the XFF walk.
//!
//! With none of them set, `X-Forwarded-For` is ignored and the socket peer is
//! the client — the safe default for a process nobody told about its proxies.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use axum::http::HeaderName;
use overslash_env as env;
use subtle::ConstantTimeEq;

/// The subject a per-IP throttle counts against: the address itself for
/// IPv4, its **/64** for IPv6. One IPv6 subscriber is handed a whole /64 and
/// can source from any of its 2^64 addresses, so a per-address bucket is no
/// bucket at all. An IPv4-mapped IPv6 address counts as the IPv4 address it
/// carries. `unknown` when there is no address (or it does not parse), so the
/// failure is one shared bucket rather than none.
///
/// For throttle keys only — audit rows keep the full address.
pub fn rate_limit_subject(ip: Option<&str>) -> String {
    match ip.and_then(|s| s.parse::<IpAddr>().ok()) {
        Some(IpAddr::V4(v4)) => v4.to_string(),
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
        },
        None => "unknown".to_string(),
    }
}

/// The request header a secret-bearing proxy stamps. Overwritten, not
/// appended, by the Vercel middleware, so a client cannot pre-seed it.
pub const PROXY_SECRET_HEADER: &str = "x-overslash-proxy-secret";

/// The client address a secret-bearing proxy observed. Believed only when
/// [`PROXY_SECRET_HEADER`] matches; the middleware sets (never passes
/// through) both.
pub const CLIENT_IP_HEADER: &str = "x-overslash-client-ip";

/// What a secret-bearing proxy stamped on the request.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProxyStamp<'a> {
    pub secret: Option<&'a [u8]>,
    pub client: Option<&'a str>,
    /// The value of [`TrustedProxies::client_ip_header`], if configured.
    pub edge_client: Option<&'a str>,
}

/// Shortest `OVERSLASH_TRUSTED_PROXY_SECRET` accepted: 32 bytes, the length
/// of `openssl rand -hex 16`, so a placeholder like `REPLACE_ME` is refused.
const MIN_SECRET_LEN: usize = 32;

/// The proxy topology this process sits behind. `Default` trusts nothing.
#[derive(Clone, Default)]
pub struct TrustedProxies {
    hops: u8,
    cidrs: Vec<ipnet::IpNet>,
    secret: Option<ProxySecret>,
    client_ip_header: Option<HeaderName>,
}

/// Held apart so `Debug` on the config can never print it.
#[derive(Clone)]
struct ProxySecret(Vec<u8>);

impl fmt::Debug for TrustedProxies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedProxies")
            .field("hops", &self.hops)
            .field("cidrs", &self.cidrs)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .field("client_ip_header", &self.client_ip_header)
            .finish()
    }
}

impl TrustedProxies {
    /// Read the four variables. An unparseable value is an error, not a
    /// warning: a dropped CIDR silently moves every client behind that proxy
    /// into one rate-limit bucket, which is worse than not starting.
    pub fn from_env() -> Result<Self, String> {
        Self::parse(
            env::optional("OVERSLASH_TRUSTED_PROXY_HOPS").as_deref(),
            env::optional("OVERSLASH_TRUSTED_PROXIES").as_deref(),
            env::optional("OVERSLASH_TRUSTED_PROXY_SECRET").as_deref(),
        )?
        .with_client_ip_header(env::optional("OVERSLASH_TRUSTED_CLIENT_IP_HEADER").as_deref())
    }

    /// [`Self::from_env`] with the raw values passed in.
    pub fn parse(
        hops: Option<&str>,
        cidrs: Option<&str>,
        secret: Option<&str>,
    ) -> Result<Self, String> {
        let hops = match hops.map(str::trim).filter(|s| !s.is_empty()) {
            None => 0,
            Some(raw) => raw.parse::<u8>().map_err(|e| {
                format!("OVERSLASH_TRUSTED_PROXY_HOPS must be a number of hops, got {raw:?} ({e})")
            })?,
        };
        let mut nets = Vec::new();
        for entry in cidrs
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
        {
            let net = entry
                .parse::<ipnet::IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(ipnet::IpNet::from))
                .map_err(|_| {
                    format!(
                        "OVERSLASH_TRUSTED_PROXIES: {entry:?} is not an IP address or CIDR range"
                    )
                })?;
            nets.push(net);
        }
        let secret = match secret.filter(|s| !s.is_empty()) {
            None => None,
            Some(raw) if raw.len() < MIN_SECRET_LEN => {
                return Err(format!(
                    "OVERSLASH_TRUSTED_PROXY_SECRET must be at least {MIN_SECRET_LEN} bytes; \
                     generate one with `openssl rand -hex 32`"
                ));
            }
            Some(raw) => Some(ProxySecret(raw.as_bytes().to_vec())),
        };
        Ok(Self {
            hops,
            cidrs: nets,
            secret,
            client_ip_header: None,
        })
    }

    /// Set `OVERSLASH_TRUSTED_CLIENT_IP_HEADER`. Blank leaves it unset.
    pub fn with_client_ip_header(mut self, name: Option<&str>) -> Result<Self, String> {
        self.client_ip_header = match name.map(str::trim).filter(|s| !s.is_empty()) {
            None => None,
            Some(raw) => Some(HeaderName::try_from(raw).map_err(|_| {
                format!("OVERSLASH_TRUSTED_CLIENT_IP_HEADER: {raw:?} is not a header name")
            })?),
        };
        Ok(self)
    }

    /// The header an edge proxy overwrites with the client it saw, if any.
    pub fn client_ip_header(&self) -> Option<&HeaderName> {
        self.client_ip_header.as_ref()
    }

    /// Whether anything is trusted at all. When not, XFF is never read.
    pub fn is_configured(&self) -> bool {
        self.hops > 0
            || !self.cidrs.is_empty()
            || self.secret.is_some()
            || self.client_ip_header.is_some()
    }

    /// One-line description for the boot log. Never includes the secret.
    pub fn summary(&self) -> String {
        format!(
            "hops={} cidrs=[{}] proxy_secret={} client_ip_header={}",
            self.hops,
            self.cidrs
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            if self.secret.is_some() {
                "set"
            } else {
                "unset"
            },
            self.client_ip_header
                .as_ref()
                .map_or("unset", HeaderName::as_str),
        )
    }

    fn secret_matches(&self, presented: Option<&[u8]>) -> bool {
        match (&self.secret, presented) {
            (Some(ProxySecret(expected)), Some(got)) => expected.ct_eq(got).into(),
            _ => false,
        }
    }

    fn trusted_at(&self, position: usize, ip: IpAddr) -> bool {
        position < usize::from(self.hops) || self.cidrs.iter().any(|n| n.contains(&ip))
    }

    /// The client address for one request.
    ///
    /// `peer` is the socket address, `xff` every `X-Forwarded-For` header
    /// value in the order received, `stamp` what a secret-bearing proxy (and
    /// the edge, via [`Self::client_ip_header`]) set.
    pub fn resolve(
        &self,
        peer: Option<IpAddr>,
        xff: &[&str],
        stamp: ProxyStamp<'_>,
    ) -> Option<IpAddr> {
        if !self.is_configured() {
            return peer.map(|p| p.to_canonical());
        }
        // The first address we don't trust is the client, unless the proxy
        // at that hop vouched with the secret: then the client is the one it
        // names. If it named none (or garbage), the proxy's own address is the
        // best we know. Either way the walk stops here: nothing left of a
        // vouching proxy was written by it.
        let vouched = self.secret_matches(stamp.secret);
        let client_at = |hop: IpAddr| -> IpAddr {
            match stamp.client {
                Some(c) if vouched => parse_entry(c.trim()).unwrap_or(hop),
                _ => hop,
            }
        };
        // The edge named the address it saw: that is the first hop we don't
        // trust, wherever Google's own hops landed in XFF.
        if self.client_ip_header.is_some()
            && let Some(edge) = stamp.edge_client.and_then(|v| parse_entry(v.trim()))
        {
            return Some(client_at(edge));
        }
        let mut last_trusted = match peer {
            Some(p) => {
                let p = p.to_canonical();
                if !self.trusted_at(0, p) {
                    return Some(client_at(p));
                }
                Some(p)
            }
            // No socket address (an in-process router in a test). Without a
            // positional hop there is nothing to anchor trust on.
            None if self.hops == 0 => return None,
            None => None,
        };

        // Right to left: last header line first, last entry of each first.
        let chain = xff
            .iter()
            .rev()
            .flat_map(|v| v.rsplit(','))
            .map(str::trim)
            .filter(|e| !e.is_empty());
        for (k, entry) in chain.enumerate() {
            // Reached only if everything to its right was trusted, so the
            // garbage came from a proxy of ours: fall back to that proxy
            // rather than guess.
            let Some(ip) = parse_entry(entry) else {
                return last_trusted;
            };
            if !self.trusted_at(k + 1, ip) {
                return Some(client_at(ip));
            }
            last_trusted = Some(ip);
        }
        // Every hop was trusted: the furthest one is the best we know.
        last_trusted
    }
}

/// One XFF entry: a bare address, or one with a port (`1.2.3.4:5`,
/// `[::1]:5`), which some proxies write.
fn parse_entry(entry: &str) -> Option<IpAddr> {
    entry
        .parse::<IpAddr>()
        .or_else(|_| entry.parse::<SocketAddr>().map(|s| s.ip()))
        .ok()
        .map(|ip| ip.to_canonical())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const LB: &str = "34.36.8.174";
    const GFE: &str = "169.254.1.1";

    fn tp(hops: &str, cidrs: &str, secret: Option<&str>) -> TrustedProxies {
        TrustedProxies::parse(Some(hops), Some(cidrs), secret).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn resolve(t: &TrustedProxies, peer: &str, xff: &[&str], secret: Option<&str>) -> String {
        vouch(t, peer, xff, secret, None)
    }

    fn vouch(
        t: &TrustedProxies,
        peer: &str,
        xff: &[&str],
        secret: Option<&str>,
        client: Option<&str>,
    ) -> String {
        edge(t, peer, xff, None, secret, client)
    }

    fn edge(
        t: &TrustedProxies,
        peer: &str,
        xff: &[&str],
        edge_client: Option<&str>,
        secret: Option<&str>,
        client: Option<&str>,
    ) -> String {
        let stamp = ProxyStamp {
            secret: secret.map(str::as_bytes),
            client,
            edge_client,
        };
        t.resolve(Some(ip(peer)), xff, stamp)
            .map(|i| i.to_string())
            .unwrap_or_else(|| "none".into())
    }

    /// Prod: the GCLB overwrites this header with `{client_ip_address}`.
    fn behind_lb(secret: Option<&str>) -> TrustedProxies {
        tp("2", &format!("{LB}/32"), secret)
            .with_client_ip_header(Some("X-Overslash-Edge-Client-Ip"))
            .unwrap()
    }

    #[test]
    fn unconfigured_ignores_xff_and_returns_the_peer() {
        let t = TrustedProxies::default();
        assert_eq!(
            resolve(&t, "198.51.100.7", &["1.2.3.4"], None),
            "198.51.100.7"
        );
        assert_eq!(t.resolve(None, &["1.2.3.4"], ProxyStamp::default()), None);
    }

    #[test]
    fn spoofed_xff_from_an_untrusted_peer_is_ignored() {
        let t = tp("0", "10.0.0.0/8", None);
        assert_eq!(
            resolve(&t, "198.51.100.7", &["1.2.3.4"], None),
            "198.51.100.7"
        );
    }

    #[test]
    fn cloud_run_direct_takes_the_entry_the_frontend_appended() {
        let t = tp("1", "", None);
        assert_eq!(
            resolve(&t, GFE, &["1.2.3.4, 203.0.113.9"], None),
            "203.0.113.9"
        );
        // No XFF at all: the frontend is the best we know.
        assert_eq!(resolve(&t, GFE, &[], None), GFE);
    }

    #[test]
    fn behind_the_lb_skips_the_lb_address() {
        let t = tp("1", &format!("{LB}/32,35.191.0.0/16"), None);
        let xff = format!("1.2.3.4, 203.0.113.9, {LB}");
        assert_eq!(resolve(&t, GFE, &[&xff], None), "203.0.113.9");
        // If the serverless-NEG path also appended a frontend address.
        let xff = format!("203.0.113.9, {LB}, 35.191.4.4");
        assert_eq!(resolve(&t, GFE, &[&xff], None), "203.0.113.9");
    }

    #[test]
    fn prepending_the_lb_address_via_run_app_buys_nothing() {
        let t = tp("1", &format!("{LB}/32"), None);
        // Attacker at 198.51.100.66 calls *.run.app directly, forging the
        // LB's shape; Cloud Run appends the real source.
        let xff = format!("1.2.3.4, {LB}, 198.51.100.66");
        assert_eq!(resolve(&t, GFE, &[&xff], None), "198.51.100.66");
    }

    // What prod's GCLB actually delivers: the LB appends `<client>, <lb-ip>`,
    // then the hop into Cloud Run appends a Google egress address of no
    // published range. With hops=1 that egress was recorded for every agent
    // call; prod trusts it by position instead (hops=2, ingress LB-only).
    const LB_EGRESS: &str = "34.96.62.132";

    #[test]
    fn behind_the_lb_with_its_egress_hop_takes_the_client() {
        let t = tp("2", &format!("{LB}/32"), None);
        let xff = format!("1.2.3.4, 203.0.113.9, {LB}, {LB_EGRESS}");
        assert_eq!(resolve(&t, GFE, &[&xff], None), "203.0.113.9");
        // Without the egress hop the LB address is still skipped by CIDR.
        let xff = format!("203.0.113.9, {LB}");
        assert_eq!(resolve(&t, GFE, &[&xff], None), "203.0.113.9");
        // The regression: one positional hop records the egress.
        let t1 = tp("1", &format!("{LB}/32"), None);
        let xff = format!("203.0.113.9, {LB}, {LB_EGRESS}");
        assert_eq!(resolve(&t1, GFE, &[&xff], None), LB_EGRESS);
    }

    #[test]
    fn behind_the_lb_forging_its_shape_buys_nothing() {
        let t = tp("2", &format!("{LB}/32"), None);
        // The caller prepends a fake client and the LB's address; the LB
        // appends the real source after them.
        let xff = format!("1.2.3.4, {LB}, 198.51.100.66, {LB}, {LB_EGRESS}");
        assert_eq!(resolve(&t, GFE, &[&xff], None), "198.51.100.66");
    }

    #[test]
    fn behind_the_lb_a_vouched_vercel_hop_names_the_browser() {
        let t = tp("2", &format!("{LB}/32"), Some(SECRET));
        let xff = format!("203.0.113.66, 76.76.21.21, {LB}, {LB_EGRESS}");
        let named = Some("128.140.96.98");
        assert_eq!(
            vouch(&t, GFE, &[&xff], Some(SECRET), named),
            "128.140.96.98"
        );
        assert_eq!(vouch(&t, GFE, &[&xff], None, named), "76.76.21.21");
    }

    // hops=2 still recorded a Google address (34.96.62.181) in prod: the
    // chain's shape isn't what the test above assumed, and it isn't
    // published. The LB-stamped header doesn't depend on it.
    #[test]
    fn the_edge_header_wins_over_any_xff_shape() {
        let t = behind_lb(None);
        let client = Some("82.213.253.53");
        for xff in [
            format!("203.0.113.9, 82.213.253.53, {LB}, 34.96.62.181"),
            format!("203.0.113.9, 82.213.253.53, 34.96.62.181, {LB}"),
            format!("203.0.113.9, 82.213.253.53, {LB}, 34.96.62.181, 34.96.62.132"),
        ] {
            assert_eq!(edge(&t, GFE, &[&xff], client, None, None), "82.213.253.53");
        }
        // Ports and mapped v6, as elsewhere.
        assert_eq!(
            edge(&t, GFE, &[], Some(" ::ffff:82.213.253.53 "), None, None),
            "82.213.253.53"
        );
    }

    #[test]
    fn the_edge_header_is_the_vouching_proxys_hop() {
        // Browser → Vercel rewrite → LB: the LB saw Vercel's egress, and
        // the secret makes the browser Vercel named the client.
        let t = behind_lb(Some(SECRET));
        let xff = format!("203.0.113.66, 76.76.21.21, {LB}, 34.96.62.181");
        let vercel = Some("76.76.21.21");
        let named = Some("128.140.96.98");
        assert_eq!(
            edge(&t, GFE, &[&xff], vercel, Some(SECRET), named),
            "128.140.96.98"
        );
        assert_eq!(edge(&t, GFE, &[&xff], vercel, None, named), "76.76.21.21");
    }

    #[test]
    fn without_a_usable_edge_header_the_xff_walk_still_runs() {
        let t = behind_lb(None);
        let xff = format!("1.2.3.4, 203.0.113.9, {LB}, 34.96.62.132");
        assert_eq!(edge(&t, GFE, &[&xff], None, None, None), "203.0.113.9");
        assert_eq!(
            edge(&t, GFE, &[&xff], Some("unknown"), None, None),
            "203.0.113.9"
        );
    }

    #[test]
    fn the_edge_header_is_ignored_unless_configured() {
        // A client sending the header to a deployment with no such edge
        // (dev) names nothing.
        let t = tp("1", "", None);
        assert_eq!(
            edge(&t, GFE, &["203.0.113.9"], Some("1.2.3.4"), None, None),
            "203.0.113.9"
        );
    }

    #[test]
    fn cidr_only_reverse_proxy_on_loopback() {
        let t = tp("0", "127.0.0.1", None);
        assert_eq!(
            resolve(&t, "127.0.0.1", &["1.2.3.4, 203.0.113.9"], None),
            "203.0.113.9"
        );
        // Someone reaching the port directly is not the proxy.
        assert_eq!(
            resolve(&t, "198.51.100.7", &["203.0.113.9"], None),
            "198.51.100.7"
        );
    }

    #[test]
    fn matching_secret_makes_the_named_client_the_client() {
        let t = tp("1", &format!("{LB}/32"), Some(SECRET));
        // What dev actually delivered: the browser's forged XFF forwarded
        // by Vercel, then Vercel's egress, then the LB.
        let xff = format!("203.0.113.66, 76.76.21.21, {LB}");
        let named = Some("128.140.96.98");
        assert_eq!(
            vouch(&t, GFE, &[&xff], Some(SECRET), named),
            "128.140.96.98"
        );
        // Wrong or missing secret: the named client is ignored and the
        // egress hop is the client.
        assert_eq!(vouch(&t, GFE, &[&xff], Some("nope"), named), "76.76.21.21");
        assert_eq!(vouch(&t, GFE, &[&xff], None, named), "76.76.21.21");
    }

    #[test]
    fn vouching_never_reads_xff_left_of_the_proxy() {
        // The regression this design exists for: with the secret matching
        // but no client named, the XFF entry behind the egress is the
        // browser's claim, not Vercel's observation. Stop at the egress.
        let t = tp("1", &format!("{LB}/32"), Some(SECRET));
        let xff = format!("203.0.113.66, 76.76.21.21, {LB}");
        assert_eq!(vouch(&t, GFE, &[&xff], Some(SECRET), None), "76.76.21.21");
        // A garbage name is no name.
        assert_eq!(
            vouch(&t, GFE, &[&xff], Some(SECRET), Some("unknown")),
            "76.76.21.21"
        );
    }

    #[test]
    fn named_client_is_ignored_where_no_untrusted_hop_is_reached() {
        // Everything in the chain is ours: there is no vouching proxy, so
        // a stamped name has nothing to stand in for.
        let t = tp("0", "10.0.0.0/8", Some(SECRET));
        assert_eq!(
            vouch(
                &t,
                "10.0.0.1",
                &["10.0.0.2"],
                Some(SECRET),
                Some("203.0.113.9")
            ),
            "10.0.0.2"
        );
    }

    #[test]
    fn secret_vouches_for_an_untrusted_peer_too() {
        // Vercel talking to the API with no frontend in between.
        let t = tp("0", "", Some(SECRET));
        let named = Some("203.0.113.9");
        assert_eq!(
            vouch(&t, "76.76.21.21", &["198.51.100.1"], Some(SECRET), named),
            "203.0.113.9"
        );
        assert_eq!(
            vouch(&t, "76.76.21.21", &["198.51.100.1"], None, named),
            "76.76.21.21"
        );
    }

    #[test]
    fn all_trusted_returns_the_furthest_hop() {
        let t = tp("0", "10.0.0.0/8", None);
        assert_eq!(
            resolve(&t, "10.0.0.1", &["10.0.0.3, 10.0.0.2"], None),
            "10.0.0.3"
        );
    }

    #[test]
    fn garbage_behind_trusted_hops_falls_back_to_the_last_trusted() {
        let t = tp("1", &format!("{LB}/32"), None);
        let xff = format!("unknown, {LB}");
        assert_eq!(resolve(&t, GFE, &[&xff], None), LB);
    }

    #[test]
    fn multiple_header_lines_read_as_one_list() {
        let t = tp("1", &format!("{LB}/32"), None);
        assert_eq!(
            resolve(&t, GFE, &["1.2.3.4", &format!("203.0.113.9, {LB}")], None),
            "203.0.113.9"
        );
    }

    #[test]
    fn mapped_v6_and_ports_are_normalised() {
        let t = tp("1", "", None);
        assert_eq!(
            resolve(&t, "::ffff:169.254.1.1", &["203.0.113.9:4711"], None),
            "203.0.113.9"
        );
        assert_eq!(
            resolve(&t, GFE, &["[2001:db8::1]:443"], None),
            "2001:db8::1"
        );
        let t = TrustedProxies::default();
        assert_eq!(
            resolve(&t, "::ffff:198.51.100.7", &[], None),
            "198.51.100.7"
        );
    }

    #[test]
    fn parse_rejects_bad_input_instead_of_dropping_it() {
        assert!(TrustedProxies::parse(Some("two"), None, None).is_err());
        assert!(TrustedProxies::parse(Some("300"), None, None).is_err());
        assert!(TrustedProxies::parse(None, Some("10.0.0.0/8, nope"), None).is_err());
        assert!(TrustedProxies::parse(None, None, Some("REPLACE_ME")).is_err());
        let none = TrustedProxies::default();
        assert!(
            none.clone()
                .with_client_ip_header(Some("bad header"))
                .is_err()
        );
        let blank = none.clone().with_client_ip_header(Some(" ")).unwrap();
        assert!(!blank.is_configured());
        let named = none.with_client_ip_header(Some("X-Edge-Ip")).unwrap();
        assert!(named.is_configured());
        assert_eq!(named.client_ip_header().unwrap(), "x-edge-ip");
        let ok = TrustedProxies::parse(Some(" 2 "), Some("10.0.0.0/8,, ::1"), None).unwrap();
        assert_eq!(ok.hops, 2);
        assert_eq!(ok.cidrs.len(), 2);
        assert!(
            !TrustedProxies::parse(None, Some(""), Some(""))
                .unwrap()
                .is_configured()
        );
    }

    #[test]
    fn debug_never_prints_the_secret() {
        let t = tp("1", "", Some(SECRET));
        let out = format!("{t:?} {}", t.summary());
        assert!(!out.contains(SECRET), "{out}");
    }

    #[test]
    fn rate_limit_subject_groups_ipv6_by_64() {
        assert_eq!(rate_limit_subject(Some("203.0.113.9")), "203.0.113.9");
        assert_eq!(
            rate_limit_subject(Some("2001:db8:1:2:aaaa::1")),
            "2001:db8:1:2::/64"
        );
        // Every address in the /64 is one subject…
        assert_eq!(
            rate_limit_subject(Some("2001:db8:1:2:ffff:ffff:ffff:ffff")),
            rate_limit_subject(Some("2001:db8:1:2::"))
        );
        // …and the neighbouring /64 is another.
        assert_ne!(
            rate_limit_subject(Some("2001:db8:1:3::1")),
            rate_limit_subject(Some("2001:db8:1:2::1"))
        );
        assert_eq!(
            rate_limit_subject(Some("::ffff:203.0.113.9")),
            "203.0.113.9"
        );
        assert_eq!(rate_limit_subject(None), "unknown");
        assert_eq!(rate_limit_subject(Some("not-an-ip")), "unknown");
    }
}
