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
//! Three knobs, parsed once at boot into [`TrustedProxies`]:
//!
//! - `OVERSLASH_TRUSTED_PROXY_HOPS` — how many addresses, counting the socket
//!   peer, are trusted by position. For platforms whose frontend has no fixed
//!   address but always appends the client: Cloud Run is `1` (the peer is
//!   Google's frontend, the rightmost XFF entry is the client it saw).
//! - `OVERSLASH_TRUSTED_PROXIES` — CIDRs trusted wherever they appear: a
//!   load balancer's own address, an nginx on loopback.
//! - `OVERSLASH_TRUSTED_PROXY_SECRET` — a proxy that has no stable address
//!   (Vercel's rewrite egress) proves itself by stamping this value in
//!   [`PROXY_SECRET_HEADER`]. A match trusts exactly one more hop.
//!
//! With none of them set, `X-Forwarded-For` is ignored and the socket peer is
//! the client — the safe default for a process nobody told about its proxies.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use overslash_env as env;
use subtle::ConstantTimeEq;

/// The request header a secret-bearing proxy stamps. Overwritten, not
/// appended, by the Vercel middleware, so a client cannot pre-seed it.
pub const PROXY_SECRET_HEADER: &str = "x-overslash-proxy-secret";

/// Shortest `OVERSLASH_TRUSTED_PROXY_SECRET` accepted: 32 bytes, the length
/// of `openssl rand -hex 16`, so a placeholder like `REPLACE_ME` is refused.
const MIN_SECRET_LEN: usize = 32;

/// The proxy topology this process sits behind. `Default` trusts nothing.
#[derive(Clone, Default)]
pub struct TrustedProxies {
    hops: u8,
    cidrs: Vec<ipnet::IpNet>,
    secret: Option<ProxySecret>,
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
            .finish()
    }
}

impl TrustedProxies {
    /// Read the three variables. An unparseable value is an error, not a
    /// warning: a dropped CIDR silently moves every client behind that proxy
    /// into one rate-limit bucket, which is worse than not starting.
    pub fn from_env() -> Result<Self, String> {
        Self::parse(
            env::optional("OVERSLASH_TRUSTED_PROXY_HOPS").as_deref(),
            env::optional("OVERSLASH_TRUSTED_PROXIES").as_deref(),
            env::optional("OVERSLASH_TRUSTED_PROXY_SECRET").as_deref(),
        )
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
        })
    }

    /// Whether anything is trusted at all. When not, XFF is never read.
    pub fn is_configured(&self) -> bool {
        self.hops > 0 || !self.cidrs.is_empty() || self.secret.is_some()
    }

    /// One-line description for the boot log. Never includes the secret.
    pub fn summary(&self) -> String {
        format!(
            "hops={} cidrs=[{}] proxy_secret={}",
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
    /// value in the order received, `secret` the [`PROXY_SECRET_HEADER`]
    /// value if present.
    pub fn resolve(
        &self,
        peer: Option<IpAddr>,
        xff: &[&str],
        secret: Option<&[u8]>,
    ) -> Option<IpAddr> {
        if !self.is_configured() {
            return peer.map(|p| p.to_canonical());
        }
        // One free pass over an address we would otherwise stop at: the hop a
        // secret-bearing proxy connected from, which it cannot name in advance.
        let mut vouched = self.secret_matches(secret);
        let mut last_trusted = match peer {
            Some(p) => {
                let p = p.to_canonical();
                if !self.trusted_at(0, p) {
                    if !vouched {
                        return Some(p);
                    }
                    vouched = false;
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
                if !vouched {
                    return Some(ip);
                }
                vouched = false;
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
        t.resolve(Some(ip(peer)), xff, secret.map(str::as_bytes))
            .map(|i| i.to_string())
            .unwrap_or_else(|| "none".into())
    }

    #[test]
    fn unconfigured_ignores_xff_and_returns_the_peer() {
        let t = TrustedProxies::default();
        assert_eq!(
            resolve(&t, "198.51.100.7", &["1.2.3.4"], None),
            "198.51.100.7"
        );
        assert_eq!(t.resolve(None, &["1.2.3.4"], None), None);
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
    fn matching_secret_trusts_exactly_one_more_hop() {
        let t = tp("1", &format!("{LB}/32"), Some(SECRET));
        let xff = format!("1.2.3.4, 203.0.113.9, 76.76.21.21, {LB}");
        // Vercel overwrites XFF, so in practice 1.2.3.4 is absent; even if a
        // client got one in, the vouch only reaches past the egress hop.
        assert_eq!(resolve(&t, GFE, &[&xff], Some(SECRET)), "203.0.113.9");
        // Wrong or missing secret: the egress hop is the client.
        assert_eq!(resolve(&t, GFE, &[&xff], Some("nope")), "76.76.21.21");
        assert_eq!(resolve(&t, GFE, &[&xff], None), "76.76.21.21");
    }

    #[test]
    fn secret_vouches_for_an_untrusted_peer_too() {
        // Vercel talking to the API with no frontend in between.
        let t = tp("0", "", Some(SECRET));
        assert_eq!(
            resolve(&t, "76.76.21.21", &["203.0.113.9"], Some(SECRET)),
            "203.0.113.9"
        );
        assert_eq!(
            resolve(&t, "76.76.21.21", &["203.0.113.9"], None),
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
}
