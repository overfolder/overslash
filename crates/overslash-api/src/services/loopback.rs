//! The request `POST /mcp` re-issues to its own REST API, and how the client
//! address survives it.
//!
//! An MCP tool call is executed as a second HTTP request (`routes::mcp::
//! forward`) so it goes through the same auth, ACL, rate-limit and audit path
//! as a REST call. That request's socket peer is this process, so on arrival
//! every resolver would name *us* as the client. Before this module it went
//! out through `PUBLIC_URL` (Vercel → GCLB → Cloud Run) and every
//! MCP-originated audit row recorded Cloud Run's own egress address
//! (34.96.x in prod).
//!
//! So the loopback:
//! - dials this process directly (`http://127.0.0.1:<port>`) when the bind
//!   address is known, rather than the public URL; and
//! - carries the address `POST /mcp` resolved for its caller in
//!   [`CLIENT_IP_HEADER`], vouched for by [`TOKEN_HEADER`]: a random value
//!   generated per process at boot. Only this process knows it, and with a
//!   direct dial the request never leaves the host, so a match means the
//!   request is our own loopback and the named address is the one we
//!   resolved. Anything else is ignored and resolution proceeds as usual.

use std::fmt;

use axum::http::HeaderMap;
use subtle::ConstantTimeEq;

/// Per-process secret proving a request is this process's own loopback.
pub const TOKEN_HEADER: &str = "x-overslash-loopback-token";

/// The client address `POST /mcp` resolved for the request it is forwarding.
/// Absent when it resolved none.
pub const CLIENT_IP_HEADER: &str = "x-overslash-loopback-client-ip";

#[derive(Clone)]
pub struct Loopback {
    /// `http://host:port` of this process, or `None` to dial `PUBLIC_URL`
    /// (the in-process test harness, whose public URL *is* its bind address).
    base: Option<String>,
    /// Hex of 32 random bytes.
    token: String,
}

impl Default for Loopback {
    fn default() -> Self {
        use rand::RngExt;
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        Self {
            base: None,
            token: hex::encode(bytes),
        }
    }
}

impl fmt::Debug for Loopback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Loopback")
            .field("base", &self.base)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl Loopback {
    /// Dial the server bound at `host:port` directly. A wildcard bind is
    /// reached on loopback.
    pub fn on_local_port(host: &str, port: u16) -> Self {
        let host = match host.trim_matches(['[', ']']) {
            "" | "0.0.0.0" | "localhost" => "127.0.0.1".to_string(),
            "::" => "[::1]".to_string(),
            h if h.contains(':') => format!("[{h}]"),
            h => h.to_string(),
        };
        Self {
            base: Some(format!("http://{host}:{port}")),
            ..Self::default()
        }
    }

    /// The URL for `path` on this API.
    pub fn url(&self, public_url: &str, path: &str) -> String {
        let base = self.base.as_deref().unwrap_or(public_url);
        format!("{}{}", base.trim_end_matches('/'), path)
    }

    /// Stamp a loopback request with the token and the caller's address.
    pub fn stamp(
        &self,
        req: reqwest::RequestBuilder,
        client_ip: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let req = req.header(TOKEN_HEADER, &self.token);
        match client_ip {
            Some(ip) => req.header(CLIENT_IP_HEADER, ip),
            None => req,
        }
    }

    /// `Some` when `headers` carry this process's token: the request is our
    /// own loopback, and the inner value is the client it named (or `None`
    /// if it named none). `None` means not a loopback; resolve normally.
    pub fn vouched_client(&self, headers: &HeaderMap) -> Option<Option<String>> {
        let presented = headers.get(TOKEN_HEADER)?;
        if !bool::from(presented.as_bytes().ct_eq(self.token.as_bytes())) {
            return None;
        }
        Some(
            headers
                .get(CLIENT_IP_HEADER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<std::net::IpAddr>().ok())
                .map(|ip| ip.to_canonical().to_string()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(token: Option<&str>, ip: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(t) = token {
            h.insert(TOKEN_HEADER, HeaderValue::from_str(t).unwrap());
        }
        if let Some(i) = ip {
            h.insert(CLIENT_IP_HEADER, HeaderValue::from_str(i).unwrap());
        }
        h
    }

    #[test]
    fn only_this_processs_token_vouches() {
        let lb = Loopback::default();
        let other = Loopback::default();
        assert_eq!(
            lb.vouched_client(&headers(Some(&lb.token), Some("82.213.253.53"))),
            Some(Some("82.213.253.53".into()))
        );
        assert_eq!(
            lb.vouched_client(&headers(Some(&other.token), Some("82.213.253.53"))),
            None
        );
        assert_eq!(
            lb.vouched_client(&headers(None, Some("82.213.253.53"))),
            None
        );
        assert_eq!(lb.vouched_client(&headers(Some(""), Some("1.2.3.4"))), None);
    }

    #[test]
    fn a_vouched_request_naming_no_valid_client_has_none() {
        let lb = Loopback::default();
        assert_eq!(
            lb.vouched_client(&headers(Some(&lb.token), None)),
            Some(None)
        );
        assert_eq!(
            lb.vouched_client(&headers(Some(&lb.token), Some("unknown"))),
            Some(None)
        );
        assert_eq!(
            lb.vouched_client(&headers(Some(&lb.token), Some("::ffff:10.1.2.3"))),
            Some(Some("10.1.2.3".into()))
        );
    }

    #[test]
    fn dials_the_bind_address_and_falls_back_to_the_public_url() {
        let p = "https://app.overslash.com/";
        assert_eq!(
            Loopback::on_local_port("0.0.0.0", 8080).url(p, "/v1/actions/call"),
            "http://127.0.0.1:8080/v1/actions/call"
        );
        assert_eq!(
            Loopback::on_local_port("::", 3000).url(p, "/x"),
            "http://[::1]:3000/x"
        );
        assert_eq!(
            Loopback::on_local_port("10.0.0.5", 3000).url(p, "/x"),
            "http://10.0.0.5:3000/x"
        );
        assert_eq!(
            Loopback::default().url(p, "/v1/actions/call"),
            "https://app.overslash.com/v1/actions/call"
        );
    }

    #[test]
    fn debug_never_prints_the_token() {
        let lb = Loopback::default();
        assert!(!format!("{lb:?}").contains(&lb.token));
    }
}
