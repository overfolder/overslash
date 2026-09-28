//! `redirect_uris` for Dynamic Client Registration, parsed at the boundary.
//!
//! `POST /oauth/register` is unauthenticated, so whatever it stores is later
//! handed a live authorization code. Only three shapes of redirect are
//! accepted (CASA 3.2.2, RFC 8252):
//!
//! - `https://` with a host;
//! - `http://` only on a loopback host — `127.0.0.1`, `[::1]`, `localhost`
//!   (RFC 8252 §7.3);
//! - a private-use app scheme (RFC 8252 §7.1): reverse-DNS (the scheme has a
//!   `.`, e.g. `com.example.app:/cb`) or one of [`NAMED_APP_SCHEMES`], for
//!   MCP clients whose scheme predates the convention (`cursor://…`).
//!
//! Fragments and userinfo are refused everywhere. The original string is kept
//! byte-for-byte: authorize and token compare against it with `==`, and
//! clients send back exactly what they registered.

use std::net::Ipv4Addr;

use url::{Host, Url};

pub const MAX_REDIRECT_URIS: usize = 10;
pub const MAX_REDIRECT_URI_LEN: usize = 2048;

/// Non-reverse-DNS app schemes that shipping MCP clients register.
const NAMED_APP_SCHEMES: &[&str] = &["cursor", "vscode", "vscode-insiders", "windsurf"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectUri(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectUris(Vec<RedirectUri>);

impl RedirectUris {
    pub fn parse(raw: Vec<String>) -> Result<Self, RedirectUriError> {
        if raw.is_empty() {
            return Err(RedirectUriError::Empty);
        }
        if raw.len() > MAX_REDIRECT_URIS {
            return Err(RedirectUriError::TooMany);
        }
        let mut out: Vec<RedirectUri> = Vec::with_capacity(raw.len());
        for (i, uri) in raw.into_iter().enumerate() {
            let uri = RedirectUri::parse(uri).map_err(|kind| RedirectUriError::Invalid(i, kind))?;
            if out.contains(&uri) {
                return Err(RedirectUriError::Invalid(i, InvalidKind::Duplicate));
            }
            out.push(uri);
        }
        Ok(Self(out))
    }

    pub fn into_strings(self) -> Vec<String> {
        self.0.into_iter().map(|u| u.0).collect()
    }
}

impl RedirectUri {
    fn parse(raw: String) -> Result<Self, InvalidKind> {
        if raw.is_empty() {
            return Err(InvalidKind::Empty);
        }
        if raw.len() > MAX_REDIRECT_URI_LEN {
            return Err(InvalidKind::TooLong);
        }
        // `Url::parse` silently trims and strips tabs/newlines, which would
        // make the stored string differ from what the parser judged.
        if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(InvalidKind::Whitespace);
        }
        let url = Url::parse(&raw).map_err(|_| InvalidKind::Unparseable)?;
        if url.fragment().is_some() {
            return Err(InvalidKind::Fragment);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(InvalidKind::Userinfo);
        }
        match url.scheme() {
            "https" => {
                if url.host_str().is_none_or(str::is_empty) {
                    return Err(InvalidKind::MissingHost);
                }
            }
            "http" => {
                let loopback = match url.host() {
                    Some(Host::Ipv4(ip)) => ip == Ipv4Addr::LOCALHOST,
                    Some(Host::Ipv6(ip)) => ip.is_loopback(),
                    Some(Host::Domain(d)) => d == "localhost",
                    None => false,
                };
                if !loopback {
                    return Err(InvalidKind::NonLoopbackHttp);
                }
            }
            scheme if scheme.contains('.') || NAMED_APP_SCHEMES.contains(&scheme) => {}
            _ => return Err(InvalidKind::UnsupportedScheme),
        }
        Ok(Self(raw))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RedirectUriError {
    #[error("at least one redirect_uri is required")]
    Empty,
    #[error("at most {MAX_REDIRECT_URIS} redirect_uris may be registered")]
    TooMany,
    #[error("redirect_uris[{0}]: {1}")]
    Invalid(usize, InvalidKind),
}

/// Why one URI was refused. The message never echoes the URI itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvalidKind {
    #[error("must not be empty")]
    Empty,
    #[error("longer than {MAX_REDIRECT_URI_LEN} bytes")]
    TooLong,
    #[error("must not contain whitespace or control characters")]
    Whitespace,
    #[error("not an absolute URI")]
    Unparseable,
    #[error("must not contain a fragment")]
    Fragment,
    #[error("must not contain userinfo")]
    Userinfo,
    #[error("https redirect_uri needs a host")]
    MissingHost,
    #[error("http is only allowed on a loopback host (127.0.0.1, [::1], localhost)")]
    NonLoopbackHttp,
    #[error(
        "scheme not allowed; use https, http on a loopback host, or a private-use app scheme (e.g. com.example.app)"
    )]
    UnsupportedScheme,
    #[error("duplicate of an earlier redirect_uri")]
    Duplicate,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(uri: &str) -> Result<(), InvalidKind> {
        RedirectUri::parse(uri.to_string()).map(|_| ())
    }

    #[test]
    fn accepts_the_allowed_shapes() {
        for uri in [
            "https://claude.ai/api/mcp/auth_callback",
            "https://chatgpt.com/connector_platform_oauth_redirect",
            "http://127.0.0.1:1234/callback",
            "http://127.0.0.1/x",
            "HTTP://127.0.0.1:9/cb",
            "http://[::1]:9/cb",
            "http://localhost:6274/oauth/callback",
            "http://LOCALHOST/cb",
            "https://example.com/cb?tenant=a",
            "com.example.app:/oauth",
            "cursor://anysphere.cursor-mcp/oauth/callback",
            "vscode://vscode.github-authentication/did-authenticate",
        ] {
            assert_eq!(one(uri), Ok(()), "{uri} should be accepted");
        }
    }

    #[test]
    fn rejects_dangerous_and_non_loopback() {
        use InvalidKind::*;
        let long = format!("https://example.com/{}", "a".repeat(MAX_REDIRECT_URI_LEN));
        for (uri, want) in [
            ("", Empty),
            (long.as_str(), TooLong),
            ("javascript:alert(1)", UnsupportedScheme),
            ("JavaScript:alert(1)", UnsupportedScheme),
            (
                "data:text/html,<script>alert(1)</script>",
                UnsupportedScheme,
            ),
            ("file:///etc/passwd", UnsupportedScheme),
            ("vbscript:msgbox", UnsupportedScheme),
            ("blob:https://example.com/x", UnsupportedScheme),
            ("about:blank", UnsupportedScheme),
            ("ftp://example.com/cb", UnsupportedScheme),
            ("wss://example.com/cb", UnsupportedScheme),
            ("myapp:/cb", UnsupportedScheme),
            ("http://evil.example/cb", NonLoopbackHttp),
            ("http://127.0.0.1.evil.com/cb", NonLoopbackHttp),
            ("http://localhost.evil.com/cb", NonLoopbackHttp),
            ("http://10.0.0.1/cb", NonLoopbackHttp),
            ("http://127.0.0.2/cb", NonLoopbackHttp),
            ("https://ok.example/cb#frag", Fragment),
            ("https://ok.example/cb#", Fragment),
            ("com.example.app:/cb#x", Fragment),
            ("https://user@ok.example/cb", Userinfo),
            ("http://a:b@127.0.0.1/cb", Userinfo),
            ("https://ok.example/c b", Whitespace),
            (" https://ok.example/cb", Whitespace),
            ("https://ok.example/cb\n", Whitespace),
            ("/relative/cb", Unparseable),
        ] {
            assert_eq!(one(uri), Err(want), "{uri:?}");
        }
    }

    #[test]
    fn keeps_the_original_bytes() {
        let raw = "HTTP://LocalHost:9/cb".to_string();
        let parsed = RedirectUris::parse(vec![raw.clone()]).unwrap();
        assert_eq!(parsed.into_strings(), vec![raw]);
    }

    #[test]
    fn array_rules() {
        assert_eq!(RedirectUris::parse(vec![]), Err(RedirectUriError::Empty));
        let many = (0..=MAX_REDIRECT_URIS)
            .map(|i| format!("http://127.0.0.1:{}/cb", 1000 + i))
            .collect();
        assert_eq!(RedirectUris::parse(many), Err(RedirectUriError::TooMany));
        let dup = vec!["https://a.example/cb".into(), "https://a.example/cb".into()];
        assert_eq!(
            RedirectUris::parse(dup),
            Err(RedirectUriError::Invalid(1, InvalidKind::Duplicate))
        );
        let mixed = vec!["https://a.example/cb".into(), "javascript:x".into()];
        assert_eq!(
            RedirectUris::parse(mixed).unwrap_err().to_string(),
            format!("redirect_uris[1]: {}", InvalidKind::UnsupportedScheme)
        );
    }
}
