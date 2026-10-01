//! Limits for the traffic the `/v1` rate-limit layer cannot see: the MCP
//! transport and the OAuth handshake (`middleware::ingress_rate_limit`).
//!
//! Instance-wide, not per org: most of this traffic arrives before the caller
//! has proven which org it belongs to, so there is no org setting to read.

use overslash_env as env;

use crate::services::rate_limit::RateLimitConfig;

/// Each limit is `None` when the operator turned it off (`…_RATE_LIMIT=0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressRateLimits {
    /// Per client IP, across `/oauth/*`, `/.well-known/oauth-*` and
    /// unauthenticated `/mcp`.
    pub oauth_ip: Option<RateLimitConfig>,
    /// Per client IP, on `POST /oauth/register` only, on top of `oauth_ip`.
    pub oauth_register_ip: Option<RateLimitConfig>,
    /// Per MCP client (per identity for an `osk_` key), on `/mcp`.
    pub mcp_client: Option<RateLimitConfig>,
}

/// A full MCP OAuth handshake is about half a dozen requests (two metadata
/// documents, register, authorize, token), so this leaves room for many
/// clients behind one NAT.
const OAUTH_IP: RateLimitConfig = RateLimitConfig {
    max_requests: 120,
    window_seconds: 60,
};
/// A client registers once per install. Twenty an hour from one address is
/// an office onboarding at once, not a client in normal use.
const OAUTH_REGISTER_IP: RateLimitConfig = RateLimitConfig {
    max_requests: 20,
    window_seconds: 3600,
};
/// Ten a second, sustained. Tool calls also spend the owner's `/v1` budget.
const MCP_CLIENT: RateLimitConfig = RateLimitConfig {
    max_requests: 600,
    window_seconds: 60,
};

impl Default for IngressRateLimits {
    fn default() -> Self {
        Self {
            oauth_ip: Some(OAUTH_IP),
            oauth_register_ip: Some(OAUTH_REGISTER_IP),
            mcp_client: Some(MCP_CLIENT),
        }
    }
}

impl IngressRateLimits {
    /// Every limit off. What the test harness runs with, so a test that
    /// registers a dozen clients from `127.0.0.1` is not throttled.
    pub const fn disabled() -> Self {
        Self {
            oauth_ip: None,
            oauth_register_ip: None,
            mcp_client: None,
        }
    }

    /// Reads `OAUTH_RATE_LIMIT` / `OAUTH_RATE_WINDOW_SECS`,
    /// `OAUTH_REGISTER_RATE_LIMIT` / `OAUTH_REGISTER_RATE_WINDOW_SECS` and
    /// `MCP_RATE_LIMIT` / `MCP_RATE_WINDOW_SECS`. A value that does not parse
    /// stops the boot: a typo that silently reverted to the default — or worse,
    /// to "off" — is the failure worth surfacing.
    pub fn from_env() -> Self {
        Self {
            oauth_ip: limit("OAUTH", OAUTH_IP),
            oauth_register_ip: limit("OAUTH_REGISTER", OAUTH_REGISTER_IP),
            mcp_client: limit("MCP", MCP_CLIENT),
        }
    }
}

fn limit(prefix: &str, default: RateLimitConfig) -> Option<RateLimitConfig> {
    let max_name = format!("{prefix}_RATE_LIMIT");
    let window_name = format!("{prefix}_RATE_WINDOW_SECS");
    let max_requests: u32 = env::parse_or_die(&max_name, default.max_requests);
    let window_seconds: u32 = env::parse_or_die(&window_name, default.window_seconds);
    assert!(window_seconds > 0, "{window_name} must be at least 1");
    (max_requests > 0).then_some(RateLimitConfig {
        max_requests,
        window_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::ENV_LOCK;

    const VARS: [&str; 6] = [
        "OAUTH_RATE_LIMIT",
        "OAUTH_RATE_WINDOW_SECS",
        "OAUTH_REGISTER_RATE_LIMIT",
        "OAUTH_REGISTER_RATE_WINDOW_SECS",
        "MCP_RATE_LIMIT",
        "MCP_RATE_WINDOW_SECS",
    ];

    fn with_env(set: &[(&str, &str)], f: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized by ENV_LOCK, like every other env test here.
        unsafe {
            for v in VARS {
                std::env::remove_var(v);
            }
            for (k, v) in set {
                std::env::set_var(k, v);
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        unsafe {
            for v in VARS {
                std::env::remove_var(v);
            }
        }
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }

    #[test]
    fn unset_is_the_defaults() {
        with_env(&[], || {
            assert_eq!(IngressRateLimits::from_env(), IngressRateLimits::default());
        });
    }

    #[test]
    fn zero_turns_one_limit_off() {
        with_env(
            &[("OAUTH_REGISTER_RATE_LIMIT", "0"), ("MCP_RATE_LIMIT", "5")],
            || {
                let l = IngressRateLimits::from_env();
                assert_eq!(l.oauth_register_ip, None);
                assert_eq!(l.oauth_ip, Some(OAUTH_IP));
                assert_eq!(
                    l.mcp_client,
                    Some(RateLimitConfig {
                        max_requests: 5,
                        window_seconds: 60
                    })
                );
            },
        );
    }

    #[test]
    #[should_panic(expected = "OAUTH_RATE_LIMIT must be a valid u32")]
    fn a_typo_stops_the_boot() {
        with_env(&[("OAUTH_RATE_LIMIT", "12O")], || {
            IngressRateLimits::from_env();
        });
    }

    #[test]
    #[should_panic(expected = "MCP_RATE_WINDOW_SECS must be at least 1")]
    fn a_zero_window_stops_the_boot() {
        with_env(&[("MCP_RATE_WINDOW_SECS", "0")], || {
            IngressRateLimits::from_env();
        });
    }
}
