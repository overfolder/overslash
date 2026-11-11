//! Credentials the platform holds on every org's behalf for the services it
//! hosts itself, and the host-pinned lookup that hands them out.

use super::Config;

/// A credential the *platform* holds on every org's behalf, for a service the
/// platform itself hosts — today only the shared overfwd Mailbox Gateway
/// (`services/email.yaml`, D39).
///
/// It sits one rung below the org vault in the credential cascade: an org that
/// stores the named secret, or binds it per instance, still wins. And it is
/// pinned to a single `host`, because the whole point of the shared gateway is
/// that a *different* org can point its instances at its own deployment — that
/// deployment must never receive our key.
///
/// One entry per platform-hosted upstream. D39 kept this to a single entry
/// until a second hosted service appeared; the platform-hosted WhatsApp and
/// Telegram gateways (hosted-runtimes.md, Phase 0) are that second and third.
/// Each entry is still bound to one secret name *and* one host, so the list
/// does not become a way to fill arbitrary third-party credentials from
/// platform env, which `OVERSLASH_DANGER_READ_AUTH_SECRET_FROM_ENVVARS`
/// (OAuth clients, tier 4) exists to gate loudly.
#[derive(Debug, Clone)]
pub struct PlatformCredential {
    /// Vault secret name this fills — `overfwd_gateway_key`. Matched against a
    /// credential slot's `default_secret_name`.
    pub secret_name: String,
    /// The only host the value may be sent to, lowercased.
    pub host: String,
    /// The credential itself. Cloud Run surfaces the Secret Manager value as
    /// an env var, same as `stripe_secret_key` and friends.
    pub value: String,
}

impl Config {
    /// The platform-held value for vault secret `secret_name`, if this
    /// deployment has one *and* `url` lands on the host it is pinned to.
    ///
    /// Both conditions matter. The name check keeps the value bound to the one
    /// credential slot it belongs to; the host check keeps it off any other
    /// upstream, so an org that points its `email` instances at a self-hosted
    /// overfwd — or at an attacker's — receives nothing.
    ///
    /// `url` is the full outgoing request URL. Anything that doesn't parse, or
    /// carries no host, resolves to `None`: a URL we can't reason about is not
    /// one we hand a credential to.
    pub fn platform_credential_for(&self, secret_name: &str, url: &str) -> Option<&str> {
        let cred = self
            .platform_credentials
            .iter()
            .find(|c| c.secret_name == secret_name)?;
        let host = url::Url::parse(url).ok()?.host_str()?.to_ascii_lowercase();
        (host == cred.host).then_some(cred.value.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse::{parse_platform_credential, parse_platform_credentials};
    use crate::config::tests::empty_test_config;

    fn platform_config() -> Config {
        let mut cfg = empty_test_config();
        cfg.platform_credentials = vec![
            PlatformCredential {
                secret_name: "overfwd_gateway_key".into(),
                host: "mailbox.overslash.com".into(),
                value: "platform-key".into(),
            },
            PlatformCredential {
                secret_name: "whatsapp_gateway_key".into(),
                host: "whatsapp-mcp.overslash.com".into(),
                value: "whatsapp-key".into(),
            },
        ];
        cfg
    }

    #[test]
    fn each_platform_credential_stays_on_its_own_host() {
        let cfg = platform_config();
        assert_eq!(
            cfg.platform_credential_for(
                "whatsapp_gateway_key",
                "https://whatsapp-mcp.overslash.com/mcp"
            ),
            Some("whatsapp-key")
        );
        // Two platform-hosted services never receive each other's key.
        assert_eq!(
            cfg.platform_credential_for(
                "whatsapp_gateway_key",
                "https://mailbox.overslash.com/email/search"
            ),
            None
        );
        assert_eq!(
            cfg.platform_credential_for(
                "overfwd_gateway_key",
                "https://whatsapp-mcp.overslash.com/mcp"
            ),
            None
        );
    }

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn platform_credentials_read_the_legacy_triple_and_suffixed_sets() {
        let creds = parse_platform_credentials(vars(&[
            (
                "OVERSLASH_PLATFORM_GATEWAY_SECRET_NAME",
                "overfwd_gateway_key",
            ),
            ("OVERSLASH_PLATFORM_GATEWAY_HOST", "mailbox.overslash.com"),
            ("OVERSLASH_PLATFORM_GATEWAY_KEY", "k0"),
            (
                "OVERSLASH_PLATFORM_GATEWAY_WHATSAPP_SECRET_NAME",
                "whatsapp_gateway_key",
            ),
            (
                "OVERSLASH_PLATFORM_GATEWAY_WHATSAPP_HOST",
                "WhatsApp-MCP.overslash.com",
            ),
            ("OVERSLASH_PLATFORM_GATEWAY_WHATSAPP_KEY", "k1"),
            (
                "OVERSLASH_PLATFORM_GATEWAY_TELEGRAM_SECRET_NAME",
                "telegram_gateway_key",
            ),
            (
                "OVERSLASH_PLATFORM_GATEWAY_TELEGRAM_HOST",
                "telegram-mcp.overslash.com",
            ),
            ("OVERSLASH_PLATFORM_GATEWAY_TELEGRAM_KEY", "k2"),
            ("UNRELATED", "x"),
        ]));
        let got: Vec<(&str, &str, &str)> = creds
            .iter()
            .map(|c| (c.secret_name.as_str(), c.host.as_str(), c.value.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("overfwd_gateway_key", "mailbox.overslash.com", "k0"),
                ("telegram_gateway_key", "telegram-mcp.overslash.com", "k2"),
                ("whatsapp_gateway_key", "whatsapp-mcp.overslash.com", "k1"),
            ]
        );
    }

    #[test]
    fn platform_credentials_skip_an_incomplete_set() {
        let creds = parse_platform_credentials(vars(&[
            (
                "OVERSLASH_PLATFORM_GATEWAY_WHATSAPP_SECRET_NAME",
                "whatsapp_gateway_key",
            ),
            (
                "OVERSLASH_PLATFORM_GATEWAY_WHATSAPP_HOST",
                "whatsapp-mcp.overslash.com",
            ),
            ("OVERSLASH_PLATFORM_GATEWAY_WHATSAPP_KEY", "   "),
        ]));
        assert!(creds.is_empty());
    }

    #[test]
    #[should_panic(expected = "whatsapp_gateway_key")]
    fn platform_credentials_refuse_one_name_on_two_hosts() {
        parse_platform_credentials(vars(&[
            (
                "OVERSLASH_PLATFORM_GATEWAY_A_SECRET_NAME",
                "whatsapp_gateway_key",
            ),
            ("OVERSLASH_PLATFORM_GATEWAY_A_HOST", "a.example"),
            ("OVERSLASH_PLATFORM_GATEWAY_A_KEY", "k"),
            (
                "OVERSLASH_PLATFORM_GATEWAY_B_SECRET_NAME",
                "whatsapp_gateway_key",
            ),
            ("OVERSLASH_PLATFORM_GATEWAY_B_HOST", "b.example"),
            ("OVERSLASH_PLATFORM_GATEWAY_B_KEY", "k"),
        ]));
    }

    #[test]
    fn platform_credential_matches_on_name_and_host() {
        let cfg = platform_config();
        assert_eq!(
            cfg.platform_credential_for(
                "overfwd_gateway_key",
                "https://mailbox.overslash.com/email/search"
            ),
            Some("platform-key")
        );
        // Case and port are not part of the identity of a host.
        assert_eq!(
            cfg.platform_credential_for(
                "overfwd_gateway_key",
                "https://MAILBOX.Overslash.com:443/email/search"
            ),
            Some("platform-key")
        );
    }

    #[test]
    fn platform_credential_withheld_from_any_other_host_or_slot() {
        let cfg = platform_config();
        // A self-hosted gateway — the containment property. `instance.url` is
        // tenant-controlled, so this is the case that must never leak.
        assert_eq!(
            cfg.platform_credential_for(
                "overfwd_gateway_key",
                "https://overfwd.some-tenant.example/email/search"
            ),
            None
        );
        // A lookalike host must not match on suffix.
        assert_eq!(
            cfg.platform_credential_for(
                "overfwd_gateway_key",
                "https://evil-mailbox.overslash.com.attacker.test/email/search"
            ),
            None
        );
        // Right host, different credential slot.
        assert_eq!(
            cfg.platform_credential_for("stripe_key", "https://mailbox.overslash.com/x"),
            None
        );
        // A URL we cannot parse is not one we hand a credential to.
        assert_eq!(
            cfg.platform_credential_for("overfwd_gateway_key", "not a url"),
            None
        );
    }

    #[test]
    fn platform_credential_absent_without_all_three_vars() {
        assert!(
            empty_test_config()
                .platform_credential_for("overfwd_gateway_key", "https://mailbox.overslash.com/x")
                .is_none()
        );
        // A partial config must not half-activate the rung.
        assert!(parse_platform_credential(Some("overfwd_gateway_key"), Some("h"), None).is_none());
        assert!(parse_platform_credential(Some("overfwd_gateway_key"), None, Some("k")).is_none());
        assert!(parse_platform_credential(None, Some("h"), Some("k")).is_none());
        assert!(parse_platform_credential(Some("n"), Some("  "), Some("k")).is_none());
    }
}
