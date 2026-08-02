//! Env-var parsing helpers behind [`Config::from_env`](super::Config::from_env).
//!
//! Each function takes the already-read raw value (or reads the env var
//! itself where the default depends on other vars) and is unit-tested
//! directly — which is why they stay `pub(super)` rather than private.

use super::*;
use std::env;

/// Parse the `PREVIEW_ORIGIN_ALLOWLIST` env var into a compiled regex.
/// Fail-closed: any error (empty string, invalid regex syntax) returns
/// None and the preview-handoff feature stays off. We also log the
/// failure so an operator who fat-fingers the regex notices instead of
/// silently disabling the feature.
///
/// Wraps the user pattern in `^(?:<pat>)$` so `is_match` does a
/// full-string match. Without this, an unanchored config like
/// `overslash\.vercel\.app` would let `overslash.vercel.app.attacker.com`
/// pass — the partial-match default would be a session-theft footgun.
/// Wrapping is idempotent for already-anchored patterns: `^foo$` becomes
/// `^(?:^foo$)$`, which the regex engine collapses to the same
/// language as `^foo$`.
pub(super) fn parse_preview_origin_allowlist(raw: Option<&str>) -> Option<regex::Regex> {
    let pattern = raw.map(str::trim).filter(|s| !s.is_empty())?;
    let anchored = format!("^(?:{pattern})$");
    match regex::Regex::new(&anchored) {
        Ok(re) => Some(re),
        Err(e) => {
            tracing::warn!(
                pattern = pattern,
                error = %e,
                "PREVIEW_ORIGIN_ALLOWLIST regex did not compile; preview handoff disabled",
            );
            None
        }
    }
}

pub(super) fn parse_connection_return_url_allowed_hosts(raw: Option<&str>) -> Vec<String> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Vec::new();
    };
    s.split(',')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect()
}

/// Build the platform credential from its three env vars. All three must be
/// present and non-empty — a partial config (a host with no key, a key with no
/// host) is a misconfiguration that must not silently degrade into "inject
/// nowhere" or, worse, "inject everywhere".
pub(super) fn parse_platform_credential(
    secret_name: Option<&str>,
    host: Option<&str>,
    value: Option<&str>,
) -> Option<PlatformCredential> {
    let secret_name = secret_name.map(str::trim).filter(|s| !s.is_empty())?;
    let host = host.map(str::trim).filter(|s| !s.is_empty())?;
    let value = value.map(str::trim).filter(|s| !s.is_empty())?;
    Some(PlatformCredential {
        secret_name: secret_name.to_string(),
        host: host.to_ascii_lowercase(),
        value: value.to_string(),
    })
}

pub(super) fn parse_service_base_overrides(raw: Option<&str>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Some(s) = raw.filter(|s| !s.trim().is_empty()) else {
        return out;
    };
    for entry in s.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((k, v)) = entry.split_once('=') else {
            continue;
        };
        let host = k.trim();
        let base = v.trim();
        if host.is_empty() || base.is_empty() {
            continue;
        }
        out.insert(host.to_string(), base.to_string());
    }
    out
}

/// Returns true if the override target is loopback or
/// `OVERSLASH_SSRF_ALLOW_PRIVATE` is set to a truthy value. Mirrors the SSRF
/// guard so production deploys can leave `OVERSLASH_SERVICE_BASE_OVERRIDES`
/// set harmlessly: a public override target is silently dropped.
pub(super) fn ssrf_allowed_for(base_url: &str) -> bool {
    if let Ok(v) = env::var("OVERSLASH_SSRF_ALLOW_PRIVATE") {
        // Accept the same truthy spellings as `CLOUD_BILLING` etc. above so a
        // stray `OVERSLASH_SSRF_ALLOW_PRIVATE=0` doesn't accidentally enable
        // the bypass.
        if matches!(v.as_str(), "true" | "1" | "yes") {
            return true;
        }
    }
    let Ok(parsed) = url::Url::parse(base_url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    false
}

/// Build the default `public_url` from the bind host/port. We map
/// wildcard binds (`0.0.0.0`, `::`) to `localhost` because the public URL
/// is meant to be reachable from a browser — `http://0.0.0.0:8080` is not
/// a valid origin to advertise. Raw IPv6 literals (e.g. `::1`,
/// `2001:db8::1`) are wrapped in brackets per RFC 3986 so the resulting
/// URL parses cleanly. Set `PUBLIC_URL` explicitly for production
/// deployments behind a reverse proxy.
/// Parse `SECRETS_ENCRYPTION_KEY_ACTIVE_ID` from the env. Defaults to `1`
/// when unset. **Panics** if set to a value that doesn't parse as a `u8`
/// (e.g. `256`, `0x02`, `two`) — silently folding such typos back to the
/// default `1` would re-tag fresh writes with the historical key id while
/// the active slot holds new key bytes, so old blobs (tagged id=1, old
/// key) would stop decrypting at runtime. Better to surface the typo at
/// boot, in the same `from_env` panic-on-misconfig path the required env
/// vars use.
pub(super) fn secrets_encryption_key_active_id_from_env() -> u8 {
    match env::var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID") {
        Err(_) => 1,
        Ok(s) if s.is_empty() => 1,
        Ok(s) => s.parse::<u8>().unwrap_or_else(|_| {
            panic!("SECRETS_ENCRYPTION_KEY_ACTIVE_ID must be a u8 (1..=255), got {s:?}")
        }),
    }
}

/// Parse `SECRETS_ENCRYPTION_KEY_PREVIOUS_ID` from the env. Defaults to
/// `active_id - 1` (the only legal rotation shape) when unset. Same
/// fail-fast posture as the active-id helper.
pub(super) fn secrets_encryption_key_previous_id_from_env(active_id: u8) -> u8 {
    match env::var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID") {
        Err(_) => active_id.saturating_sub(1),
        Ok(s) if s.is_empty() => active_id.saturating_sub(1),
        Ok(s) => s.parse::<u8>().unwrap_or_else(|_| {
            panic!("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID must be a u8 (1..=255), got {s:?}")
        }),
    }
}

pub fn default_public_url(host: &str, port: u16) -> String {
    let display: std::borrow::Cow<'_, str> = match host {
        "0.0.0.0" | "::" | "[::]" => "localhost".into(),
        h if h.starts_with('[') => h.into(),
        // An unbracketed colon means an IPv6 literal — bracket it so
        // `host:port` doesn't collide with the address's own colons.
        h if h.contains(':') => format!("[{h}]").into(),
        h => h.into(),
    };
    format!("http://{display}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::ENV_LOCK;

    #[test]
    fn default_public_url_maps_wildcard_hosts_to_localhost() {
        assert_eq!(default_public_url("0.0.0.0", 8080), "http://localhost:8080");
        assert_eq!(default_public_url("::", 3000), "http://localhost:3000");
        assert_eq!(default_public_url("[::]", 7676), "http://localhost:7676");
    }

    #[test]
    fn default_public_url_passes_through_explicit_hosts() {
        assert_eq!(
            default_public_url("127.0.0.1", 7676),
            "http://127.0.0.1:7676"
        );
        assert_eq!(
            default_public_url("api.example.com", 8080),
            "http://api.example.com:8080"
        );
    }

    #[test]
    fn default_public_url_brackets_raw_ipv6_literals() {
        // RFC 3986 requires IPv6 in URLs to be bracketed so the host's
        // colons can be told apart from the host:port colon.
        assert_eq!(default_public_url("::1", 8080), "http://[::1]:8080");
        assert_eq!(
            default_public_url("2001:db8::1", 8080),
            "http://[2001:db8::1]:8080"
        );
    }

    #[test]
    fn default_public_url_does_not_double_bracket_already_bracketed_ipv6() {
        assert_eq!(default_public_url("[::1]", 8080), "http://[::1]:8080");
        assert_eq!(
            default_public_url("[2001:db8::1]", 8080),
            "http://[2001:db8::1]:8080"
        );
    }

    #[test]
    fn parse_service_base_overrides_handles_multiple_entries() {
        let map = parse_service_base_overrides(Some(
            "api.github.com=http://127.0.0.1:9101,slack.com=http://127.0.0.1:9102",
        ));
        assert_eq!(
            map.get("api.github.com"),
            Some(&"http://127.0.0.1:9101".to_string())
        );
        assert_eq!(
            map.get("slack.com"),
            Some(&"http://127.0.0.1:9102".to_string())
        );
    }

    #[test]
    fn parse_service_base_overrides_skips_malformed_entries() {
        let map = parse_service_base_overrides(Some(
            "api.github.com=http://127.0.0.1:9101,bad-no-equals,=http://x,foo=",
        ));
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("api.github.com"));
    }

    // ── connection_return_url_allowed_hosts ─────────────────────────────
    //
    // The OAuth callback uses this list as its fail-closed gate on whether
    // to honour a flow row's `return_url` (see
    // `routes/connections.rs::resolve_redirect_target`). An empty list
    // *disables* the redirect feature entirely. Parsing has to be
    // forgiving (operators set comma-separated env vars by hand) but never
    // silently widen the host set.

    #[test]
    fn parse_connection_return_url_hosts_handles_multiple_entries() {
        let hosts = parse_connection_return_url_allowed_hosts(Some(
            "cloud.overfolder.com,cloud-dev.overfolder.com,localhost",
        ));
        assert_eq!(
            hosts,
            vec![
                "cloud.overfolder.com".to_string(),
                "cloud-dev.overfolder.com".to_string(),
                "localhost".to_string(),
            ]
        );
    }

    #[test]
    fn parse_connection_return_url_hosts_lowercases_and_trims() {
        // The callback's allow-list check lowercases the URL's host_str()
        // before comparing — entries must come out of the parser in the
        // same shape or a `Cloud.Overfolder.COM` allow-list entry would
        // silently never match a `cloud.overfolder.com` host.
        let hosts =
            parse_connection_return_url_allowed_hosts(Some("  Cloud.Overfolder.COM ,  Localhost "));
        assert_eq!(
            hosts,
            vec!["cloud.overfolder.com".to_string(), "localhost".to_string()]
        );
    }

    #[test]
    fn parse_connection_return_url_hosts_empty_disables_feature() {
        // Empty / unset / whitespace-only all mean "the operator did not
        // opt in" and the callback path stays on the historical JSON
        // response. Important that none of these silently parse as a list
        // with an empty-string entry that could be matched by a bug.
        assert!(parse_connection_return_url_allowed_hosts(None).is_empty());
        assert!(parse_connection_return_url_allowed_hosts(Some("")).is_empty());
        assert!(parse_connection_return_url_allowed_hosts(Some("   ")).is_empty());
        assert!(parse_connection_return_url_allowed_hosts(Some(",,,")).is_empty());
    }

    #[test]
    fn parse_connection_return_url_hosts_skips_blank_entries() {
        // Operators occasionally leave a trailing comma or double-comma
        // in env-var syntax. Drop the empties; keep the rest.
        let hosts =
            parse_connection_return_url_allowed_hosts(Some(",cloud.overfolder.com, ,localhost,"));
        assert_eq!(
            hosts,
            vec!["cloud.overfolder.com".to_string(), "localhost".to_string()]
        );
    }

    #[test]
    fn from_env_loads_connection_return_url_hosts() {
        // The full `from_env` boot path. Exercises that the env-var name
        // is wired correctly and that the parser feeds Config without
        // mangling. We can't call `Config::from_env()` itself (it expects
        // DATABASE_URL / SECRETS_ENCRYPTION_KEY / SIGNING_KEY to be set
        // and panics otherwise), so the assertion mirrors the read-line
        // in `from_env`.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var(
                "OVERSLASH_CONNECTION_RETURN_URL_HOSTS",
                "cloud.overfolder.com,localhost",
            );
        }
        let hosts = parse_connection_return_url_allowed_hosts(
            std::env::var("OVERSLASH_CONNECTION_RETURN_URL_HOSTS")
                .ok()
                .as_deref(),
        );
        unsafe {
            std::env::remove_var("OVERSLASH_CONNECTION_RETURN_URL_HOSTS");
        }
        assert_eq!(
            hosts,
            vec!["cloud.overfolder.com".to_string(), "localhost".to_string()]
        );
    }

    #[test]
    fn from_env_unset_connection_return_url_hosts_disables_feature() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::remove_var("OVERSLASH_CONNECTION_RETURN_URL_HOSTS");
        }
        let hosts = parse_connection_return_url_allowed_hosts(
            std::env::var("OVERSLASH_CONNECTION_RETURN_URL_HOSTS")
                .ok()
                .as_deref(),
        );
        assert!(hosts.is_empty());
    }

    #[test]
    fn parse_preview_origin_allowlist_disabled_when_empty_or_invalid() {
        assert!(parse_preview_origin_allowlist(None).is_none());
        assert!(parse_preview_origin_allowlist(Some("")).is_none());
        assert!(parse_preview_origin_allowlist(Some("   ")).is_none());
        // Unbalanced group — regex compile fails, fall back to disabled.
        assert!(parse_preview_origin_allowlist(Some("(unbalanced")).is_none());
    }

    #[test]
    fn parse_preview_origin_allowlist_compiles_valid_pattern() {
        let re =
            parse_preview_origin_allowlist(Some(r"^https://overslash-[a-z0-9-]+\.vercel\.app$"))
                .expect("compiles");
        assert!(re.is_match("https://overslash-feat-x.vercel.app"));
        assert!(!re.is_match("https://attacker.example.com"));
    }

    #[test]
    fn parse_preview_origin_allowlist_full_string_matches_even_unanchored_input() {
        // An operator who forgets to anchor their regex must not create a
        // session-theft hole. Substring matches like "...vercel.app..."
        // could otherwise pass.
        let re = parse_preview_origin_allowlist(Some(r"https://allowed\.preview\.test"))
            .expect("compiles");
        assert!(re.is_match("https://allowed.preview.test"));
        assert!(
            !re.is_match("https://allowed.preview.test.attacker.com"),
            "unanchored pattern must not be exploitable via suffix injection"
        );
        assert!(
            !re.is_match("https://prefix.allowed.preview.test"),
            "unanchored pattern must not be exploitable via prefix injection"
        );
    }

    #[test]
    fn parse_preview_origin_allowlist_anchoring_is_idempotent() {
        // Already-anchored input must keep working — the wrapper is
        // `^(?:<pat>)$`, so `^foo$` becomes `^(?:^foo$)$` which is the
        // same language as `^foo$`.
        let re = parse_preview_origin_allowlist(Some(r"^foo$")).expect("compiles");
        assert!(re.is_match("foo"));
        assert!(!re.is_match("foofoo"));
        assert!(!re.is_match("xfoo"));
    }

    #[test]
    fn parse_preview_origin_allowlist_alternation_anchors_each_branch() {
        // `foo|bar` becomes `^(?:foo|bar)$` — both branches must be
        // full-string-matched, not just the first.
        let re = parse_preview_origin_allowlist(Some("foo|bar")).expect("compiles");
        assert!(re.is_match("foo"));
        assert!(re.is_match("bar"));
        assert!(!re.is_match("foobar"));
        assert!(!re.is_match("xfoo"));
        assert!(!re.is_match("barx"));
    }

    // ── env-var helpers ──────────────────────────────────────────────────

    #[test]
    fn previous_id_defaults_to_active_minus_one() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID");
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID");
        }
        assert_eq!(secrets_encryption_key_active_id_from_env(), 1);
        assert_eq!(
            secrets_encryption_key_previous_id_from_env(secrets_encryption_key_active_id_from_env()),
            0,
            "previous_id defaults to active_id - 1 (0 when active is 1)"
        );
    }

    #[test]
    fn active_id_reads_env_when_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID", "7");
        }
        assert_eq!(secrets_encryption_key_active_id_from_env(), 7);
        unsafe {
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID");
        }
    }

    #[test]
    fn previous_id_reads_env_when_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID", "5");
        }
        assert_eq!(secrets_encryption_key_previous_id_from_env(8), 5);
        unsafe {
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID");
        }
    }

    #[test]
    fn active_id_panics_on_unparseable_value() {
        // Silent fallback to 1 would be unsafe: typo'd `_ACTIVE_ID=256`
        // would re-tag new writes with the historical id while the
        // active slot holds new key bytes, breaking decryption of every
        // old blob. The helper must surface the typo.
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID", "256");
        }
        let panicked = std::panic::catch_unwind(secrets_encryption_key_active_id_from_env).is_err();
        unsafe {
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID");
        }
        assert!(panicked, "out-of-range u8 must panic at startup");
    }

    #[test]
    fn active_id_panics_on_non_numeric_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID", "not-a-number");
        }
        let panicked = std::panic::catch_unwind(secrets_encryption_key_active_id_from_env).is_err();
        unsafe {
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID");
        }
        assert!(panicked, "non-numeric value must panic at startup");
    }

    #[test]
    fn previous_id_panics_on_unparseable_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID", "not-a-number");
        }
        let panicked =
            std::panic::catch_unwind(|| secrets_encryption_key_previous_id_from_env(2)).is_err();
        unsafe {
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID");
        }
        assert!(panicked, "non-numeric previous_id must panic at startup");
    }

    #[test]
    fn empty_env_falls_back_to_default() {
        // Empty string is treated as "unset" — Cloud Run secret mounts
        // sometimes materialise unset vars as empty strings.
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID", "");
            std::env::set_var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID", "");
        }
        assert_eq!(secrets_encryption_key_active_id_from_env(), 1);
        assert_eq!(secrets_encryption_key_previous_id_from_env(3), 2);
        unsafe {
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_ACTIVE_ID");
            std::env::remove_var("SECRETS_ENCRYPTION_KEY_PREVIOUS_ID");
        }
    }
}
