use crate::service_icon::{MAX_ICON_LEN, ServiceIcon};
use crate::template_validation::Issues;
use crate::types::{Runtime, ServiceDefinition};

// --- service-level ---------------------------------------------------------

pub(super) fn check_service_shape(def: &ServiceDefinition, issues: &mut Issues) {
    if def.key.is_empty() {
        issues.err("missing_field", "key is required", "key");
    } else if !is_valid_service_key(&def.key) {
        issues.err("invalid_key", "key must match ^[a-z][a-z0-9_-]*$", "key");
    }

    if def.display_name.trim().is_empty() {
        issues.err("missing_field", "display_name is required", "display_name");
    }

    // Ahead of the platform early-return below: a platform service still
    // carries an icon.
    check_service_icon(def.icon.as_ref(), "icon", issues);

    // Platform services have no hosts — they dispatch in-process.
    if def.runtime == Runtime::Platform {
        return;
    }

    for (i, host) in def.hosts.iter().enumerate() {
        let path = format!("hosts[{i}]");
        if host.trim().is_empty() {
            issues.err("invalid_host", "host must be non-empty", path);
        } else if !is_valid_hostname(host) {
            issues.err(
                "invalid_host",
                "host must be a plain hostname (no scheme, no path, no whitespace)",
                path,
            );
        }
    }
}

/// Validate an icon wherever one is authored — a template's `info` block or a
/// derived layer's delta.
///
/// `https://` only. An icon is the one piece of template metadata that becomes
/// a URL the operator's browser fetches, so `http:` (mixed content), `data:`
/// and `javascript:` are refused outright rather than dropped silently: a
/// dropped value teaches the author it worked, and a reviewer reading the
/// validation report wants the attempt named.
pub(crate) fn check_service_icon(icon: Option<&ServiceIcon>, path: &str, issues: &mut Issues) {
    let Some(icon) = icon else {
        return;
    };

    match icon {
        ServiceIcon::Builtin { slug } => {
            if !is_valid_icon_slug(slug) {
                issues.err(
                    "invalid_icon",
                    "builtin icon name must match ^[a-z0-9][a-z0-9_-]*$",
                    path,
                );
            } else if !icon.is_known_builtin() {
                // A warning, not an error: a self-hoster may legitimately trim
                // the shipped asset set, and the dashboard falls back to the
                // letter tile either way.
                issues.warn(
                    "unknown_builtin_icon",
                    format!("no built-in icon named \"{slug}\" is shipped; it will render as a letter tile"),
                    path,
                );
            }
        }
        ServiceIcon::Remote { url } => {
            if url.len() > MAX_ICON_LEN {
                issues.err(
                    "invalid_icon",
                    format!("icon URL must be at most {MAX_ICON_LEN} bytes"),
                    path,
                );
            } else if !is_https_url(url) {
                issues.err(
                    "invalid_icon",
                    "icon URL must start with https:// (or use builtin:<name>)",
                    path,
                );
            }
        }
    }
}

fn is_valid_icon_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn is_https_url(s: &str) -> bool {
    // Case-insensitive on the scheme only; `HTTPS://` is a legal URL and a
    // case-sensitive check would reject it while a browser accepts it.
    let Some(rest) = s.get(..8) else {
        return false;
    };
    rest.eq_ignore_ascii_case("https://") && s.len() > 8
}

fn is_valid_service_key(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn is_valid_hostname(s: &str) -> bool {
    !s.is_empty() && !s.contains("://") && !s.contains('/') && !s.chars().any(|c| c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use crate::service_icon::ServiceIcon;
    use crate::template_validation::core::tests::{minimal_valid, run};

    fn icon_report(raw: &str) -> crate::template_validation::ValidationReport {
        let mut d = minimal_valid();
        d.icon = Some(ServiceIcon::try_from(raw.to_string()).expect("parses"));
        run(&d)
    }

    #[test]
    fn icon_rejects_every_scheme_but_https() {
        // Each of these parses fine — policy is what stops them, and it has to
        // stop them loudly rather than dropping the value.
        for raw in [
            "http://example.com/a.svg",
            "javascript:alert(1)",
            "data:image/svg+xml,<svg/>",
            "//evil.example/a.svg",
            "https://",
        ] {
            let r = icon_report(raw);
            assert!(!r.valid, "{raw} should be rejected");
            assert!(
                r.errors.iter().any(|e| e.code == "invalid_icon"),
                "{raw} should raise invalid_icon, got {:?}",
                r.errors
            );
        }
    }

    #[test]
    fn icon_accepts_https_in_any_case() {
        assert!(icon_report("https://example.com/a.svg").valid);
        assert!(icon_report("HTTPS://example.com/a.svg").valid);
    }

    #[test]
    fn icon_rejects_a_malformed_builtin_name() {
        for raw in ["builtin:../../etc/passwd", "builtin:Nope", "builtin:a b"] {
            match ServiceIcon::try_from(raw.to_string()) {
                // Whitespace never gets past parsing.
                Err(_) => continue,
                Ok(icon) => {
                    let mut d = minimal_valid();
                    d.icon = Some(icon);
                    let r = run(&d);
                    assert!(
                        r.errors.iter().any(|e| e.code == "invalid_icon"),
                        "{raw} should raise invalid_icon"
                    );
                }
            }
        }
    }

    #[test]
    fn unknown_builtin_icon_only_warns() {
        // A self-hoster may legitimately trim the shipped asset set; the
        // dashboard falls back to the letter tile either way.
        let r = icon_report("builtin:not_shipped");
        assert!(r.valid);
        assert!(r.warnings.iter().any(|w| w.code == "unknown_builtin_icon"));
    }

    #[test]
    fn shipped_builtin_icon_is_clean() {
        let r = icon_report("builtin:github");
        assert!(r.valid);
        assert!(r.warnings.iter().all(|w| w.code != "unknown_builtin_icon"));
    }

    #[test]
    fn invalid_key() {
        let mut d = minimal_valid();
        d.key = "Bad-Key".into();
        let r = run(&d);
        assert!(!r.valid);
        assert!(r.errors.iter().any(|e| e.code == "invalid_key"));
    }

    #[test]
    fn missing_display_name() {
        let mut d = minimal_valid();
        d.display_name = "".into();
        let r = run(&d);
        assert!(
            r.errors
                .iter()
                .any(|e| e.code == "missing_field" && e.path == "display_name")
        );
    }

    #[test]
    fn invalid_host() {
        let mut d = minimal_valid();
        d.hosts = vec!["https://api.example.com/foo".into()];
        let r = run(&d);
        assert!(r.errors.iter().any(|e| e.code == "invalid_host"));
    }
}
