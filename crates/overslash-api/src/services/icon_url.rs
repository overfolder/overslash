//! Turning a template's [`ServiceIcon`] into a URL a browser may load.
//!
//! Everything that renders an icon goes through [`resolve_icon_url`], which is
//! also the last line of defence: `template_validation` rejects a non-https
//! remote icon at write time, but a delta stored before that rule existed — or
//! written by some future path that forgets to validate — must still never
//! reach a browser. Re-checking here costs a string comparison.

use overslash_core::service_icon::ServiceIcon;

/// Resolve an icon to an absolute URL, or `None` when there is nothing safe to
/// render. `None` means "no icon" — callers fall back to the letter tile.
///
/// The URL is absolute rather than relative because the same JSON is read by
/// the dashboard (a *different* origin in cloud: `app.` vs `api.`), the CLI and
/// the SDK. A relative `/icons/x.svg` would resolve against whatever origin
/// served the page and 404.
pub fn resolve_icon_url(icon: Option<&ServiceIcon>, public_url: &str) -> Option<String> {
    match icon? {
        // An unknown slug resolves to nothing rather than a URL that would 404:
        // a broken image is a worse rendering than the letter tile.
        ServiceIcon::Builtin { slug } => icon?
            .is_known_builtin()
            .then(|| format!("{}/icons/{}.svg", public_url.trim_end_matches('/'), slug)),
        ServiceIcon::Remote { url } => is_browser_safe(url).then(|| url.clone()),
    }
}

/// `https://` only, case-insensitive on the scheme. Rules out `http:` (mixed
/// content), `data:` and `javascript:` (script execution in the dashboard's
/// origin), and protocol-relative `//host/x.svg`.
fn is_browser_safe(url: &str) -> bool {
    url.len() > 8
        && url
            .get(..8)
            .is_some_and(|s| s.eq_ignore_ascii_case("https://"))
        && !url.chars().any(|c| c.is_control() || c.is_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builtin(slug: &str) -> ServiceIcon {
        ServiceIcon::Builtin { slug: slug.into() }
    }
    fn remote(url: &str) -> ServiceIcon {
        ServiceIcon::Remote { url: url.into() }
    }

    #[test]
    fn builds_an_absolute_url_for_a_shipped_asset() {
        assert_eq!(
            resolve_icon_url(Some(&builtin("github")), "https://api.overslash.com"),
            Some("https://api.overslash.com/icons/github.svg".to_string())
        );
    }

    #[test]
    fn a_trailing_slash_does_not_double_up() {
        assert_eq!(
            resolve_icon_url(Some(&builtin("github")), "https://api.overslash.com/"),
            Some("https://api.overslash.com/icons/github.svg".to_string())
        );
    }

    #[test]
    fn an_unshipped_slug_resolves_to_nothing() {
        assert_eq!(
            resolve_icon_url(Some(&builtin("not_shipped")), "https://api.overslash.com"),
            None
        );
    }

    #[test]
    fn only_https_remotes_reach_the_browser() {
        let base = "https://api.overslash.com";
        assert_eq!(
            resolve_icon_url(Some(&remote("https://cdn.example.com/a.svg")), base),
            Some("https://cdn.example.com/a.svg".to_string())
        );
        // Uppercase scheme is a legal URL a browser accepts, so we must too.
        assert_eq!(
            resolve_icon_url(Some(&remote("HTTPS://cdn.example.com/a.svg")), base),
            Some("HTTPS://cdn.example.com/a.svg".to_string())
        );
        for bad in [
            "http://cdn.example.com/a.svg",
            "javascript:alert(1)",
            "data:image/svg+xml,<svg/>",
            "//cdn.example.com/a.svg",
            "https://",
        ] {
            assert_eq!(
                resolve_icon_url(Some(&remote(bad)), base),
                None,
                "{bad} must not reach a browser"
            );
        }
    }

    #[test]
    fn absent_icon_resolves_to_nothing() {
        assert_eq!(resolve_icon_url(None, "https://api.overslash.com"), None);
    }
}
