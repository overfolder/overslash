//! The icon a service template presents in catalogs and pickers.
//!
//! Two forms share one authored string, because the value has to survive as a
//! plain string in three places — the template YAML, the stored `openapi`
//! jsonb, and the `delta` jsonb the layer editor renders as a JSON textarea. A
//! tagged object would leak into all three.
//!
//! ```yaml
//! info:
//!   icon: builtin:github                      # shipped with Overslash
//!   # icon: https://cdn.example.com/logo.svg  # hosted by someone else
//! ```
//!
//! Most templates declare nothing: an omitted `icon:` resolves to
//! `builtin:<key>` whenever we ship an asset under that name (see
//! [`BUILTIN_ICON_SLUGS`]), which is why the shipped assets are named after the
//! template key rather than the upstream icon-set slug.
//!
//! [`TryFrom<String>`] is deliberately permissive: it classifies and rejects
//! only trivia. Policy — https-only, known slug — lives in
//! `template_validation`, and is re-checked when the URL is handed to a browser.
//! Parsing must stay lenient because [`crate::types::ServiceDefinition`] is
//! `Deserialize`, and a stored artifact whose icon later became policy-invalid
//! must not fail to deserialize in its entirety over a logo.

use serde::{Deserialize, Serialize};

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../assets/service-icons/slugs.rs"
));

/// Longest authored icon string we accept. Generous for a URL, small enough
/// that a runaway value can't bloat every catalog row.
pub const MAX_ICON_LEN: usize = 512;

const BUILTIN_PREFIX: &str = "builtin:";

/// Where a service template's icon comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum ServiceIcon {
    /// An asset we ship and serve ourselves, named by template key.
    Builtin { slug: String },
    /// An icon hosted by someone else. Only `https://` ever reaches a browser.
    Remote { url: String },
}

impl ServiceIcon {
    /// True when this names a built-in asset that actually exists.
    pub fn is_known_builtin(&self) -> bool {
        match self {
            Self::Builtin { slug } => BUILTIN_ICON_SLUGS.contains(&slug.as_str()),
            Self::Remote { .. } => false,
        }
    }

    /// The implicit icon for a template key: `builtin:<key>` when we ship an
    /// asset under that name, otherwise nothing.
    ///
    /// Resolved at compile time rather than at response time so that a derived
    /// layer inherits it. A layer keyed `acme_github` extending `github` has no
    /// `acme_github.svg`; looking the icon up any later would find nothing and
    /// silently demote the layer to a letter tile.
    pub fn implicit_for_key(key: &str) -> Option<Self> {
        BUILTIN_ICON_SLUGS.contains(&key).then(|| Self::Builtin {
            slug: key.to_string(),
        })
    }
}

impl TryFrom<String> for ServiceIcon {
    type Error = String;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        let value = raw.trim();
        if value.is_empty() {
            return Err("icon must not be empty".to_string());
        }
        if value.len() > MAX_ICON_LEN {
            return Err(format!(
                "icon must be at most {MAX_ICON_LEN} bytes (got {})",
                value.len()
            ));
        }
        // Whitespace and control characters land in an HTML attribute and in a
        // response header, so they're rejected at the boundary rather than
        // escaped downstream.
        if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err("icon must not contain whitespace or control characters".to_string());
        }

        match value.strip_prefix(BUILTIN_PREFIX) {
            Some("") => Err(format!("`{BUILTIN_PREFIX}` must be followed by a name")),
            Some(slug) => Ok(Self::Builtin {
                slug: slug.to_string(),
            }),
            None => Ok(Self::Remote {
                url: value.to_string(),
            }),
        }
    }
}

impl From<ServiceIcon> for String {
    fn from(icon: ServiceIcon) -> Self {
        match icon {
            ServiceIcon::Builtin { slug } => format!("{BUILTIN_PREFIX}{slug}"),
            ServiceIcon::Remote { url } => url,
        }
    }
}

impl std::fmt::Display for ServiceIcon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Builtin { slug } => write!(f, "{BUILTIN_PREFIX}{slug}"),
            Self::Remote { url } => f.write_str(url),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<ServiceIcon, String> {
        ServiceIcon::try_from(s.to_string())
    }

    #[test]
    fn classifies_builtin_and_remote() {
        assert_eq!(
            parse("builtin:github").unwrap(),
            ServiceIcon::Builtin {
                slug: "github".into()
            }
        );
        assert_eq!(
            parse("https://example.com/a.svg").unwrap(),
            ServiceIcon::Remote {
                url: "https://example.com/a.svg".into()
            }
        );
    }

    #[test]
    fn round_trips_through_string() {
        for raw in [
            "builtin:github",
            "https://example.com/a.svg",
            // Still parses — policy rejects it later, not here.
            "http://example.com/a.svg",
        ] {
            let icon = parse(raw).unwrap();
            assert_eq!(String::from(icon), raw, "round-trip changed {raw}");
        }
    }

    #[test]
    fn rejects_trivia_only() {
        assert!(parse("").is_err());
        assert!(parse("   ").is_err());
        assert!(parse("builtin:").is_err());
        assert!(parse("https://example.com/a b.svg").is_err());
        assert!(parse("https://example.com/\u{7}.svg").is_err());
        assert!(parse(&format!("https://e.com/{}", "a".repeat(MAX_ICON_LEN))).is_err());
    }

    #[test]
    fn parsing_stays_permissive_for_policy_violations() {
        // These must survive parsing so a stored definition still deserializes;
        // `template_validation` and the response builder reject them.
        assert!(parse("javascript:alert(1)").is_ok());
        assert!(parse("data:image/svg+xml,<svg/>").is_ok());
        assert!(parse("//evil.example/a.svg").is_ok());
    }

    #[test]
    fn implicit_icon_follows_the_shipped_asset_set() {
        assert_eq!(
            ServiceIcon::implicit_for_key("github"),
            Some(ServiceIcon::Builtin {
                slug: "github".into()
            })
        );
        assert_eq!(ServiceIcon::implicit_for_key("no_such_service"), None);
    }

    #[test]
    fn known_builtin_tracks_the_generated_table() {
        assert!(parse("builtin:github").unwrap().is_known_builtin());
        assert!(!parse("builtin:nope").unwrap().is_known_builtin());
        assert!(
            !parse("https://example.com/a.svg")
                .unwrap()
                .is_known_builtin()
        );
    }

    #[test]
    fn generated_slug_table_is_sorted_and_unique() {
        // The generator sorts; a hand-edit that broke this would make the
        // committed table diff noisily against the next regeneration.
        let mut sorted = BUILTIN_ICON_SLUGS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.as_slice(), BUILTIN_ICON_SLUGS);
        assert!(!BUILTIN_ICON_SLUGS.is_empty());
    }
}
