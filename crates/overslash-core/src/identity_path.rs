//! SPIFFE-style identity paths.
//!
//! Overslash renders identities throughout the UI (audit log, approval pages,
//! detail panels) as a hierarchical SPIFFE-like path of the form
//! `spiffe://<org_slug>/<kind>/<name>/<kind>/<name>/...`. The leading
//! `spiffe://` scheme is conventional and may be stripped for display.
//!
//! See `UI_SPEC.md` §"Audit Log" for the rendering rules. Sub-agents are
//! normalized to the `agent` segment kind so the path scales to arbitrary
//! nesting (`agent/a/agent/b/...`) without inventing new prefixes.

/// Normalize an `identities.kind` value into a path segment kind. `sub_agent`
/// collapses to `agent` per UI_SPEC.
pub fn normalize_kind(kind: &str) -> &str {
    if kind == "sub_agent" { "agent" } else { kind }
}

/// Build a SPIFFE-style path from an org slug and an ordered list of
/// `(kind, name)` segments (root first, leaf last).
///
/// ```
/// use overslash_core::identity_path::build_spiffe_path;
/// let p = build_spiffe_path("acme", &[
///     ("user", "alice"),
///     ("agent", "henry"),
///     ("agent", "researcher"),
/// ]);
/// assert_eq!(p, "spiffe://acme/user/alice/agent/henry/agent/researcher");
/// ```
pub fn build_spiffe_path(org_slug: &str, segments: &[(&str, &str)]) -> String {
    let mut s = String::with_capacity(16 + org_slug.len() + segments.len() * 16);
    s.push_str("spiffe://");
    s.push_str(org_slug);
    for (kind, name) in segments {
        s.push('/');
        s.push_str(normalize_kind(kind));
        s.push('/');
        s.push_str(name);
    }
    s
}

/// Maximum number of agent segments below the user in an impersonation
/// target. The hierarchy is User → Agent → SubAgent → SubAgent → …; eight
/// levels below the user is far past any real nesting and keeps a malformed
/// header from walking the database one INSERT at a time.
pub const MAX_AGENT_PATH_SEGMENTS: usize = 8;

/// Why an impersonation target could not be parsed. Rendered verbatim into
/// the 400 so the caller sees which half of the value was wrong.
#[derive(Debug, PartialEq, Eq)]
pub enum TargetPathError {
    /// The value was empty or only separators.
    Empty,
    /// A `//`, a leading/trailing `/`, or an all-whitespace segment.
    EmptySegment,
    /// The root segment is neither a UUID nor an email.
    RootNotUuidOrEmail,
    /// More than [`MAX_AGENT_PATH_SEGMENTS`] agent segments below the user.
    TooDeep,
}

impl std::fmt::Display for TargetPathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("impersonation target is empty"),
            Self::EmptySegment => f.write_str("impersonation target has an empty segment"),
            Self::RootNotUuidOrEmail => {
                f.write_str("impersonation target must start with an identity UUID or an email")
            }
            Self::TooDeep => write!(
                f,
                "impersonation target has more than {MAX_AGENT_PATH_SEGMENTS} agent segments"
            ),
        }
    }
}

impl std::error::Error for TargetPathError {}

/// How the root of an impersonation target names its identity.
#[derive(Debug, PartialEq, Eq)]
pub enum TargetRoot<'a> {
    /// An identity UUID — resolved directly, never created.
    Id(uuid::Uuid),
    /// A user's email — resolved within the caller's org, created if absent.
    Email(&'a str),
}

/// A parsed `X-Overslash-As` value: who to act as, and optionally a path of
/// agent names beneath them.
#[derive(Debug, PartialEq, Eq)]
pub struct TargetPath<'a> {
    pub root: TargetRoot<'a>,
    /// Agent names below the root, outermost first. Empty when the target is
    /// the root identity itself.
    pub agents: Vec<&'a str>,
}

/// Parse an `X-Overslash-As` value.
///
/// Three accepted forms, distinguished by splitting on `/` — neither a UUID
/// nor an email can contain one, so the root segment is unambiguous:
///
/// ```
/// use overslash_core::identity_path::{parse_target_path, TargetRoot};
///
/// let t = parse_target_path("alice@acme.com/henry/researcher").unwrap();
/// assert_eq!(t.root, TargetRoot::Email("alice@acme.com"));
/// assert_eq!(t.agents, vec!["henry", "researcher"]);
///
/// let t = parse_target_path("alice@acme.com").unwrap();
/// assert!(t.agents.is_empty());
///
/// let t = parse_target_path("6f1a4d3c-0000-4000-8000-000000000000").unwrap();
/// assert!(matches!(t.root, TargetRoot::Id(_)));
/// ```
///
/// Segments are trimmed and the separator has no escape, so an agent whose
/// name contains `/` is not addressable this way — it stays reachable by the
/// UUID form.
pub fn parse_target_path(raw: &str) -> Result<TargetPath<'_>, TargetPathError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(TargetPathError::Empty);
    }

    let segments: Vec<&str> = trimmed.split('/').map(str::trim).collect();
    if segments.iter().any(|s| s.is_empty()) {
        return Err(TargetPathError::EmptySegment);
    }
    if segments.len() - 1 > MAX_AGENT_PATH_SEGMENTS {
        return Err(TargetPathError::TooDeep);
    }

    let root_raw = segments[0];
    // UUID first: an identity id is the pre-existing contract and can never
    // contain '@', so there's no overlap to disambiguate.
    let root = match root_raw.parse::<uuid::Uuid>() {
        Ok(id) => TargetRoot::Id(id),
        // Structural check only — the same bar the invite path applies. The
        // email is matched against `identities.email`, which was verified by
        // an IdP at sign-in; nothing here trusts the string itself.
        Err(_) if root_raw.contains('@') && !root_raw.contains(char::is_whitespace) => {
            TargetRoot::Email(root_raw)
        }
        Err(_) => return Err(TargetPathError::RootNotUuidOrEmail),
    };

    Ok(TargetPath {
        root,
        agents: segments[1..].to_vec(),
    })
}

/// Maximum length, in characters, of a display name supplied via
/// `X-Overslash-As-Name`. Long enough for any real human or agent label and
/// short enough that a header cannot stuff the members list.
pub const MAX_DISPLAY_NAME_CHARS: usize = 128;

/// The RFC 8187 `ext-value` charset prefix this parser accepts. Matched
/// case-insensitively — RFC 8187 says the charset token is case-insensitive.
const UTF8_EXT_PREFIX: &str = "utf-8''";

/// Why a display name supplied via `X-Overslash-As-Name` was refused.
/// Rendered verbatim into the 400.
#[derive(Debug, PartialEq, Eq)]
pub enum DisplayNameError {
    /// Empty, or only whitespace.
    Empty,
    /// More than [`MAX_DISPLAY_NAME_CHARS`] characters. Deliberately an error
    /// rather than a truncation: silently storing half a name is worse than
    /// telling the caller its name did not fit.
    TooLong,
    /// A control character survived decoding.
    ControlCharacter,
    /// A `%` in the `UTF-8''` form was not followed by two hex digits.
    BadEscape,
    /// The decoded bytes are not valid UTF-8.
    NotUtf8,
}

impl std::fmt::Display for DisplayNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("display name is empty"),
            Self::TooLong => write!(
                f,
                "display name is longer than {MAX_DISPLAY_NAME_CHARS} characters"
            ),
            Self::ControlCharacter => f.write_str("display name contains a control character"),
            Self::BadEscape => {
                f.write_str("display name has a % that is not followed by two hex digits")
            }
            Self::NotUtf8 => f.write_str("display name does not decode to valid UTF-8"),
        }
    }
}

impl std::error::Error for DisplayNameError {}

/// Parse an `X-Overslash-As-Name` value into the display name it carries.
///
/// Two accepted forms. A bare value is taken literally; a value prefixed
/// `UTF-8''` is the RFC 8187 `ext-value` form used by `Content-Disposition`'s
/// `filename*`, percent-decoded here:
///
/// ```
/// use overslash_core::identity_path::parse_display_name;
///
/// assert_eq!(parse_display_name("Alice Smith").unwrap(), "Alice Smith");
/// assert_eq!(parse_display_name("UTF-8''Jos%C3%A9").unwrap(), "José");
/// // A literal % is safe precisely because decoding is opt-in.
/// assert_eq!(parse_display_name("50% Club").unwrap(), "50% Club");
/// ```
///
/// The prefix exists because the alternatives do not work end to end: a JS
/// `fetch` client isomorphic-encodes header values and throws above U+00FF,
/// so it cannot put `José` in a header at all — while percent-decoding
/// *every* value unconditionally would quietly mangle `50% Club`.
pub fn parse_display_name(raw: &str) -> Result<std::borrow::Cow<'_, str>, DisplayNameError> {
    let trimmed = raw.trim();

    // Compare as bytes, never `&trimmed[..7]`: a byte slice cannot land
    // mid-codepoint. Once the ASCII prefix matches, index 7 is a boundary.
    let has_prefix = trimmed
        .as_bytes()
        .get(..UTF8_EXT_PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(UTF8_EXT_PREFIX.as_bytes()));

    let decoded: std::borrow::Cow<'_, str> = if has_prefix {
        // Trim again: the encoded form may decode to padded whitespace.
        let s = percent_decode_utf8(&trimmed[UTF8_EXT_PREFIX.len()..])?;
        std::borrow::Cow::Owned(s.trim().to_owned())
    } else {
        std::borrow::Cow::Borrowed(trimmed)
    };

    if decoded.is_empty() {
        return Err(DisplayNameError::Empty);
    }
    if decoded.chars().any(char::is_control) {
        return Err(DisplayNameError::ControlCharacter);
    }
    if decoded.chars().count() > MAX_DISPLAY_NAME_CHARS {
        return Err(DisplayNameError::TooLong);
    }
    Ok(decoded)
}

/// Strict percent-decoding: every `%` must introduce two hex digits, and the
/// resulting bytes must be UTF-8. Deliberately stricter than the usual
/// permissive decoders, which pass a malformed `%ZZ` through untouched — for
/// a value we are about to persist as someone's name, a caller that meant to
/// encode and got it wrong should hear about it.
fn percent_decode_utf8(s: &str) -> Result<String, DisplayNameError> {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = bytes.get(i + 1).copied().and_then(hex);
            let lo = bytes.get(i + 2).copied().and_then(hex);
            match (hi, lo) {
                (Some(hi), Some(lo)) => out.push(hi * 16 + lo),
                _ => return Err(DisplayNameError::BadEscape),
            }
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| DisplayNameError::NotUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_only() {
        assert_eq!(
            build_spiffe_path("acme", &[("user", "alice")]),
            "spiffe://acme/user/alice"
        );
    }

    #[test]
    fn nested_agents_normalize_sub_agent() {
        assert_eq!(
            build_spiffe_path(
                "acme",
                &[
                    ("user", "alice"),
                    ("agent", "henry"),
                    ("sub_agent", "researcher")
                ]
            ),
            "spiffe://acme/user/alice/agent/henry/agent/researcher"
        );
    }

    #[test]
    fn empty_segments() {
        assert_eq!(build_spiffe_path("acme", &[]), "spiffe://acme");
    }

    const UUID: &str = "6f1a4d3c-0000-4000-8000-000000000000";

    #[test]
    fn bare_uuid_has_no_agent_path() {
        let t = parse_target_path(UUID).unwrap();
        assert_eq!(t.root, TargetRoot::Id(UUID.parse().unwrap()));
        assert!(t.agents.is_empty());
    }

    #[test]
    fn bare_email_has_no_agent_path() {
        let t = parse_target_path("alice@acme.com").unwrap();
        assert_eq!(t.root, TargetRoot::Email("alice@acme.com"));
        assert!(t.agents.is_empty());
    }

    #[test]
    fn email_with_nested_agents() {
        let t = parse_target_path("alice@acme.com/henry/researcher").unwrap();
        assert_eq!(t.root, TargetRoot::Email("alice@acme.com"));
        assert_eq!(t.agents, vec!["henry", "researcher"]);
    }

    #[test]
    fn uuid_root_may_also_carry_a_path() {
        let raw = format!("{UUID}/henry");
        let t = parse_target_path(&raw).unwrap();
        assert_eq!(t.root, TargetRoot::Id(UUID.parse().unwrap()));
        assert_eq!(t.agents, vec!["henry"]);
    }

    #[test]
    fn trims_whitespace_around_segments() {
        let t = parse_target_path("  alice@acme.com / henry  ").unwrap();
        assert_eq!(t.root, TargetRoot::Email("alice@acme.com"));
        assert_eq!(t.agents, vec!["henry"]);
    }

    #[test]
    fn rejects_empty_and_malformed() {
        assert_eq!(parse_target_path(""), Err(TargetPathError::Empty));
        assert_eq!(parse_target_path("   "), Err(TargetPathError::Empty));
        assert_eq!(
            parse_target_path("/alice@acme.com"),
            Err(TargetPathError::EmptySegment)
        );
        assert_eq!(
            parse_target_path("alice@acme.com/"),
            Err(TargetPathError::EmptySegment)
        );
        assert_eq!(
            parse_target_path("alice@acme.com//henry"),
            Err(TargetPathError::EmptySegment)
        );
        assert_eq!(
            parse_target_path("alice@acme.com/ /henry"),
            Err(TargetPathError::EmptySegment)
        );
    }

    #[test]
    fn rejects_a_root_that_is_neither_uuid_nor_email() {
        assert_eq!(
            parse_target_path("not-a-uuid"),
            Err(TargetPathError::RootNotUuidOrEmail)
        );
        assert_eq!(
            parse_target_path("henry/researcher"),
            Err(TargetPathError::RootNotUuidOrEmail)
        );
        // A space inside the root disqualifies it as an email rather than
        // sending a header-smuggled value to the database.
        assert_eq!(
            parse_target_path("alice acme@example.com"),
            Err(TargetPathError::RootNotUuidOrEmail)
        );
    }

    #[test]
    fn rejects_paths_deeper_than_the_cap() {
        let ok = format!(
            "alice@acme.com/{}",
            ["a"; MAX_AGENT_PATH_SEGMENTS].join("/")
        );
        assert_eq!(
            parse_target_path(&ok).unwrap().agents.len(),
            MAX_AGENT_PATH_SEGMENTS
        );

        let too_deep = format!(
            "alice@acme.com/{}",
            ["a"; MAX_AGENT_PATH_SEGMENTS + 1].join("/")
        );
        assert_eq!(parse_target_path(&too_deep), Err(TargetPathError::TooDeep));
    }

    #[test]
    fn preserves_non_ascii_agent_names() {
        let t = parse_target_path("alice@acme.com/café/naïve").unwrap();
        assert_eq!(t.agents, vec!["café", "naïve"]);
    }
}
#[cfg(test)]
mod display_name_tests {
    use super::*;

    #[test]
    fn takes_a_bare_value_literally() {
        assert_eq!(parse_display_name("Alice Smith").unwrap(), "Alice Smith");
        assert_eq!(parse_display_name("  Alice  ").unwrap(), "Alice");
        // No decoding happens without the prefix, so a literal % survives.
        assert_eq!(parse_display_name("50% Club").unwrap(), "50% Club");
        assert_eq!(parse_display_name("a%ZZb").unwrap(), "a%ZZb");
    }

    #[test]
    fn decodes_the_rfc8187_form() {
        assert_eq!(
            parse_display_name("UTF-8''Jos%C3%A9%20%C3%81lvarez").unwrap(),
            "José Álvarez"
        );
        // The charset token is case-insensitive.
        assert_eq!(parse_display_name("utf-8''Ren%C3%A9").unwrap(), "René");
        // Unreserved characters need no escaping in the encoded form either.
        assert_eq!(parse_display_name("UTF-8''Alice").unwrap(), "Alice");
    }

    #[test]
    fn rejects_a_malformed_escape() {
        assert_eq!(
            parse_display_name("UTF-8''a%ZZb"),
            Err(DisplayNameError::BadEscape)
        );
        assert_eq!(
            parse_display_name("UTF-8''trailing%"),
            Err(DisplayNameError::BadEscape)
        );
        assert_eq!(
            parse_display_name("UTF-8''short%A"),
            Err(DisplayNameError::BadEscape)
        );
    }

    #[test]
    fn rejects_bytes_that_are_not_utf8() {
        assert_eq!(
            parse_display_name("UTF-8''%FF%FE"),
            Err(DisplayNameError::NotUtf8)
        );
    }

    #[test]
    fn rejects_empty_and_whitespace_only() {
        assert_eq!(parse_display_name(""), Err(DisplayNameError::Empty));
        assert_eq!(parse_display_name("   "), Err(DisplayNameError::Empty));
        assert_eq!(parse_display_name("UTF-8''"), Err(DisplayNameError::Empty));
        assert_eq!(
            parse_display_name("UTF-8''%20%20"),
            Err(DisplayNameError::Empty)
        );
    }

    #[test]
    fn rejects_control_characters() {
        assert_eq!(
            parse_display_name("UTF-8''Alice%09Smith"),
            Err(DisplayNameError::ControlCharacter)
        );
        assert_eq!(
            parse_display_name("UTF-8''Alice%00"),
            Err(DisplayNameError::ControlCharacter)
        );
    }

    #[test]
    fn rejects_an_over_long_name() {
        let ok = "a".repeat(MAX_DISPLAY_NAME_CHARS);
        assert_eq!(parse_display_name(&ok).unwrap(), ok);

        let too_long = "a".repeat(MAX_DISPLAY_NAME_CHARS + 1);
        assert_eq!(
            parse_display_name(&too_long),
            Err(DisplayNameError::TooLong)
        );

        // The cap counts characters, not bytes — a multi-byte name that fits
        // must not be refused for being fat.
        let wide = "é".repeat(MAX_DISPLAY_NAME_CHARS);
        assert_eq!(parse_display_name(&wide).unwrap(), wide);
    }
}
