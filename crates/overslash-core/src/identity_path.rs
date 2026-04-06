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
}
