//! An agent's mark: its MCP client's logo, plus a colour stripe that is its own.
//!
//! The logo answers "what kind of thing is this agent" and is shared by every
//! agent on the same client — two Claude Code agents are two identical logos.
//! The stripe answers "*which* agent is this", by deriving three colours from a
//! hash of the agent's id. Together they let a reader pick one agent out of a
//! tree of siblings without reading a single name. See DECISIONS.md D70.
//!
//! Both halves are pure functions of data we already store, which is why an
//! agent icon needs no column, no migration and no picker.

use overslash_core::{mcp_client_icon::icon_key_for_client, service_icon::ServiceIcon};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::icon_url::resolve_icon_url;

/// How many colour segments the stripe carries.
pub const STRIPE_SEGMENTS: usize = 3;

/// Bytes of hash each segment consumes — one per RGB channel.
const BYTES_PER_SEGMENT: usize = 3;

/// The three colours identifying one agent, as `#rrggbb`.
///
/// Taken from the **last** `STRIPE_SEGMENTS * BYTES_PER_SEGMENT` bytes of
/// `sha256(agent id)`. The tail rather than the head purely so the stripe
/// cannot ever visually echo some other consumer of the same digest's prefix;
/// with SHA-256 either end is equally well distributed.
///
/// Stable forever for a given agent, because the id is.
pub fn stripe_for(id: Uuid) -> [String; STRIPE_SEGMENTS] {
    let digest = Sha256::digest(id.to_string().as_bytes());
    let tail = &digest[digest.len() - STRIPE_SEGMENTS * BYTES_PER_SEGMENT..];
    std::array::from_fn(|i| {
        let rgb = &tail[i * BYTES_PER_SEGMENT..(i + 1) * BYTES_PER_SEGMENT];
        format!("#{:02x}{:02x}{:02x}", rgb[0], rgb[1], rgb[2])
    })
}

/// The absolute URL of the mark for an agent bound to this MCP client, or
/// `None` when even the fallback glyph is missing from the build.
///
/// `None` is not the normal "no client" case — an unrecognised or absent client
/// still resolves to the generic bot. It only happens if the shipped asset set
/// and the code disagree, which
/// `mcp_client_icon::tests::the_fallback_glyph_is_actually_shipped` exists to
/// prevent. The dashboard degrades to a letter tile either way.
pub fn icon_url_for_client(
    client_info_name: Option<&str>,
    client_name: Option<&str>,
    software_id: Option<&str>,
    public_url: &str,
) -> Option<String> {
    let key = icon_key_for_client(client_info_name, client_name, software_id);
    resolve_icon_url(
        Some(&ServiceIcon::Builtin {
            slug: key.to_string(),
        }),
        public_url,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "3f2504e0-4f89-11d3-9a0c-0305e82c3301";
    const B: &str = "9c5b94b1-35ad-49bb-b118-8e8fc24abf80";

    fn uuid(s: &str) -> Uuid {
        Uuid::parse_str(s).unwrap()
    }

    #[test]
    fn a_stripe_is_stable_for_an_id() {
        assert_eq!(stripe_for(uuid(A)), stripe_for(uuid(A)));
    }

    #[test]
    fn different_agents_get_different_stripes() {
        assert_ne!(stripe_for(uuid(A)), stripe_for(uuid(B)));
    }

    #[test]
    fn every_segment_is_a_css_hex_colour() {
        for colour in stripe_for(uuid(A)) {
            assert_eq!(colour.len(), 7, "{colour} is not #rrggbb");
            assert!(colour.starts_with('#'));
            assert!(
                colour[1..].chars().all(|c| c.is_ascii_hexdigit()),
                "{colour} has a non-hex digit"
            );
            // Lowercase, so a snapshot or a DOM assertion has one spelling to
            // match rather than two.
            assert_eq!(colour, colour.to_ascii_lowercase());
        }
    }

    #[test]
    fn the_stripe_reads_the_tail_of_the_digest() {
        // Pins the derivation itself, not just its shape: a change to which
        // bytes are used would silently repaint every agent in every
        // deployment, and this is the test that makes that deliberate.
        let digest = Sha256::digest(A.as_bytes());
        let tail = &digest[digest.len() - 9..];
        let expected = [
            format!("#{:02x}{:02x}{:02x}", tail[0], tail[1], tail[2]),
            format!("#{:02x}{:02x}{:02x}", tail[3], tail[4], tail[5]),
            format!("#{:02x}{:02x}{:02x}", tail[6], tail[7], tail[8]),
        ];
        assert_eq!(stripe_for(uuid(A)), expected);
    }

    #[test]
    fn a_known_client_resolves_to_its_shipped_mark() {
        assert_eq!(
            icon_url_for_client(Some("claude-code"), None, None, "https://api.overslash.com"),
            Some("https://api.overslash.com/icons/client_claude.svg".to_string())
        );
    }

    #[test]
    fn an_unrecognised_client_resolves_to_the_bot() {
        assert_eq!(
            icon_url_for_client(Some("bespoke"), None, None, "https://api.overslash.com"),
            Some("https://api.overslash.com/icons/client_unknown.svg".to_string())
        );
        // No binding at all lands in the same place.
        assert_eq!(
            icon_url_for_client(None, None, None, "https://api.overslash.com"),
            Some("https://api.overslash.com/icons/client_unknown.svg".to_string())
        );
    }

    #[test]
    fn a_pending_mark_resolves_to_nothing_rather_than_a_404() {
        // `client_vscode` is in the mapping table but ships no asset. A URL
        // here would render as a broken image; `None` renders as a letter tile.
        assert_eq!(
            icon_url_for_client(
                Some("Visual Studio Code"),
                None,
                None,
                "https://api.overslash.com"
            ),
            None
        );
    }
}
