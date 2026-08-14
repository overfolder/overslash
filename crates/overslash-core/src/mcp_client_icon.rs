//! Which shipped mark stands for an agent's MCP client.
//!
//! An agent's icon is the logo of the client it is bound to — Claude Code,
//! Cursor, Zed — because that is the useful thing to know at a glance about an
//! agent you did not create yourself. See DECISIONS.md D70.
//!
//! The client announces itself in three places, none of them a controlled
//! vocabulary: `clientInfo.name` at `initialize`, `client_name` from Dynamic
//! Client Registration, and `software_id`. All three are free text chosen by
//! whoever wrote the client, so matching is by normalized substring against a
//! table of the clients we ship a mark for, and anything unrecognised lands on
//! the generic bot rather than on nothing.
//!
//! This is presentation only. Nothing here gates access, so a wrong guess costs
//! a wrong logo and never a wrong permission.

/// The generic bot glyph. Every unrecognised client, and every agent with no
/// MCP binding at all, resolves here — so an agent icon is never absent.
pub const UNKNOWN_CLIENT_ICON: &str = "client_unknown";

/// Needles matched against the normalized client string, paired with the icon
/// key they select. Order matters: the first hit wins, so a more specific
/// needle must precede any needle that is a substring of it.
///
/// `claudecode` before `claude` is the case that actually bites — both resolve
/// to the same mark today, but they would not if we ever shipped a separate
/// Claude Desktop glyph, and the ordering makes that change a one-liner.
const CLIENT_ICONS: &[(&str, &str)] = &[
    ("claudecode", "client_claude"),
    ("claudedesktop", "client_claude"),
    ("claude", "client_claude"),
    ("anthropic", "client_claude"),
    ("cline", "client_cline"),
    ("githubcopilot", "client_copilot"),
    ("copilot", "client_copilot"),
    ("cursor", "client_cursor"),
    ("windsurf", "client_windsurf"),
    ("zed", "client_zed"),
    ("geminicli", "client_gemini"),
    ("gemini", "client_gemini"),
    // Shipped as `pending`: these resolve to a key we do not yet have an asset
    // for, and `resolve_icon_url` turns an unknown slug into `None`. Keeping
    // them in the table means the day the mark lands, nothing else changes.
    ("chatgpt", "client_chatgpt"),
    ("openai", "client_chatgpt"),
    ("visualstudiocode", "client_vscode"),
    ("vscode", "client_vscode"),
];

/// Lowercase and drop everything that is not a letter or digit, so
/// `"Claude Code"`, `"claude-code"` and `"claude_code"` all normalize to
/// `"claudecode"`. Version suffixes survive as trailing digits, which is
/// harmless: matching is by substring, not equality.
fn normalize(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Resolve one candidate string to an icon key, or `None` when nothing matches.
fn match_one(candidate: &str) -> Option<&'static str> {
    let normalized = normalize(candidate);
    if normalized.is_empty() {
        return None;
    }
    CLIENT_ICONS
        .iter()
        .find(|(needle, _)| normalized.contains(needle))
        .map(|(_, icon)| *icon)
}

/// The icon key for an MCP client, falling back to [`UNKNOWN_CLIENT_ICON`].
///
/// Candidates are tried most-truthful first. `clientInfo.name` is what the
/// client announced at `initialize` and is the one an implementer actually
/// maintains; `client_name` is whatever was typed at DCR time and may be a
/// deployment's own label ("Ada's laptop"); `software_id` is the last resort
/// because it is frequently a bare UUID.
pub fn icon_key_for_client(
    client_info_name: Option<&str>,
    client_name: Option<&str>,
    software_id: Option<&str>,
) -> &'static str {
    [client_info_name, client_name, software_id]
        .into_iter()
        .flatten()
        .find_map(match_one)
        .unwrap_or(UNKNOWN_CLIENT_ICON)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_spellings_clients_actually_send() {
        for raw in [
            "claude-code",
            "Claude Code",
            "claude_code",
            "claudeCode",
            "Claude Code 2.1.0",
        ] {
            assert_eq!(
                icon_key_for_client(Some(raw), None, None),
                "client_claude",
                "{raw} should resolve to the Claude mark"
            );
        }
        assert_eq!(
            icon_key_for_client(Some("Cursor"), None, None),
            "client_cursor"
        );
        assert_eq!(icon_key_for_client(Some("Zed"), None, None), "client_zed");
        assert_eq!(
            icon_key_for_client(Some("Visual Studio Code"), None, None),
            "client_vscode"
        );
    }

    #[test]
    fn falls_back_to_the_bot_for_anything_unrecognised() {
        assert_eq!(
            icon_key_for_client(Some("some-bespoke-client"), None, None),
            UNKNOWN_CLIENT_ICON
        );
        // No binding at all — the common case for an API-key agent.
        assert_eq!(icon_key_for_client(None, None, None), UNKNOWN_CLIENT_ICON);
        // Present but useless.
        assert_eq!(
            icon_key_for_client(Some(""), Some("   "), None),
            UNKNOWN_CLIENT_ICON
        );
    }

    #[test]
    fn prefers_client_info_then_registration_then_software_id() {
        // clientInfo wins over a DCR label that says something else.
        assert_eq!(
            icon_key_for_client(Some("Cursor"), Some("Claude Code"), None),
            "client_cursor"
        );
        // An unmatchable clientInfo falls through rather than short-circuiting.
        assert_eq!(
            icon_key_for_client(Some("Ada's laptop"), Some("Claude Code"), None),
            "client_claude"
        );
        assert_eq!(
            icon_key_for_client(None, None, Some("com.cursor.app")),
            "client_cursor"
        );
    }

    #[test]
    fn specific_needles_precede_the_general_ones() {
        // A regression guard on table order: were `claude` listed first,
        // a future Claude Desktop mark would be unreachable.
        let claudecode = CLIENT_ICONS.iter().position(|(n, _)| *n == "claudecode");
        let claude = CLIENT_ICONS.iter().position(|(n, _)| *n == "claude");
        assert!(claudecode < claude);
        let gh = CLIENT_ICONS.iter().position(|(n, _)| *n == "githubcopilot");
        let copilot = CLIENT_ICONS.iter().position(|(n, _)| *n == "copilot");
        assert!(gh < copilot);
        let vsc = CLIENT_ICONS
            .iter()
            .position(|(n, _)| *n == "visualstudiocode");
        let vscode = CLIENT_ICONS.iter().position(|(n, _)| *n == "vscode");
        assert!(vsc < vscode);
    }

    #[test]
    fn every_icon_key_is_a_client_key() {
        // The `client_` prefix is what keeps these out of the implicit
        // `builtin:<template key>` rule in `service_icon::implicit_for_key`.
        for (_, icon) in CLIENT_ICONS {
            assert!(
                icon.starts_with("client_"),
                "{icon} must live in the client namespace"
            );
        }
        assert!(UNKNOWN_CLIENT_ICON.starts_with("client_"));
    }

    #[test]
    fn the_fallback_glyph_is_actually_shipped() {
        // Every other key may legitimately be `pending` — an unshipped mark
        // resolves to `None` and degrades to the letter tile. The fallback
        // cannot: it is what the degrading is *to*, so if it were missing an
        // unrecognised agent would render nothing at all.
        assert!(
            crate::service_icon::ServiceIcon::Builtin {
                slug: UNKNOWN_CLIENT_ICON.to_string(),
            }
            .is_known_builtin(),
            "{UNKNOWN_CLIENT_ICON} must be a shipped asset — run `make service-icons`"
        );
    }
}
