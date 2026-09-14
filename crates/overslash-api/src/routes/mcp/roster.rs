//! Caller-derived service roster for the MCP tool catalog.
//!
//! `tools/list` advertises five generic tools whose names say nothing about
//! what this deployment can actually reach. An agent therefore has to call
//! `overslash_search` speculatively just to learn whether Gmail or HubSpot is
//! wired up at all. `tools/list` is a per-request JSON-RPC method with the
//! caller's identity in scope, so we can answer that question in the tool
//! description itself: a sorted list of the *template keys* the caller has
//! connected.
//!
//! Template keys, not instance names, on purpose — the roster is a capability
//! hint ("Overslash can reach Gmail for you"), not a list of arguments. The
//! sentence built here says so explicitly, because `overslash_call.service`
//! wants an instance name (`gmail_work`) and a bare list of template keys
//! would invite exactly the mistake the tool description warns against.
//!
//! Freshness is per-request only. We do not advertise `tools.listChanged` and
//! have no channel to push `notifications/tools/list_changed` down (`GET /mcp`
//! is a 405 and the only SSE we emit is the one-shot elicitation stream), so a
//! client that caches the catalog at handshake time keeps a stale roster until
//! it reconnects. That is accepted: a stale roster costs one redundant search,
//! which is the status quo for every caller today.

use std::collections::BTreeSet;

use axum::http::Extensions;
use overslash_db::scopes::OrgScope;
use uuid::Uuid;

use crate::{AppState, error::AppError, extractors::AuthContext, services::group_ceiling};

/// Most template keys to name before collapsing the tail into "and N more".
const MAX_KEYS: usize = 40;

/// Byte ceiling for the joined key list. Belt-and-braces alongside `MAX_KEYS`:
/// keys are org-authored for the org/user tiers and nothing bounds their
/// length. Enforced by dropping whole keys, never by slicing a string — see
/// CLAUDE.md rule 5.
const MAX_BYTES: usize = 600;

/// Template keys the caller has at least one active, visible service instance
/// for, sorted and deduplicated.
///
/// Best-effort by contract: every failure path returns an empty vec rather
/// than an error, because `tools/list` must not start failing on account of a
/// cosmetic addition to a description.
pub(super) async fn connected_template_keys(
    state: &AppState,
    ext: &Extensions,
    auth: &AuthContext,
) -> Vec<String> {
    // Org-level API keys have no identity ancestor, and the group ceiling
    // needs one. `kernel_list_services` rejects this case outright; here we
    // just fall back to the un-personalized description.
    let Some(identity_id) = auth.identity_id else {
        return Vec::new();
    };

    // Constructed rather than extracted: `post_mcp` takes `auth` as a
    // `Result` so it can answer an unauthenticated request with the RFC 9728
    // challenge, which rules out a fallible `OrgScope` extractor on that
    // handler. Same construction `kernel_list_services` uses.
    let scope = OrgScope::new(auth.org_id, state.db_pool(ext));

    match load_keys(state, &scope, identity_id).await {
        Ok(keys) => keys,
        Err(e) => {
            tracing::warn!("mcp tools/list roster lookup failed: {e}");
            Vec::new()
        }
    }
}

async fn load_keys(
    state: &AppState,
    scope: &OrgScope,
    identity_id: Uuid,
) -> Result<Vec<String>, AppError> {
    // Same three steps as `kernel_list_services` and `collect_visible_
    // templates`, deliberately — the roster must not imply a reachability the
    // group ceiling would deny at call time.
    let ceiling_user_id = group_ceiling::resolve_ceiling_user_id(scope, identity_id).await?;
    let visible_ids = scope.get_visible_service_ids(ceiling_user_id).await?;
    let rows = scope
        .list_available_service_instances_with_groups(
            Some(identity_id),
            Some(ceiling_user_id),
            Some(&visible_ids),
        )
        .await?;

    let mut keys: BTreeSet<String> = BTreeSet::new();
    for row in rows {
        // `active` is the same "connected" test search uses; draft and
        // archived instances are not callable.
        if row.status != "active" {
            continue;
        }
        // `overslash` and `http` are seeded into every org by `org_bootstrap`
        // and granted to Everyone, so naming them says nothing about what this
        // caller has connected. They are also the *only* rows a fresh org has,
        // which would make the roster claim two things are connected when
        // nothing is — the case `roster_sentence` returns `None` for, and the
        // one a new caller most needs told straight.
        if row.is_system {
            continue;
        }
        // Shipped templates marked `x-overslash-hidden` stay out of the
        // agent-facing catalog. In-memory lookup, no DB cost. Org- and
        // user-tier templates would need their layered definition resolved to
        // read the same flag; not worth three more queries for a hint string.
        if row.template_source == "global"
            && state
                .registry
                .get(&row.template_key)
                .is_some_and(|def| def.hidden)
        {
            continue;
        }
        keys.insert(row.template_key);
    }
    Ok(keys.into_iter().collect())
}

/// Render the roster as a sentence to append to a tool description, or `None`
/// when there is nothing to say (no keys — never a dangling "…: .").
pub(super) fn roster_sentence(keys: &[String]) -> Option<String> {
    if keys.is_empty() {
        return None;
    }

    let mut shown: Vec<&str> = Vec::new();
    let mut bytes = 0usize;
    for key in keys.iter().take(MAX_KEYS) {
        // +2 for the ", " separator. Whole keys only: dropping the tail keeps
        // us off raw byte indices entirely.
        let cost = key.len() + if shown.is_empty() { 0 } else { 2 };
        if bytes + cost > MAX_BYTES && !shown.is_empty() {
            break;
        }
        bytes += cost;
        shown.push(key);
    }

    let mut list = shown.join(", ");
    let omitted = keys.len() - shown.len();
    if omitted > 0 {
        list.push_str(&format!(", and {omitted} more"));
    }

    Some(format!(
        " Connected service types for this caller: {list}. Those are template \
         keys, not callable service names — search one to get the instance \
         name before passing it to overslash_call."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn empty_roster_yields_no_sentence() {
        assert!(roster_sentence(&[]).is_none());
    }

    #[test]
    fn names_every_key_and_warns_they_are_not_callable() {
        let s = roster_sentence(&keys(&["email", "gmail", "hubspot"])).unwrap();
        assert!(s.contains("email, gmail, hubspot"), "{s}");
        assert!(s.contains("not callable service names"), "{s}");
        assert!(!s.contains("and 0 more"), "{s}");
    }

    #[test]
    fn collapses_the_tail_past_max_keys() {
        let many: Vec<String> = (0..MAX_KEYS + 5).map(|i| format!("svc{i:03}")).collect();
        let s = roster_sentence(&many).unwrap();
        assert!(s.contains("and 5 more"), "{s}");
        assert!(s.contains("svc000"), "{s}");
    }

    #[test]
    fn drops_whole_keys_to_stay_under_the_byte_cap() {
        let long = "x".repeat(400);
        let s = roster_sentence(&keys(&[&long, &long, &long])).unwrap();
        // Two fit (400 + 2 + 400 = 802 > 600), so only the first survives.
        assert!(s.contains("and 2 more"), "{s}");
        assert!(s.len() < 800, "roster sentence unbounded: {}", s.len());
    }

    #[test]
    fn a_single_oversized_key_is_still_named_whole() {
        // Never slice mid-key: one key over the cap is emitted intact rather
        // than truncated (CLAUDE.md rule 5).
        let long = "é".repeat(400);
        let s = roster_sentence(&keys(&[&long])).unwrap();
        assert!(s.contains(&long), "oversized key was mangled");
    }
}
