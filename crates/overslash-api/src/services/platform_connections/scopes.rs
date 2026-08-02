//! Scope-set algebra shared by the connection create/upgrade/import paths.

use super::*;

/// Return the union of `existing` and `incoming`, preserving an order
/// that's deterministic for downstream comparison (lexicographic via
/// `BTreeSet`). Used by both the REST upgrade-scopes route and the
/// action handler's reauth/missing-scopes URL minters so they can't
/// drift on dedup or ordering.
pub fn merge_scopes(existing: &[String], incoming: &[String]) -> Vec<String> {
    let mut set: BTreeSet<String> = existing.iter().cloned().collect();
    for s in incoming {
        set.insert(s.clone());
    }
    set.into_iter().collect()
}

/// Whether an in-place re-import's `incoming` scopes broaden beyond the
/// connection's `existing` recorded scopes — i.e. `incoming` contains at least
/// one scope not already granted. Returns `Some(comma-joined-new-scopes)` when
/// it broadens, `None` otherwise (unknown recorded set, no incoming scopes, or
/// incoming ⊆ existing).
///
/// Used by [`kernel_import_connection`] to refuse a re-import that widens the
/// grant while carrying no fresh refresh token — see the guard there for the
/// full rationale (connection `85844f1a` metadata-refresh-token divergence).
/// An `existing` of `None` (recorded scopes unknown) returns `None`: we can't
/// prove the incoming set is broader than an unknown one, and the benefit-of-
/// the-doubt scope-gate already tolerates that connection.
pub(super) fn scopes_broadened(
    existing: Option<&[String]>,
    incoming: Option<&[String]>,
) -> Option<String> {
    let incoming = incoming?;
    let existing = existing?;
    let existing_set: BTreeSet<&str> = existing.iter().map(String::as_str).collect();
    let mut added: Vec<&str> = incoming
        .iter()
        .map(String::as_str)
        .filter(|s| !existing_set.contains(s))
        .collect();
    if added.is_empty() {
        return None;
    }
    added.sort_unstable();
    added.dedup();
    Some(added.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_scopes_dedupes_and_sorts() {
        let existing = vec!["b".into(), "a".into()];
        let incoming = vec!["a".into(), "c".into()];
        assert_eq!(
            merge_scopes(&existing, &incoming),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn merge_scopes_handles_empty_inputs() {
        assert!(merge_scopes(&[], &[]).is_empty());
        assert_eq!(merge_scopes(&["x".into()], &[]), vec!["x".to_string()]);
        assert_eq!(merge_scopes(&[], &["x".into()]), vec!["x".to_string()]);
    }

    #[test]
    fn scopes_broadened_detects_new_scope() {
        let existing = vec!["calendar".to_string(), "openid".to_string()];
        let incoming = vec![
            "calendar".to_string(),
            "openid".to_string(),
            "gmail.readonly".to_string(),
        ];
        assert_eq!(
            scopes_broadened(Some(&existing), Some(&incoming)),
            Some("gmail.readonly".to_string())
        );
    }

    #[test]
    fn scopes_broadened_none_when_subset_or_equal() {
        let existing = vec!["calendar".to_string(), "gmail.readonly".to_string()];
        // Equal set.
        assert_eq!(
            scopes_broadened(Some(&existing), Some(&existing.clone())),
            None
        );
        // Narrower incoming set (a downgrade, not a broadening).
        let narrower = vec!["calendar".to_string()];
        assert_eq!(scopes_broadened(Some(&existing), Some(&narrower)), None);
    }

    #[test]
    fn scopes_broadened_none_when_recorded_or_incoming_unknown() {
        let some = vec!["gmail.readonly".to_string()];
        // Unknown recorded set: can't prove broadening.
        assert_eq!(scopes_broadened(None, Some(&some)), None);
        // No incoming scopes declared.
        assert_eq!(scopes_broadened(Some(&some), None), None);
    }
}
