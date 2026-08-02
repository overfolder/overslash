use super::key::PermissionKey;
use super::matching::rule_matches;
use crate::types::{PermissionEffect, PermissionRule};

/// Result of checking permissions against rules.
#[derive(Debug, PartialEq, Eq)]
pub enum PermissionResult {
    /// All keys are covered by allow rules.
    Allowed,
    /// Some keys need approval.
    NeedsApproval(Vec<PermissionKey>),
    /// Explicitly denied by a deny rule.
    Denied(String),
}

/// Check whether the given permission keys are authorized by the rules.
///
/// Rules are evaluated in order: deny rules override allow rules.
/// All keys must be covered by allow rules for the result to be `Allowed`.
pub fn check_permissions(rules: &[PermissionRule], keys: &[PermissionKey]) -> PermissionResult {
    check_permissions_screened(rules, keys, &[])
}

/// [`check_permissions`] with an extra set of **deny-screen** keys: keys a
/// deny rule can match (→ hard `Denied`) but that never need allow coverage.
///
/// This is the D42 column tier: a parser yields *referenced identifiers*,
/// not resolved columns, so requiring an allow rule per column would force
/// operators to enumerate grants for something the gateway cannot actually
/// guarantee — but a deny rule over them is sound, because matching a
/// referenced identifier fails closed (`SELECT *` screens as `column_star`,
/// forcing enumeration; a named PII column screens as itself).
pub fn check_permissions_screened(
    rules: &[PermissionRule],
    keys: &[PermissionKey],
    deny_screen_keys: &[PermissionKey],
) -> PermissionResult {
    // First check for explicit denies — over the required keys *and* the
    // screen-only keys.
    for key in keys.iter().chain(deny_screen_keys) {
        for rule in rules {
            if rule.effect == PermissionEffect::Deny && rule_matches(&rule.action_pattern, &key.0) {
                return PermissionResult::Denied(format!(
                    "denied by rule: {}",
                    rule.action_pattern
                ));
            }
        }
    }

    // Then check for allows — required keys only; screen keys need none.
    let mut uncovered = Vec::new();
    for key in keys {
        let covered = rules.iter().any(|rule| {
            rule.effect == PermissionEffect::Allow && rule_matches(&rule.action_pattern, &key.0)
        });
        if !covered {
            uncovered.push(key.clone());
        }
    }

    if uncovered.is_empty() {
        PermissionResult::Allowed
    } else {
        PermissionResult::NeedsApproval(uncovered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::{key_covers, parse_derived_key};
    use uuid::Uuid;

    fn rule(pattern: &str, effect: PermissionEffect) -> PermissionRule {
        PermissionRule {
            id: Uuid::new_v4(),
            org_id: Uuid::new_v4(),
            identity_id: Uuid::new_v4(),
            action_pattern: pattern.to_string(),
            effect,
            created_at: time::OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn exact_match_allows() {
        let rules = vec![rule(
            "http:POST:api.stripe.com/v1/charges",
            PermissionEffect::Allow,
        )];
        let keys = vec![PermissionKey("http:POST:api.stripe.com/v1/charges".into())];
        assert_eq!(check_permissions(&rules, &keys), PermissionResult::Allowed);
    }

    #[test]
    fn wildcard_match_allows() {
        let rules = vec![rule("http:POST:api.stripe.com/**", PermissionEffect::Allow)];
        let keys = vec![PermissionKey("http:POST:api.stripe.com/v1/charges".into())];
        assert_eq!(check_permissions(&rules, &keys), PermissionResult::Allowed);
    }

    #[test]
    fn no_rules_needs_approval() {
        let keys = vec![PermissionKey("http:GET:api.github.com/repos".into())];
        assert!(matches!(
            check_permissions(&[], &keys),
            PermissionResult::NeedsApproval(_)
        ));
    }

    #[test]
    fn deny_overrides_allow() {
        let rules = vec![
            rule("http:*:api.stripe.com/**", PermissionEffect::Allow),
            rule("http:DELETE:api.stripe.com/**", PermissionEffect::Deny),
        ];
        let keys = vec![PermissionKey(
            "http:DELETE:api.stripe.com/v1/charges/ch_123".into(),
        )];
        assert!(matches!(
            check_permissions(&rules, &keys),
            PermissionResult::Denied(_)
        ));
    }

    #[test]
    fn partial_coverage_needs_approval() {
        let rules = vec![rule("http:GET:api.github.com/**", PermissionEffect::Allow)];
        let keys = vec![
            PermissionKey("http:GET:api.github.com/repos".into()),
            PermissionKey("http:POST:api.github.com/repos/x/pulls".into()),
        ];
        match check_permissions(&rules, &keys) {
            PermissionResult::NeedsApproval(uncovered) => {
                assert_eq!(uncovered.len(), 1);
                assert_eq!(uncovered[0].0, "http:POST:api.github.com/repos/x/pulls");
            }
            other => panic!("expected NeedsApproval, got {other:?}"),
        }
    }

    #[test]
    fn empty_keys_always_allowed() {
        assert_eq!(check_permissions(&[], &[]), PermissionResult::Allowed);
    }

    // ── Value-only rules stay label-agnostic ─────────────────────────────

    /// The compat direction that matters, and the only one that can be
    /// inferred: rules are long-lived, keys are re-derived on every call, so a
    /// grant written before labels existed must keep covering the labelled key
    /// the same call derives today. The value-only match form bridges them.
    #[test]
    fn value_only_rule_covers_a_labelled_key() {
        let rules = vec![rule("email:send:*@example.com", PermissionEffect::Allow)];
        let keys = vec![PermissionKey("email:send:recipient=a@example.com".into())];
        assert_eq!(check_permissions(&rules, &keys), PermissionResult::Allowed);
    }

    #[test]
    fn label_qualified_rule_does_not_cover_another_label() {
        let rules = vec![rule("email:send:cc=*@example.com", PermissionEffect::Allow)];
        let cc = vec![PermissionKey("email:send:cc=a@example.com".into())];
        assert_eq!(check_permissions(&rules, &cc), PermissionResult::Allowed);

        let to = vec![PermissionKey("email:send:to=a@example.com".into())];
        assert_eq!(
            check_permissions(&rules, &to),
            PermissionResult::NeedsApproval(to.clone()),
            "a cc-scoped grant must not launder the same address on `to`"
        );
    }

    /// The reverse direction does **not** hold, deliberately: a `label=`-
    /// qualified rule does not cover a *label-less* key.
    ///
    /// This is reachable, because approvals persist their derived keys and
    /// `cascade_resolve` re-matches those stored strings against rules written
    /// later. An approval filed before labels shipped holds
    /// `email:send:a@example.com`; a rule remembered afterwards may well be
    /// `email:send:recipient=a@example.com`, and the two do not match.
    ///
    /// Matching them would mean guessing: the stored key records no label, so
    /// nothing says whether that address was a `to`, a `cc`, or a `bcc`, and
    /// honouring a `cc=`-scoped grant over it would grant strictly more than
    /// the operator wrote. Failing closed costs one human click on approvals
    /// filed in the window before the upgrade (they expire in
    /// `APPROVAL_EXPIRY_SECS`, 30 min by default); failing open would silently
    /// widen a narrow grant. Operators who want the old keys covered write the
    /// value-only form, which is the tier the ladder offers directly beneath
    /// the labelled one.
    #[test]
    fn a_labelled_rule_does_not_cover_a_label_less_key() {
        let legacy = vec![PermissionKey("email:send:a@example.com".into())];

        for pattern in [
            "email:send:recipient=a@example.com",
            "email:send:recipient=*@example.com",
        ] {
            let rules = vec![rule(pattern, PermissionEffect::Allow)];
            assert_eq!(
                check_permissions(&rules, &legacy),
                PermissionResult::NeedsApproval(legacy.clone()),
                "{pattern} must not cover a key that records no label"
            );
        }

        // The value-only form is the one that does cover it.
        let rules = vec![rule("email:send:*@example.com", PermissionEffect::Allow)];
        assert_eq!(
            check_permissions(&rules, &legacy),
            PermissionResult::Allowed
        );
    }

    #[test]
    fn value_only_deny_denies_whatever_label_carries_it() {
        let rules = vec![
            rule("email:send:*", PermissionEffect::Allow),
            rule("email:send:blocked@example.com", PermissionEffect::Deny),
        ];
        let keys = vec![PermissionKey(
            "email:send:recipient=blocked@example.com".into(),
        )];
        assert!(matches!(
            check_permissions(&rules, &keys),
            PermissionResult::Denied(_)
        ));
    }

    /// The split is lexical, so an arg that merely *reads* like `ident=rest` is
    /// taken as labelled and therefore also answers to its value-only form.
    /// Pinned because it widens what a rule matches: the exact key matches as
    /// always, and `sheets:query:* from t` now matches too. Derived args are
    /// `*`, a URL/host, or a real `label=` scope value, so this only concerns
    /// hand-written rules.
    #[test]
    fn an_identifier_prefix_is_always_read_as_a_label() {
        let dk = parse_derived_key("sheets:query:select=* from t");
        assert_eq!(dk.label.as_deref(), Some("select"));
        assert_eq!(dk.value, "* from t");

        let keys = vec![PermissionKey("sheets:query:select=* from t".into())];
        let exact = vec![rule("sheets:query:select=*", PermissionEffect::Allow)];
        assert_eq!(check_permissions(&exact, &keys), PermissionResult::Allowed);
        let value_only = vec![rule("sheets:query:* from t", PermissionEffect::Allow)];
        assert_eq!(
            check_permissions(&value_only, &keys),
            PermissionResult::Allowed
        );
    }

    #[test]
    fn glob_matches_service_action_keys() {
        let rules = vec![rule("github:*:overfolder/*", PermissionEffect::Allow)];
        let keys = vec![PermissionKey(
            "github:create_pull_request:overfolder/backend".into(),
        )];
        assert_eq!(check_permissions(&rules, &keys), PermissionResult::Allowed);
    }

    /// Service-HTTP keys (`{service}:{METHOD}:{path}`) need globstar (`/**`)
    /// to span path segments — plain `*` does not match across `/`. Pin the
    /// matching contract so a rule like `github:POST:/**` actually allows
    /// `github:POST:/repos/x/pulls`.
    #[test]
    fn glob_matches_service_http_keys_with_globstar() {
        let rules = vec![rule("github:POST:/**", PermissionEffect::Allow)];
        let keys = PermissionKey::from_service_http("github", "POST", "/repos/x/pulls");
        assert_eq!(check_permissions(&rules, &keys), PermissionResult::Allowed);
    }

    /// Sanity: `*` (without globstar) does NOT match a path containing `/`.
    /// This is what motivates the path-aware broadening ladder for
    /// service-HTTP keys (it suggests `/**`, not `*`).
    #[test]
    fn glob_star_without_globstar_does_not_span_slashes() {
        let rules = vec![rule("github:POST:*", PermissionEffect::Allow)];
        let keys = PermissionKey::from_service_http("github", "POST", "/repos/x/pulls");
        assert!(matches!(
            check_permissions(&rules, &keys),
            PermissionResult::NeedsApproval { .. }
        ));
    }

    #[test]
    fn service_action_deny_specific_scope() {
        let rules = vec![
            rule("github:*:*", PermissionEffect::Allow),
            rule("github:*:overfolder/secret-repo", PermissionEffect::Deny),
        ];
        let keys = vec![PermissionKey(
            "github:create_issue:overfolder/secret-repo".into(),
        )];
        assert!(matches!(
            check_permissions(&rules, &keys),
            PermissionResult::Denied(_)
        ));
    }

    /// The D43 read/mut split: a read grant never covers a mutation of the
    /// same table (and vice versa), while the value-only form covers both —
    /// "this table, whichever way".
    #[test]
    fn sql_table_read_and_mut_labels_are_disjoint() {
        let read_key = "metabase:run_query:table=pagila/public.film";
        let mut_key = "metabase:run_query:table_mut=pagila/public.film";

        // A remembered read grant does not authorize writes…
        assert!(!key_covers(
            "metabase:run_query:table=pagila/public.film",
            mut_key
        ));
        assert!(!key_covers("metabase:run_query:table=pagila/*", mut_key));
        // …and a write grant does not cover reads.
        assert!(!key_covers(
            "metabase:run_query:table_mut=pagila/public.film",
            read_key
        ));

        // The label-less value-only form covers both classes (D40 compat).
        for key in [read_key, mut_key] {
            assert!(
                key_covers("metabase:run_query:pagila/public.film", key),
                "{key}"
            );
            assert!(key_covers("metabase:run_query:pagila/*", key), "{key}");
        }

        // Asymmetric policy: read anything + write only scratch.
        let rules = vec![
            rule("metabase:run_query:table=pagila/*", PermissionEffect::Allow),
            rule(
                "metabase:run_query:table_mut=pagila/public.scratch",
                PermissionEffect::Allow,
            ),
        ];
        let allowed = vec![
            PermissionKey("metabase:run_query:table=pagila/public.film".to_string()),
            PermissionKey("metabase:run_query:table_mut=pagila/public.scratch".to_string()),
        ];
        assert_eq!(
            check_permissions(&rules, &allowed),
            PermissionResult::Allowed
        );
        let blocked = vec![PermissionKey(
            "metabase:run_query:table_mut=pagila/public.film".to_string(),
        )];
        assert!(matches!(
            check_permissions(&rules, &blocked),
            PermissionResult::NeedsApproval(_)
        ));

        // Write-only deny: mutations blocked, reads untouched.
        let rules = vec![
            rule("metabase:**", PermissionEffect::Allow),
            rule("metabase:*:table_mut=pagila/*", PermissionEffect::Deny),
        ];
        assert!(matches!(
            check_permissions(&rules, &[PermissionKey(mut_key.to_string())]),
            PermissionResult::Denied(_)
        ));
        assert_eq!(
            check_permissions(&rules, &[PermissionKey(read_key.to_string())]),
            PermissionResult::Allowed
        );
    }

    #[test]
    fn deny_screen_keys_deny_but_need_no_allow() {
        let rules = vec![
            rule("metabase:run_query:**", PermissionEffect::Allow),
            rule("metabase:*:column=*/ssn", PermissionEffect::Deny),
        ];
        let keys = vec![PermissionKey(
            "metabase:run_query:table=prod/users".to_string(),
        )];

        // Screen keys don't require allow coverage…
        let screen = vec![PermissionKey(
            "metabase:run_query:column=prod/id".to_string(),
        )];
        assert_eq!(
            check_permissions_screened(&rules, &keys, &screen),
            PermissionResult::Allowed
        );

        // …but a deny rule matching one is a hard denial.
        let screen = vec![PermissionKey(
            "metabase:run_query:column=prod/ssn".to_string(),
        )];
        assert!(matches!(
            check_permissions_screened(&rules, &keys, &screen),
            PermissionResult::Denied(_)
        ));
    }

    #[test]
    fn column_star_deny_forces_enumeration() {
        let rules = vec![
            rule("metabase:**", PermissionEffect::Allow),
            rule("metabase:*:column_star=*", PermissionEffect::Deny),
        ];
        let keys = vec![PermissionKey(
            "metabase:run_query:table=prod/users".to_string(),
        )];

        // `SELECT *` screens as column_star → denied.
        let star = vec![PermissionKey(
            "metabase:run_query:column_star=prod".to_string(),
        )];
        assert!(matches!(
            check_permissions_screened(&rules, &keys, &star),
            PermissionResult::Denied(_)
        ));

        // Enumerated columns pass — and the deny never bleeds onto them.
        let named = vec![
            PermissionKey("metabase:run_query:column=prod/id".to_string()),
            PermissionKey("metabase:run_query:column=prod/total".to_string()),
        ];
        assert_eq!(
            check_permissions_screened(&rules, &keys, &named),
            PermissionResult::Allowed
        );
    }
}
