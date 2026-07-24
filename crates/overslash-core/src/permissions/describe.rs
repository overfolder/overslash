use super::key::{DerivedKey, SuggestedTier};
use super::matching::{broadening_ladder, derive_keys, parse_derived_key};

/// Convert a snake_case action name to human-readable form.
/// e.g., "create_pull_request" → "Create pull request"
fn humanize_action(action: &str) -> String {
    let mut s = action.replace('_', " ");
    if let Some(first) = s.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    s
}

/// Name the wildcard in a scoped arg, as the noun phrase that follows "on".
///
/// A stored rule is a *pattern*, not a concrete key, so its arg is routinely a
/// glob — `*` for the whole action, `*@acme.com` for a domain. Left verbatim
/// those render as "Send on recipient *", which reads like a bug. `subject` is
/// the label when the key carries one, so the same two shapes come out as "any
/// recipient" and "any recipient at acme.com".
///
/// Returns `None` for a glob with no shape we can name (`jane@*`, `*-prod-*`);
/// the caller then falls back to the arg verbatim rather than inventing prose.
fn describe_arg_glob(value: &str, subject: Option<&str>) -> Option<String> {
    let anything = match subject {
        Some(s) => format!("any {s}"),
        None => "anything".to_string(),
    };
    if value == "*" {
        return Some(anything);
    }
    value
        .strip_prefix("*@")
        .filter(|domain| !domain.contains('*'))
        .map(|domain| format!("{anything} at {domain}"))
}

/// Name a `/**` path glob, as the noun phrase that follows "to".
/// `/repos/**` → "anything under /repos"; a bare `/**` → "any path".
fn describe_path_glob(path: &str) -> Option<String> {
    let prefix = path.strip_suffix("/**")?;
    if prefix.is_empty() {
        Some("any path".to_string())
    } else {
        Some(format!("anything under {prefix}"))
    }
}

/// Does this segment stand for "everything"? A rule an operator typed by hand
/// is as likely to say `github:**` as `github:*:*`, and both mean the service
/// entire.
fn is_catch_all(segment: &str) -> bool {
    segment == "*" || segment == "**"
}

/// Generate a human-readable description for a single derived key at a given
/// broadness, with no service label (the legacy self-contained wording).
fn describe_key(dk: &DerivedKey) -> String {
    describe_key_named(dk, None)
}

/// Like [`describe_key`], but leads with a resolved service `label` when one is
/// supplied: "GitHub · Create pull request on any resource". The label is the
/// catalog display name (optionally carrying a principal, "GitHub (alice@acme.com)")
/// and is composed by the caller — this stays a pure string function.
///
/// With `service_label = None` the output is byte-identical to the pre-label
/// wording, which names the service inline for the whole-service cases
/// ("Any Github action"). That path still feeds approval tiers and any rule on
/// a service the registry can't name.
fn describe_key_named(dk: &DerivedKey, service_label: Option<&str>) -> String {
    // Prefix a self-contained predicate with the label when we have one. The
    // predicate never embeds the service itself, so "GitHub · " never doubles
    // up on it.
    let prefixed = |predicate: String| match service_label {
        Some(label) => format!("{label} · {predicate}"),
        None => predicate,
    };
    match dk.service.as_str() {
        "http" => {
            if dk.action == "ANY" || is_catch_all(&dk.action) {
                let host = dk.arg.split('/').next().unwrap_or(&dk.arg);
                match (service_label, host) {
                    // The one whole-service case that names "HTTP" inline when
                    // unprefixed; the label ("Raw HTTP") carries it otherwise.
                    (None, "*") => "Any HTTP request".to_string(),
                    (Some(label), "*") => format!("{label} · Any request"),
                    (_, host) => prefixed(format!("Any request to {host}")),
                }
            } else {
                let target = describe_path_glob(&dk.arg).unwrap_or_else(|| dk.arg.clone());
                prefixed(format!("{} to {}", dk.action, target))
            }
        }
        "secret" => {
            // No registry display name resolves for `secret`; callers pass
            // `None`. Keep the legacy wording regardless of any label.
            if dk.arg == "*" {
                format!("{} (any target)", humanize_action(&dk.action))
            } else {
                humanize_action(&dk.action)
            }
        }
        _ => {
            if is_catch_all(&dk.action) {
                match service_label {
                    Some(label) => format!("{label} · Any action"),
                    None => format!("Any {} action", humanize_action(&dk.service)),
                }
            } else if dk.arg == "*" {
                prefixed(format!("{} on any resource", humanize_action(&dk.action)))
            } else if dk.arg.starts_with('/') {
                // Service-HTTP key: the arg is a path, so it reads "to", not "on".
                match describe_path_glob(&dk.arg) {
                    Some(target) => {
                        prefixed(format!("{} to {}", humanize_action(&dk.action), target))
                    }
                    None => prefixed(format!("{} on {}", humanize_action(&dk.action), dk.arg)),
                }
            } else if let Some(ref label) = dk.label {
                // "Send on recipient=jane@example.com" reads like a bug; the
                // label is a noun the approver already understands.
                let target = describe_arg_glob(&dk.value, Some(label))
                    .unwrap_or_else(|| format!("{label} {}", dk.value));
                prefixed(format!("{} on {}", humanize_action(&dk.action), target))
            } else {
                let target = describe_arg_glob(&dk.arg, None).unwrap_or_else(|| dk.arg.clone());
                prefixed(format!("{} on {}", humanize_action(&dk.action), target))
            }
        }
    }
}

/// Drop repeats while keeping first-seen order.
pub(crate) fn dedup_preserving(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items
        .into_iter()
        .filter(|s| seen.insert(s.clone()))
        .collect()
}

/// Describe a stored permission rule's `action_pattern` in one line.
///
/// The public entry point onto [`describe_key`], so a rule list and an approval's
/// suggested tiers say the same thing about the same key rather than drifting
/// apart in two implementations.
pub fn describe_pattern(pattern: &str) -> String {
    describe_pattern_named(pattern, None)
}

/// Like [`describe_pattern`], but leads with a resolved service `label` when one
/// is supplied — "GitHub · Any action", "Email (ops@acme.com) · Send on …".
///
/// The label is the catalog display name, optionally carrying a principal, and
/// is composed by the caller (which owns the registry + connection lookups this
/// pure function deliberately does not). `None` reproduces the label-less
/// wording exactly.
pub fn describe_pattern_named(pattern: &str, service_label: Option<&str>) -> String {
    describe_key_named(&parse_derived_key(pattern), service_label)
}

/// Generate a combined description for a tier's set of derived keys.
fn generate_tier_description(keys: &[DerivedKey]) -> String {
    // Separate primary keys (http/service-action) from auxiliary (secret)
    let primary: Vec<&DerivedKey> = keys.iter().filter(|k| k.service != "secret").collect();
    let secrets: Vec<&DerivedKey> = keys.iter().filter(|k| k.service == "secret").collect();

    // At the broader rungs several keys collapse onto the same phrase — two
    // recipients both become "Send on any resource". Say it once.
    let mut desc = if primary.is_empty() {
        keys.first().map(describe_key).unwrap_or_default()
    } else {
        dedup_preserving(primary.iter().map(|k| describe_key(k))).join(", ")
    };

    if !secrets.is_empty() {
        let secret_names = dedup_preserving(secrets.iter().map(|s| s.action.clone()));
        desc.push_str(&format!(" with {}", secret_names.join(", ")));
    }

    desc
}

/// Generate 2-4 suggested tiers of progressively broader permission keys.
pub fn suggest_tiers(permission_keys: &[String]) -> Vec<SuggestedTier> {
    if permission_keys.is_empty() {
        return vec![];
    }

    let derived = derive_keys(permission_keys);
    let ladders: Vec<Vec<String>> = derived.iter().map(broadening_ladder).collect();

    // Determine the max ladder length
    let max_len = ladders.iter().map(|l| l.len()).max().unwrap_or(1);

    let mut tiers: Vec<SuggestedTier> = Vec::new();
    let mut prev_keys: Option<Vec<String>> = None;

    for i in 0..max_len {
        // For each key, pick the tier at index i (or the last available)
        // Several keys converge on the same rung as the ladders broaden — an
        // N-recipient send collapses to one `svc:send:*`. Dedupe so the tier
        // (and the rules "Allow & Remember" writes from it) carries each key
        // once.
        let tier_keys: Vec<String> = dedup_preserving(ladders.iter().map(|ladder| {
            let idx = i.min(ladder.len() - 1);
            ladder[idx].clone()
        }));

        // Deduplicate: skip if same as previous tier
        if prev_keys.as_ref() == Some(&tier_keys) {
            continue;
        }

        // Build derived keys for this tier's key set to generate description
        let tier_derived: Vec<DerivedKey> =
            tier_keys.iter().map(|k| parse_derived_key(k)).collect();
        let description = generate_tier_description(&tier_derived);

        prev_keys = Some(tier_keys.clone());
        tiers.push(SuggestedTier {
            keys: tier_keys,
            description,
        });
    }

    // Cap at 4 tiers: keep first, last, and evenly spaced middle ones
    if tiers.len() > 4 {
        let last = tiers.len() - 1;
        let mid1 = last / 3;
        let mid2 = 2 * last / 3;
        tiers = vec![
            tiers[0].clone(),
            tiers[mid1].clone(),
            tiers[mid2].clone(),
            tiers[last].clone(),
        ];
    }

    tiers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_key_reads_the_label_as_a_noun() {
        let dk = parse_derived_key("email:send:recipient=jane@example.com");
        assert_eq!(describe_key(&dk), "Send on recipient jane@example.com");
    }

    #[test]
    fn tiers_single_service_action() {
        let keys = vec!["github:create_pull_request:overfolder/backend".to_string()];
        let tiers = suggest_tiers(&keys);
        assert_eq!(tiers.len(), 3);
        assert_eq!(
            tiers[0].keys,
            vec!["github:create_pull_request:overfolder/backend"]
        );
        assert_eq!(tiers[1].keys, vec!["github:create_pull_request:*"]);
        assert_eq!(tiers[2].keys, vec!["github:*:*"]);
    }

    #[test]
    fn tiers_single_http_key() {
        let keys = vec!["http:POST:api.stripe.com/v1/charges".to_string()];
        let tiers = suggest_tiers(&keys);
        assert_eq!(tiers.len(), 3);
        assert_eq!(tiers[0].keys, vec!["http:POST:api.stripe.com/v1/charges"]);
        assert_eq!(tiers[1].keys, vec!["http:POST:api.stripe.com/**"]);
        assert_eq!(tiers[2].keys, vec!["http:ANY:api.stripe.com/**"]);
    }

    #[test]
    fn tiers_multi_key_http_plus_secret() {
        let keys = vec![
            "http:POST:api.example.com".to_string(),
            "secret:api_key:api.example.com".to_string(),
        ];
        let tiers = suggest_tiers(&keys);
        assert!(tiers.len() >= 2);
        // First tier: both exact
        assert_eq!(
            tiers[0].keys,
            vec![
                "http:POST:api.example.com",
                "secret:api_key:api.example.com"
            ]
        );
        // Last tier should be the broadest
        let last = tiers.last().unwrap();
        assert!(last.keys.iter().any(|k| k.contains("ANY")));
    }

    #[test]
    fn tiers_dedup_when_arg_is_star() {
        let keys = vec!["github:list_repos:*".to_string()];
        let tiers = suggest_tiers(&keys);
        // Tier 0 = github:list_repos:* , Tier 1 would also be github:list_repos:* (deduped), Tier 2 = github:*:*
        assert_eq!(tiers.len(), 2);
        assert_eq!(tiers[0].keys, vec!["github:list_repos:*"]);
        assert_eq!(tiers[1].keys, vec!["github:*:*"]);
    }

    /// A multi-recipient send derives one key per recipient. The exact tier
    /// must keep both, but every broader rung collapses them onto one key —
    /// and must say so once, not "Send on any resource, Send on any resource".
    #[test]
    fn tiers_multi_recipient_dedupes_broad_rungs() {
        let keys = vec![
            "email:send:recipient=ada@example.com".to_string(),
            "email:send:recipient=bob@example.com".to_string(),
        ];
        let tiers = suggest_tiers(&keys);

        assert_eq!(tiers[0].keys, keys);
        assert!(tiers[0].description.contains("ada@example.com"));
        assert!(tiers[0].description.contains("bob@example.com"));

        let broad = tiers
            .iter()
            .find(|t| t.keys == vec!["email:send:*"])
            .expect("a `send on any resource` tier");
        assert_eq!(broad.description, "Send on any resource");

        let broadest = tiers.last().unwrap();
        assert_eq!(broadest.keys, vec!["email:*:*"]);
        assert_eq!(broadest.description, "Any Email action");
    }

    #[test]
    fn tiers_empty_input() {
        assert!(suggest_tiers(&[]).is_empty());
    }

    #[test]
    fn description_service_action_exact() {
        let dk = parse_derived_key("github:create_pull_request:overfolder/backend");
        assert_eq!(
            describe_key(&dk),
            "Create pull request on overfolder/backend"
        );
    }

    #[test]
    fn description_service_action_wildcard() {
        let dk = parse_derived_key("github:create_pull_request:*");
        assert_eq!(describe_key(&dk), "Create pull request on any resource");
    }

    #[test]
    fn description_service_any_action() {
        let dk = parse_derived_key("github:*:*");
        assert_eq!(describe_key(&dk), "Any Github action");
    }

    #[test]
    fn description_service_any_action_underscore() {
        let dk = parse_derived_key("google_calendar:*:*");
        assert_eq!(describe_key(&dk), "Any Google calendar action");
    }

    #[test]
    fn description_http_exact() {
        let dk = parse_derived_key("http:POST:api.stripe.com/v1/charges");
        assert_eq!(describe_key(&dk), "POST to api.stripe.com/v1/charges");
    }

    #[test]
    fn description_http_any() {
        let dk = parse_derived_key("http:ANY:api.stripe.com/**");
        assert_eq!(describe_key(&dk), "Any request to api.stripe.com");
    }

    /// Stored rules are patterns, not concrete keys, so every glob shape the
    /// rule list can hold has to read as a sentence. `describe_pattern` is the
    /// entry point the permissions API renders through.
    #[test]
    fn description_of_stored_rule_patterns() {
        let cases = [
            ("github:*:*", "Any Github action"),
            (
                "github:create_pull_request:*",
                "Create pull request on any resource",
            ),
            ("email:send:recipient=*", "Send on any recipient"),
            (
                "email:send:recipient=*@acme.com",
                "Send on any recipient at acme.com",
            ),
            ("email:send:*@acme.com", "Send on anything at acme.com"),
            (
                "email:send:recipient=jane@example.com",
                "Send on recipient jane@example.com",
            ),
            (
                "http:ANY:api.stripe.com/**",
                "Any request to api.stripe.com",
            ),
            (
                "http:POST:api.stripe.com/v1/**",
                "POST to anything under api.stripe.com/v1",
            ),
            ("github:POST:/**", "POST to any path"),
            // Two-segment patterns an operator types by hand.
            ("github:**", "Any Github action"),
            ("http:**", "Any HTTP request"),
            ("github:POST:/repos/**", "POST to anything under /repos"),
            ("github:POST:/repos/overfolder", "POST on /repos/overfolder"),
        ];
        for (pattern, expected) in cases {
            assert_eq!(describe_pattern(pattern), expected, "pattern: {pattern}");
        }
    }

    /// A glob we have no wording for stays verbatim — better a raw key than
    /// prose that misstates what the rule covers.
    #[test]
    fn description_leaves_unnameable_globs_verbatim() {
        assert_eq!(
            describe_pattern("email:send:recipient=jane@*"),
            "Send on recipient jane@*"
        );
        assert_eq!(describe_pattern("deploy:run:*-prod-*"), "Run on *-prod-*");
    }

    /// With a resolved service label the sentence leads with the catalog display
    /// name and the predicate drops the inline service word, so nothing doubles
    /// up ("GitHub · Any action", never "GitHub · Any Github action").
    #[test]
    fn description_leads_with_the_service_label() {
        let cases = [
            ("github:*:*", "GitHub", "GitHub · Any action"),
            (
                "github:create_pull_request:*",
                "GitHub",
                "GitHub · Create pull request on any resource",
            ),
            (
                "email:send:recipient=*@acme.com",
                "Email",
                "Email · Send on any recipient at acme.com",
            ),
            (
                "http:POST:api.stripe.com/v1/**",
                "Raw HTTP",
                "Raw HTTP · POST to anything under api.stripe.com/v1",
            ),
            ("http:**", "Raw HTTP", "Raw HTTP · Any request"),
            (
                "http:ANY:api.stripe.com/**",
                "Raw HTTP",
                "Raw HTTP · Any request to api.stripe.com",
            ),
        ];
        for (pattern, label, expected) in cases {
            assert_eq!(
                describe_pattern_named(pattern, Some(label)),
                expected,
                "pattern: {pattern}"
            );
        }
    }

    /// The label carries a principal when the caller resolved one; the describer
    /// just prefixes whatever string it is handed.
    #[test]
    fn description_label_can_carry_a_principal() {
        assert_eq!(
            describe_pattern_named("github:*:*", Some("GitHub (alice@acme.com)")),
            "GitHub (alice@acme.com) · Any action"
        );
        assert_eq!(
            describe_pattern_named(
                "email:send:recipient=*@acme.com",
                Some("Email (ops@acme.com)")
            ),
            "Email (ops@acme.com) · Send on any recipient at acme.com"
        );
    }

    /// `None` reproduces the label-less wording exactly — the path approval
    /// tiers and unnameable services still ride.
    #[test]
    fn description_named_with_none_matches_unlabelled() {
        for pattern in [
            "github:*:*",
            "github:create_pull_request:*",
            "email:send:recipient=*@acme.com",
            "http:POST:api.stripe.com/v1/**",
            "http:**",
            "secret:api_key:*",
        ] {
            assert_eq!(
                describe_pattern_named(pattern, None),
                describe_pattern(pattern),
                "pattern: {pattern}"
            );
        }
    }
}
