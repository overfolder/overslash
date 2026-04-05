use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::types::service::Risk;
use crate::types::{PermissionEffect, PermissionRule};

/// A derived permission key from an action request.
///
/// Two formats depending on execution mode:
/// - Raw HTTP / connection: `http:{METHOD}:{host}{path}`
/// - Service action (Mode C): `{service}:{action}:{arg}`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionKey(pub String);

/// A parsed permission key with its structural components exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivedKey {
    pub key: String,
    pub service: String,
    pub action: String,
    pub arg: String,
}

/// A suggested tier of permission keys at a specific broadness level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuggestedTier {
    pub keys: Vec<String>,
    pub description: String,
}

impl PermissionKey {
    /// Derive permission keys from an HTTP request (Mode A / Mode B).
    /// Format: `http:{METHOD}:{host}{path}`
    pub fn from_http(method: &str, url: &str) -> Vec<Self> {
        let host_path = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);

        vec![Self(format!("http:{method}:{host_path}"))]
    }

    /// Derive permission keys from a service action request (Mode C).
    /// Format: `{service}:{action}:{arg}` where arg comes from `scope_param` or defaults to `*`.
    pub fn from_service_action(
        service_key: &str,
        action_key: &str,
        scope_param: Option<&str>,
        params: &HashMap<String, serde_json::Value>,
    ) -> Vec<Self> {
        let arg = scope_param
            .and_then(|sp| params.get(sp))
            .map(|v| match v.as_str() {
                Some(s) => s.to_string(),
                None => v.to_string(),
            })
            .unwrap_or_else(|| "*".to_string());
        vec![Self(format!("{service_key}:{action_key}:{arg}"))]
    }
}

/// Parse a flat permission key string into its structured components.
/// Format: `{service}:{action}:{arg}` where arg may contain colons.
pub fn parse_derived_key(key: &str) -> DerivedKey {
    let mut parts = key.splitn(3, ':');
    let service = parts.next().unwrap_or("").to_string();
    let action = parts.next().unwrap_or("").to_string();
    let arg = parts.next().unwrap_or("*").to_string();
    DerivedKey {
        key: key.to_string(),
        service,
        action,
        arg,
    }
}

/// Parse all permission key strings into structured `DerivedKey`s.
pub fn derive_keys(permission_keys: &[String]) -> Vec<DerivedKey> {
    permission_keys
        .iter()
        .map(|k| parse_derived_key(k))
        .collect()
}

/// Compute the broadening ladder for a single derived key.
/// Returns a list of progressively broader key strings (including the original).
fn broadening_ladder(dk: &DerivedKey) -> Vec<String> {
    let mut ladder = vec![dk.key.clone()];

    match dk.service.as_str() {
        "http" => {
            // http:{METHOD}:{host}{path} → http:{METHOD}:{host}/** → http:ANY:{host}/**
            let host = dk.arg.split('/').next().unwrap_or(&dk.arg);
            let host_wildcard = format!("http:{}:{host}/**", dk.action);
            if host_wildcard != dk.key {
                ladder.push(host_wildcard);
            }
            if dk.action != "ANY" {
                ladder.push(format!("http:ANY:{host}/**"));
            }
        }
        "secret" => {
            // secret:{name}:{target} → secret:{name}:*
            if dk.arg != "*" {
                ladder.push(format!("secret:{}:*", dk.action));
            }
        }
        _ => {
            // Service action: {service}:{action}:{arg} → {service}:{action}:* → {service}:*:*
            if dk.arg != "*" {
                ladder.push(format!("{}:{}:*", dk.service, dk.action));
            }
            ladder.push(format!("{}:*:*", dk.service));
        }
    }

    ladder
}

/// Convert a snake_case action name to human-readable form.
/// e.g., "create_pull_request" → "Create pull request"
fn humanize_action(action: &str) -> String {
    let mut s = action.replace('_', " ");
    if let Some(first) = s.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    s
}

/// Generate a human-readable description for a single derived key at a given broadness.
fn describe_key(dk: &DerivedKey) -> String {
    match dk.service.as_str() {
        "http" => {
            if dk.action == "ANY" {
                let host = dk.arg.split('/').next().unwrap_or(&dk.arg);
                if host == "*" {
                    "Any HTTP request".to_string()
                } else {
                    format!("Any request to {host}")
                }
            } else {
                format!("{} to {}", dk.action, dk.arg)
            }
        }
        "secret" => {
            if dk.arg == "*" {
                format!("{} (any target)", humanize_action(&dk.action))
            } else {
                humanize_action(&dk.action)
            }
        }
        _ => {
            if dk.action == "*" {
                format!("Any {} action", humanize_action(&dk.service))
            } else if dk.arg == "*" {
                format!("{} on any resource", humanize_action(&dk.action))
            } else {
                format!("{} on {}", humanize_action(&dk.action), dk.arg)
            }
        }
    }
}

/// Generate a combined description for a tier's set of derived keys.
fn generate_tier_description(keys: &[DerivedKey]) -> String {
    // Separate primary keys (http/service-action) from auxiliary (secret)
    let primary: Vec<&DerivedKey> = keys.iter().filter(|k| k.service != "secret").collect();
    let secrets: Vec<&DerivedKey> = keys.iter().filter(|k| k.service == "secret").collect();

    let mut desc = if primary.is_empty() {
        keys.first().map(describe_key).unwrap_or_default()
    } else {
        primary
            .iter()
            .map(|k| describe_key(k))
            .collect::<Vec<_>>()
            .join(", ")
    };

    if !secrets.is_empty() {
        let secret_names: Vec<String> = secrets.iter().map(|s| s.action.clone()).collect();
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
        let tier_keys: Vec<String> = ladders
            .iter()
            .map(|ladder| {
                let idx = i.min(ladder.len() - 1);
                ladder[idx].clone()
            })
            .collect();

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
    // First check for explicit denies
    for key in keys {
        for rule in rules {
            if rule.effect == PermissionEffect::Deny
                && glob_match::glob_match(&rule.action_pattern, &key.0)
            {
                return PermissionResult::Denied(format!(
                    "denied by rule: {}",
                    rule.action_pattern
                ));
            }
        }
    }

    // Then check for allows
    let mut uncovered = Vec::new();
    for key in keys {
        let covered = rules.iter().any(|rule| {
            rule.effect == PermissionEffect::Allow
                && glob_match::glob_match(&rule.action_pattern, &key.0)
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

// ── Layer 1: Group Ceiling ───────────────────────────────────────────

/// Access level hierarchy for group grants.
/// Maps to the existing `Risk` enum: read < write < admin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLevel {
    Read,
    Write,
    Admin,
}

impl AccessLevel {
    /// Does this access level permit the given risk?
    pub fn permits_risk(self, risk: Risk) -> bool {
        match self {
            AccessLevel::Admin => true,
            AccessLevel::Write => matches!(risk, Risk::Read | Risk::Write),
            AccessLevel::Read => matches!(risk, Risk::Read),
        }
    }

    /// Parse from a string. Returns `None` for invalid values.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(AccessLevel::Read),
            "write" => Some(AccessLevel::Write),
            "admin" => Some(AccessLevel::Admin),
            _ => None,
        }
    }
}

impl fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccessLevel::Read => write!(f, "read"),
            AccessLevel::Write => write!(f, "write"),
            AccessLevel::Admin => write!(f, "admin"),
        }
    }
}

/// A resolved group grant for ceiling checking.
#[derive(Debug, Clone)]
pub struct CeilingGrant {
    pub service_name: String,
    pub access_level: AccessLevel,
    pub auto_approve_reads: bool,
}

/// Result of a group ceiling check.
#[derive(Debug, PartialEq, Eq)]
pub enum GroupCeilingResult {
    /// All keys are within the group ceiling.
    WithinCeiling,
    /// Within ceiling AND auto-approve-reads applies (non-mutating + flag set).
    WithinCeilingAutoApprove,
    /// Exceeds ceiling — denied, not approvable.
    ExceedsCeiling(String),
    /// Identity has no groups assigned — no ceiling enforced (permissive).
    NoGroups,
}

/// Check if a request is within the group ceiling.
///
/// - `service_name`: the resolved service name (e.g., "github") or "http" for raw HTTP (Mode A)
/// - `risk`: the action's risk level
/// - `grants`: all grants from the owner-user's groups
/// - `allow_raw_http`: OR of `allow_raw_http` across the user's groups
/// - `has_groups`: whether the user has any group assignments
pub fn check_group_ceiling(
    service_name: &str,
    risk: Risk,
    grants: &[CeilingGrant],
    allow_raw_http: bool,
    has_groups: bool,
) -> GroupCeilingResult {
    if !has_groups {
        return GroupCeilingResult::NoGroups;
    }

    // Mode A raw HTTP — gated by the allow_raw_http flag, not by service grants
    if service_name == "http" {
        return if allow_raw_http {
            GroupCeilingResult::WithinCeiling
        } else {
            GroupCeilingResult::ExceedsCeiling("raw HTTP access not allowed by group".into())
        };
    }

    // Find matching grant(s) for this service across all groups
    let matching: Vec<&CeilingGrant> = grants
        .iter()
        .filter(|g| g.service_name == service_name)
        .collect();

    if matching.is_empty() {
        return GroupCeilingResult::ExceedsCeiling(format!(
            "service '{}' not granted by any group",
            service_name
        ));
    }

    // Check if any matching grant permits this risk level (take the most permissive)
    let permitted = matching.iter().any(|g| g.access_level.permits_risk(risk));
    if !permitted {
        return GroupCeilingResult::ExceedsCeiling(format!(
            "access level insufficient for {} on '{}'",
            risk, service_name
        ));
    }

    // Auto-approve: if risk is read AND any matching grant has auto_approve_reads
    if !risk.is_mutating() && matching.iter().any(|g| g.auto_approve_reads) {
        return GroupCeilingResult::WithinCeilingAutoApprove;
    }

    GroupCeilingResult::WithinCeiling
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn derive_keys_from_http() {
        let keys = PermissionKey::from_http("POST", "https://api.github.com/repos/x/pulls");
        assert_eq!(keys[0].0, "http:POST:api.github.com/repos/x/pulls");
    }

    #[test]
    fn service_action_with_scope_param() {
        let mut params = HashMap::new();
        params.insert(
            "repo".to_string(),
            serde_json::Value::String("overfolder/backend".to_string()),
        );
        let keys = PermissionKey::from_service_action(
            "github",
            "create_pull_request",
            Some("repo"),
            &params,
        );
        assert_eq!(keys[0].0, "github:create_pull_request:overfolder/backend");
    }

    #[test]
    fn service_action_scope_param_missing_value() {
        let params = HashMap::new();
        let keys = PermissionKey::from_service_action(
            "github",
            "create_pull_request",
            Some("repo"),
            &params,
        );
        assert_eq!(keys[0].0, "github:create_pull_request:*");
    }

    #[test]
    fn service_action_no_scope_param() {
        let params = HashMap::new();
        let keys = PermissionKey::from_service_action("github", "list_repos", None, &params);
        assert_eq!(keys[0].0, "github:list_repos:*");
    }

    #[test]
    fn glob_matches_service_action_keys() {
        let rules = vec![rule("github:*:overfolder/*", PermissionEffect::Allow)];
        let keys = vec![PermissionKey(
            "github:create_pull_request:overfolder/backend".into(),
        )];
        assert_eq!(check_permissions(&rules, &keys), PermissionResult::Allowed);
    }

    // ── DerivedKey / SuggestedTier tests ───────────────────────────────

    #[test]
    fn parse_service_action_key() {
        let dk = parse_derived_key("github:create_pull_request:overfolder/backend");
        assert_eq!(dk.service, "github");
        assert_eq!(dk.action, "create_pull_request");
        assert_eq!(dk.arg, "overfolder/backend");
    }

    #[test]
    fn parse_http_key() {
        let dk = parse_derived_key("http:POST:api.github.com/repos/x/pulls");
        assert_eq!(dk.service, "http");
        assert_eq!(dk.action, "POST");
        assert_eq!(dk.arg, "api.github.com/repos/x/pulls");
    }

    #[test]
    fn parse_key_with_star_arg() {
        let dk = parse_derived_key("github:list_repos:*");
        assert_eq!(dk.arg, "*");
    }

    #[test]
    fn parse_key_missing_arg_defaults_to_star() {
        let dk = parse_derived_key("github:list_repos");
        assert_eq!(dk.arg, "*");
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

    // ── Group Ceiling tests ──────────────────────────────────────────

    fn grant(service: &str, level: AccessLevel, auto_read: bool) -> CeilingGrant {
        CeilingGrant {
            service_name: service.to_string(),
            access_level: level,
            auto_approve_reads: auto_read,
        }
    }

    #[test]
    fn ceiling_no_groups_is_permissive() {
        assert_eq!(
            check_group_ceiling("github", Risk::Write, &[], false, false),
            GroupCeilingResult::NoGroups,
        );
    }

    #[test]
    fn ceiling_read_allowed_by_read_grant() {
        let grants = vec![grant("github", AccessLevel::Read, false)];
        assert_eq!(
            check_group_ceiling("github", Risk::Read, &grants, false, true),
            GroupCeilingResult::WithinCeiling,
        );
    }

    #[test]
    fn ceiling_write_denied_by_read_grant() {
        let grants = vec![grant("github", AccessLevel::Read, false)];
        assert!(matches!(
            check_group_ceiling("github", Risk::Write, &grants, false, true),
            GroupCeilingResult::ExceedsCeiling(_),
        ));
    }

    #[test]
    fn ceiling_write_allowed_by_write_grant() {
        let grants = vec![grant("github", AccessLevel::Write, false)];
        assert_eq!(
            check_group_ceiling("github", Risk::Write, &grants, false, true),
            GroupCeilingResult::WithinCeiling,
        );
    }

    #[test]
    fn ceiling_delete_denied_by_write_grant() {
        let grants = vec![grant("github", AccessLevel::Write, false)];
        assert!(matches!(
            check_group_ceiling("github", Risk::Delete, &grants, false, true),
            GroupCeilingResult::ExceedsCeiling(_),
        ));
    }

    #[test]
    fn ceiling_delete_allowed_by_admin_grant() {
        let grants = vec![grant("github", AccessLevel::Admin, false)];
        assert_eq!(
            check_group_ceiling("github", Risk::Delete, &grants, false, true),
            GroupCeilingResult::WithinCeiling,
        );
    }

    #[test]
    fn ceiling_service_not_granted() {
        let grants = vec![grant("slack", AccessLevel::Write, false)];
        assert!(matches!(
            check_group_ceiling("github", Risk::Read, &grants, false, true),
            GroupCeilingResult::ExceedsCeiling(_),
        ));
    }

    #[test]
    fn ceiling_raw_http_allowed() {
        assert_eq!(
            check_group_ceiling("http", Risk::Write, &[], true, true),
            GroupCeilingResult::WithinCeiling,
        );
    }

    #[test]
    fn ceiling_raw_http_denied() {
        assert!(matches!(
            check_group_ceiling("http", Risk::Write, &[], false, true),
            GroupCeilingResult::ExceedsCeiling(_),
        ));
    }

    #[test]
    fn ceiling_auto_approve_reads() {
        let grants = vec![grant("github", AccessLevel::Write, true)];
        assert_eq!(
            check_group_ceiling("github", Risk::Read, &grants, false, true),
            GroupCeilingResult::WithinCeilingAutoApprove,
        );
    }

    #[test]
    fn ceiling_auto_approve_reads_not_for_writes() {
        let grants = vec![grant("github", AccessLevel::Write, true)];
        assert_eq!(
            check_group_ceiling("github", Risk::Write, &grants, false, true),
            GroupCeilingResult::WithinCeiling,
        );
    }

    #[test]
    fn ceiling_most_permissive_grant_wins() {
        // Two groups: one with read, one with admin
        let grants = vec![
            grant("github", AccessLevel::Read, false),
            grant("github", AccessLevel::Admin, false),
        ];
        assert_eq!(
            check_group_ceiling("github", Risk::Delete, &grants, false, true),
            GroupCeilingResult::WithinCeiling,
        );
    }

    #[test]
    fn ceiling_auto_approve_from_any_grant() {
        // One grant without auto_approve, one with
        let grants = vec![
            grant("github", AccessLevel::Write, false),
            grant("github", AccessLevel::Read, true),
        ];
        assert_eq!(
            check_group_ceiling("github", Risk::Read, &grants, false, true),
            GroupCeilingResult::WithinCeilingAutoApprove,
        );
    }

    #[test]
    fn access_level_parse() {
        assert_eq!(AccessLevel::parse("read"), Some(AccessLevel::Read));
        assert_eq!(AccessLevel::parse("write"), Some(AccessLevel::Write));
        assert_eq!(AccessLevel::parse("admin"), Some(AccessLevel::Admin));
        assert_eq!(AccessLevel::parse("invalid"), None);
    }
}
